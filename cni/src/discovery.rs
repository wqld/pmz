use std::{net::IpAddr, os::fd::OwnedFd, sync::Arc, time::Duration};

use anyhow::{Result, anyhow, bail};
use cni::InterceptRuleCache;
use proto::{
    Ack, DiscoveryRequest, InterceptEndpoint, discovery_request::Payload as ReqPayload,
    discovery_response::Payload as RespPayload,
    intercept_discovery_client::InterceptDiscoveryClient,
};
use tokio::{
    fs::File,
    sync::{RwLock, broadcast, mpsc},
    time::sleep,
};
use tokio_stream::{StreamExt, wrappers::ReceiverStream};
use tonic::transport;
use tracing::{Instrument, debug, error, info, instrument, trace_span, warn};

use crate::{
    config::Config,
    intercept::{setup_inpod_redirection, stop_inpod_redirection},
};

const MAX_RETRIES: u32 = 5;
const INITIAL_DELAY_MS: u64 = 500;
const SELF_NETNS_PATH: &str = "/proc/self/ns/net";

pub struct Discovery {
    config: Config,
    intercept_rule_cache: Arc<RwLock<InterceptRuleCache>>,
}

impl Discovery {
    pub fn new(config: Config, intercept_rule_cache: Arc<RwLock<InterceptRuleCache>>) -> Self {
        Self {
            config,
            intercept_rule_cache,
        }
    }

    #[instrument(
        name = "discovery", skip_all, err,
        fields(
            host_ip = %self.config.host_ip,
            discovery_url = %self.config.discovery_url
        )
    )]
    pub async fn run(self) -> Result<()> {
        loop {
            let mut client = match self.connect().await {
                Ok(c) => c,
                Err(e) => {
                    error!(error = ?e, "Failed to connect. Retrying in 5s..");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
            };

            info!("Connection established. Starting stream...");

            let (tx, rx) = mpsc::channel(128);

            let stream = ReceiverStream::new(rx);
            let request = tonic::Request::new(stream);
            let mut response = client
                .intercepts(request)
                .instrument(trace_span!("intercepts", node_ip = %self.config.host_ip))
                .await?
                .into_inner();

            tx.send(DiscoveryRequest {
                payload: Some(ReqPayload::Hello(proto::PdsHello {
                    node_ip: self.config.host_ip.to_owned(),
                    revision: "1".to_owned(),
                })),
            })
            .await?;

            let current_netns = File::open(SELF_NETNS_PATH).await?;
            let current_netns: Arc<OwnedFd> = Arc::new(current_netns.into_std().await.into());

            let mut snapshot_complete = false;
            // let mut received_rules = HashMap::new();

            while let Some(resp) = response.next().await {
                match resp {
                    Ok(resp) => match resp.payload {
                        Some(RespPayload::Add(add_msg)) => {
                            info!("Snapshot Add: {}", add_msg.uid);

                            if let Some(endpoint) = add_msg.endpoint {
                                self.handle_add(
                                    &add_msg.uid,
                                    &endpoint,
                                    &current_netns,
                                    self.intercept_rule_cache.clone(),
                                    &tx,
                                )
                                .await?;
                            }
                        }
                        Some(RespPayload::SnapshotSent(_)) => {
                            info!("Snapshot complete.");
                            snapshot_complete = true;

                            self.reconcile_local_state(self.intercept_rule_cache.clone())
                                .await;

                            tx.send(DiscoveryRequest {
                                payload: Some(ReqPayload::Ack(Ack {
                                    uid: "".to_string(),
                                    error: "".to_string(),
                                })),
                            })
                            .await?;

                            break;
                        }
                        Some(RespPayload::Remove(remove_msg)) => {
                            bail!("Received Remove during snapshot: {}", remove_msg.uid);
                        }
                        None => {}
                    },
                    Err(e) => {
                        bail!("Error in discovery stream (snapshot): {:?}", e);
                    }
                }
            }

            if !snapshot_complete {
                bail!("Stream ended before snapshot completed");
            }

            info!("Entering live update mode...");
            while let Some(resp) = response.next().await {
                match resp {
                    Ok(resp) => match resp.payload {
                        Some(RespPayload::Add(add_msg)) => {
                            info!("Live Add/Update: {}", add_msg.uid);

                            if let Some(endpoint) = add_msg.endpoint {
                                self.handle_add(
                                    &add_msg.uid,
                                    &endpoint,
                                    &current_netns,
                                    self.intercept_rule_cache.clone(),
                                    &tx,
                                )
                                .await?;
                            }
                        }
                        Some(RespPayload::Remove(remove_msg)) => {
                            self.handle_remove(
                                &remove_msg.uid,
                                &current_netns,
                                self.intercept_rule_cache.clone(),
                                &tx,
                            )
                            .await?;
                        }
                        _ => {
                            error!(
                                "Received unexpected message in live update mode. Protocol error."
                            );
                            return Err(anyhow!(
                                "Protocol error: Received unexpected message in live mode"
                            ));
                        }
                    },
                    Err(e) => {
                        error!(error = ?e, "Error in discovery stream (live update)");
                        return Err(e.into());
                    }
                }
            }
        }
    }

    #[instrument(skip_all, err)]
    async fn connect(&self) -> Result<InterceptDiscoveryClient<tonic::transport::Channel>> {
        for attempt in 0..MAX_RETRIES {
            match transport::Endpoint::from_shared(self.config.discovery_url.to_owned())?
                .connect()
                .await
            {
                Ok(ch) => {
                    info!("Successfully connected to discovery server");
                    return Ok(InterceptDiscoveryClient::new(ch));
                }
                Err(e) => {
                    warn!(
                        error = ?e,
                        attempt = attempt + 1,
                        max_retries = MAX_RETRIES,
                        "Connection failed, will retry..."
                    );

                    if attempt == MAX_RETRIES - 1 {
                        break;
                    }

                    let delay = Duration::from_millis(INITIAL_DELAY_MS * 2_u64.pow(attempt));
                    warn!(?delay, "Retrying connection");
                    sleep(delay).await;
                }
            }
        }

        bail!("Failed to connect after all retries.");
    }

    async fn handle_add(
        &self,
        uid: &str,
        endpoint: &InterceptEndpoint,
        current_netns: &Arc<OwnedFd>,
        rule_cache: Arc<RwLock<InterceptRuleCache>>,
        tx: &mpsc::Sender<DiscoveryRequest>,
    ) -> Result<()> {
        info!("Handling ADD for endpoint: {:?}", endpoint);

        let (stop_tx, _) = broadcast::channel::<()>(1);

        let pod_ips: Vec<IpAddr> = endpoint
            .pod_ids
            .clone()
            .into_iter()
            .map(|id| id.ip)
            .filter_map(|pod_ip| pod_ip.parse::<IpAddr>().ok())
            .collect();

        {
            let mut cache = rule_cache.write().await;
            match cache.insert(uid.to_string(), (pod_ips.clone(), stop_tx)) {
                Some((old_pod_ips, _)) => {
                    debug!(?uid, ?old_pod_ips, ?pod_ips, "Inserted");
                }
                None => {
                    debug!(?uid, ?pod_ips, "Newerly Inserted");
                }
            }
        }

        for pod_ip in pod_ips {
            if let Err(e) = setup_inpod_redirection(
                pod_ip,
                &self.config.intercept_gate_addr,
                current_netns.clone(),
                None,
            )
            .await
            {
                error!(?pod_ip, error = ?e, "Failed to setup redirection for pod");
            }
        }

        tx.send(DiscoveryRequest {
            payload: Some(ReqPayload::Ack(Ack {
                uid: "".to_string(),
                error: "".to_string(),
            })),
        })
        .await?;

        Ok(())
    }

    #[instrument(name = "remove", skip_all, err)]
    async fn handle_remove(
        &self,
        uid: &str,
        current_netns: &Arc<OwnedFd>,
        rule_cche: Arc<RwLock<InterceptRuleCache>>,
        tx: &mpsc::Sender<DiscoveryRequest>,
    ) -> Result<()> {
        info!("Handling REMOVE for rule_id: {:?}", uid);

        let mut cache = rule_cche.write().await;

        if let Some((pod_ips, stop_tx)) = cache.get(uid) {
            for pod_ip in pod_ips {
                stop_inpod_redirection(pod_ip.clone(), current_netns.clone()).await?;
            }

            match cache.remove(uid) {
                Some((pod_ips, _)) => {
                    debug!(?uid, ?pod_ips, "Removed from Intercept Rule Cache");
                }
                None => {
                    debug!(?uid, "It doesn't exist");
                }
            }

            tx.send(DiscoveryRequest {
                payload: Some(ReqPayload::Ack(Ack {
                    uid: "".to_string(),
                    error: "".to_string(),
                })),
            })
            .await?;
        }

        Ok(())
    }

    // Mock-up of reconcile_local_state
    async fn reconcile_local_state(&self, rule_cache: Arc<RwLock<InterceptRuleCache>>) {
        info!("Reconciling local state. Active rules: {:?}", rule_cache);
        // TODO
    }
}
