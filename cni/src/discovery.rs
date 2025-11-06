use std::{net::IpAddr, os::fd::OwnedFd, sync::Arc, time::Duration};

use anyhow::{Result, bail};
use proto::{
    DiscoveryRequest, DiscoveryResponse, intercept_discovery_client::InterceptDiscoveryClient,
};
use tokio::{fs::File, time::sleep};
use tokio_stream::StreamExt;
use tonic::transport;
use tracing::{Instrument, error, info, instrument, trace_span, warn};

use crate::{config::Config, intercept::setup_inpod_redirection};

const MAX_RETRIES: u32 = 5;
const INITIAL_DELAY_MS: u64 = 500;
const SELF_NETNS_PATH: &str = "/proc/self/ns/net";

pub struct Discovery {
    config: Config,
}

impl Discovery {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    #[instrument(
        name = "discovery",
        skip_all,
        err,
        fields(
            host_ip = %self.config.host_ip,
            discovery_url = %self.config.discovery_url
        )
    )]
    pub async fn run(self) -> Result<()> {
        let mut client = self.connect().await?;

        let mut stream = client
            .intercepts(DiscoveryRequest {
                node_ip: self.config.host_ip.to_owned(),
            })
            .instrument(trace_span!("discovery_request", node_ip = %self.config.host_ip))
            .await?
            .into_inner();

        let current_netns = File::open(SELF_NETNS_PATH).await?;
        let current_netns: Arc<OwnedFd> = Arc::new(current_netns.into_std().await.into());

        while let Some(resp) = stream.next().await {
            match resp {
                Ok(resp) => self.handle_response(resp, &current_netns).await,
                Err(e) => error!(error = ?e, "Error in discovery stream"),
            }
        }

        Ok(())
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

    #[instrument(
        skip_all,
        fields(
            resource_count = response.resources.len(),
            total_pod_count = response.resources.iter().map(|r| r.pod_ids.len()).sum::<usize>(),
        )
    )]
    async fn handle_response(&self, response: DiscoveryResponse, current_netns: &Arc<OwnedFd>) {
        let pod_ips = response
            .resources
            .into_iter()
            .flat_map(|endpoint| endpoint.pod_ids.into_iter())
            .map(|identifier| identifier.ip)
            .filter_map(|pod_ip| pod_ip.parse::<IpAddr>().ok());

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
    }
}
