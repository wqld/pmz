use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use anyhow::{Result, bail};
use aya::maps::{HashMap, MapData};
use common::{DnsQuery, DnsRecordA};
use h2::{RecvStream, SendStream, client::SendRequest};
use http::Request;
use hyper::body::Bytes;
use proxy::{
    InterceptContext, InterceptRequest,
    tunnel::{client::establish_h2_connection, stream::TunnelStream},
};
use tokio::{
    net::TcpStream,
    sync::{
        Mutex, RwLock,
        broadcast::{self},
        mpsc,
    },
    time::sleep,
};
use tracing::{Instrument, debug, error, info, instrument};
use uuid::Uuid;

use crate::{deploy::Deploy, discovery::Discovery};

const DIAL_PREFACE: &[u8] = b"dial-preface-from-agent";

pub struct Interceptor {
    service_registry: Arc<RwLock<HashMap<MapData, DnsQuery, DnsRecordA>>>,
    intercept_ctx_rx: Arc<Mutex<mpsc::Receiver<InterceptContext>>>,
    shutdown: broadcast::Receiver<()>,
    client: kube::Client,
}

impl Interceptor {
    pub fn new(
        service_registry: Arc<RwLock<HashMap<MapData, DnsQuery, DnsRecordA>>>,
        intercept_ctx_rx: Arc<Mutex<mpsc::Receiver<InterceptContext>>>,
        shutdown: broadcast::Receiver<()>,
        client: kube::Client,
    ) -> Self {
        Self {
            service_registry,
            intercept_ctx_rx,
            shutdown,
            client,
        }
    }

    #[instrument(name = "interceptor", skip_all, err)]
    pub async fn launch(mut self) -> Result<()> {
        let agent_ip = self.find_agent_ip().await?;
        let (sender, conn) = establish_h2_connection(&agent_ip, 8101, false).await?;
        tokio::spawn(conn);
        let mut send_req = sender.ready().await?;

        let (send, recv, client_id) = establish_dial_stream(&mut send_req).await?;
        let (intercept_tx, intercept_rx) = mpsc::channel::<Bytes>(1);
        let shutdown_receive_task = self.shutdown.resubscribe();
        let shutdown_process_task = self.shutdown.resubscribe();

        tokio::spawn(
            async move { register_intercept_rule(self.intercept_ctx_rx, send, client_id).await }
                .in_current_span(),
        );

        tokio::spawn(
            async move { receive_target_port(recv, intercept_tx, shutdown_receive_task).await }
                .in_current_span(),
        );

        tokio::spawn(
            async move {
                process_intercept_request(intercept_rx, send_req, client_id, shutdown_process_task)
                    .await
            }
            .in_current_span(),
        );

        if let Err(e) = self.shutdown.recv().await {
            error!(error = ?e, "Interceptor shudown");
        }

        Ok(())
    }

    #[instrument(skip_all)]
    async fn find_agent_ip(&mut self) -> Result<String> {
        const INITIAL_BACKOFF: Duration = Duration::from_millis(100);
        const MAX_BACKOFF: Duration = Duration::from_secs(5);
        let mut current_delay = INITIAL_BACKOFF;

        let (_, ns) = Deploy::get_pod_info_by_label(self.client.clone(), "app=pmz-agent").await?;
        let dns_query = Discovery::create_dns_query("pmz-agent", &ns);

        loop {
            let service_registry = self.service_registry.read().await;
            if let Ok(ip) = service_registry.get(&dns_query, 0) {
                let agent_ip = Ipv4Addr::from(ip.ip).to_string();
                debug!("Found IP for pmz-agent: {}", agent_ip);
                return Ok(agent_ip);
            } else {
                drop(service_registry);
                error!(
                    "service 'pmz-agent' not yet available in registry. Retrying in {:?}...",
                    current_delay
                );

                tokio::select! {
                    _ = sleep(current_delay) => current_delay = (current_delay * 2).min(MAX_BACKOFF),
                    _ = self.shutdown.recv() => bail!("Shutdown received while waiting to retry connection."),
                }
            }
        }
    }
}

#[instrument(skip_all)]
async fn establish_dial_stream(
    send_req: &mut SendRequest<Bytes>,
) -> Result<(SendStream<Bytes>, RecvStream, Uuid)> {
    let req = Request::builder().uri("/dial").body(()).unwrap();

    // send the preface
    let (resp, mut send) = send_req.send_request(req, false).unwrap();
    send.send_data(DIAL_PREFACE.into(), false).unwrap();

    let resp = resp.await.unwrap();
    let mut recv = resp.into_body();

    // get an uuid
    let uuid = if let Some(data) = recv.data().await {
        let data = data.unwrap();
        Uuid::from_slice(&data).unwrap()
    } else {
        bail!("Failed to establish with agent");
    };

    debug!("UUID is allocated from agent: {uuid:?}");
    Ok((send, recv, uuid))
}

#[instrument(skip_all)]
pub async fn register_intercept_rule(
    intercept_ctx_rx: Arc<Mutex<mpsc::Receiver<InterceptContext>>>,
    mut send: SendStream<Bytes>,
    uuid: Uuid,
) {
    info!("Starting intercept rule registration task");

    while let Some(mut ctx) = intercept_ctx_rx.lock().await.recv().await {
        ctx.id = uuid.into_bytes();
        let rule_id = ctx.id;

        let payload = match serde_json::to_vec(&ctx) {
            Ok(v) => v,
            Err(e) => {
                error!(
                    ctx_id = ?rule_id,
                    error = ?e,
                    "Failed to serialize intercept context"
                );
                continue;
            }
        };

        debug!(
            ctx_id = ?rule_id,
            payload_size = payload.len(),
            "Sending intercept rule"
        );

        if let Err(e) = send.send_data(payload.into(), false) {
            error!(
                ctx_id = ?rule_id,
                error = ?e,
                "Failed to send intercept rule. Stopping task."
            );
            break;
        }
    }

    info!("Intercept context channel closed. Shutting down task.");
}

#[instrument(skip_all)]
pub async fn receive_target_port(
    mut recv: RecvStream,
    intercept_tx: mpsc::Sender<Bytes>,
    mut shutdown: broadcast::Receiver<()>,
) {
    debug!("Start");

    loop {
        tokio::select! {
            Some(data) = recv.data() => {
                match data {
                    Ok(target_port) => {
                        if let Err(e) = intercept_tx.send(target_port).await {
                            error!("intercept_tx.send failed: {e:?}")
                        }
                    },
                    Err(e) => {
                        error!("recv.data failed, stream is broken: {e:?}");
                        break;
                    },
                }
            }
            _ = shutdown.recv() => break
        }
    }

    debug!("Exit");
}

#[instrument(skip_all)]
pub async fn process_intercept_request(
    mut intercept_rx: mpsc::Receiver<Bytes>,
    send_req: SendRequest<Bytes>,
    client_id: Uuid,
    mut shutdown: broadcast::Receiver<()>,
) {
    debug!("Start");

    loop {
        tokio::select! {
            Some(target_port) = intercept_rx.recv() => {
                let target_port = {
                    let byte_slice = target_port.as_ref();

                    if byte_slice.len() != 2 {
                        error!("target_port's slice must be 2 bytes");
                        continue
                    }

                    u16::from_be_bytes([byte_slice[0], byte_slice[1]])
                };

                let send_req = send_req.clone();

                tokio::spawn(async move {
                    establish_intercept_tunnel(send_req, client_id, target_port).await.unwrap();
                }.in_current_span());
            }
            _ = shutdown.recv() => break
        }
    }

    debug!("Stop");
}

#[instrument(skip_all, err)]
pub async fn establish_intercept_tunnel(
    mut send_req: SendRequest<Bytes>,
    client_id: Uuid,
    target_port: u16,
) -> Result<()> {
    let req = Request::builder().uri("/intercept").body(())?;

    let (resp, mut send) = send_req.send_request(req, false)?;
    let intercept_req = InterceptRequest {
        id: client_id.into_bytes(),
        target_port,
    };
    let intercept_req = serde_json::to_vec(&intercept_req)?;
    send.send_data(intercept_req.into(), false)?;

    let resp = resp.await?;
    debug!("got response: {:?}", resp);

    let recv = resp.into_body();

    let mut downstream = TunnelStream { recv, send };
    let target_addr = format!("localhost:{}", target_port);
    let mut upstream = TcpStream::connect(target_addr).await?;

    tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await?;

    Ok(())
}
