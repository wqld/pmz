use std::{sync::Arc, time::Duration};

use anyhow::{Result, bail};
use h2::{RecvStream, SendStream, client::SendRequest};
use http::Request;
use hyper::body::Bytes;
use k8s_openapi::api::core::v1::Pod;
use proxy::{
    InterceptContext, InterceptRequest,
    tunnel::{
        client::{TunnelClient, establish_h2_with_forward},
        stream::TunnelStream,
    },
};
use tokio::{
    net::TcpStream,
    sync::{
        Mutex,
        broadcast::{self},
        mpsc,
    },
};
use tracing::{Instrument, debug, error, info, instrument, warn};
use uuid::Uuid;

const DIAL_PREFACE: &[u8] = b"dial-preface-from-agent";

pub struct Interceptor {
    intercept_ctx_rx: Arc<Mutex<mpsc::Receiver<InterceptContext>>>,
    shutdown: broadcast::Receiver<()>,
    client: kube::Client,
}

impl Interceptor {
    pub fn new(
        intercept_ctx_rx: Arc<Mutex<mpsc::Receiver<InterceptContext>>>,
        shutdown: broadcast::Receiver<()>,
        client: kube::Client,
    ) -> Self {
        Self {
            intercept_ctx_rx,
            shutdown,
            client,
        }
    }

    #[instrument(name = "interceptor", skip_all, err)]
    pub async fn launch(self) -> Result<()> {
        let mut uuid: Option<Uuid> = None;
        // let agent_ip = self.find_agent_ip().await?;

        loop {
            let (agent_name, agent_namespace) =
                TunnelClient::get_pod_info_by_label(self.client.clone(), "app=pmz-agent").await?;
            let agent_port = 8101;
            let pods: kube::Api<Pod> = kube::Api::namespaced(self.client.clone(), &agent_namespace);

            let (sender, conn, _) =
                match establish_h2_with_forward(&pods, &agent_name, agent_port).await {
                    Ok(res) => res,
                    Err(e) => {
                        error!("Failed to connect agent: {e}. Retry in 1s...");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                };

            let conn_handle = tokio::spawn(conn);
            info!("connected to agent");

            let mut send_req = sender.ready().await?;
            match establish_dial_stream(&mut send_req, uuid).await {
                Ok((send, recv, client_id)) => {
                    info!("Connected to Agent. Session UUID: {client_id}");
                    uuid = Some(client_id);

                    let (intercept_tx, intercept_rx) = mpsc::channel::<Bytes>(1);
                    let intercept_ctx_rx = self.intercept_ctx_rx.clone();

                    let register_handle = tokio::spawn(
                        async move {
                            register_intercept_rule(intercept_ctx_rx.clone(), send, client_id).await
                        }
                        .in_current_span(),
                    );

                    let shutdown_receive_task = self.shutdown.resubscribe();
                    let shutdown_process_task = self.shutdown.resubscribe();

                    let receive_handle = tokio::spawn(
                        async move {
                            receive_target_port(recv, intercept_tx, shutdown_receive_task).await
                        }
                        .in_current_span(),
                    );

                    let process_handle = tokio::spawn(
                        async move {
                            process_intercept_request(
                                intercept_rx,
                                send_req,
                                client_id,
                                shutdown_process_task,
                            )
                            .await
                        }
                        .in_current_span(),
                    );

                    tokio::select! {
                        _ = register_handle => warn!("Register task ended"),
                        _ = receive_handle => warn!("Receive task ended"),
                        _ = process_handle => warn!("Process task ended"),
                        _ = conn_handle => warn!("Connection lost"),
                    }
                }
                Err(e) => {
                    error!("Failed to establish dial stream: {e}");
                }
            };
        }
    }
}

#[instrument(skip_all)]
async fn establish_dial_stream(
    send_req: &mut SendRequest<Bytes>,
    uuid: Option<Uuid>,
) -> Result<(SendStream<Bytes>, RecvStream, Uuid)> {
    let mut builder = Request::builder().uri("/dial");

    if let Some(id) = uuid {
        builder = builder.header("x-pmz-daemon-id", id.to_string());
        debug!("Trying to restore session with UUID: {id}");
    }

    let req = builder.body(())?;

    // send the preface
    let (resp, mut send) = send_req.send_request(req, false)?;
    send.send_data(DIAL_PREFACE.into(), false)?;

    let resp = resp.await?;
    let mut recv = resp.into_body();

    // get an uuid
    let uuid = if let Some(data) = recv.data().await {
        let data = data?;
        Uuid::from_slice(&data)?
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
