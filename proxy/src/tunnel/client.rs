use std::{path::Path, pin::Pin, sync::Arc, time::Duration};

use anyhow::{Result, bail};
use h2::client::SendRequest;
use hyper::body::Bytes;
use k8s_openapi::api::core::v1::{Pod, Secret};
use kube::{
    Api, Resource, ResourceExt,
    api::ListParams,
    runtime::{conditions::is_pod_running, wait::await_condition},
};
use tokio::{
    fs::File,
    io::AsyncWriteExt,
    sync::{Mutex, broadcast, mpsc::Receiver, oneshot},
};
use tracing::{Instrument, debug, error, info, instrument};

use crate::tunnel::stream::{ProxyStream, TunnelStream};

use super::PMZ_PROTO_HDR;

type ConnectionFuture = Pin<Box<dyn Future<Output = Result<(), h2::Error>> + Send>>;

pub struct TunnelClient {
    tunnel_port: u16,
    req_rx: Arc<Mutex<Receiver<TunnelRequest>>>,
    shutdown: broadcast::Receiver<()>,
}

impl TunnelClient {
    pub fn new(
        tunnel_port: u16,
        req_rx: Arc<Mutex<Receiver<TunnelRequest>>>,
        shutdown: broadcast::Receiver<()>,
    ) -> Self {
        Self {
            tunnel_port,
            req_rx,
            shutdown,
        }
    }

    pub async fn get_pod_info_by_label(
        client: kube::Client,
        label: &str,
    ) -> Result<(String, String)> {
        let pods: Api<Pod> = Api::all(client);

        let lp = ListParams::default().labels(label);
        let res = pods.list(&lp).await?;
        match res.iter().last() {
            Some(p) => Ok((
                p.name_any(),
                p.meta().namespace.clone().unwrap_or("default".to_owned()),
            )),
            None => bail!("failed to get resource"),
        }
    }

    #[instrument(name = "tunnel_client", skip_all, err, fields(port = %self.tunnel_port))]
    pub async fn run(&mut self) -> Result<()> {
        const INITIAL_BACKOFF: Duration = Duration::from_millis(100);
        const MAX_BACKOFF: Duration = Duration::from_secs(10);

        let mut current_delay = INITIAL_BACKOFF;

        'retry_loop: loop {
            debug!("Attempting to establish H2 connection...");

            let client = match kube::Client::try_default().await {
                Ok(c) => c,
                Err(e) => {
                    error!(error = ?e, "Failed to create kube client. Retrying in {:?}...", current_delay);
                    tokio::time::sleep(current_delay).await;
                    current_delay = (current_delay * 2).min(MAX_BACKOFF);
                    continue 'retry_loop;
                }
            };

            let (agent_name, agent_namespace) = match Self::get_pod_info_by_label(
                client.clone(),
                "app=pmz-agent",
            )
            .await
            {
                Ok(pod_info) => pod_info,
                Err(e) => {
                    error!(error = ?e, "pmz-agent not found. Retrying in {:?}...", current_delay);
                    tokio::time::sleep(current_delay).await;
                    current_delay = (current_delay * 2).min(MAX_BACKOFF);
                    continue 'retry_loop;
                }
            };

            if let Ok(secrets) = Api::<Secret>::namespaced(client.clone(), &agent_namespace)
                .get("pmz-tls")
                .await
            {
                if let Some(data) = secrets.data {
                    if let Some(crt_data) = data.get("tls.crt") {
                        if let Ok(home_dir) = std::env::var("HOME") {
                            let cert_path = Path::new(&home_dir).join(".config/pmz/certs/pmz.crt");
                            let needs_update = if cert_path.exists() {
                                match std::fs::read(&cert_path) {
                                    Ok(existing_bytes) => existing_bytes != crt_data.0,
                                    Err(_) => true,
                                }
                            } else {
                                true
                            };

                            if needs_update {
                                if let Some(parent) = cert_path.parent() {
                                    let _ = std::fs::create_dir_all(parent);
                                }
                                if let Ok(mut cert_file) = File::create(&cert_path).await {
                                    let _ = cert_file.write_all(&crt_data.0).await;
                                    debug!("Updated tls.crt file");
                                }
                            }
                        }
                    }
                }
            }

            let pods: Api<Pod> = Api::namespaced(client.clone(), &agent_namespace);
            let running = await_condition(pods.clone(), &agent_name, is_pod_running());
            if let Err(e) = tokio::time::timeout(std::time::Duration::from_secs(5), running).await {
                error!(error = ?e, "Timed out waiting for pod to be running. Retrying...");
                tokio::time::sleep(current_delay).await;
                continue 'retry_loop;
            }

            let agent_port = 8100;

            let (sender, conn, mut ping_pong) = match establish_h2_with_forward(
                &pods,
                &agent_name,
                agent_port,
            )
            .await
            {
                Ok(res) => {
                    info!("Tunnel connection established!");
                    current_delay = INITIAL_BACKOFF;
                    res
                }
                Err(e) => {
                    error!(error = ?e, "Failed to establish connection. Retrying in {:?}...", current_delay);

                    tokio::select! {
                        _ = tokio::time::sleep(current_delay) => {
                            current_delay = (current_delay * 2).min(MAX_BACKOFF);
                            continue 'retry_loop;
                        }
                        _ = self.shutdown.recv() => {
                            debug!("Shutdown received while waiting to retry connection.");
                            return Ok(());
                        }
                    }
                }
            };

            tokio::pin!(conn);

            let (ping_tx, mut ping_rx) = oneshot::channel::<()>();

            tokio::spawn(async move {
                loop {
                    let ping = ping_pong.ping(h2::Ping::opaque());
                    match tokio::time::timeout(Duration::from_secs(20), ping).await {
                        Ok(Ok(_)) => {
                            tokio::time::sleep(Duration::from_secs(10)).await;
                        }
                        _ => {
                            let _ = ping_tx.send(());
                            return;
                        }
                    }
                }
            });

            loop {
                let mut req_rx = self.req_rx.lock().await;

                tokio::select! {
                    res = &mut conn => {
                        error!(error = ?res, "H2 connection finished unexpectedly. Reconnecting...");
                        continue 'retry_loop;
                    },
                    _ = &mut ping_rx => {
                        error!("Heartbeat failed. Reconnecting...");
                        continue 'retry_loop;
                    },
                    Some(tunnel_req) = req_rx.recv() => {
                        self.handle_tunnel_request(sender.clone(), tunnel_req).await;
                    },
                    _ = self.shutdown.recv() => {
                        debug!("Tunnel shutdown");
                        return Ok(())
                    }
                }
            }
        }
    }

    #[instrument(name = "handle", skip_all)]
    async fn handle_tunnel_request(
        &self,
        send_req: SendRequest<Bytes>,
        mut tunnel_req: TunnelRequest,
    ) {
        let mut send_req = send_req.clone();
        tokio::spawn(
            async move {
                let target = tunnel_req.target;

                let req = http::Request::builder()
                    .uri(target)
                    .method(http::Method::CONNECT)
                    .version(http::Version::HTTP_2)
                    .header(PMZ_PROTO_HDR, tunnel_req.protocol)
                    .body(())
                    .unwrap();

                futures::future::poll_fn(|cx| send_req.poll_ready(cx))
                    .await
                    .unwrap();

                let (resp, send) = send_req.send_request(req, false).unwrap();
                let recv = resp.await.unwrap().into_body();

                let mut server = TunnelStream { recv, send };

                let (from_client, from_server) =
                    tokio::io::copy_bidirectional(&mut tunnel_req.stream, &mut server)
                        .await
                        .unwrap();

                debug!(
                    "Client wrote {} bytes and received {} bytes",
                    from_client, from_server
                );
            }
            .in_current_span(),
        );
    }
}

pub async fn establish_h2_with_forward(
    pods: &Api<Pod>,
    agent_name: &str,
    agent_port: u16,
) -> Result<(SendRequest<Bytes>, ConnectionFuture, h2::PingPong)> {
    let mut forwarder = pods.portforward(agent_name, &[agent_port]).await?;
    let stream = forwarder.take_stream(agent_port).unwrap();

    // let mut client_config = ClientConfig::builder()
    //     .dangerous()
    //     .with_custom_certificate_verifier(PmzCertVerifier::new())
    //     .with_no_client_auth();
    // client_config.alpn_protocols = vec![b"h2".to_vec()];
    // let tls_connector = TlsConnector::from(Arc::new(client_config));

    // let tls_stream = tls_connector
    //     .connect(ServerName::try_from(host.to_owned())?, stream)
    //     .await?;

    let mut builder = h2::client::Builder::new();
    let (sender, mut conn) = builder
        .initial_window_size(4 * 1024 * 1024)
        .initial_connection_window_size(16 * 1025 * 1024)
        .max_frame_size(1024 * 1024)
        .max_header_list_size(65536)
        .max_send_buffer_size(1024 * 400)
        .max_concurrent_streams(200)
        .handshake(stream)
        .await?;

    let ping_pong = conn.ping_pong().unwrap();

    Ok((sender, Box::pin(conn), ping_pong))
}

pub struct TunnelRequest {
    pub protocol: &'static str,
    pub stream: ProxyStream,
    pub target: String,
}
