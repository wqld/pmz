use std::{pin::Pin, sync::Arc, time::Duration};

use anyhow::Result;
use h2::client::SendRequest;
use hyper::body::Bytes;
use rustls::{ClientConfig, pki_types::ServerName};
use socket2::{SockRef, TcpKeepalive};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::{Mutex, broadcast, mpsc::Receiver},
    time::{Instant, sleep},
};
use tokio_rustls::TlsConnector;
use tracing::{Instrument, debug, error, instrument};

use crate::tunnel::stream::TunnelStream;

use super::{PMZ_PROTO_HDR, verifier::PmzCertVerifier};

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

    #[instrument(name = "tunnel_client", skip_all, err, fields(port = %self.tunnel_port))]
    pub async fn run(&mut self) -> Result<()> {
        const INITIAL_BACKOFF: Duration = Duration::from_millis(100);
        const MAX_BACKOFF: Duration = Duration::from_secs(10);
        let mut current_delay = INITIAL_BACKOFF;

        'retry_loop: loop {
            debug!("Attempting to establish H2 connection...");

            let (sender, conn) = match establish_h2_connection("localhost", self.tunnel_port, true)
                .await
            {
                Ok(res) => res,
                Err(e) => {
                    error!(error = ?e, "Failed to establish connection. Retrying in {:?}...", current_delay);

                    tokio::select! {
                        _ = sleep(current_delay) => {
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

            let send_req = sender.ready().await?;

            loop {
                let mut req_rx = self.req_rx.lock().await;
                let mut interval = tokio::time::interval_at(
                    Instant::now() + Duration::from_secs(60),
                    Duration::from_secs(60),
                );

                tokio::select! {
                    res = &mut conn => {
                        error!(error = ?res, "H2 connection task finished unexpectedly. Shutting down tunnel.");
                        continue 'retry_loop;
                    },
                    Some(tunnel_req) = req_rx.recv() => self.handle_tunnel_request(send_req.clone(), tunnel_req).await,
                    _ = interval.tick() => self.heartbeat(send_req.clone()).await,
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

                tokio::spawn(
                    async move {
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
            .in_current_span(),
        );
    }

    #[instrument(skip_all)]
    async fn heartbeat(&self, send_req: SendRequest<Bytes>) {
        let mut send_req = send_req.clone();

        tokio::spawn(async move {
            let req = http::Request::builder()
                .uri("/health")
                .method(http::Method::GET)
                .version(http::Version::HTTP_11)
                .body(())
                .unwrap();

            futures::future::poll_fn(|cx| send_req.poll_ready(cx))
                .await
                .unwrap();
            let (resp, _) = send_req.send_request(req, true).unwrap();
            let resp = resp.await.unwrap();

            debug!(status = ?resp.status(), "Heartbeat");
        });
    }
}

pub async fn establish_h2_connection(
    host: &str,
    port: u16,
    use_tls: bool,
) -> Result<(SendRequest<Bytes>, ConnectionFuture)> {
    let tunnel_addr = format!("{}:{}", host, port);
    let stream = TcpStream::connect(tunnel_addr).await?;
    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(30))
        .with_interval(Duration::from_secs(30));
    let sock_ref = SockRef::from(&stream);
    sock_ref.set_tcp_keepalive(&keepalive)?;

    Ok(if use_tls {
        let mut client_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(PmzCertVerifier::new())
            .with_no_client_auth();
        client_config.alpn_protocols = vec![b"h2".to_vec()];
        let tls_connector = TlsConnector::from(Arc::new(client_config));

        let tls_stream = tls_connector
            .connect(ServerName::try_from(host.to_owned())?, stream)
            .await?;

        let (sender, conn) = h2::client::handshake(tls_stream).await?;
        (sender, Box::pin(conn) as ConnectionFuture)
    } else {
        let (sender, conn) = h2::client::handshake(stream).await?;
        (sender, Box::pin(conn) as ConnectionFuture)
    })
}

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> Stream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub struct TunnelRequest {
    pub protocol: &'static str,
    pub stream: Box<dyn Stream>,
    pub target: String,
}
