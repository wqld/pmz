use core::str;
use std::{io::ErrorKind, pin::Pin, sync::Arc, task::Poll, time::Duration};

use anyhow::Result;
use futures::ready;
use h2::{client::SendRequest, Reason, RecvStream, SendStream};
use hyper::body::Bytes;
use log::debug;
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName},
    ClientConfig, SignatureScheme,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::{broadcast, mpsc::Receiver, Mutex},
    time::Instant,
};
use tokio_rustls::TlsConnector;

pub struct Tunnel {
    tunnel_host: String,
    tunnel_port: u16,
    req_rx: Arc<Mutex<Receiver<TunnelRequest>>>,
}

impl Tunnel {
    pub fn new(
        tunnel_host: &str,
        tunnel_port: u16,
        req_rx: Arc<Mutex<Receiver<TunnelRequest>>>,
    ) -> Self {
        Self {
            tunnel_host: tunnel_host.to_owned(),
            tunnel_port,
            req_rx,
        }
    }

    pub async fn run(&self, mut shutdown: broadcast::Receiver<()>) -> Result<()> {
        let tunnel_addr = format!("{}:{}", self.tunnel_host, self.tunnel_port);
        let stream = TcpStream::connect(tunnel_addr).await.unwrap();

        let mut client_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(NoVerifier::new())
            .with_no_client_auth();
        client_config.alpn_protocols = vec![b"h2".to_vec()];
        let tls_connector = TlsConnector::from(Arc::new(client_config));

        let tls_stream = tls_connector
            .connect(
                ServerName::try_from(self.tunnel_host.clone()).unwrap(),
                stream,
            )
            .await
            .unwrap();

        let (sender, conn) = h2::client::handshake(tls_stream).await.unwrap();
        tokio::spawn(conn);

        let send_req = sender.ready().await.unwrap();

        loop {
            let mut req_rx = self.req_rx.lock().await;
            let mut interval = tokio::time::interval_at(
                Instant::now() + Duration::from_secs(60),
                Duration::from_secs(60),
            );

            tokio::select! {
                Some(tunnel_req) = req_rx.recv() => self.handle_tunnel_request(send_req.clone(), tunnel_req).await,
                _ = interval.tick() => self.heartbeat(send_req.clone()).await,
                _ = shutdown.recv() => {
                    debug!("tunnel shutdown");
                    return Ok(())
                }
            }
        }
    }

    async fn handle_tunnel_request(
        &self,
        send_req: SendRequest<Bytes>,
        mut tunnel_req: TunnelRequest,
    ) {
        let send_req = send_req.clone();

        tokio::spawn(async move {
            let target = tunnel_req.target;

            let req = http::Request::builder()
                .uri(target)
                .method(http::Method::CONNECT)
                .version(http::Version::HTTP_2)
                .body(())
                .unwrap();

            let mut send_req = send_req.ready().await.unwrap();
            let (resp, send) = send_req.send_request(req, false).unwrap();
            let recv = resp.await.unwrap().into_body();

            tokio::spawn(async move {
                let mut server = TunnelStream { recv, send };

                let (from_client, from_server) =
                    tokio::io::copy_bidirectional(&mut tunnel_req.stream, &mut server)
                        .await
                        .unwrap();

                debug!(
                    "client wrote {} bytes and received {} bytes",
                    from_client, from_server
                );
            });
        });
    }

    async fn heartbeat(&self, send_req: SendRequest<Bytes>) {
        let send_req = send_req.clone();

        tokio::spawn(async move {
            let req = http::Request::builder()
                .uri("127.0.0.1:8101")
                .method(http::Method::CONNECT)
                .version(http::Version::HTTP_2)
                .body(())
                .unwrap();

            let mut send_req = send_req.ready().await.unwrap();
            let (resp, _) = send_req.send_request(req, true).unwrap();
            let resp = resp.await.unwrap();

            debug!("heartbeat: {}", resp.status());
        });
    }
}

pub struct TunnelRequest {
    pub stream: TcpStream,
    pub target: String,
}

struct TunnelStream {
    recv: RecvStream,
    send: SendStream<Bytes>,
}

impl TunnelStream {
    fn send_data(&mut self, buf: &[u8], end_of_stream: bool) -> std::result::Result<(), h2::Error> {
        let bytes = Bytes::copy_from_slice(buf);
        self.send.send_data(bytes, end_of_stream)
    }

    fn handle_io_error(e: h2::Error) -> std::io::Error {
        if e.is_io() {
            e.into_io().unwrap()
        } else {
            std::io::Error::new(std::io::ErrorKind::Other, e)
        }
    }
}

impl AsyncRead for TunnelStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            match ready!(self.recv.poll_data(cx)) {
                Some(Ok(bytes)) if bytes.is_empty() && !self.recv.is_end_stream() => continue,
                Some(Ok(bytes)) => {
                    let _ = self.recv.flow_control().release_capacity(bytes.len());
                    buf.put_slice(&bytes);
                    return Poll::Ready(Ok(()));
                }
                Some(Err(e)) => {
                    let err = match e.reason() {
                        Some(Reason::NO_ERROR) | Some(Reason::CANCEL) => {
                            return Poll::Ready(Ok(()))
                        }
                        Some(Reason::STREAM_CLOSED) => {
                            std::io::Error::new(std::io::ErrorKind::BrokenPipe, e)
                        }
                        _ => TunnelStream::handle_io_error(e),
                    };

                    return Poll::Ready(Err(err));
                }
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl AsyncWrite for TunnelStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::result::Result<usize, std::io::Error>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        self.send.reserve_capacity(buf.len());

        let cnt = match ready!(self.send.poll_capacity(cx)) {
            Some(Ok(cnt)) => match self.send_data(&buf[..cnt], false) {
                _ => Some(cnt),
            },
            Some(Err(_)) => None,
            None => Some(0),
        };

        if let Some(cnt) = cnt {
            return Poll::Ready(Ok(cnt));
        }

        let err = match ready!(self.send.poll_reset(cx)) {
            Ok(Reason::NO_ERROR) | Ok(Reason::CANCEL) | Ok(Reason::STREAM_CLOSED) => {
                ErrorKind::BrokenPipe.into()
            }
            Ok(reason) => TunnelStream::handle_io_error(reason.into()),
            Err(e) => TunnelStream::handle_io_error(e),
        };

        Poll::Ready(Err(err))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        let res = self.send_data(&[], true);

        if res.is_ok() {
            return Poll::Ready(Ok(()));
        }

        let err = match ready!(self.send.poll_reset(cx)) {
            Ok(Reason::NO_ERROR) => return Poll::Ready(Ok(())),
            Ok(Reason::CANCEL) | Ok(Reason::STREAM_CLOSED) => {
                return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
            }
            Ok(reason) => TunnelStream::handle_io_error(reason.into()),
            Err(e) => TunnelStream::handle_io_error(e),
        };

        Poll::Ready(Err(err))
    }
}

#[derive(Debug)]
struct NoVerifier;

impl NoVerifier {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl ServerCertVerifier for NoVerifier {
    fn requires_raw_public_keys(&self) -> bool {
        false
    }

    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::ED25519,
        ]
    }
}
