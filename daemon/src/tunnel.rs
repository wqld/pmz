use core::str;
use std::{sync::Arc, time::Duration};

use anyhow::Result;
use h2::client::SendRequest;
use hyper::body::Bytes;
use log::debug;
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName},
    ClientConfig, SignatureScheme,
};
use tokio::{
    net::TcpStream,
    sync::{broadcast, mpsc::Receiver, Mutex},
    time::Instant,
};
use tokio_rustls::TlsConnector;

use crate::HttpRequest;

pub struct Tunnel {
    tunnel_host: String,
    tunnel_port: u16,
    req_rx: Arc<Mutex<Receiver<HttpRequest>>>,
}

impl Tunnel {
    pub fn new(
        tunnel_host: &str,
        tunnel_port: u16,
        req_rx: Arc<Mutex<Receiver<HttpRequest>>>,
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
                Some(http_request) = req_rx.recv() => self.handle_http_request(send_req.clone(), http_request).await,
                _ = interval.tick() => self.heartbeat(send_req.clone()).await,
                _ = shutdown.recv() => {
                    debug!("tunnel shutdown");
                    return Ok(())
                }
            }
        }
    }

    async fn handle_http_request(&self, send_req: SendRequest<Bytes>, http_request: HttpRequest) {
        let mut send_req = send_req.clone();

        tokio::task::spawn(async move {
            let target = http_request.target;

            let req = http::Request::builder()
                .uri(target)
                .method(http::Method::CONNECT)
                .version(http::Version::HTTP_2)
                .body(())
                .unwrap();

            let (response, mut send_stream) = send_req.send_request(req, false).unwrap();
            let mut recv_stream = response.await.unwrap().into_body();

            tokio::task::spawn(async move {
                let req = http_request.request;

                debug!("req: {:?}", req);
                send_stream.send_data(Bytes::from(req), false).unwrap();

                if let Some(res) = http_request.response {
                    let mut total_len: Option<usize> = None;
                    let mut current_len: usize = 0;
                    let mut completed_data = Vec::with_capacity(8192);

                    while let Some(chunk) = recv_stream.data().await {
                        let chunk = chunk.unwrap();
                        current_len += chunk.len();
                        completed_data.extend_from_slice(&chunk);

                        if total_len.is_none() {
                            let mut headers = [httparse::EMPTY_HEADER; 32];
                            let mut parser = httparse::Response::new(&mut headers);

                            if let Ok(httparse::Status::Complete(header_len)) = parser.parse(&chunk)
                            {
                                debug!("header_len: {header_len}");
                                if let Some(content_len_val) = headers
                                    .iter()
                                    .find(|h| h.name.eq_ignore_ascii_case("Content-Length"))
                                    .and_then(|h| {
                                        String::from_utf8_lossy(h.value).parse::<usize>().ok()
                                    })
                                {
                                    total_len = match http_request.method {
                                        http::Method::HEAD => Some(header_len),
                                        _ => Some(header_len + content_len_val),
                                    };
                                }
                            }
                        }

                        debug!("get a chunk: {chunk:?}");

                        if let Some(len) = total_len {
                            debug!("{current_len}/{len}");
                            if len == current_len {
                                res.send(completed_data.into())
                                    .expect("Failed to send response");
                                break;
                            }
                        }
                    }
                }
            })
        });
    }

    async fn heartbeat(&self, send_req: SendRequest<Bytes>) {
        debug!("ping");

        let http_request = HttpRequest {
            method: http::Method::GET,
            request: String::new(),
            _source: String::new(),
            target: "127.0.0.1:8101".to_string(),
            response: None,
        };

        self.handle_http_request(send_req.clone(), http_request)
            .await;
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
