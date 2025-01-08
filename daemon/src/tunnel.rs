use std::sync::Arc;

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

            tokio::select! {
                Some(http_request) = req_rx.recv() => self.handle_http_request(send_req.clone(), http_request).await,
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

                http_request
                    .response
                    .send(recv_stream.data().await.unwrap().unwrap())
                    .unwrap();
            })
        });
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
