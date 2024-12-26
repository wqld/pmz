use std::{fs, net::SocketAddr, os::unix::fs::PermissionsExt, path::Path, sync::Arc};

use anyhow::{Context, Result};
use futures::TryStreamExt;
use http_body_util::Full;
use hyper::{body::Bytes, server::conn::http1, service::service_fn, Response};
use hyper_util::rt::TokioIo;
use ipnet::IpNet;
use k8s_openapi::api::core::v1::Pod;
use kube::{
    api::Api,
    runtime::wait::{await_condition, conditions::is_pod_running},
    Client,
};
use log::{debug, info};
use rsln::{
    netlink::Netlink,
    types::{link::LinkAttrs, routing::RoutingBuilder},
};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName},
    ClientConfig, SignatureScheme,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    join,
    net::{TcpListener, TcpStream, UnixListener},
    sync::{mpsc::Receiver, Mutex, Notify},
};
use tokio_rustls::TlsConnector;
use tokio_stream::wrappers::TcpListenerStream;

use crate::HttpRequest;

pub struct Command {
    req_rx: Arc<Mutex<Receiver<HttpRequest>>>,
}

impl Command {
    pub fn new(req_rx: Receiver<HttpRequest>) -> Self {
        Self {
            req_rx: Arc::new(Mutex::new(req_rx)),
        }
    }

    pub async fn run(&self) -> Result<()> {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .unwrap();

        let path = Path::new("/tmp/pmz.sock");

        if path.exists() {
            fs::remove_file(path)?;
        }

        let listener = UnixListener::bind(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o766))?;
        debug!("Listening for connections at {}.", path.display());

        loop {
            let (stream, _) = listener.accept().await?;
            let req_rx = self.req_rx.clone();

            tokio::task::spawn(async move {
                if let Err(err) = http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |_req| connect(req_rx.clone())),
                        // service_fn(move |req| async move {
                        //     match (req.method(), req.uri().path()) {
                        //         (&Method::POST, "/connect") => connect(rx).await,
                        //         (&Method::POST, "/disconnect") => {
                        //             Ok(Response::new(Full::<Bytes>::from("Disconnected")))
                        //         }
                        //         _ => Ok(Response::builder()
                        //             .status(StatusCode::NOT_FOUND)
                        //             .body(Full::<Bytes>::from("Not Found"))
                        //             .unwrap()),
                        //     }
                        // }),
                    )
                    .await
                {
                    debug!("Error serving connection: {:?}", err);
                }
            });
        }
    }
}

async fn connect(req_rx: Arc<Mutex<Receiver<HttpRequest>>>) -> Result<Response<Full<Bytes>>> {
    let namespace = "default";
    let agent_name = "test";
    let agent_port = 8100; // TODO
    let tunnel_host = "localhost";
    let tunnel_port = 18329;

    let client = Client::try_default().await.unwrap();
    let pods: Api<Pod> = Api::namespaced(client, &namespace);

    debug!("Checking if agent is running");

    let running = await_condition(pods.clone(), &agent_name, is_pod_running());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), running)
        .await
        .unwrap();

    // route
    let service_cidr = "10.96.0.0/16";
    let service_cidr_net = service_cidr.parse::<IpNet>()?;
    let mut netlink = Netlink::new();

    let link = netlink.link_get(&LinkAttrs::new("lo"))?;

    let route = RoutingBuilder::default()
        .oif_index(link.attrs().index)
        .dst(Some(service_cidr_net))
        .build()?;

    if let Err(e) = netlink.route_add(&route) {
        if e.to_string().contains("File exists") {
            debug!("route already exists");
        } else {
            return Err(e);
        }
    }

    // port forward
    let forward_ready = Arc::new(Notify::new());
    let forward_ready_clone = forward_ready.clone();

    let forward_future = async move {
        let addr = SocketAddr::from(([127, 0, 0, 1], tunnel_port));

        let server = TcpListenerStream::new(TcpListener::bind(addr).await.unwrap()).try_for_each(
            |client_conn| async {
                if let Ok(peer_addr) = client_conn.peer_addr() {
                    debug!("new connection: {}", peer_addr);
                }

                let pods = pods.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        forward_connection(&pods, &agent_name, agent_port, client_conn).await
                    {
                        debug!("failed to forward connection: {:?}", e);
                    }
                });

                Ok(())
            },
        );

        forward_ready_clone.notify_one();

        if let Err(e) = server.await {
            debug!("server error: {:?}", e);
        }
    };

    // proxy tunnel
    let tunnel_future = async move {
        forward_ready.notified().await;
        info!("port_forward completed");

        let tunnel_addr = format!("{tunnel_host}:{tunnel_port}");
        let stream = TcpStream::connect(tunnel_addr).await.unwrap();

        let mut client_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(NoVerifier::new())
            .with_no_client_auth();
        client_config.alpn_protocols = vec![b"h2".to_vec()];
        let tls_connector = TlsConnector::from(Arc::new(client_config));

        let tls_stream = tls_connector
            .connect(ServerName::try_from(tunnel_host).unwrap(), stream)
            .await
            .unwrap();

        let (sender, conn) = h2::client::handshake(tls_stream).await.unwrap();
        tokio::spawn(conn);

        let send_req = sender.ready().await.unwrap();

        loop {
            if let Some(http_request) = req_rx.lock().await.recv().await {
                let mut send_req = send_req.clone();
                tokio::task::spawn(async move {
                    let req = http_request.req;
                    let (res, _) = send_req.send_request(req, false).unwrap();
                    http_request
                        .res
                        .send(
                            res.await
                                .unwrap()
                                .into_body()
                                .data()
                                .await
                                .unwrap()
                                .unwrap(),
                        )
                        .unwrap();
                });
            }
        }

        // let req = http::Request::builder()
        //     .uri(pmz_target)
        //     .method("CONNECT")
        //     .header(http::header::USER_AGENT, APP_USER_AGENT)
        //     .body(())
        //     .unwrap();

        // let mut send_req = sender.ready().await.unwrap();
        // let (res, mut send_stream) = send_req.send_request(req, false).unwrap();

        // tokio::task::spawn(async move {
        //     let mut response = res.await.unwrap().into_body();
        //     // Process the response
        //     while let Some(chunk) = response.data().await {
        //         info!("chunk: {:?}", chunk);
        //     }
        // });

        // let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(1);

        // tokio::task::spawn(async move {
        //     while let Some(http_request) = rx.recv().await {
        //         info!("http_request: {:?}", http_request);

        //         send_stream
        //             .send_data(Bytes::from(http_request), false)
        //             .unwrap();
        //     }
        // });

        // let host = pmz_target.split(':').next().unwrap();

        // let http_request = format!(
        //     "GET {uri} HTTP/1.1\r\n\
        //  Host: {host}\r\n\
        //  user-agent: {APP_USER_AGENT}\r\n\
        //  Accept: */*\r\n\r\n",
        //     uri = "/?echo_body=amazing",
        //     host = host,
        // );

        // info!("http_request: {:?}", http_request);

        // tx.send(http_request).await.unwrap();
    };

    let (_, _) = join!(forward_future, tunnel_future);

    // netlink.route_handle(RtCmd::Delete, &route)?;

    Ok(Response::new(Full::<Bytes>::from("Connected")))
}

async fn forward_connection(
    pods: &Api<Pod>,
    agent_name: &str,
    agent_port: u16,
    mut client_conn: impl AsyncRead + AsyncWrite + Unpin,
) -> Result<()> {
    let mut forwarder = pods.portforward(agent_name, &[agent_port]).await?;
    let mut upstream_conn = forwarder
        .take_stream(agent_port)
        .context("port not found in forwarder")?;
    info!("notify_one");
    tokio::io::copy_bidirectional(&mut client_conn, &mut upstream_conn).await?;
    drop(upstream_conn);
    forwarder.join().await?;
    debug!("connection closed");
    Ok(())
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
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
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
