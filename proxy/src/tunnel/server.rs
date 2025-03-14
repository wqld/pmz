use std::{fs, io, net::SocketAddr, sync::Arc};

use anyhow::Result;
use bytes::{Buf, Bytes};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::{body::Incoming, server::conn::http2, service::service_fn, upgrade::Upgraded};
use hyper_util::rt::{TokioExecutor, TokioIo};
use log::{debug, error, info};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use udp_stream::UdpStream;

use crate::tunnel::{PMZ_PROTO_HDR, PROTO};

pub struct Args {
    pub ip: String,
    pub proxy_port: u16,
    pub cert: String,
    pub key: String,
}

pub struct TunnelServer {
    args: Args,
}

impl TunnelServer {
    pub fn new(args: Args) -> Self {
        Self { args }
    }

    pub async fn start(&self) -> Result<()> {
        let addr = SocketAddr::from((
            self.args.ip.parse::<std::net::IpAddr>()?,
            self.args.proxy_port,
        ));

        let proxy_listener = TcpListener::bind(addr).await?;
        let proxy_tls_acceptor = create_tls_acceptor(&self.args.cert, &self.args.key)?;
        info!("Listening on {} w/ tls", addr);

        loop {
            let (tcp_stream, peer_addr) = proxy_listener.accept().await?;
            let tls_acceptor = proxy_tls_acceptor.clone();
            debug!("peer addr: {peer_addr:?}");

            tokio::task::spawn(async move {
                let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                    Ok(tls_stream) => tls_stream,
                    Err(e) => {
                        error!("failed to perform tls handshake: {:?}", e);
                        return;
                    }
                };

                if let Err(e) = http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls_stream), service_fn(move |req| proxy(req)))
                    .await
                {
                    error!("failed to serve connection: {:?}", e);
                }
            });
        }
    }
}

fn create_tls_acceptor(cert_path: &str, key_path: &str) -> Result<TlsAcceptor> {
    let cert = load_cert(cert_path).expect("failed to load crt file");
    let key = load_key(key_path).expect("failed to load key file");

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert, key)
        .map_err(|e| error(e.to_string()))?;
    server_config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

async fn proxy(req: Request<Incoming>) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    debug!("req: {:?}", req);

    if Method::CONNECT == req.method() {
        handle_connect(req).await
    } else {
        handle_http(req).await
    }
}

async fn handle_connect(req: Request<Incoming>) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    debug!("handle_connect: {:?}", req);
    match host_addr(req.uri()) {
        Some(addr) => {
            let proto = req
                .headers()
                .get(PMZ_PROTO_HDR)
                .and_then(|hdr_val| hdr_val.to_str().ok())
                .map(|proto| PROTO::from(proto))
                .unwrap_or_else(|| PROTO::TCP);

            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(e) = tunnel(upgraded, addr, proto).await {
                            error!("server io error: {}", e);
                        };
                    }
                    Err(e) => error!("upgrade error: {}", e),
                }
            });

            Ok(Response::new(empty()))
        }
        _ => {
            error!("CONNECT host is not socket addr: {:?}", req.uri());
            let mut resp = Response::new(full("CONNECT must be to a socket address"));
            *resp.status_mut() = http::StatusCode::BAD_REQUEST;

            Ok(resp)
        }
    }
}

async fn handle_http(req: Request<Incoming>) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    debug!("handle_http: {:?}", req);

    match (req.method(), req.uri().path()) {
        (&Method::GET, "/health") => Ok(Response::new(full("healthy"))),
        (&Method::POST, "/intercept") => start_intercept(req.into_body()).await,
        _ => not_found(),
    }
}

async fn tunnel(upgraded: Upgraded, addr: String, proto: PROTO) -> io::Result<()> {
    debug!("tunnel addr: {:?}", addr);
    debug!("upgraded: {:?}", upgraded);

    let mut upgraded = TokioIo::new(upgraded);

    let (from_client, from_server) = match proto {
        PROTO::TCP => {
            tokio::io::copy_bidirectional(&mut upgraded, &mut TcpStream::connect(addr).await?)
                .await?
        }
        PROTO::UDP => {
            tokio::io::copy_bidirectional(
                &mut upgraded,
                &mut UdpStream::connect(addr.parse::<SocketAddr>().unwrap()).await?,
            )
            .await?
        }
    };

    debug!(
        "tcp client wrote {} bytes and received {} bytes",
        from_client, from_server
    );

    Ok(())
}

async fn start_intercept(req: Incoming) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    debug!("start_intercept with {req:?}");
    let body = req.collect().await?.aggregate();
    let props: serde_json::Value = serde_json::from_reader(body.reader())?;
    debug!("data: {props:?}");

    Ok(Response::new(full("intercept started")))
}

fn not_found() -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(full("Not found"))?)
}

fn host_addr(uri: &http::Uri) -> Option<String> {
    uri.authority().map(|auth| auth.to_string())
}

fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

fn load_cert(filename: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    let certfile = fs::File::open(filename)?;
    let mut reader = io::BufReader::new(certfile);
    rustls_pemfile::certs(&mut reader).collect()
}

fn load_key(filename: &str) -> io::Result<PrivateKeyDer<'static>> {
    let keyfile = fs::File::open(filename)?;
    let mut reader = io::BufReader::new(keyfile);
    rustls_pemfile::private_key(&mut reader).map(|key| key.unwrap())
}

fn error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}
