use std::net::SocketAddr;
use std::sync::Arc;
use std::{fs, io};

use anyhow::Result;
use aya::programs::{Xdp, XdpFlags};
use bytes::Bytes;
use clap::Parser;
use http::StatusCode;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response};

use hyper_util::rt::{TokioExecutor, TokioIo};
use log::{debug, error, info, warn};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use udp_stream::UdpStream;

static PMZ_PROTO_HDR: &str = "Pmz-Proto";
static PROTO_UDP: &str = "UDP";

enum PROTO {
    TCP,
    UDP,
}

impl PROTO {
    pub fn from(s: &str) -> Self {
        if s.eq(PROTO_UDP) {
            return PROTO::UDP;
        }

        PROTO::TCP
    }
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[clap(short, long, default_value = "eth0")]
    iface: String,

    #[arg(short, long, default_value = "127.0.0.1")]
    ip: String,

    #[arg(short, long, default_value_t = 8100)]
    proxy_port: u16,

    #[arg(short, long, default_value_t = 8101)]
    health_check_port: u16,

    #[arg(short, long, default_value = "/certs/pmz.crt")]
    cert: String,

    #[arg(short, long, default_value = "/certs/pmz.key")]
    key: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/pmz"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let interceptor: &mut Xdp = ebpf.program_mut("interceptor").unwrap().try_into()?;
    interceptor.load()?;
    interceptor.attach(&args.iface, XdpFlags::default())?;

    let addr = SocketAddr::from((args.ip.parse::<std::net::IpAddr>()?, args.proxy_port));

    let proxy_listener = TcpListener::bind(addr).await?;
    let proxy_tls_acceptor = create_tls_acceptor(&args.cert, &args.key)?;
    info!("Listening on {} w/ tls", addr);

    let health_check_addr = SocketAddr::from(([0, 0, 0, 0], args.health_check_port));
    let health_check_listener = TcpListener::bind(health_check_addr).await?;
    info!("Health check listening on {}", health_check_addr);

    tokio::spawn(async move {
        loop {
            let (mut stream, _) = health_check_listener.accept().await.unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 6\r\n\r\nhealth"
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        }
    });

    loop {
        let (tcp_stream, _) = proxy_listener.accept().await?;
        let tls_acceptor = proxy_tls_acceptor.clone();

        tokio::task::spawn(async move {
            let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                Ok(tls_stream) => tls_stream,
                Err(e) => {
                    error!("failed to perform tls handshake: {:?}", e);
                    return;
                }
            };

            if let Err(e) = http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(tls_stream), service_fn(proxy))
                .await
            {
                error!("failed to serve connection: {:?}", e);
            }
        });
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
    if let Some(addr) = host_addr(req.uri()) {
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
    } else {
        error!("CONNECT host is not socket addr: {:?}", req.uri());
        let mut resp = Response::new(full("CONNECT must be to a socket address"));
        *resp.status_mut() = http::StatusCode::BAD_REQUEST;

        Ok(resp)
    }
}

async fn handle_http(req: Request<Incoming>) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    debug!("handle_http: {:?}", req);

    match (req.method(), req.uri().path()) {
        (&Method::POST, "/intercept") => start_intercept().await,
        _ => not_found().await,
    }
}

async fn tunnel(upgraded: Upgraded, addr: String, proto: PROTO) -> io::Result<()> {
    debug!("tunnel addr: {:?}", addr);
    debug!("upgraded: {:?}", upgraded);

    let mut upgraded = TokioIo::new(upgraded);

    let (from_client, from_server) = match proto {
        PROTO::TCP => {
            let mut server = TcpStream::connect(addr).await?;
            tokio::io::copy_bidirectional(&mut upgraded, &mut server).await?
        }
        PROTO::UDP => {
            let mut server = UdpStream::connect(addr.parse::<SocketAddr>().unwrap()).await?;
            tokio::io::copy_bidirectional(&mut upgraded, &mut server).await?
        }
    };

    debug!(
        "tcp client wrote {} bytes and received {} bytes",
        from_client, from_server
    );

    Ok(())
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

async fn start_intercept() -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    Ok(Response::new(full("intercept started")))
}

async fn not_found() -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(full("Not found"))?)
}
