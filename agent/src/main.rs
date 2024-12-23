use std::net::SocketAddr;
use std::sync::Arc;
use std::{fs, io};

use anyhow::Result;
use bytes::Bytes;
use clap::Parser;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response};

use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "127.0.0.1")]
    ip: String,

    #[arg(short, long, default_value_t = 8100)]
    port: u16,

    #[arg(short, long, required = true)]
    cert: String,

    #[arg(short, long, required = true)]
    key: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let addr = SocketAddr::from((args.ip.parse::<std::net::IpAddr>()?, args.port));

    let listener = TcpListener::bind(addr).await?;
    println!("Listening on {}", addr);

    let tls_acceptor = create_tls_acceptor(&args.cert, &args.key)?;

    loop {
        let (tcp_stream, _) = listener.accept().await?;
        let tls_acceptor = tls_acceptor.clone();

        tokio::task::spawn(async move {
            let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                Ok(tls_stream) => tls_stream,
                Err(e) => {
                    eprintln!("failed to perform tls handshake: {:?}", e);
                    return;
                }
            };
            if let Err(e) = auto::Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(TokioIo::new(tls_stream), service_fn(proxy))
                .await
            {
                eprintln!("failed to serve connection: {:?}", e);
            }
        });
    }
}

fn create_tls_acceptor(cert_path: &str, key_path: &str) -> Result<TlsAcceptor> {
    let cert = load_cert(cert_path)?;
    let key = load_key(key_path)?;

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert, key)
        .map_err(|e| error(e.to_string()))?;
    server_config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

async fn proxy(req: Request<Incoming>) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    println!("req: {:?}", req);

    if Method::CONNECT == req.method() {
        handle_connect(req).await
    } else {
        handle_http(req).await
    }
}

async fn handle_connect(req: Request<Incoming>) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    if let Some(addr) = host_addr(req.uri()) {
        tokio::task::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    if let Err(e) = tunnel(upgraded, addr).await {
                        eprintln!("server io error: {}", e);
                    };
                }
                Err(e) => eprintln!("upgrade error: {}", e),
            }
        });

        Ok(Response::new(empty()))
    } else {
        eprintln!("CONNECT host is not socket addr: {:?}", req.uri());
        let mut resp = Response::new(full("CONNECT must be to a socket address"));
        *resp.status_mut() = http::StatusCode::BAD_REQUEST;

        Ok(resp)
    }
}

async fn handle_http(req: Request<Incoming>) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    let host = req.uri().host().expect("uri has no host");
    let port = req.uri().port_u16().unwrap_or(80);

    let stream = TcpStream::connect((host, port)).await.unwrap();

    let (mut sender, conn) = http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .handshake(TokioIo::new(stream))
        .await?;
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            println!("Connection failed: {:?}", err);
        }
    });

    let resp = sender.send_request(req).await?;
    Ok(resp.map(|b| b.boxed()))
}

async fn tunnel(upgraded: Upgraded, addr: String) -> io::Result<()> {
    let mut server = TcpStream::connect(addr).await?;
    let mut upgraded = TokioIo::new(upgraded);

    let (from_client, from_server) =
        tokio::io::copy_bidirectional(&mut upgraded, &mut server).await?;

    println!(
        "client wrote {} bytes and received {} bytes",
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
