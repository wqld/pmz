use std::net::SocketAddr;

use anyhow::Result;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use log::error;
use reqwest::{ClientBuilder, Proxy};
use tokio::net::TcpListener;

static APP_USER_AGENT: &str = "pmz";

pub async fn start() -> Result<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let proxy_host = "localhost";
    let proxy_port = "8102";
    let cert_path = "/home/wq/Workspace/panmunzom/agent/certs/server.crt";

    let listener = TcpListener::bind(addr).await?;
    println!("Listening on {}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let peer_addr = stream.peer_addr()?;
        println!("peer_addr: {:?}", peer_addr);

        tokio::task::spawn(async move {
            if let Err(e) = auto::Builder::new(TokioExecutor::new())
                .serve_connection(
                    TokioIo::new(stream),
                    service_fn(move |req| request(req, &proxy_host, &proxy_port, &cert_path)),
                )
                .await
            {
                error!("error serving connection: {e:#?}");
            }
        });
    }
}

async fn request(
    req: Request<Incoming>,
    proxy_host: &str,
    proxy_port: &str,
    cert_path: &str,
) -> Result<Response<Full<Bytes>>> {
    let proxy = Proxy::all(format!("https://{}:{}", proxy_host, proxy_port))?;
    let cert = reqwest::Certificate::from_pem(&std::fs::read(cert_path)?)?;
    let client = ClientBuilder::new()
        .user_agent(APP_USER_AGENT)
        .add_root_certificate(cert)
        .proxy(proxy)
        .build()?;

    let (parts, body) = req.into_parts();
    let target_addr = parts.headers.get("X-PMZ-TARGET").unwrap().to_str()?;
    let body = body.collect().await?.to_bytes();
    let url = format!("http://{}/{}", target_addr, parts.uri);
    let resp = client
        .request(parts.method, url)
        .headers(parts.headers)
        .body(body)
        .send()
        .await?;

    Ok(Response::new(Full::new(Bytes::from(resp.bytes().await?))))
}
