use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};

use anyhow::Result;
use aya::maps::{HashMap, MapData};
use common::{NatKey, NatOrigin};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use log::{debug, error};
use tokio::net::TcpListener;
use tokio::sync::mpsc::Sender;

use crate::HttpRequest;

pub struct Proxy {
    nat_table: Arc<RwLock<HashMap<MapData, NatKey, NatOrigin>>>,
    req_tx: Sender<HttpRequest>,
}

impl Proxy {
    pub fn new(
        nat_table: HashMap<MapData, NatKey, NatOrigin>,
        req_tx: Sender<HttpRequest>,
    ) -> Self {
        Self {
            nat_table: Arc::new(RwLock::new(nat_table)),
            req_tx,
        }
    }

    pub async fn start(&self) -> Result<()> {
        let proxy_port = 18328;
        let addr = SocketAddr::from(([127, 0, 0, 1], proxy_port));

        let listener = TcpListener::bind(addr).await?;
        debug!("Proxy: Listening on {}", addr);

        loop {
            let (stream, _) = listener.accept().await?;
            let peer_addr = stream.peer_addr()?;
            debug!("peer_addr: {:?}", peer_addr);

            let peer_ip = match peer_addr.ip() {
                IpAddr::V4(ipv4_addr) => ipv4_addr.to_bits(),
                IpAddr::V6(_) => 0,
            };

            let nat_key = NatKey {
                src_addr: u32::to_be(peer_ip),
                src_port: u16::to_be(peer_addr.port()),
                dst_addr: u32::to_be(2130706433),
                dst_port: u16::to_be(proxy_port),
            };

            debug!(
                "NatKey found src: {}:{} dst: {}:{}",
                nat_key.src_addr, nat_key.src_port, nat_key.dst_addr, nat_key.dst_port
            );

            let nat_table = self.nat_table.read().unwrap();
            let nat_origin = nat_table.get(&nat_key, 0)?;

            debug!(
                "NatOrigin found: {:?}:{}",
                Ipv4Addr::from_bits(u32::from_be(nat_origin.addr)),
                u16::from_be(nat_origin.port)
            );

            let pmz_target = format!(
                "{}:{}",
                Ipv4Addr::from_bits(u32::from_be(nat_origin.addr)),
                u16::from_be(nat_origin.port)
            );

            let tx = self.req_tx.clone();

            tokio::task::spawn(async move {
                if let Err(e) = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |req| {
                            handle_request(
                                req,
                                peer_addr.to_string(),
                                pmz_target.clone(),
                                tx.clone(),
                            )
                        }),
                    )
                    .await
                {
                    error!("error serving connection: {e:#?}");
                }
            });
        }
    }
}

async fn handle_request(
    req: Request<Incoming>,
    peer_addr: String,
    pmz_target: String,
    tx: Sender<HttpRequest>,
) -> Result<Response<Full<Bytes>>> {
    let (request, method) = format_request_as_http(req).await;

    let (oneshot_tx, oneshot_rx) = tokio::sync::oneshot::channel::<Bytes>();
    tx.send(HttpRequest {
        method,
        request,
        _source: peer_addr,
        target: pmz_target,
        response: Some(oneshot_tx),
    })
    .await?;

    Ok(Response::new(Full::new(Bytes::from(oneshot_rx.await?))))
}

pub async fn format_request_as_http(req: Request<Incoming>) -> (String, http::Method) {
    let (parts, body) = req.into_parts();
    let body = body.collect().await.unwrap().to_bytes();

    let method = parts.method;
    let uri = parts.uri;

    let version = match parts.version {
        http::Version::HTTP_09 => "HTTP/0.9",
        http::Version::HTTP_10 => "HTTP/1.0",
        http::Version::HTTP_11 => "HTTP/1.1",
        http::Version::HTTP_2 => "HTTP/2.0",
        http::Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/1.1",
    };

    let headers: String = parts
        .headers
        .into_iter()
        .map(|(key, value)| {
            let key = key.unwrap().to_string();
            let value = value.to_str().unwrap();
            format!("{key}: {value}")
        })
        .collect::<Vec<String>>()
        .join("\r\n");

    let body = String::from_utf8_lossy(&body);

    (
        format!("{method} {uri} {version}\r\n{headers}\r\n{body}\r\n"),
        method,
    )
}
