use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};

use anyhow::Result;
use aya::maps::{HashMap, MapData};
use common::{NatKey, NatOrigin};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use log::error;
use tokio::net::TcpListener;
use tokio::sync::mpsc::Sender;

use crate::HttpRequest;

static APP_USER_AGENT: &str = "pmz";

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
        let _proxy_addr = "";
        let proxy_port = 18328;
        let addr = SocketAddr::from(([127, 0, 0, 1], proxy_port));
        // let tunnel_addr = "localhost";
        // let tunnel_port = "18329";
        // let cert_path = "/home/wq/Workspace/panmunzom/agent/certs/server.crt";

        let listener = TcpListener::bind(addr).await?;
        println!("Proxy: Listening on {}", addr);

        loop {
            let (stream, _) = listener.accept().await?;
            let peer_addr = stream.peer_addr()?;
            println!("peer_addr: {:?}", peer_addr);

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

            println!(
                "NatKey found src: {}:{} dst: {}:{}",
                nat_key.src_addr, nat_key.src_port, nat_key.dst_addr, nat_key.dst_port
            );

            let nat_table = self.nat_table.read().unwrap();
            let nat_origin = nat_table.get(&nat_key, 0)?;

            println!(
                "NatOrigin found: {:?}:{}",
                std::net::Ipv4Addr::from_bits(u32::from_be(nat_origin.addr)),
                u16::from_be(nat_origin.port)
            );

            let pmz_target = format!(
                "{}:{}",
                std::net::Ipv4Addr::from_bits(u32::from_be(nat_origin.addr)),
                u16::from_be(nat_origin.port)
            );

            let tx = self.req_tx.clone();

            tokio::task::spawn(async move {
                if let Err(e) = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |req| {
                            let pmz_target = pmz_target.to_owned();
                            let tx = tx.clone();
                            request(req, pmz_target, tx)
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

async fn request(
    req: Request<Incoming>,
    pmz_target: String,
    tx: Sender<HttpRequest>,
) -> Result<Response<Full<Bytes>>> {
    let (parts, _body) = req.into_parts();
    // let body = body.collect().await?.to_bytes();
    let url = format!("http://{}{}", pmz_target, parts.uri);

    let req = http::Request::builder()
        .uri(url)
        .method(parts.method)
        .header(http::header::USER_AGENT, APP_USER_AGENT)
        .header(http::header::HOST, pmz_target)
        .body(())
        .unwrap();

    let (oneshot_tx, oneshot_rx) = tokio::sync::oneshot::channel::<Bytes>();
    tx.send(HttpRequest {
        req,
        res: oneshot_tx,
    })
    .await?;

    Ok(Response::new(Full::new(Bytes::from(oneshot_rx.await?))))
}
