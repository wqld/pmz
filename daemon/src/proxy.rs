use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};

use anyhow::Result;
use aya::maps::{HashMap, MapData};
use common::{NatKey, NatOrigin};
use log::debug;
use tokio::net::TcpListener;
use tokio::sync::mpsc::Sender;

use crate::TunnelRequest;

pub struct Proxy {
    nat_table: Arc<RwLock<HashMap<MapData, NatKey, NatOrigin>>>,
    req_tx: Sender<TunnelRequest>,
}

impl Proxy {
    pub fn new(
        nat_table: HashMap<MapData, NatKey, NatOrigin>,
        req_tx: Sender<TunnelRequest>,
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

            let target = format!(
                "{}:{}",
                Ipv4Addr::from_bits(u32::from_be(nat_origin.addr)),
                u16::from_be(nat_origin.port)
            );

            let tx = self.req_tx.clone();
            tokio::spawn(async move {
                tx.send(TunnelRequest { stream, target }).await.unwrap();
            });
        }
    }
}
