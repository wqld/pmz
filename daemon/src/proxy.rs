use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};

use anyhow::{bail, Result};
use aya::maps::{HashMap, MapData};
use common::{NatKey, NatOrigin};
use log::debug;
use tokio::net::TcpListener;
use tokio::sync::mpsc::Sender;
use udp_stream::UdpListener;

use crate::TunnelRequest;

static PROTO_TCP: &str = "TCP";
static PROTO_UDP: &str = "UDP";

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
        match tokio::join!(self.start_tcp(), self.start_udp()) {
            (Ok(_), Ok(_)) => Ok(()),
            (Ok(_), Err(e)) | (Err(e), Ok(_)) => Err(e),
            (Err(e1), Err(e2)) => bail!("{:?} + {:?}", e1, e2),
        }
    }

    pub async fn start_tcp(&self) -> Result<()> {
        let tcp_proxy_port = 18328;
        let addr = SocketAddr::from(([127, 0, 0, 1], tcp_proxy_port));

        let listener = TcpListener::bind(addr).await?;
        debug!("TCP Proxy: Listening on {}", addr);

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            debug!("peer_addr: {:?}", peer_addr);

            let target = self.get_target(peer_addr, tcp_proxy_port)?;

            let tx = self.req_tx.clone();
            tokio::spawn(async move {
                tx.send(TunnelRequest {
                    protocol: PROTO_TCP,
                    stream: Box::new(stream),
                    target,
                })
                .await
                .unwrap();
            });
        }
    }

    pub async fn start_udp(&self) -> Result<()> {
        let udp_proxy_port = 18327;
        let addr = SocketAddr::from(([127, 0, 0, 1], udp_proxy_port));

        let listener = UdpListener::bind(addr).await?;
        debug!("UDP Proxy: Listening on {}", addr);

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            debug!("peer_addr: {:?}", peer_addr);

            let target = self.get_target(peer_addr, udp_proxy_port)?;

            let tx = self.req_tx.clone();
            tx.send(TunnelRequest {
                protocol: PROTO_UDP,
                stream: Box::new(stream),
                target,
            })
            .await
            .unwrap();
        }
    }

    fn get_target(&self, peer_addr: SocketAddr, proxy_port: u16) -> Result<String> {
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

        Ok(format!(
            "{}:{}",
            Ipv4Addr::from_bits(u32::from_be(nat_origin.addr)),
            u16::from_be(nat_origin.port)
        ))
    }
}
