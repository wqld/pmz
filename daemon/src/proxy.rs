use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{Result, bail};
use aya::maps::{HashMap, MapData};
use common::{SockAddr, SockPair};
use proxy::tunnel::{PROTO_TCP, PROTO_UDP};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio::sync::mpsc::Sender;
use tracing::{Instrument, debug, error, info_span, instrument};
use udp_stream::UdpListener;

use crate::TunnelRequest;
use crate::connect::ConnectionStatus;

pub struct Proxy {
    nat_table: Arc<RwLock<HashMap<MapData, SockPair, SockAddr>>>,
    req_tx: Sender<TunnelRequest>,
    connection_status: Arc<RwLock<ConnectionStatus>>,
}

impl Proxy {
    pub fn new(
        nat_table: HashMap<MapData, SockPair, SockAddr>,
        req_tx: Sender<TunnelRequest>,
        connection_status: Arc<RwLock<ConnectionStatus>>,
    ) -> Self {
        Self {
            nat_table: Arc::new(RwLock::new(nat_table)),
            req_tx,
            connection_status,
        }
    }

    #[instrument(name = "proxy", skip_all)]
    pub async fn start(&self) -> Result<()> {
        match tokio::join!(self.start_tcp(), self.start_udp()) {
            (Ok(_), Ok(_)) => Ok(()),
            (Ok(_), Err(e)) | (Err(e), Ok(_)) => Err(e),
            (Err(e1), Err(e2)) => bail!("{:?} + {:?}", e1, e2),
        }
    }

    #[instrument(name = "tcp", skip_all)]
    pub async fn start_tcp(&self) -> Result<()> {
        let tcp_proxy_port = 18328;
        let addr = SocketAddr::from(([127, 0, 0, 1], tcp_proxy_port));

        let listener = TcpListener::bind(addr).await?;
        debug!(ip = %addr.ip(), port = addr.port(), "Proxy listening");

        ConnectionStatus::proxy(&self.connection_status, true, "Up").await;

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            let target = self.get_target(peer_addr, tcp_proxy_port).await?;
            let target_for_span = target.clone();
            let tx = self.req_tx.clone();

            tokio::spawn(
                async move {
                    debug!("Forwarding request to tunnel");

                    if let Err(e) = tx
                        .send(TunnelRequest {
                            protocol: PROTO_TCP,
                            stream: Box::new(stream),
                            target,
                        })
                        .await
                    {
                        error!(error = ?e, "Failed to send TunnelRequest");
                    }
                }
                .instrument(info_span!("handle", peer = ?peer_addr, target = ?target_for_span)),
            );
        }
    }

    #[instrument(name = "udp", skip_all)]
    pub async fn start_udp(&self) -> Result<()> {
        let udp_proxy_port = 18327;
        let addr = SocketAddr::from(([127, 0, 0, 1], udp_proxy_port));

        let listener = UdpListener::bind(addr).await?;
        debug!(ip = %addr.ip(), port = addr.port(), "Proxy listening");

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            let target = self.get_target(peer_addr, udp_proxy_port).await?;
            let target_for_span = target.clone();
            let tx = self.req_tx.clone();

            tokio::spawn(
                async move {
                    debug!("Forwarding request to tunnel");

                    if let Err(e) = tx
                        .send(TunnelRequest {
                            protocol: PROTO_UDP,
                            stream: Box::new(stream),
                            target,
                        })
                        .await
                    {
                        error!(error = ?e, "Failed to send TunnelRequest")
                    }
                }
                .instrument(info_span!("handle", peer = ?peer_addr, target = ?target_for_span)),
            );
        }
    }

    #[instrument(
        skip_all,
        fields(
            peer.addr = %peer_addr.ip(),
            peer.port = peer_addr.port(),
            proxy_port
        )
    )]
    async fn get_target(&self, peer_addr: SocketAddr, proxy_port: u16) -> Result<String> {
        let peer_ip = match peer_addr.ip() {
            IpAddr::V4(ipv4_addr) => ipv4_addr.to_bits(),
            IpAddr::V6(_) => 0,
        };

        let nat_key = SockPair {
            src_addr: u32::to_be(peer_ip),
            src_port: u16::to_be(peer_addr.port()),
            dst_addr: u32::to_be(2130706433), // 127.0.0.1
            dst_port: u16::to_be(proxy_port),
        };

        debug!(
            nat.src_addr = %Ipv4Addr::from_bits(u32::from_be(nat_key.src_addr)),
            nat.src_port = u16::from_be(nat_key.src_port),
            nat.dst_addr = %Ipv4Addr::from_bits(u32::from_be(nat_key.dst_addr)),
            nat.dst_port = u16::from_be(nat_key.dst_port),
            "Looking up NAT key"
        );

        let nat_table = self.nat_table.read().await;
        let nat_origin = nat_table.get(&nat_key, 0)?;
        let target_ip = Ipv4Addr::from_bits(u32::from_be(nat_origin.addr));
        let target_port = u16::from_be(nat_origin.port);

        debug!(target.ip = %target_ip, target.port = target_port, "NAT origin found");

        Ok(format!("{}:{}", target_ip, target_port))
    }
}
