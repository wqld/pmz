use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use aya::maps::{HashMap, MapData};
use common::{SockAddr, SockPair};
use proxy::tunnel::{PROTO_TCP, PROTO_UDP};
use socket2::TcpKeepalive;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio::sync::mpsc::Sender;
use tracing::{Instrument, debug, error, info, info_span, instrument};
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
    pub async fn start(self: Arc<Self>) -> Result<()> {
        let tcp_server = self.clone();
        let tcp_handle = tokio::spawn(async move { tcp_server.start_tcp().await });

        let udp_server = self.clone();
        let udp_handle = tokio::spawn(async move { udp_server.start_udp().await });
        match tokio::join!(tcp_handle, udp_handle) {
            (Ok(_), Ok(_)) => Ok(()),
            (Ok(_), Err(e)) | (Err(e), Ok(_)) => Err(e.into()),
            (Err(e1), Err(e2)) => bail!("{:?} + {:?}", e1, e2),
        }
    }

    fn get_original_dst(stream: &impl AsRawFd) -> Result<SocketAddr> {
        let fd = stream.as_raw_fd();

        let mut sockaddr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut len: libc::socklen_t = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_IP,
                libc::SO_ORIGINAL_DST,
                &mut sockaddr as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };

        if ret != 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        let ip = Ipv4Addr::from(u32::from_be(sockaddr.sin_addr.s_addr));
        let port = u16::from_be(sockaddr.sin_port);

        Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
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

            let tx = self.req_tx.clone();

            tokio::spawn(
                async move {
                    stream.set_nodelay(true).unwrap();

                    let keepalive_time = Duration::from_secs(45);
                    let keepalive_interval = Duration::from_secs(10);
                    let keepalive_retries = 5;

                    let ka = TcpKeepalive::new()
                        .with_time(keepalive_time)
                        .with_interval(keepalive_interval)
                        .with_retries(keepalive_retries);

                    let sock_ref = socket2::SockRef::from(&stream);
                    sock_ref.set_tcp_keepalive(&ka).unwrap();

                    let target = match Self::get_original_dst(&stream) {
                        Ok(addr) => format!("{}", addr),
                        Err(e) => {
                            error!("Failed to get original dst via getsockopt: {}", e);
                            return;
                        }
                    };

                    info!("Original DST retrieved via BPF: {}", target);

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
                .instrument(info_span!("handle", peer = ?peer_addr)),
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
            let target =
                Self::lookup_target(self.nat_table.clone(), peer_addr, udp_proxy_port).await?;
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

    async fn lookup_target(
        nat_table: Arc<RwLock<HashMap<MapData, SockPair, SockAddr>>>,
        peer_addr: SocketAddr,
        proxy_port: u16,
    ) -> Result<String> {
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

        let nat_origin = {
            let nat_table = nat_table.read().await;
            nat_table.get(&nat_key, 0)?
        };
        let target_ip = Ipv4Addr::from_bits(u32::from_be(nat_origin.addr));
        let target_port = u16::from_be(nat_origin.port);

        debug!(target.ip = %target_ip, target.port = target_port, "NAT origin found");

        Ok(format!("{}:{}", target_ip, target_port))
    }
}
