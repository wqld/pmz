use std::{io, net::SocketAddr, time::Duration};

use socket2::{SockRef, TcpKeepalive};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};

pub mod client;
pub mod server;
pub mod stream;
pub mod verifier;

pub const PMZ_PROTO_HDR: &str = "Pmz-Proto";
pub const PROTO_TCP: &str = "TCP";
pub const PROTO_UDP: &str = "UDP";

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

pub trait TcpListenerTunnelExt {
    fn accept_tun(&self) -> impl Future<Output = io::Result<(TcpStream, SocketAddr)>> + Send + '_;
}

impl TcpListenerTunnelExt for TcpListener {
    async fn accept_tun(&self) -> io::Result<(TcpStream, SocketAddr)> {
        let (stream, addr) = self.accept().await?;

        stream.set_nodelay(true)?;

        let ka = TcpKeepalive::new()
            .with_time(Duration::from_secs(45))
            .with_interval(Duration::from_secs(10))
            .with_retries(5);

        SockRef::from(&stream).set_tcp_keepalive(&ka)?;

        Ok((stream, addr))
    }
}

pub trait TcpStreamTunnelExt {
    fn connect_tun<A: ToSocketAddrs>(addr: A) -> impl Future<Output = io::Result<TcpStream>>;
}

impl TcpStreamTunnelExt for TcpStream {
    async fn connect_tun<A: ToSocketAddrs>(addr: A) -> io::Result<TcpStream> {
        let stream = TcpStream::connect(addr).await?;

        stream.set_nodelay(true)?;

        let ka = TcpKeepalive::new()
            .with_time(Duration::from_secs(45))
            .with_interval(Duration::from_secs(10))
            .with_retries(5);

        SockRef::from(&stream).set_tcp_keepalive(&ka)?;

        Ok(stream)
    }
}
