use aya_ebpf::programs::TcContext;
use network_types::{eth::EthHdr, ip::Ipv4Hdr, udp::UdpHdr};

pub struct SocketPair {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
}

impl SocketPair {
    pub fn load(ctx: &TcContext) -> Result<Self, &'static str> {
        let ip_hdr: Ipv4Hdr = ctx
            .load(EthHdr::LEN)
            .map_err(|_| "failed to load ip header")?;
        let udp_hdr: UdpHdr = ctx
            .load(EthHdr::LEN + Ipv4Hdr::LEN)
            .map_err(|_| "failed to load udp header")?;

        Ok(Self {
            src_ip: u32::from_be(ip_hdr.src_addr),
            dst_ip: u32::from_be(ip_hdr.dst_addr),
            src_port: u16::from_be(udp_hdr.source),
            dst_port: u16::from_be(udp_hdr.dest),
        })
    }

    pub fn is_dns_query(&self) -> bool {
        self.dst_port == 53
    }
}
