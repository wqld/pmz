use core::{
    mem,
    ops::{Deref, DerefMut},
};

use aya_ebpf::{
    bindings::{BPF_F_PSEUDO_HDR, TC_ACT_PIPE},
    helpers::bpf_csum_diff,
};
use aya_log_ebpf::debug;
use common::{NatKey, NatOrigin};
use memoffset::offset_of;
use network_types::{eth::EthHdr, ip::Ipv4Hdr, tcp::TcpHdr, udp::UdpHdr};

use crate::{
    context::{Context, Protocol},
    NAT_TABLE, SERVICE_CIDR_MAP,
};

pub struct TrafficForwarder<'a> {
    ctx: &'a mut Context<'a>,
}

impl<'a> Deref for TrafficForwarder<'a> {
    type Target = Context<'a>;

    fn deref(&self) -> &Self::Target {
        self.ctx
    }
}

impl<'a> DerefMut for TrafficForwarder<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.ctx
    }
}

impl<'a> TrafficForwarder<'a> {
    pub fn new(ctx: &'a mut Context<'a>) -> Self {
        Self { ctx }
    }

    pub fn handle_ingress(&mut self) -> Result<i32, &'static str> {
        let subnet_mask: u32 = 4294901760; // u32::MAX << (32 - 16)
        let proxy_addr: u32 = 16777343; // 2130706433 (127.0.0.1)
        let (kind, proxy_port) = match self.proto {
            Some(Protocol::TCP) => (Protocol::TCP, 38983 /* 18328 */),
            Some(Protocol::UDP) => (Protocol::UDP, 38727 /* 18327 */),
            _ => return Ok(TC_ACT_PIPE),
        };

        let service_cidr_addr: u32 = match unsafe { SERVICE_CIDR_MAP.get(&0) } {
            Some(cidr) => *cidr,
            None => return Ok(TC_ACT_PIPE),
        };

        unsafe {
            let (src_addr, dst_addr) = ((*self.ip_hdr).src_addr, (*self.ip_hdr).dst_addr);
            let (src_port, dst_port) = match kind {
                Protocol::TCP => ((*self.tcp_hdr).source, (*self.tcp_hdr).dest),
                Protocol::UDP => ((*self.udp_hdr).source, (*self.udp_hdr).dest),
                _ => return Ok(TC_ACT_PIPE),
            };

            let network_addr = service_cidr_addr & subnet_mask;
            let masked_addr = u32::from_be(dst_addr) & subnet_mask;

            if network_addr == masked_addr {
                return self.dnat(
                    kind, src_addr, src_port, dst_addr, dst_port, proxy_addr, proxy_port,
                );
            }
        }

        Ok(TC_ACT_PIPE)
    }

    pub fn handle_egress(&mut self) -> Result<i32, &'static str> {
        unsafe {
            let proxy_addr: u32 = 16777343; // 2130706433 (127.0.0.1)
            let (kind, proxy_port) = match self.proto {
                Some(Protocol::TCP) => (Protocol::TCP, 38983 /* 18328 */),
                Some(Protocol::UDP) => (Protocol::UDP, 38727 /* 18327 */),
                _ => return Ok(TC_ACT_PIPE),
            };

            let (src_addr, dst_addr) = ((*self.ip_hdr).src_addr, (*self.ip_hdr).dst_addr);
            let (src_port, dst_port) = match kind {
                Protocol::TCP => ((*self.tcp_hdr).source, (*self.tcp_hdr).dest),
                Protocol::UDP => ((*self.udp_hdr).source, (*self.udp_hdr).dest),
                _ => return Ok(TC_ACT_PIPE),
            };

            if src_addr == proxy_addr && src_port == proxy_port {
                return self.snat(kind, src_addr, src_port, dst_addr, dst_port);
            }
        }

        Ok(TC_ACT_PIPE)
    }

    #[inline(always)]
    unsafe fn dnat(
        &mut self,
        kind: Protocol,
        src_addr: u32,
        src_port: u16,
        dst_addr: u32,
        dst_port: u16,
        proxy_addr: u32,
        proxy_port: u16,
    ) -> Result<i32, &'static str> {
        debug!(
            self.ctx.ctx,
            "{} ingress src: {:i}:{}, dst: {:i}:{}->{:i}:{}",
            kind.kind(),
            u32::from_be(src_addr),
            u16::from_be(src_port),
            u32::from_be(dst_addr),
            u16::from_be(dst_port),
            u32::from_be(proxy_addr),
            u16::from_be(proxy_port),
        );

        let (port_offset, csum_offset) = match kind {
            Protocol::TCP => (offset_of!(TcpHdr, dest), offset_of!(TcpHdr, check)),
            Protocol::UDP => (offset_of!(UdpHdr, dest), offset_of!(UdpHdr, check)),
            _ => return Ok(TC_ACT_PIPE),
        };

        self.nat_v4_rewrite_headers(
            dst_addr,
            proxy_addr,
            offset_of!(Ipv4Hdr, dst_addr),
            dst_port,
            proxy_port,
            port_offset,
            csum_offset,
        )?;

        let nat_key = NatKey {
            src_addr,
            dst_addr: proxy_addr,
            src_port,
            dst_port: proxy_port,
        };

        match NAT_TABLE.get(&nat_key) {
            Some(_) => return Ok(TC_ACT_PIPE),
            None => {}
        };

        let nat_orign = NatOrigin {
            addr: dst_addr,
            dummy: 0,
            port: dst_port,
        };

        match NAT_TABLE.insert(&nat_key, &nat_orign, 0) {
            Ok(_) => debug!(
                self.ctx.ctx,
                "NatKey inserted src: {:i}:{} dst: {:i}:{}",
                u32::from_be(src_addr),
                u16::from_be(src_port),
                u32::from_be(dst_addr),
                u16::from_be(dst_port),
            ),
            Err(e) => debug!(
                self.ctx.ctx,
                "Failed to insert NAT information to nat table: {}", e
            ),
        }

        Ok(TC_ACT_PIPE)
    }

    #[inline(always)]
    unsafe fn snat(
        &mut self,
        kind: Protocol,
        src_addr: u32,
        src_port: u16,
        dst_addr: u32,
        dst_port: u16,
    ) -> Result<i32, &'static str> {
        let nat_key = NatKey {
            src_addr: dst_addr,
            src_port: dst_port,
            dst_addr: src_addr,
            dst_port: src_port,
        };

        let nat_origin = match NAT_TABLE.get(&nat_key) {
            Some(origin) => origin,
            None => return Ok(TC_ACT_PIPE),
        };

        debug!(
            self.ctx.ctx,
            "{} egress src: {:i}:{}->{:i}:{}, dst: {:i}:{}",
            kind.kind(),
            u32::from_be(src_addr),
            u16::from_be(src_port),
            u32::from_be(nat_origin.addr),
            u16::from_be(nat_origin.port),
            u32::from_be(dst_addr),
            u16::from_be(dst_port),
        );

        let (port_offset, csum_offset) = match kind {
            Protocol::TCP => (offset_of!(TcpHdr, source), offset_of!(TcpHdr, check)),
            Protocol::UDP => (offset_of!(UdpHdr, source), offset_of!(UdpHdr, check)),
            _ => return Ok(TC_ACT_PIPE),
        };

        self.nat_v4_rewrite_headers(
            src_addr,
            nat_origin.addr,
            offset_of!(Ipv4Hdr, src_addr),
            src_port,
            nat_origin.port,
            port_offset,
            csum_offset,
        )?;

        Ok(TC_ACT_PIPE)
    }

    #[inline(always)]
    fn nat_v4_rewrite_headers(
        &mut self,
        old_addr: u32,
        new_addr: u32,
        addr_offset: usize,
        old_port: u16,
        new_port: u16,
        port_offset: usize,
        l4_csum_offset: usize,
    ) -> Result<(), &'static str> {
        let sum = unsafe {
            bpf_csum_diff(
                &old_addr as *const _ as *mut _,
                4,
                &new_addr as *const _ as *mut _,
                4,
                0,
            )
        } as u64;

        self.store(EthHdr::LEN + addr_offset, &new_addr, 0)
            .map_err(|_| "Failed to store the updated address")?;

        self.l4_csum_replace(
            EthHdr::LEN + Ipv4Hdr::LEN + l4_csum_offset,
            old_port as u64,
            new_port as u64,
            mem::size_of_val(&new_port) as u64,
        )
        .map_err(|_| "Failed to update the L4 checksum for port replacement")?;

        self.store(EthHdr::LEN + Ipv4Hdr::LEN + port_offset, &new_port, 0)
            .map_err(|_| "Failed to store the updated port value")?;

        self.l4_csum_replace(
            EthHdr::LEN + Ipv4Hdr::LEN + l4_csum_offset,
            0,
            sum,
            BPF_F_PSEUDO_HDR as u64,
        )
        .map_err(|_| "Failed to finalize the L4 checksum adjustment (pseudo header update)")?;

        self.l3_csum_replace(EthHdr::LEN + offset_of!(Ipv4Hdr, check), 0, sum, 0)
            .map_err(|_| "Failed to update the L3 checksum for IP header")?;

        Ok(())
    }
}
