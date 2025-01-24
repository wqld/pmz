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
use network_types::{eth::EthHdr, ip::Ipv4Hdr, tcp::TcpHdr};

use crate::{context::Context, NAT_TABLE, SERVICE_CIDR_MAP};

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
        let subnet_mask: u32 = u32::MAX << (32 - 16);
        let proxy_addr: u32 = u32::to_be(2130706433); // 127.0.0.1
        let proxy_port: u16 = u16::to_be(18328);

        let service_cidr_addr: u32 = match unsafe { SERVICE_CIDR_MAP.get(&0) } {
            Some(cidr) => *cidr,
            None => return Ok(TC_ACT_PIPE),
        };

        unsafe {
            let dst_addr = (*self.ip_hdr).dst_addr;
            let dst_port = (*self.tcp_hdr).dest;

            let network_addr = service_cidr_addr & subnet_mask;
            let masked_addr = u32::from_be(dst_addr) & subnet_mask;

            if network_addr == masked_addr {
                let src_addr = (*self.ip_hdr).src_addr;
                let src_port = (*self.tcp_hdr).source;

                let syn = (*self.tcp_hdr).syn();
                let ack = (*self.tcp_hdr).ack();
                let psh = (*self.tcp_hdr).psh();
                let fin = (*self.tcp_hdr).fin();

                debug!(
                    self.ctx.ctx,
                    "ingress src: {:i}:{}, dst: {:i}:{}->{:i}:{} {}/{}/{}/{}",
                    u32::from_be(src_addr),
                    u16::from_be(src_port),
                    u32::from_be(dst_addr),
                    u16::from_be(dst_port),
                    u32::from_be(proxy_addr),
                    u16::from_be(proxy_port),
                    (u16::from_be(syn) != 0) as u8,
                    (u16::from_be(ack) != 0) as u8,
                    (u16::from_be(psh) != 0) as u8,
                    (u16::from_be(fin) != 0) as u8,
                );

                self.nat_v4_rewrite_headers(
                    dst_addr,
                    proxy_addr,
                    offset_of!(Ipv4Hdr, dst_addr),
                    dst_port,
                    proxy_port,
                    offset_of!(TcpHdr, dest),
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

                NAT_TABLE
                    .insert(&nat_key, &nat_orign, 0)
                    .map_err(|_| "Failed to insert NAT information to nat table")?;

                debug!(
                    self.ctx.ctx,
                    "NatKey inserted src: {}:{} dst: {}:{}",
                    nat_key.src_addr,
                    nat_key.src_port,
                    nat_key.dst_addr,
                    nat_key.dst_port
                );
            }
        }

        Ok(TC_ACT_PIPE)
    }

    pub fn handle_egress(&mut self) -> Result<i32, &'static str> {
        unsafe {
            let proxy_addr: u32 = u32::to_be(2130706433); // 127.0.0.1
            let proxy_port: u16 = u16::to_be(18328);

            let src_addr = (*self.ip_hdr).src_addr;
            let src_port = (*self.tcp_hdr).source;

            if src_addr == proxy_addr && src_port == proxy_port {
                let dst_addr = (*self.ip_hdr).dst_addr;
                let dst_port = (*self.tcp_hdr).dest;

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

                let syn = (*self.tcp_hdr).syn();
                let ack = (*self.tcp_hdr).ack();
                let psh = (*self.tcp_hdr).psh();
                let fin = (*self.tcp_hdr).fin();

                debug!(
                    self.ctx.ctx,
                    "egress src: {:i}:{}->{:i}:{}, dst: {:i}:{} {}/{}/{}/{}",
                    u32::from_be(src_addr),
                    u16::from_be(src_port),
                    u32::from_be(nat_origin.addr),
                    u16::from_be(nat_origin.port),
                    u32::from_be(dst_addr),
                    u16::from_be(dst_port),
                    (u16::from_be(syn) != 0) as u8,
                    (u16::from_be(ack) != 0) as u8,
                    (u16::from_be(psh) != 0) as u8,
                    (u16::from_be(fin) != 0) as u8,
                );

                self.nat_v4_rewrite_headers(
                    src_addr,
                    nat_origin.addr,
                    offset_of!(Ipv4Hdr, src_addr),
                    src_port,
                    nat_origin.port,
                    offset_of!(TcpHdr, source),
                )?;
            }
        }

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
            EthHdr::LEN + Ipv4Hdr::LEN + offset_of!(TcpHdr, check),
            old_port as u64,
            new_port as u64,
            mem::size_of_val(&new_port) as u64,
        )
        .map_err(|_| "Failed to update the L4 checksum for port replacement")?;

        self.store(EthHdr::LEN + Ipv4Hdr::LEN + port_offset, &new_port, 0)
            .map_err(|_| "Failed to store the updated port value")?;

        self.l4_csum_replace(
            EthHdr::LEN + Ipv4Hdr::LEN + offset_of!(TcpHdr, check),
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
