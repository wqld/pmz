use core::{
    mem,
    ops::{Deref, DerefMut},
};

use aya_ebpf::programs::TcContext;
use common::DnsHdr;
use ebpf::ptr_at_mut;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

pub struct Context<'a> {
    pub ctx: &'a mut TcContext,
    pub eth_hdr: *mut EthHdr,
    pub ip_hdr: *mut Ipv4Hdr,
    pub udp_hdr: *mut UdpHdr,
    pub dns_hdr: *mut DnsHdr,
}

impl Deref for Context<'_> {
    type Target = TcContext;

    fn deref(&self) -> &Self::Target {
        self.ctx
    }
}

impl DerefMut for Context<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.ctx
    }
}

impl<'a> Context<'a> {
    pub fn load_dns_context(ctx: &'a mut TcContext) -> Result<Self, ()> {
        let eth_hdr: *mut EthHdr = ptr_at_mut(ctx, 0)?;

        match unsafe { (*eth_hdr).ether_type } {
            EtherType::Ipv4 => {}
            _ => return Err(()),
        }

        let ip_hdr: *mut Ipv4Hdr = ptr_at_mut(ctx, EthHdr::LEN)?;

        match unsafe { (*ip_hdr).proto } {
            IpProto::Udp => {}
            _ => return Err(()),
        }

        let udp_hdr: *mut UdpHdr = ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

        if (unsafe { *udp_hdr }).dest != u16::to_be(53) {
            return Err(());
        }

        let dns_hdr: *mut DnsHdr = ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN)?;

        Ok(Self {
            ctx,
            eth_hdr,
            ip_hdr,
            udp_hdr,
            dns_hdr,
        })
    }

    pub fn update_hdrs(&mut self) -> Result<(), ()> {
        self.eth_hdr = ptr_at_mut(self, 0)?;
        self.ip_hdr = ptr_at_mut(self, EthHdr::LEN)?;
        self.udp_hdr = ptr_at_mut(self, EthHdr::LEN + Ipv4Hdr::LEN)?;
        self.dns_hdr = ptr_at_mut(self, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN)?;

        Ok(())
    }

    pub unsafe fn swap_src_dst(&self) {
        mem::swap(&mut (*self.eth_hdr).src_addr, &mut (*self.eth_hdr).dst_addr);
        mem::swap(&mut (*self.ip_hdr).src_addr, &mut (*self.ip_hdr).dst_addr);
        mem::swap(&mut (*self.udp_hdr).source, &mut (*self.udp_hdr).dest);
    }

    pub unsafe fn ignore_udp_csum(&self) {
        let udp_len = self.len() as usize - EthHdr::LEN - Ipv4Hdr::LEN;
        (*self.udp_hdr).len = u16::to_be(udp_len as u16);
        (*self.udp_hdr).check = 0;
    }

    pub unsafe fn recompute_ip_csum(&self) {
        let ip_len = self.len() as usize - EthHdr::LEN;
        (*self.ip_hdr).tot_len = u16::to_be(ip_len as u16);
        (*self.ip_hdr).check = self.compute_ip_csum(false);
    }

    pub unsafe fn compute_ip_csum(&self, verify: bool) -> u16 {
        let mut checksum = 0u32;
        let mut next = self.ip_hdr as *mut u16;

        if !verify {
            (*self.ip_hdr).check = 0;
        }

        for _ in 0..(mem::size_of::<Ipv4Hdr>() >> 1) {
            checksum += *next as u32;
            next = next.add(1);
        }

        !((checksum & 0xffff) + (checksum >> 16)) as u16
    }
}
