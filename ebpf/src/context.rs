use core::{
    mem,
    ops::{Deref, DerefMut},
    ptr,
};

use aya_ebpf::programs::TcContext;
use aya_log_ebpf::info;
use common::DnsHdr;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

pub enum Kind {
    DNS,
    TCP,
}

pub struct Context<'a> {
    pub ctx: &'a mut TcContext,
    pub kind: Option<Kind>,
    pub eth_hdr: *mut EthHdr,
    pub ip_hdr: *mut Ipv4Hdr,
    pub tcp_hdr: *mut TcpHdr,
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
    fn new(ctx: &'a mut TcContext) -> Self {
        Self {
            ctx,
            kind: None,
            eth_hdr: ptr::null_mut(),
            ip_hdr: ptr::null_mut(),
            tcp_hdr: ptr::null_mut(),
            udp_hdr: ptr::null_mut(),
            dns_hdr: ptr::null_mut(),
        }
    }

    pub fn load(ctx: &'a mut TcContext) -> Result<Self, ()> {
        let mut ctx = Self::new(ctx);

        ctx.eth_hdr = ctx.ptr_at_mut(0)?;

        match unsafe { (*ctx.eth_hdr).ether_type } {
            EtherType::Ipv4 => {}
            _ => return Err(()),
        }

        ctx.ip_hdr = ctx.ptr_at_mut(EthHdr::LEN)?;

        match unsafe { (*ctx.ip_hdr).proto } {
            IpProto::Udp => {
                ctx.kind = Some(Kind::DNS);
                ctx.udp_hdr = ctx.ptr_at_mut(EthHdr::LEN + Ipv4Hdr::LEN)?;

                if (unsafe { *ctx.udp_hdr }).dest != u16::to_be(53) {
                    return Err(());
                }

                ctx.dns_hdr = ctx.ptr_at_mut(EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN)?;
            }
            IpProto::Tcp => {
                ctx.kind = Some(Kind::TCP);
                ctx.tcp_hdr = ctx.ptr_at_mut(EthHdr::LEN + Ipv4Hdr::LEN)?;
            }
            _ => return Err(()),
        }

        Ok(ctx)
    }

    pub fn update_hdrs(&mut self) -> Result<(), ()> {
        self.eth_hdr = self.ptr_at_mut(0)?;
        self.ip_hdr = self.ptr_at_mut(EthHdr::LEN)?;
        self.udp_hdr = self.ptr_at_mut(EthHdr::LEN + Ipv4Hdr::LEN)?;
        self.dns_hdr = self.ptr_at_mut(EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN)?;

        // match unsafe { (*self.ip_hdr).proto } {
        //     IpProto::Udp => {
        //         self.udp_hdr = self.ptr_at_mut(EthHdr::LEN + Ipv4Hdr::LEN)?;
        //         self.dns_hdr = self.ptr_at_mut(EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN)?;
        //     }
        //     IpProto::Tcp => self.tcp_hdr = self.ptr_at_mut(EthHdr::LEN + Ipv4Hdr::LEN)?,
        //     _ => {}
        // };

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

    pub fn ptr_at_mut<T>(&self, offset: usize) -> Result<*mut T, ()> {
        let start = self.data();
        let end = self.data_end();
        let len = mem::size_of::<T>();

        if start + offset + len > end {
            return Err(());
        }

        Ok((start + offset) as *mut T)
    }
}
