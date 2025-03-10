use core::{
    mem,
    ops::{Deref, DerefMut},
    ptr,
};

use aya_ebpf::{
    EbpfContext,
    bindings::{__sk_buff, xdp_md},
};
use common::DnsHdr;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

pub enum Kind {
    TC,
    XDP,
}

#[derive(PartialEq, Eq)]
pub enum Protocol {
    DNS,
    TCP,
    UDP,
}

static PROTO_DNS: &str = "DNS";
static PROTO_TCP: &str = "TCP";
static PROTO_UDP: &str = "UDP";

impl Protocol {
    pub fn kind(&self) -> &'static str {
        match self {
            Protocol::DNS => PROTO_DNS,
            Protocol::TCP => PROTO_TCP,
            Protocol::UDP => PROTO_UDP,
        }
    }
}

pub struct Context<'a, C: EbpfContext> {
    pub ctx: &'a mut C,
    pub kind: Kind,
    pub proto: Option<Protocol>,
    pub eth_hdr: *mut EthHdr,
    pub ip_hdr: *mut Ipv4Hdr,
    pub tcp_hdr: *mut TcpHdr,
    pub udp_hdr: *mut UdpHdr,
    pub dns_hdr: *mut DnsHdr,
}

impl<C: EbpfContext> Deref for Context<'_, C> {
    type Target = C;

    fn deref(&self) -> &Self::Target {
        self.ctx
    }
}

impl<C: EbpfContext> DerefMut for Context<'_, C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.ctx
    }
}

impl<'a, C> Context<'a, C>
where
    C: EbpfContext,
{
    fn new(ctx: &'a mut C, kind: Kind) -> Self {
        Self {
            ctx,
            kind,
            proto: None,
            eth_hdr: ptr::null_mut(),
            ip_hdr: ptr::null_mut(),
            tcp_hdr: ptr::null_mut(),
            udp_hdr: ptr::null_mut(),
            dns_hdr: ptr::null_mut(),
        }
    }

    #[inline(always)]
    pub fn load(ctx: &'a mut C, kind: Kind) -> Result<Self, ()> {
        let mut ctx = Self::new(ctx, kind);

        ctx.eth_hdr = ctx.ptr_at_mut(0)?;

        match unsafe { (*ctx.eth_hdr).ether_type } {
            EtherType::Ipv4 => {}
            _ => return Err(()),
        }

        ctx.ip_hdr = ctx.ptr_at_mut(EthHdr::LEN)?;

        match unsafe { (*ctx.ip_hdr).proto } {
            IpProto::Udp => {
                ctx.udp_hdr = ctx.ptr_at_mut(EthHdr::LEN + Ipv4Hdr::LEN)?;
                ctx.proto = match (unsafe { *ctx.udp_hdr }).dest {
                    13568 /* 53 */ => {
                        ctx.dns_hdr = ctx.ptr_at_mut(EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN)?;
                        Some(Protocol::DNS)
                    }
                    _ => Some(Protocol::UDP),
                };
            }
            IpProto::Tcp => {
                ctx.proto = Some(Protocol::TCP);
                ctx.tcp_hdr = ctx.ptr_at_mut(EthHdr::LEN + Ipv4Hdr::LEN)?;
            }
            _ => return Err(()),
        }

        Ok(ctx)
    }

    pub fn update_hdrs_for_dns(&mut self) -> Result<(), ()> {
        self.eth_hdr = self.ptr_at_mut(0)?;
        self.ip_hdr = self.ptr_at_mut(EthHdr::LEN)?;
        self.udp_hdr = self.ptr_at_mut(EthHdr::LEN + Ipv4Hdr::LEN)?;
        self.dns_hdr = self.ptr_at_mut(EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN)?;

        Ok(())
    }

    pub fn swap_src_dst(&self) {
        unsafe {
            mem::swap(&mut (*self.eth_hdr).src_addr, &mut (*self.eth_hdr).dst_addr);
            mem::swap(&mut (*self.ip_hdr).src_addr, &mut (*self.ip_hdr).dst_addr);
            mem::swap(&mut (*self.udp_hdr).source, &mut (*self.udp_hdr).dest);
        }
    }

    pub fn ignore_udp_csum(&self) {
        let udp_len = self.len() as usize - EthHdr::LEN - Ipv4Hdr::LEN;
        unsafe {
            (*self.udp_hdr).len = u16::to_be(udp_len as u16);
            (*self.udp_hdr).check = 0;
        }
    }

    pub fn recompute_ip_csum(&self) {
        let ip_len = self.len() as usize - EthHdr::LEN;
        unsafe {
            (*self.ip_hdr).tot_len = u16::to_be(ip_len as u16);
            (*self.ip_hdr).check = self.compute_ip_csum(false);
        }
    }

    pub fn compute_ip_csum(&self, verify: bool) -> u16 {
        let mut checksum = 0u32;
        let mut next = self.ip_hdr as *mut u16;

        unsafe {
            if !verify {
                (*self.ip_hdr).check = 0;
            }

            for _ in 0..(mem::size_of::<Ipv4Hdr>() >> 1) {
                checksum += *next as u32;
                next = next.add(1);
            }
        }

        !((checksum & 0xffff) + (checksum >> 16)) as u16
    }

    #[inline(always)]
    pub fn ptr_at_mut<T>(&self, offset: usize) -> Result<*mut T, ()> {
        let start = self.data();
        let end = self.data_end();
        let len = mem::size_of::<T>();

        if start + offset + len > end {
            return Err(());
        }

        Ok((start + offset) as *mut T)
    }

    fn len(&self) -> u32 {
        match self.kind {
            Kind::TC => unsafe { (&*(self.as_ptr() as *const __sk_buff)).len },
            Kind::XDP => 0,
        }
    }

    fn data(&self) -> usize {
        match self.kind {
            Kind::TC => unsafe { (&*(self.as_ptr() as *const __sk_buff)).data as usize },
            Kind::XDP => unsafe { (&*(self.as_ptr() as *const xdp_md)).data as usize },
        }
    }

    fn data_end(&self) -> usize {
        match self.kind {
            Kind::TC => unsafe { (&*(self.as_ptr() as *const __sk_buff)).data_end as usize },
            Kind::XDP => unsafe { (&*(self.as_ptr() as *const xdp_md)).data_end as usize },
        }
    }
}
