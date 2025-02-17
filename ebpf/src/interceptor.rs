use core::ops::{Deref, DerefMut};

use aya_ebpf::{bindings::xdp_action::XDP_PASS, programs::XdpContext};
use aya_log_ebpf::debug;
use common::SockAddr;

use crate::{
    context::{Context, Protocol},
    INTERCEPT_RULE,
};

pub struct Interceptor<'a> {
    ctx: &'a mut Context<'a, XdpContext>,
}

impl<'a> Deref for Interceptor<'a> {
    type Target = Context<'a, XdpContext>;

    fn deref(&self) -> &Self::Target {
        self.ctx
    }
}

impl<'a> DerefMut for Interceptor<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.ctx
    }
}

impl<'a> Interceptor<'a> {
    pub fn new(ctx: &'a mut Context<'a, XdpContext>) -> Self {
        Self { ctx }
    }

    pub unsafe fn handle_xdp(&mut self) -> Result<u32, ()> {
        let (src_addr, dst_addr) = ((*self.ip_hdr).src_addr, (*self.ip_hdr).dst_addr);
        let (src_port, dst_port) = match self.proto {
            Some(Protocol::TCP) => ((*self.tcp_hdr).source, (*self.tcp_hdr).dest),
            Some(Protocol::UDP) => ((*self.udp_hdr).source, (*self.udp_hdr).dest),
            _ => return Ok(XDP_PASS),
        };

        // debug!(
        //     self.ctx.ctx,
        //     "{:i}:{} -> {:i}:{}",
        //     u32::from_be(src_addr),
        //     u16::from_be(src_port),
        //     u32::from_be(dst_addr),
        //     u16::from_be(dst_port),
        // );

        let key = SockAddr {
            addr: dst_addr,
            dummy: 0,
            port: dst_port,
        };

        if let Some(rule) = INTERCEPT_RULE.get(&key) {
            debug!(
                self.ctx.ctx,
                "xdp src: {:i}:{}, dst: {:i}:{}->{:i}:{}",
                u32::from_be(src_addr),
                u16::from_be(src_port),
                u32::from_be(dst_addr),
                u16::from_be(dst_port),
                u32::from_be(rule.addr),
                u16::from_be(rule.port),
            );
        }

        Ok(XDP_PASS)
    }
}
