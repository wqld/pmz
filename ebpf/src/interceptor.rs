use core::ops::{Deref, DerefMut};

use aya_ebpf::{bindings::TC_ACT_PIPE, programs::TcContext};
use aya_log_ebpf::debug;

use crate::context::{Context, Protocol};

pub struct Interceptor<'a> {
    ctx: &'a mut Context<'a, TcContext>,
}

impl<'a> Deref for Interceptor<'a> {
    type Target = Context<'a, TcContext>;

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
    pub fn new(ctx: &'a mut Context<'a, TcContext>) -> Self {
        Self { ctx }
    }

    pub fn handle_ingress(&mut self) -> Result<i32, &'static str> {
        unsafe {
            let (src_addr, dst_addr) = ((*self.ip_hdr).src_addr, (*self.ip_hdr).dst_addr);
            let (src_port, dst_port) = match self.proto {
                Some(Protocol::TCP) => ((*self.tcp_hdr).source, (*self.tcp_hdr).dest),
                Some(Protocol::UDP) => ((*self.udp_hdr).source, (*self.udp_hdr).dest),
                _ => return Ok(TC_ACT_PIPE),
            };

            debug!(
                self.ctx.ctx,
                "{:i}:{} -> {:i}:{}",
                u32::from_be(src_addr),
                u16::from_be(src_port),
                u32::from_be(dst_addr),
                u16::from_be(dst_port),
            );
        }

        Ok(TC_ACT_PIPE)
    }
}
