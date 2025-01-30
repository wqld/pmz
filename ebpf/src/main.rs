#![no_std]
#![no_main]

mod context;
mod forwarder;
mod resolver;

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::{HashMap, LruHashMap},
    programs::TcContext,
};
use aya_log_ebpf::error;
use common::{DnsQuery, DnsRecordA, NatKey, NatOrigin};
use context::{Context, Kind};
use forwarder::TrafficForwarder;
use resolver::DnsResolver;

#[map]
static SERVICE_CIDR_MAP: HashMap<u8, u32> = HashMap::with_max_entries(1, 0);

#[map]
static SERVICE_REGISTRY: HashMap<DnsQuery, DnsRecordA> = HashMap::with_max_entries(65536, 0);

#[map]
static NAT_TABLE: LruHashMap<NatKey, NatOrigin> = LruHashMap::with_max_entries(65536, 0);

#[classifier]
pub fn resolver(mut ctx: TcContext) -> i32 {
    match try_resolve_dns(&mut ctx) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "error: {}", e);
            TC_ACT_PIPE
        }
    }
}

fn try_resolve_dns(ctx: &mut TcContext) -> Result<i32, &'static str> {
    let mut ctx = match Context::load(ctx) {
        Ok(ctx) => ctx,
        _ => return Ok(TC_ACT_PIPE),
    };

    match ctx.kind {
        Some(Kind::DNS) => {
            let mut dns_resolver = DnsResolver::new(&mut ctx);
            dns_resolver.handle()
        }
        _ => Ok(TC_ACT_PIPE),
    }
}

#[classifier]
pub fn ingress_forwarder(mut ctx: TcContext) -> i32 {
    match try_forward_ingress(&mut ctx) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "error: {}", e);
            TC_ACT_PIPE
        }
    }
}

fn try_forward_ingress(ctx: &mut TcContext) -> Result<i32, &'static str> {
    let mut ctx = match Context::load(ctx) {
        Ok(ctx) => ctx,
        _ => return Ok(TC_ACT_PIPE),
    };

    let mut forwarder = TrafficForwarder::new(&mut ctx);
    forwarder.handle_ingress()
}

#[classifier]
pub fn egress_forwarder(mut ctx: TcContext) -> i32 {
    match try_forward_egress(&mut ctx) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "error: {}", e);
            TC_ACT_PIPE
        }
    }
}

fn try_forward_egress(ctx: &mut TcContext) -> Result<i32, &'static str> {
    let mut ctx = match Context::load(ctx) {
        Ok(ctx) => ctx,
        _ => return Ok(TC_ACT_PIPE),
    };

    let mut forwarder = TrafficForwarder::new(&mut ctx);
    forwarder.handle_egress()
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
