#![no_std]
#![no_main]

mod context;
mod resolver;

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    macros::{classifier, map},
    maps::HashMap,
    programs::TcContext,
};
use aya_log_ebpf::error;
use common::{DnsQuery, DnsRecordA};
use context::Context;
use resolver::DnsResolver;

#[map]
static SERVICE_REGISTRY: HashMap<DnsQuery, DnsRecordA> =
    HashMap::<DnsQuery, DnsRecordA>::with_max_entries(1024, 0);

#[classifier]
pub fn resolver(mut ctx: TcContext) -> i32 {
    match try_resolve_dns(&mut ctx) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "error: {}", e);
            TC_ACT_SHOT
        }
    }
}

fn try_resolve_dns(ctx: &mut TcContext) -> Result<i32, &'static str> {
    let mut ctx = match Context::load_dns_context(ctx) {
        Ok(ctx) => ctx,
        _ => return Ok(TC_ACT_PIPE),
    };

    let mut dns_resolver = DnsResolver::new(&mut ctx);
    dns_resolver.handle_query()
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
