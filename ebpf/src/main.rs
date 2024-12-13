#![no_std]
#![no_main]

mod dns;
mod sock;

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    macros::classifier,
    programs::TcContext,
};
use aya_log_ebpf::error;
use dns::{DnsHdr, DnsQuery};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
};
use sock::SocketPair;

#[classifier]
pub fn resolver(ctx: TcContext) -> i32 {
    match catch_dns_query(&ctx) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "error: {}", e);
            TC_ACT_SHOT
        }
    }
}

fn catch_dns_query(ctx: &TcContext) -> Result<i32, &'static str> {
    match load_eth_and_ip_headers(ctx) {
        Ok((_, ipv4hdr)) => match ipv4hdr.proto {
            IpProto::Udp => handle_udp_egress(ctx),
            _ => Ok(TC_ACT_PIPE),
        },
        _ => Ok(TC_ACT_PIPE),
    }
}

fn load_eth_and_ip_headers(ctx: &TcContext) -> Result<(EthHdr, Ipv4Hdr), &'static str> {
    let eth_hdr: EthHdr = ctx.load(0).map_err(|_| "failed to load ethernet header")?;
    match eth_hdr.ether_type {
        EtherType::Ipv4 => {
            let ipv4hdr: Ipv4Hdr = ctx
                .load(EthHdr::LEN)
                .map_err(|_| "failed to load ip header")?;
            Ok((eth_hdr, ipv4hdr))
        }
        _ => Err("not UPv4"),
    }
}

fn handle_udp_egress(ctx: &TcContext) -> Result<i32, &'static str> {
    let socket_pair = SocketPair::load(ctx)?;

    if socket_pair.is_dns_query() {
        let dns_hdr = DnsHdr::load(ctx)?;

        if !dns_hdr.is_standard_query() {
            return Ok(TC_ACT_PIPE);
        }

        DnsQuery::handle(ctx, &dns_hdr)?;
    }

    Ok(TC_ACT_PIPE)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
