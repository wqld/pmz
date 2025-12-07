#![no_std]
#![no_main]

mod context;
mod forwarder;
mod resolver;

use aya_ebpf::{
    EbpfContext,
    bindings::{
        BPF_F_INGRESS, BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB, BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB,
        TC_ACT_PIPE, sk_action::SK_PASS,
    },
    helpers::{
        bpf_get_current_pid_tgid,
        r#gen::{
            bpf_get_netns_cookie, bpf_get_socket_cookie, bpf_msg_redirect_hash,
            bpf_sock_hash_update,
        },
    },
    macros::{cgroup_sock_addr, cgroup_sockopt, classifier, map, sk_msg, sock_ops},
    maps::{HashMap, LruHashMap, SockHash},
    programs::{SkMsgContext, SockAddrContext, SockOpsContext, SockoptContext, TcContext},
};
use aya_log_ebpf::error;
use common::{Config, DnsQuery, DnsRecordA, SockAddr, SockAddrIn, SockKey, SockPair};
use context::{Context, Kind, Protocol};
use resolver::DnsResolver;

use crate::forwarder::TrafficForwarder;

#[map]
static CONFIG_MAP: HashMap<u8, Config> = HashMap::with_max_entries(1, 0);

#[map]
static COOKIE_ORIGIN_MAP: LruHashMap<u64, SockAddr> = LruHashMap::with_max_entries(131072, 0);

#[map]
static PORT_COOKIE_MAP: HashMap<u16, u64> = HashMap::with_max_entries(65536, 0);

#[map]
static PROXY_SOCK_MAP: SockHash<SockKey> = SockHash::with_max_entries(65536, 0);

#[map]
static SERVICE_CIDR_MAP: HashMap<u8, u32> = HashMap::with_max_entries(1, 0);

#[map]
static SERVICE_REGISTRY: HashMap<DnsQuery, DnsRecordA> = HashMap::with_max_entries(65536, 0);

#[map]
static NAT_TABLE: LruHashMap<SockPair, SockAddr> = LruHashMap::with_max_entries(65536, 0);

#[map]
static INTERCEPT_RULE: HashMap<u16, SockAddr> = HashMap::with_max_entries(256, 0);

#[classifier]
pub fn resolver(mut ctx: TcContext) -> i32 {
    match try_resolve_dns(&mut ctx) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "pipe: {}", e);
            TC_ACT_PIPE
        }
    }
}

fn try_resolve_dns(ctx: &mut TcContext) -> Result<i32, &'static str> {
    let mut ctx = Context::load(ctx, Kind::TC)?;

    match ctx.proto {
        Some(Protocol::DNS) => {
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
    let mut ctx = match Context::load(ctx, Kind::TC) {
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
    let mut ctx = match Context::load(ctx, Kind::TC) {
        Ok(ctx) => ctx,
        _ => return Ok(TC_ACT_PIPE),
    };

    let mut forwarder = TrafficForwarder::new(&mut ctx);
    forwarder.handle_egress()
}

#[cgroup_sock_addr(connect4)]
pub fn tcp_connect(ctx: SockAddrContext) -> i32 {
    let sock = unsafe { &mut *ctx.sock_addr };

    if sock.user_family != 2 || sock.protocol != 6 {
        return 1;
    }

    let cfg = match unsafe { CONFIG_MAP.get(&0) } {
        Some(c) => c,
        None => return 1,
    };

    if cfg.proxy_pid == (bpf_get_current_pid_tgid() >> 32) as u32 {
        return 1;
    }

    let current_netns = unsafe { bpf_get_netns_cookie(ctx.sock_addr as *mut _) };

    if current_netns != cfg.host_netns {
        return 1;
    }

    let dst_ip = u32::from_be(sock.user_ip4);
    let dst_port = u16::from_be(sock.user_port as u16);
    let proxy_addr = 2130706433_u32;

    let network_addr = cfg.service_addr & cfg.subnet_mask;
    let masked_addr = dst_ip & cfg.subnet_mask;

    if network_addr != masked_addr {
        return 1;
    }

    // info!(&ctx, "matched!!!!!!!!!!!!!!!: {:i}:{}", dst_ip, dst_port);

    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };

    let origin = SockAddr {
        addr: dst_ip,
        dummy: 0,
        port: dst_port,
    };

    COOKIE_ORIGIN_MAP.insert(&cookie, &origin, 0).ok();

    sock.user_ip4 = proxy_addr.to_be();
    sock.user_port = cfg.proxy_port.to_be() as u32;

    // info!(
    //     &ctx,
    //     "Redirecting client connection to proxy {:i}:{} -> {:i}:{}",
    //     dst_ip,
    //     dst_port,
    //     proxy_addr,
    //     cfg.proxy_port
    // );

    1
}

#[sock_ops]
pub fn tcp_sockops(ctx: SockOpsContext) -> u32 {
    let ops = unsafe { &*ctx.ops };

    if ops.family != 2 {
        return 0;
    }

    let mut is_target_connection = false;

    if ops.op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB {
        let cookie = unsafe { bpf_get_socket_cookie(ctx.ops as *mut _) };

        let _ = unsafe {
            match COOKIE_ORIGIN_MAP.get(&cookie) {
                Some(_) => {
                    let src_port = ops.local_port as u16;
                    PORT_COOKIE_MAP.insert(&src_port, &cookie, 0).ok();
                    // info!(&ctx, "BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB ");
                    is_target_connection = true;
                }
                None => (),
            }
        };
    }

    if ops.op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB {
        if ops.local_port == 18328 {
            // info!(&ctx, "BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB");
            is_target_connection = true;
        }
    }

    if is_target_connection {
        let mut key = SockKey {
            src_ip: u32::from_be(ctx.local_ip4()),
            dst_ip: u32::from_be(ctx.remote_ip4()),
            src_port: ctx.local_port(),
            dst_port: u32::from_be(ctx.remote_port()),
        };

        unsafe {
            bpf_sock_hash_update(
                ctx.ops as *mut _,
                &PROXY_SOCK_MAP as *const _ as *mut _,
                &mut key as *mut _ as *mut _,
                0,
            );
        }
    }

    // info!(&ctx, "sockops hook successful");

    0
}

#[sk_msg]
pub fn tcp_accelerate(ctx: SkMsgContext) -> u32 {
    let msg = unsafe { *ctx.msg };

    let mut key = SockKey {
        src_ip: u32::from_be(msg.remote_ip4),
        dst_ip: u32::from_be(msg.local_ip4),
        src_port: u32::from_be(msg.remote_port),
        dst_port: msg.local_port,
    };

    unsafe {
        bpf_msg_redirect_hash(
            ctx.msg as *mut _,
            &PROXY_SOCK_MAP as *const _ as *mut _,
            &mut key as *mut _ as *mut _,
            BPF_F_INGRESS as u64,
        )
    };

    // info!(&ctx, "tcp_acceleration");

    SK_PASS
}

#[cgroup_sockopt(getsockopt)]
pub fn cg_sockopt(ctx: SockoptContext) -> i32 {
    let sockopt = unsafe { &mut *ctx.sockopt };
    let sk = unsafe { &*sockopt.__bindgen_anon_1.sk };

    if sockopt.optname != 80 {
        return 1;
    }

    if sk.family != 2 || sk.protocol != 6 {
        return 1;
    }

    let src_port = u16::from_be(sk.dst_port as u16);
    let cookie = unsafe {
        match PORT_COOKIE_MAP.get(&src_port) {
            Some(c) => c,
            None => return 1,
        }
    };

    let origin = unsafe {
        match COOKIE_ORIGIN_MAP.get(cookie) {
            Some(s) => s,
            None => return 1,
        }
    };

    let optval = unsafe { sockopt.__bindgen_anon_2.optval };
    let optval_end = unsafe { sockopt.__bindgen_anon_3.optval_end };

    let sockaddr_size = size_of::<SockAddrIn>();

    if optval.is_null() || (optval as usize + sockaddr_size) > (optval_end as usize) {
        return 1;
    }

    let sa = unsafe { &mut *(optval as *mut SockAddrIn) };

    sockopt.optlen = sockaddr_size as i32;
    sa.sin_family = sk.family as u16;
    sa.sin_addr = origin.addr.to_be();
    sa.sin_port = (origin.port as u16).to_be();
    sa.sin_zero = [0; 8];
    sockopt.retval = 0;

    // info!(&ctx, "sockopt succeed");

    1
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
