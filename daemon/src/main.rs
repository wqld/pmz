use std::{fs::File, sync::Arc};

use ::proxy::tunnel::client::TunnelRequest;
use aya::{
    maps::{HashMap, SockHash},
    programs::{
        CgroupAttachMode, CgroupSockAddr, CgroupSockopt, SchedClassifier, SkMsg, SockOps,
        TcAttachType, tc,
    },
};
use clap::Parser;
use command::Command;
use common::{Config, DnsQuery, DnsRecordA, SockAddr, SockKey, SockPair};
use connect::ConnectionStatus;
use proxy::Proxy;
use sudo::PrivilegeLevel;
use tokio::{
    signal,
    sync::{RwLock, mpsc},
};
use tracing::{debug, warn};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

mod command;
mod connect;
mod deploy;
mod discovery;
mod intercept;
mod proxy;
mod route;
mod sudo;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let (non_blocking, _guard) = tracing_appender::non_blocking(std::io::stdout());
    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(fmt::layer().with_writer(non_blocking))
        .init();

    PrivilegeLevel::escalate_if_needed()?;

    // console_subscriber::init();

    let opt = Opt::parse();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!(ret = ret, "Remove limit on locked memory failed");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/pmz"
    )))?;
    // if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
    //     // This can happen if you remove all log statements from your eBPF program.
    //     warn!(error = ?e, "Failed to initialize eBPF logger");
    // }
    let Opt { iface } = opt;
    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(&iface);
    let _ = tc::qdisc_add_clsact("lo");

    let resolver: &mut SchedClassifier = ebpf.program_mut("resolver").unwrap().try_into()?;
    resolver.load()?;
    resolver.attach(&iface, TcAttachType::Egress)?;

    // let ingress_forwarder: &mut SchedClassifier =
    //     ebpf.program_mut("ingress_forwarder").unwrap().try_into()?;
    // ingress_forwarder.load()?;
    // ingress_forwarder.attach("lo", TcAttachType::Ingress)?;

    // let egress_forwarder: &mut SchedClassifier =
    //     ebpf.program_mut("egress_forwarder").unwrap().try_into()?;
    // egress_forwarder.load()?;
    // egress_forwarder.attach("lo", TcAttachType::Egress)?;

    let cgroup_file = File::open("/sys/fs/cgroup")?;
    let tcp_connect: &mut CgroupSockAddr = ebpf.program_mut("tcp_connect").unwrap().try_into()?;
    tcp_connect.load()?;
    tcp_connect.attach(cgroup_file.try_clone()?, CgroupAttachMode::Single)?;

    let sock_ops: &mut SockOps = ebpf.program_mut("tcp_sockops").unwrap().try_into()?;
    sock_ops.load()?;
    sock_ops.attach(cgroup_file.try_clone()?, CgroupAttachMode::Single)?;

    let sockopt: &mut CgroupSockopt = ebpf.program_mut("cg_sockopt").unwrap().try_into()?;
    sockopt.load()?;
    sockopt.attach(cgroup_file.try_clone()?, CgroupAttachMode::Single)?;

    let proxy_sock_map: SockHash<_, SockKey> =
        SockHash::try_from(ebpf.take_map("PROXY_SOCK_MAP").unwrap())?;

    let sk_msg_prog: &mut SkMsg = ebpf.program_mut("tcp_accelerate").unwrap().try_into()?;
    sk_msg_prog.load()?;
    sk_msg_prog.attach(&proxy_sock_map.fd())?;

    let (req_tx, req_rx) = mpsc::channel::<TunnelRequest>(1024);

    let config_map: HashMap<_, u8, Config> =
        HashMap::try_from(ebpf.take_map("CONFIG_MAP").unwrap())?;

    let nat_table: HashMap<_, SockPair, SockAddr> =
        HashMap::try_from(ebpf.take_map("NAT_TABLE").unwrap())?;

    let service_registry: HashMap<_, DnsQuery, DnsRecordA> =
        HashMap::try_from(ebpf.take_map("SERVICE_REGISTRY").unwrap())?;

    let service_cidr_map: HashMap<_, u8, u32> =
        HashMap::try_from(ebpf.take_map("SERVICE_CIDR_MAP").unwrap())?;

    let connection_status = Arc::new(RwLock::new(ConnectionStatus::new()));
    let connection_status_clone = connection_status.clone();

    let proxy = Proxy::new(nat_table, req_tx, connection_status);
    let proxy = Arc::new(proxy);
    let command = Command::new(
        req_rx,
        service_registry,
        service_cidr_map,
        config_map,
        connection_status_clone,
    );

    tokio::spawn(async move { proxy.start().await });
    tokio::spawn(async move { command.run().await });

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
