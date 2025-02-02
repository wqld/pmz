use aya::{
    maps::HashMap,
    programs::{tc, SchedClassifier, TcAttachType},
};
use clap::Parser;
use command::Command;
use common::{DnsQuery, DnsRecordA, NatKey, NatOrigin};
use log::{debug, warn};
use proxy::Proxy;
use sudo::PrivilegeLevel;
use tokio::signal;
use tunnel::TunnelRequest;

mod command;
mod connect;
mod deploy;
mod discovery;
mod forward;
mod proxy;
mod route;
mod sudo;
mod tunnel;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    PrivilegeLevel::escalate_if_needed()?;

    let opt = Opt::parse();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/pmz"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let Opt { iface } = opt;
    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(&iface);
    let _ = tc::qdisc_add_clsact("lo");

    let resolver: &mut SchedClassifier = ebpf.program_mut("resolver").unwrap().try_into()?;
    resolver.load()?;
    resolver.attach(&iface, TcAttachType::Egress)?;

    let ingress_forwarder: &mut SchedClassifier =
        ebpf.program_mut("ingress_forwarder").unwrap().try_into()?;
    ingress_forwarder.load()?;
    ingress_forwarder.attach("lo", TcAttachType::Ingress)?;

    let egress_forwarder: &mut SchedClassifier =
        ebpf.program_mut("egress_forwarder").unwrap().try_into()?;
    egress_forwarder.load()?;
    egress_forwarder.attach("lo", TcAttachType::Egress)?;

    let (req_tx, req_rx) = tokio::sync::mpsc::channel::<TunnelRequest>(1);

    let nat_table: HashMap<_, NatKey, NatOrigin> =
        HashMap::try_from(ebpf.take_map("NAT_TABLE").unwrap())?;

    let service_registry: HashMap<_, DnsQuery, DnsRecordA> =
        HashMap::try_from(ebpf.take_map("SERVICE_REGISTRY").unwrap())?;

    let service_cidr_map: HashMap<_, u8, u32> =
        HashMap::try_from(ebpf.take_map("SERVICE_CIDR_MAP").unwrap())?;

    let proxy = Proxy::new(nat_table, req_tx);
    let command = Command::new(req_rx, service_registry, service_cidr_map);

    tokio::spawn(async move { proxy.start().await });
    tokio::spawn(async move { command.run().await });

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
