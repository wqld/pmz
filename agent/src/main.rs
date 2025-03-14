use anyhow::{Result, bail};
use aya::maps::HashMap;
use aya::programs::{Xdp, XdpFlags};
use clap::Parser;
use common::SockAddr;

use ::proxy::tunnel;
use ::proxy::tunnel::server::TunnelServer;
use log::{debug, warn};
use server::Server;

mod server;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[clap(short, long, default_value = "eth0")]
    iface: String,

    #[arg(short, long, default_value = "127.0.0.1")]
    ip: String,

    #[arg(short, long, default_value_t = 8100)]
    tunnel_port: u16,

    #[arg(short, long, default_value_t = 8101)]
    api_port: u16,

    #[arg(short, long, default_value = "/certs/pmz.crt")]
    cert: String,

    #[arg(short, long, default_value = "/certs/pmz.key")]
    key: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/pmz"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let interceptor: &mut Xdp = ebpf.program_mut("interceptor").unwrap().try_into()?;
    interceptor.load()?;
    interceptor.attach(&args.iface, XdpFlags::default())?;

    let _intercept_rule: HashMap<_, SockAddr, SockAddr> =
        HashMap::try_from(ebpf.take_map("INTERCEPT_RULE").unwrap())?;

    let server = Server::new(args.api_port);

    let tunnel = TunnelServer::new(tunnel::server::Args {
        ip: args.ip,
        proxy_port: args.tunnel_port,
        cert: args.cert,
        key: args.key,
    });

    match tokio::join!(server.start(), tunnel.start()) {
        (Ok(_), Ok(_)) => Ok(()),
        (Ok(_), Err(e)) | (Err(e), Ok(_)) => Err(e),
        (Err(e1), Err(e2)) => bail!("{:?} + {:?}", e1, e2),
    }
}
