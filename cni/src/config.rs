use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[clap(short, long, default_value = "eth0")]
    iface: String,

    #[arg(short, long, default_value = "/etc/cni/net.d")]
    cni_conf_dir: String,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub iface: String,
    pub cni_conf_dir: String,
    pub namespace: String,
    pub host_ip: String,
    pub discovery_url: String,
    pub intercept_gate_addr: String,
    pub cni_socket_path: String,
}

impl Config {
    pub fn load() -> Result<Self> {
        let args = Args::parse();
        let namespace = std::env::var("CNI_NAMESPACE")?;
        let host_ip = std::env::var("HOST_IP")?;

        Ok(Self {
            iface: args.iface,
            cni_conf_dir: args.cni_conf_dir,
            discovery_url: format!("http://pmz-agent.{}.svc:50018", namespace),
            intercept_gate_addr: format!("pmz-agent.{}.svc.cluster.local:18326", namespace),
            namespace,
            host_ip,
            cni_socket_path: "/var/run/pmz/cni.sock".to_string(),
        })
    }
}
