use anyhow::Result;
use rsln::{netlink::Netlink, types::addr::AddrFamily};
use socket2::SockRef;
use std::{
    net::{IpAddr, SocketAddr},
    os::fd::OwnedFd,
    path::Path,
    sync::Arc,
};
use tokio::{fs::File, io::AsyncWriteExt, net::TcpStream};
use tracing::{Instrument, debug, error, info, instrument};

use crate::netns::InpodNetns;

const PROXY_LISTENER_PORT: u16 = 18325;
const INTERCEPT_GATE_ADDR: &str = "127.0.0.1:18326";

#[instrument(name = "inpod_redirection", skip_all, fields(%pod_ip))]
pub async fn setup_inpod_redirection(
    pod_ip: IpAddr,
    current_netns: Arc<OwnedFd>,
    target_netns: Option<OwnedFd>,
) -> Result<()> {
    let target_netns = resolve_target_netns(pod_ip, current_netns, target_netns).await?;

    if let Some(inpod_netns) = target_netns {
        debug!("Found target netns: {:?}", inpod_netns);
        start_proxy(inpod_netns).await?;
    } else {
        error!("Could not find target netns for pod IP: {}", pod_ip);
    }

    Ok(())
}

#[instrument(skip_all, err)]
async fn resolve_target_netns(
    pod_ip: IpAddr,
    current_netns: Arc<OwnedFd>,
    target_netns: Option<OwnedFd>,
) -> Result<Option<InpodNetns>> {
    if let Some(netns) = target_netns {
        return Ok(Some(InpodNetns::new(current_netns, netns)));
    };

    let procs = procfs::process::all_processes_with_root("/host/proc")?;
    let mut matched_netns = None;
    let mut oldest_starttime = u64::MAX;

    for proc_result in procs {
        if let Ok(proc) = proc_result {
            let pid = proc.pid();
            let target_netns_path_str = format!("/host/proc/{pid}/ns/net");
            let target_netns_path = Path::new(&target_netns_path_str);

            if let Ok(netns_file) = File::open(target_netns_path).await {
                let target_netns = netns_file.into_std().await.into();
                let inpod_netns = InpodNetns::new(current_netns.clone(), target_netns);

                if inpod_netns.run(|| has_local_ip_address(pod_ip))? {
                    debug!(
                        "Found matching process {:?}({}) for IP {}",
                        proc.exe()?,
                        pid,
                        pod_ip
                    );

                    if let Ok(stat) = proc.stat() {
                        if stat.starttime < oldest_starttime {
                            oldest_starttime = stat.starttime;
                            matched_netns = Some(inpod_netns);
                        }
                    }
                }
            }
        }
    }

    Ok(matched_netns)
}

#[instrument(skip_all, err)]
async fn start_proxy(inpod_netns: InpodNetns) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], PROXY_LISTENER_PORT));

    let sock = inpod_netns.run(|| {
        match setup_inpod_iptables_rule(addr) {
            Ok(_) => {}
            Err(e) => {
                error!(error = ?e, "Failed to set up in-pod iptables rule");
            }
        }
        Ok(tokio::net::TcpSocket::new_v4())
    })??;

    sock.set_reuseport(true)?;
    sock.bind(addr)?;
    let listener = sock.listen(128)?;

    info!("Starting intercept listener in pod netns at {}", addr);
    // SockRef::from(&listener).set_ip_transparent_v4(true)?;
    // let listener = SockRef::from(&listener);

    tokio::spawn(
        async move {
            loop {
                match listener.accept().await {
                    Ok((inbound_stream, remote_addr)) => {
                        tokio::spawn(
                            proxy_connection(inbound_stream, remote_addr).in_current_span(),
                        );
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {:?}", e)
                    }
                }
            }
        }
        .in_current_span(),
    );

    Ok(())
}

#[instrument(skip_all, fields(%remote_addr))]
async fn proxy_connection(mut inbound_stream: tokio::net::TcpStream, remote_addr: SocketAddr) {
    let socket_ref = SockRef::from(&inbound_stream);
    let original_dst = match socket_ref.original_dst_v4() {
        Ok(addr) => addr.as_socket().unwrap(),
        Err(e) => {
            error!("Failed to get original destination: {:?}", e);
            return;
        }
    };

    debug!("Original destination: {:?}", original_dst);

    let mut gate_stream = match TcpStream::connect(INTERCEPT_GATE_ADDR).await {
        Ok(stream) => stream,
        Err(e) => {
            error!("Failed to connect to intercept gate: {:?}", e);
            return;
        }
    };

    match original_dst.ip() {
        IpAddr::V4(ipv4_addr) => {
            let ip_bytes = ipv4_addr.octets();
            let port_bytes = original_dst.port().to_be_bytes();

            let mut header = [0u8; 6];
            header[0..4].copy_from_slice(&ip_bytes);
            header[4..6].copy_from_slice(&port_bytes);

            if let Err(e) = gate_stream.write_all(&header).await {
                error!("Failed to write header to gate stream: {:?}", e);
                return;
            }
        }
        IpAddr::V6(ipv6_addr) => {
            error!("IPv6 is not supported for interception: {:?}", ipv6_addr);
            return;
        }
    }

    if let Err(e) = tokio::io::copy_bidirectional(&mut inbound_stream, &mut gate_stream).await {
        debug!("Error during proxying: {:?}", e);
    }
}

#[instrument(skip_all, fields(%target_ip))]
fn has_local_ip_address(target_ip: IpAddr) -> Result<bool> {
    let mut netlink = Netlink::new();
    let addrs = netlink.addr_list_all(AddrFamily::All)?;
    debug!(
        "netlink.addr_list_all: {:?}",
        addrs.iter().map(|a| a.ip.to_string()).collect::<String>()
    );

    Ok(addrs
        .iter()
        .map(|addr| addr.ip.addr())
        .any(|ip| ip == target_ip))
}

#[instrument(skip_all, fields(%addr))]
fn setup_inpod_iptables_rule(addr: SocketAddr) -> Result<()> {
    let proxy_port_str = addr.port().to_string();
    let intercept_chain = "PMZ_INTERCEPT";
    let conn_mark = "1337";

    let rules = vec![
        vec!["-t", "nat", "-N", intercept_chain],
        vec!["-t", "nat", "-F", intercept_chain],
        vec![
            "-t",
            "nat",
            "-A",
            "PREROUTING",
            "-p",
            "tcp",
            "-j",
            intercept_chain,
        ],
        vec![
            "-t",
            "nat",
            "-A",
            intercept_chain,
            "-m",
            "mark",
            "--mark",
            conn_mark,
            "-j",
            "RETURN",
        ],
        vec![
            "-t",
            "nat",
            "-A",
            intercept_chain,
            "-d",
            "127.0.0.1/32",
            "-j",
            "RETURN",
        ],
        vec![
            "-t",
            "nat",
            "-A",
            intercept_chain,
            "-p",
            "tcp",
            "-j",
            "CONNMARK",
            "--set-mark",
            conn_mark,
        ],
        vec![
            "-t",
            "nat",
            "-A",
            intercept_chain,
            "-p",
            "tcp",
            "-j",
            "REDIRECT",
            "--to-ports",
            &proxy_port_str,
        ],
    ];

    for rule in rules {
        let mut command = std::process::Command::new("iptables");
        command.args(&rule);

        let output = command.output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);

            if rule.get(2) == Some(&"-N") && stderr.contains("Chain already exists") {
                debug!(
                    "Chain '{}' already exists, which is safe to ignore.",
                    rule[3]
                );
                continue;
            }

            anyhow::bail!(
                "Iptables command failed: {:?}, status: {}, stderr: {}",
                &rule,
                output.status,
                stderr
            );
        }
    }

    info!("Successfully applied iptables INTERCEPT rules.");
    Ok(())
}
