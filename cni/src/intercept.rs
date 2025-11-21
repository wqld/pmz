use anyhow::{Result, bail};
use rsln::{netlink::Netlink, types::addr::AddrFamily};
use socket2::SockRef;
use std::{
    net::{IpAddr, SocketAddr},
    os::fd::OwnedFd,
    path::Path,
    sync::Arc,
};
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpSocket, TcpStream},
};
use tracing::{Instrument, debug, error, info, instrument};

use crate::netns::InpodNetns;

const PROXY_LISTENER_PORT: u16 = 18325;

#[instrument(name = "inpod_redirection", skip_all, fields(%pod_ip))]
pub async fn setup_inpod_redirection(
    pod_ip: IpAddr,
    intercept_gate_addr: &str,
    current_netns: Arc<OwnedFd>,
    target_netns: Option<OwnedFd>,
) -> Result<()> {
    let target_netns = resolve_target_netns(pod_ip, current_netns, target_netns).await?;

    if let Some(inpod_netns) = target_netns {
        debug!("Found target netns: {:?}", inpod_netns);
        start_proxy(inpod_netns, intercept_gate_addr).await?;
    } else {
        error!(pod_ip = %pod_ip, "Could not find target netns");
        bail!("Could not find target netns for pod IP {}", pod_ip);
    }

    Ok(())
}

#[instrument(name = "stop_inpod_redirection", skip_all, fields(%pod_ip))]
pub async fn stop_inpod_redirection(pod_ip: IpAddr, current_netns: Arc<OwnedFd>) -> Result<()> {
    let target_netns = resolve_target_netns(pod_ip, current_netns, None).await?;

    if let Some(inpod_netns) = target_netns {
        debug!("Found target netns: {:?}", inpod_netns);
        inpod_netns.run(|| cleanup_inpod_iptables_rules())?;
    } else {
        error!(pod_ip = %pod_ip, "Could not find target netns");
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
                        pid,
                        pod_ip = %pod_ip,
                        exe = ?proc.exe(),
                        "Found matching process"
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
async fn start_proxy(inpod_netns: InpodNetns, intercept_gate_url: &str) -> Result<()> {
    // TODO: udp support
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
    let intercept_gate_addr = intercept_gate_url.to_owned();

    tokio::spawn(
        async move {
            loop {
                match listener.accept().await {
                    Ok((inbound_stream, remote_addr)) => {
                        tokio::spawn(
                            proxy_connection(
                                inbound_stream,
                                remote_addr,
                                inpod_netns.clone(),
                                intercept_gate_addr.clone(),
                            )
                            .in_current_span(),
                        );
                    }
                    Err(e) => {
                        error!(error = ?e, "Failed to accept connection");
                    }
                }
            }
        }
        .in_current_span(),
    );

    Ok(())
}

#[instrument(skip_all, fields(%remote_addr))]
async fn proxy_connection(
    inbound_stream: tokio::net::TcpStream,
    remote_addr: SocketAddr,
    inpod_netns: InpodNetns,
    intercept_gate_addr: String,
) {
    let socket_ref = SockRef::from(&inbound_stream);
    let original_dst = match socket_ref.original_dst_v4() {
        Ok(addr) => addr.as_socket().unwrap(),
        Err(e) => {
            error!(error = ?e, "Failed to get original destination");
            return;
        }
    };

    debug!("Original destination: {:?}", original_dst);

    let mut inbound_stream = BufReader::new(inbound_stream);
    let buf = match inbound_stream.fill_buf().await {
        Ok(buf) if buf.is_empty() => {
            debug!("Client closed connection before sending data.");
            return;
        }
        Ok(buf) => buf,
        Err(e) => {
            error!(error = ?e, "Failed to buffer inbound stream");
            return;
        }
    };

    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    let mut should_forward_to_original = false;

    match req.parse(buf) {
        Ok(status) if status.is_complete() => {
            for header in req.headers {
                if header.name.eq_ignore_ascii_case("pmz-origin") && header.value == b"true" {
                    should_forward_to_original = true;
                    debug!("Found 'pmz-origin: true' header. Forwarding to original destination.");
                    break;
                }
            }
            if !should_forward_to_original {
                debug!("HTTP request parsed, but 'pmz-origin: true' header not found.");
            }
        }
        Ok(status) if status.is_partial() => {
            debug!("Partial HTTP request received. Defaulting to intercept gate.");
        }
        Err(e) => {
            debug!(error = ?e, "Failed to parse HTTP request. Defaulting to intercept gate.");
        }
        _ => {
            debug!("Defaulting to intercept gate.");
        }
    }

    if should_forward_to_original {
        let socket = inpod_netns
            .run(|| {
                let socket = match original_dst {
                    SocketAddr::V4(_) => TcpSocket::new_v4().unwrap(),
                    SocketAddr::V6(_) => TcpSocket::new_v6().unwrap(),
                };
                Ok(socket)
            })
            .unwrap();

        SockRef::from(&socket).set_mark(1337).unwrap();

        let mut original_dst_stream = match socket.connect(original_dst).await {
            Ok(stream) => stream,
            Err(e) => {
                error!(error = ?e, "Failed to connect to original destination");
                return;
            }
        };

        if let Err(e) =
            tokio::io::copy_bidirectional(&mut inbound_stream, &mut original_dst_stream).await
        {
            debug!(error = ?e, "Error during proxying to original destination");
        }
        debug!("Proxying to original destination completed.");
    } else {
        let mut gate_stream = match TcpStream::connect(intercept_gate_addr).await {
            Ok(stream) => stream,
            Err(e) => {
                error!(error = ?e, "Failed to connect to intercept gate");
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
                    error!(errpr = ?e, "Failed to write header to gate stream");
                    return;
                }
            }
            IpAddr::V6(ipv6_addr) => {
                error!(ip = %ipv6_addr, "IPv6 is not supported for interception");
                return;
            }
        }

        if let Err(e) = tokio::io::copy_bidirectional(&mut inbound_stream, &mut gate_stream).await {
            debug!(error = ?e, "Error during proxying");
        }
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
            "-D",
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
            let op = rule.get(2).map(|s| *s);

            if op == Some("-N") && stderr.contains("Chain already exists") {
                debug!(
                    "Chain '{}' already exists, which is safe to ignore.",
                    rule[3]
                );
                continue;
            }

            if op == Some("-D") && stderr.contains("No chain/target/match") {
                debug!(
                    "Rule to delete not found, which is safe to ignore: {:?}",
                    &rule
                );
                continue;
            }

            bail!(
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

#[instrument(skip_all)]
fn cleanup_inpod_iptables_rules() -> Result<()> {
    let intercept_chain = "PMZ_INTERCEPT";

    let cleanup_rules = vec![
        vec![
            "-t",
            "nat",
            "-D",
            "PREROUTING",
            "-p",
            "tcp",
            "-j",
            intercept_chain,
        ],
        vec!["-t", "nat", "-F", intercept_chain],
        vec!["-t", "nat", "-X", intercept_chain],
    ];

    info!("Cleaning up iptables INTERCEPT rules...");

    for rule in cleanup_rules {
        let mut command = std::process::Command::new("iptables");
        command.args(&rule);

        let output = command.output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);

            if stderr.contains("No chain/target/match") || stderr.contains("No chain by that name")
            {
                debug!(
                    "Rule/chain to clean up not found, which is fine: {:?}",
                    &rule
                );
                continue;
            }

            bail!(
                "Iptables cleanup command failed: {:?}, status: {}, stderr: {}",
                &rule,
                output.status,
                stderr
            );
        }
    }

    info!("Successfully cleaned up iptables INTERCEPT rules.");
    Ok(())
}
