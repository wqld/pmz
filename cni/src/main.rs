use std::{
    ffi::OsStr,
    net::{IpAddr, SocketAddr},
    os::{fd::AsFd, unix::fs::PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Result, bail};
use clap::Parser;
use http_body_util::Full;
use hyper::{
    Request, Response,
    body::{Bytes, Incoming},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use log::{debug, error, info, warn};
use nix::sched::{CloneFlags, setns};
use proto::{DiscoveryRequest, intercept_discovery_client::InterceptDiscoveryClient};
use rsln::{netlink::Netlink, types::addr::AddrFamily};
use serde::{Deserialize, Serialize};
use socket2::SockRef;
use tokio::{
    fs::File,
    net::{TcpStream, UnixListener},
    time::sleep,
};
use tokio_stream::StreamExt;
use tonic::transport;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[clap(short, long, default_value = "eth0")]
    iface: String,

    #[arg(short, long, default_value = "/etc/cni/net.d")]
    cni_conf_dir: String,
}

#[derive(Serialize)]
struct CniPluginConfig {
    #[serde(rename = "type")]
    plugin_type: String,
}

#[derive(Deserialize)]
struct CniConfList {
    plugins: Vec<serde_json::Value>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();
    let namespace = std::env::var("CNI_NAMESPACE")?;
    let host_ip = std::env::var("HOST_IP")?;

    // discovery thread
    tokio::spawn(async move {
        const MAX_RETRIES: u32 = 5;
        const INITIAL_DELAY_MS: u64 = 500;

        let url = format!("http://pmz-agent.{}.svc:50018", namespace);
        debug!("Discovery: {namespace}, {host_ip}, {url}");

        let mut client = None;

        for attempt in 0..MAX_RETRIES {
            let endpoint = match transport::Endpoint::from_shared(url.clone()) {
                Ok(ep) => ep,
                Err(e) => {
                    error!(
                        "Failed to create endpoint ({}/{MAX_RETRIES}): {e:?}",
                        attempt + 1,
                    );
                    bail!("Invalid URL format for endpoint: {}", e);
                }
            };

            match endpoint.connect().await {
                Ok(ch) => {
                    info!("Successfully connected to discovery server");
                    client = Some(InterceptDiscoveryClient::new(ch));
                }
                Err(e) => {
                    error!("Connection failed ({}/{MAX_RETRIES}): {e:?}", attempt + 1);

                    if attempt == MAX_RETRIES - 1 {
                        error!("Failed to connect after all retries");
                        bail!("Failed to connect after {MAX_RETRIES} attemps: {e:?}");
                    }

                    let delay_ms = INITIAL_DELAY_MS * 2_u64.pow(attempt);
                    warn!(
                        "Retrying connection after {delay_ms} ({}/{MAX_RETRIES})",
                        attempt + 1
                    );
                    sleep(Duration::from_millis(delay_ms)).await;
                }
            }
        }

        let mut client = match client {
            Some(c) => c,
            None => bail!("Client could not be initialized after retries (logic error?)"),
        };

        info!("Requesting intercepts stream");

        let mut stream = client
            .intercepts(DiscoveryRequest { node_ip: host_ip })
            .await?
            .into_inner();

        debug!("Discovery: streaming started..");

        let self_netns_path = "/proc/self/ns/net";
        let current_netns = File::open(self_netns_path).await.unwrap();
        let current_netns_fd = current_netns.as_fd();

        while let Some(resp) = stream.next().await {
            debug!("received: {resp:?}");

            if let Ok(resp) = resp {
                for intercept_endpoints in resp.resources {
                    // let namespace = intercept_endpoints.namespace;
                    // let target_port = intercept_endpoints.target_port;

                    // let mut target_netns_list = vec![];

                    for pod_identifier in intercept_endpoints.pod_ids {
                        // let pod_name = pod_identifier.name;
                        let pod_ip = pod_identifier.ip;
                        let pod_ip = pod_ip.parse()?;

                        let mut oldest_starttime = u64::MAX;
                        let mut matched_netns_path = None;

                        let procs = procfs::process::all_processes_with_root("/host/proc").unwrap();

                        for proc in procs {
                            let p = match proc {
                                Ok(p) => p,
                                Err(_) => continue,
                            };

                            let pid = p.pid();
                            let target_netns_path_str = format!("/host/proc/{}/ns/net", pid);
                            let target_netns_path = Path::new(&target_netns_path_str);

                            let target_netns = match File::open(target_netns_path).await {
                                Ok(f) => f,
                                Err(_) => continue,
                            };
                            let target_netns_fd = target_netns.as_fd();

                            let match_found = run_in_ns(current_netns_fd, target_netns_fd, || {
                                has_local_ip_address(pod_ip)
                            })?;

                            if !match_found {
                                continue;
                            }

                            let exec_cmd = p.exe()?;
                            debug!("match {pod_ip:?} with {exec_cmd:?}");

                            match p.stat() {
                                Ok(stat) => {
                                    if stat.starttime < oldest_starttime {
                                        matched_netns_path = Some(target_netns_path_str);
                                        oldest_starttime = stat.starttime;
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to read proc {pid} stats: {e:?}");

                                    if matched_netns_path.is_none() {
                                        matched_netns_path = Some(target_netns_path_str);
                                    }
                                }
                            }
                        }

                        if let Some(netns_path) = matched_netns_path {
                            debug!("target netns: {netns_path}");
                            let target_netns = match File::open(netns_path).await {
                                Ok(f) => f,
                                Err(_) => continue,
                            };
                            let target_netns_fd = target_netns.as_fd();
                            let addr = SocketAddr::from(([0, 0, 0, 0], 18325));

                            debug!("addr: {:?}", addr);

                            let sock = run_in_ns(current_netns_fd, target_netns_fd, || {
                                match setup_inpod_iptables_rule(addr) {
                                    Ok(_) => {}
                                    Err(e) => {
                                        error!("Failed to set up in-pod iptables rule: {:?}", e);
                                    }
                                }
                                Ok(tokio::net::TcpSocket::new_v4())
                            })??;

                            sock.set_reuseport(true)?;
                            sock.bind(addr)?;
                            let listener = sock.listen(128)?;
                            // SockRef::from(&listener).set_ip_transparent_v4(true)?;
                            // let listener = SockRef::from(&listener);
                            const INTERCEPT_GATE_ADDR: &str = "127.0.0.1:18326";

                            tokio::spawn(async move {
                                debug!(
                                    "intercept listener is now running, accepting connections.."
                                );
                                loop {
                                    match listener.accept().await {
                                        Ok((mut inbound_stream, remote_addr)) => {
                                            debug!(
                                                "Accepted new connection from {:?}",
                                                remote_addr
                                            );

                                            let socket_ref = SockRef::from(&inbound_stream);
                                            let original_dst = match socket_ref.original_dst_v4() {
                                                Ok(addr) => addr.as_socket().unwrap(),
                                                Err(_) => todo!(),
                                            };
                                            debug!("Original dest: {:?}", original_dst);

                                            tokio::spawn(async move {
                                                let mut gate_stream =
                                                    TcpStream::connect(INTERCEPT_GATE_ADDR)
                                                        .await
                                                        .unwrap();

                                                debug!(
                                                    "Proxying connection from {} to {}",
                                                    remote_addr, INTERCEPT_GATE_ADDR
                                                );

                                                tokio::io::copy_bidirectional(
                                                    &mut inbound_stream,
                                                    &mut gate_stream,
                                                )
                                                .await
                                                .unwrap();
                                            });
                                        }
                                        Err(e) => {
                                            error!("Failed to accept connection: {:?}", e)
                                        }
                                    }
                                }
                            });

                            // target_netns_list.push(netns_path);
                        } else {
                            error!("Can't find target netns for {pod_ip:?}");
                        }
                    }
                }
            }
        }

        Ok(())
    });

    // update the existing CNI configuration to enable the invocation of pmz-cni via chaining
    let dir_path = Path::new(&args.cni_conf_dir);
    debug!("cni conf dir: {dir_path:?}");
    if let Some(conflist_path) = get_first_lexicographical_conflist(dir_path).await? {
        update_cni_conflist(&conflist_path).await?;
    } else {
        error!("no conflist exists");
    }

    let unix_sock_path = Path::new("/var/run/pmz/cni.sock");

    if unix_sock_path.exists() {
        tokio::fs::remove_file(unix_sock_path).await?;
    }

    let listener = UnixListener::bind(unix_sock_path)?;
    tokio::fs::set_permissions(unix_sock_path, std::fs::Permissions::from_mode(0o700)).await?;
    loop {
        let (stream, _) = listener.accept().await?;

        tokio::spawn(async move {
            if let Err(e) = http1::Builder::new()
                .serve_connection(
                    TokioIo::new(stream),
                    service_fn(move |req| handle_request(req)),
                )
                .await
            {
                error!("Error serving connection: {e:#?}");
            }
        });
    }
}

fn has_local_ip_address(target_ip: IpAddr) -> Result<bool> {
    let mut netlink = Netlink::new();
    let addrs = netlink.addr_list_all(AddrFamily::All)?;

    Ok(addrs
        .iter()
        .map(|addr| addr.ip.addr())
        .any(|ip| ip == target_ip))
}

fn run_in_ns<Fd, F, T>(current_netns: Fd, target_netns: Fd, f: F) -> Result<T>
where
    Fd: AsFd,
    F: FnOnce() -> Result<T>,
{
    if let Err(e) = setns(&target_netns, CloneFlags::CLONE_NEWNET) {
        return Err(e.into());
    }

    let ret = f()?;

    if let Err(e) = setns(&current_netns, CloneFlags::CLONE_NEWNET) {
        return Err(e.into());
    }

    Ok(ret)
}

// If there are multiple CNI configuration files in the directory,
// the kubelet uses the configuration file that comes first by name in lexicographic order.
async fn get_first_lexicographical_conflist(dir_path: &Path) -> Result<Option<PathBuf>> {
    let mut conflist_paths: Vec<PathBuf> = Vec::new();
    let mut entries = tokio::fs::read_dir(dir_path).await?;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let metadata = tokio::fs::metadata(&path).await?;

        if metadata.is_file() && path.extension() == Some(&OsStr::new("conflist")) {
            conflist_paths.push(path);
        }
    }

    conflist_paths.sort_unstable();

    for path in conflist_paths {
        let content = match tokio::fs::read(&path).await {
            Ok(c) => c,
            Err(_) => continue,
        };

        match serde_json::from_slice::<CniConfList>(&content) {
            Ok(conflist) => {
                if conflist.plugins.is_empty() {
                    continue;
                }
                return Ok(Some(path));
            }
            Err(_) => continue,
        }
    }

    Ok(None)
}

// Reads a CNI conflist file, adds or updates the pmz-cni plugin configuration,
// and atomically writes the modified contents back to the same file path.
async fn update_cni_conflist(conflist_path: &Path) -> Result<()> {
    let content = tokio::fs::read(&conflist_path).await?;

    let mut root_value: serde_json::Value = serde_json::from_slice(&content)?;
    if let Some(plugins) = root_value.get_mut("plugins").and_then(|v| v.as_array_mut()) {
        upsert_plugin_config(plugins)?;

        let updated_content = serde_json::to_vec_pretty(&root_value)?;
        let temp_name = format!(
            "{}.tmp.{}",
            conflist_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy(),
            std::process::id()
        );
        let temp_path = conflist_path.with_file_name(temp_name);
        tokio::fs::write(&temp_path, &updated_content).await?;
        tokio::fs::rename(&temp_path, &conflist_path).await?;
    }

    Ok(())
}

fn upsert_plugin_config(plugins: &mut Vec<serde_json::Value>) -> Result<()> {
    let pmz_cni_plugin_config = CniPluginConfig {
        plugin_type: "pmz-cni".to_owned(),
    };
    let pmz_cni_plugin_config = serde_json::to_value(&pmz_cni_plugin_config)?;

    for plugin in plugins.iter_mut() {
        if let Some(plugin_type) = plugin.get("type").and_then(|v| v.as_str()) {
            if plugin_type == "pmz-cni" {
                *plugin = pmz_cni_plugin_config.clone();
                return Ok(());
            }
        }
    }

    plugins.push(pmz_cni_plugin_config);
    Ok(())
}

async fn handle_request(_req: Request<Incoming>) -> Result<Response<Full<Bytes>>> {
    Ok(Response::new(Full::from("handle requested")))
}

fn setup_inpod_iptables_rule(addr: SocketAddr) -> Result<()> {
    debug!("Start to setup inpod iptables rule..");
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
                "iptables command failed: {:?}, status: {}, stderr: {}",
                &rule,
                output.status,
                stderr
            );
        }
    }
    info!("Successfully applied iptables INTERCEPT rules.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    async fn create_file(dir: &Path, name: &str, content: &str) -> Result<PathBuf> {
        let path = dir.join(name);
        tokio::fs::write(&path, content).await?;
        Ok(path)
    }

    #[tokio::test]
    async fn test_get_first_lexicographical_conflist() -> Result<()> {
        let dir = tempdir()?;
        let valid_content = r#"{"plugins": [{"type": "bridge"}]}"#;
        create_file(dir.path(), "99-last.conflist", valid_content).await?;
        let expected_path = create_file(dir.path(), "10-first.conflist", valid_content).await?;
        create_file(dir.path(), "05-other.conf", "{}").await?;

        let result = get_first_lexicographical_conflist(dir.path()).await?;
        assert_eq!(result, Some(expected_path));
        Ok(())
    }

    #[test]
    fn test_upsert_plugin_config() -> Result<()> {
        let mut plugins: Vec<serde_json::Value> = vec![serde_json::json!({"type": "bridge"})];
        upsert_plugin_config(&mut plugins)?;

        assert_eq!(plugins.len(), 2);
        assert_eq!(plugins[0]["type"], "bridge");
        assert_eq!(plugins[1]["type"], "pmz-cni");
        Ok(())
    }

    #[tokio::test]
    async fn test_update_cni_conflist() -> Result<()> {
        let dir = tempdir()?;
        let initial_content = serde_json::json!({
            "name": "testnet_add",
            "cniVersion": "0.4.0",
            "plugins": [
                {"type": "bridge"},
                {"type": "pmz-cni"},
                {"type": "portmap"}
            ]
        });
        let file_path = create_file(
            dir.path(),
            "test-add.conflist",
            &initial_content.to_string(),
        )
        .await?;

        update_cni_conflist(&file_path).await?;

        let updated_content_bytes = tokio::fs::read(&file_path).await?;
        let updated_value: serde_json::Value = serde_json::from_slice(&updated_content_bytes)?;

        let plugins = updated_value["plugins"].as_array().unwrap();
        assert_eq!(plugins.len(), 3);
        assert_eq!(plugins[1]["type"], "pmz-cni");
        Ok(())
    }
}
