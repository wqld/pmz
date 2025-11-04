use std::{
    env,
    fs::OpenOptions,
    path::{Path, PathBuf},
};

use anyhow::{Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use http::Method;
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, client::conn::http1};
use hyper_util::rt::TokioIo;
use serde::Serialize;
use tokio::{
    fs::{self, File},
    io::AsyncWriteExt,
    net::UnixStream,
};
use tracing::{debug, error};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, Parser)]
#[command(name = "pmzctl")]
#[command(version, about = "pmzctl controls the pmz daemon", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Run(RunArgs),
    Stop,
    Agent(AgentArgs),
    Connect,
    Disconnect,
    Dns(DnsArgs),
    Intercept(InterceptArgs),
}

#[derive(Debug, Args, Serialize)]
struct RunArgs {
    #[arg(short, long, default_value = "eth0")]
    interface: String,
}

#[derive(Debug, Args)]
struct AgentArgs {
    #[command(subcommand)]
    command: AgentCommands,
}

#[derive(Debug, Subcommand)]
enum AgentCommands {
    Deploy(AgentDeployArgs),
    Delete,
}

#[derive(Debug, Args, Serialize)]
struct AgentDeployArgs {
    #[arg(short, long, default_value = "default")]
    namespace: String,
}

#[derive(Debug, Args)]
struct DnsArgs {
    #[command(subcommand)]
    command: DnsCommands,
}

#[derive(Debug, Subcommand)]
enum DnsCommands {
    Add(DnsAddArgs),
    Remove(DnsRemoveArgs),
    List,
}

#[derive(Debug, Args, Serialize)]
struct DnsAddArgs {
    #[arg(short, long)]
    domain: String,
    #[arg(short, long)]
    service: String,
    #[arg(short, long, default_value = "default")]
    namespace: String,
}

#[derive(Debug, Args, Serialize)]
struct DnsRemoveArgs {
    #[arg(short, long)]
    domain: String,
}

#[derive(Debug, Args)]
struct InterceptArgs {
    #[command(subcommand)]
    command: InterceptCommands,
}

#[derive(Debug, Subcommand)]
enum InterceptCommands {
    Add(InterceptAddArgs),
    Remove,
    List,
}

#[derive(Debug, Args, Serialize)]
struct InterceptAddArgs {
    #[arg(short, long)]
    service: String,
    #[arg(short, long, default_value = "default")]
    namespace: String,
    #[arg(short, long)]
    port: String,
    #[arg(short = 'H', value_parser = parse_key_val)]
    header: Vec<(String, String)>,
    #[arg(short, long)]
    uri: Option<String>,
}

const PID_FILE_PATH: &str = "/tmp/pmz.pid";
const LOG_FILE_PATH: &str = "/tmp/pmz.log";

#[tokio::main]
async fn main() -> Result<()> {
    let (non_blocking, _guard) = tracing_appender::non_blocking(std::io::stdout());
    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(fmt::layer().with_writer(non_blocking))
        .init();

    let args = Cli::parse();

    match args.command {
        Commands::Run(args) => {
            debug!("pmzctl run with {args:?}");
            run_daemon(&args).await?;
        }
        Commands::Stop => {
            stop_daemon().await?;
        }
        Commands::Agent(agent) => match agent.command {
            AgentCommands::Deploy(args) => {
                debug!("pmzctl agent deploy");
                let json = serde_json::to_string(&args)?;
                send_request_to_daemon(Method::POST, "/agent", Some(json)).await?;
            }
            AgentCommands::Delete => {
                debug!("pmzctl agent delete");
                send_request_to_daemon(Method::DELETE, "/agent", None).await?;
            }
        },
        Commands::Connect => {
            debug!("pmzctl connect");
            send_request_to_daemon(Method::POST, "/connect", None).await?;
        }
        Commands::Disconnect => {
            debug!("pmzctl disconnect");
            send_request_to_daemon(Method::DELETE, "/connect", None).await?;
        }
        Commands::Dns(dns) => match dns.command {
            DnsCommands::Add(args) => {
                debug!("pmzctl dns add");
                let json = serde_json::to_string(&args)?;
                send_request_to_daemon(Method::POST, "/dns", Some(json)).await?;
            }
            DnsCommands::Remove(args) => {
                debug!("pmzctl dns remove");
                let json = serde_json::to_string(&args)?;
                send_request_to_daemon(Method::DELETE, "/dns", Some(json)).await?;
            }
            DnsCommands::List => {
                debug!("pmzctl dns list");
                send_request_to_daemon(Method::GET, "/dns", None).await?;
            }
        },
        Commands::Intercept(intercept) => match intercept.command {
            InterceptCommands::Add(args) => {
                debug!(args=?args, "pmzctl intercept add");
                let json = serde_json::to_string(&args)?;
                send_request_to_daemon(Method::POST, "/intercept", Some(json)).await?;
            }
            InterceptCommands::Remove => todo!(),
            InterceptCommands::List => todo!(),
        },
    };

    Ok(())
}

async fn run_daemon(args: &RunArgs) -> Result<()> {
    let current_exe_path = env::current_exe()?;
    let parent_dir = current_exe_path
        .parent()
        .ok_or_else(|| anyhow!("Failed to get parent directory of executable"))?;
    let pmz_path = parent_dir.join("pmz");

    if !pmz_path.exists() {
        bail!(
            "pmz executable was not found at {}. Please install pmz first.",
            pmz_path.display()
        );
    }

    if Path::new(PID_FILE_PATH).exists() {
        bail!("pmz daemon appears to be running. Try `pmzctl stop` first.");
    }

    if !nix::unistd::geteuid().is_root() {
        bail!(
            "Root privileges are required to run the daemon. Try running the command again with `sudo`.",
        );
    }

    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(LOG_FILE_PATH)?;

    let log_file_stdout = log_file.try_clone()?;
    let log_file_stderr = log_file.try_clone()?;

    let mut user_kubeconfig: Option<PathBuf> = None;
    let (uid, gid) = {
        let uid_val = env::var("SUDO_UID")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0); // 0 = root
        let gid_val = env::var("SUDO_GID")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0); // 0 = root

        if uid_val != 0 {
            if let Ok(Some(user)) = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid_val))
            {
                let path = PathBuf::from(format!("{:?}/.kube/config", user.dir));
                if path.exists() {
                    debug!(kubeconfig=%path.display(), "Found user kubeconfig");
                    user_kubeconfig = Some(path);
                } else {
                    debug!(path=%path.display(), "User kubeconfig not found at path");
                }
            }
        }
        (
            nix::unistd::Uid::from_raw(uid_val),
            nix::unistd::Gid::from_raw(gid_val),
        )
    };

    let mut command = tokio::process::Command::new(pmz_path);
    command
        .args(&["--iface", &args.interface])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(log_file_stdout))
        .stderr(std::process::Stdio::from(log_file_stderr));

    if let Some(config_path) = user_kubeconfig {
        debug!(path=%config_path.display(), "Setting KUBECONFIG env var for pmz daemon");
        command.env("KUBECONFIG", config_path);
    } else {
        debug!("KUBECONFIG env var not set. pmz will use default (e.g., /root/.kube/config)");
    }

    let daemon = command.spawn()?;

    if let Some(pid) = daemon.id() {
        let mut pid_file = File::create(PID_FILE_PATH).await?;
        pid_file.write_all(pid.to_string().as_bytes()).await?;

        if uid.as_raw() != 0 {
            nix::unistd::chown(PID_FILE_PATH, Some(uid), Some(gid))?;
            nix::unistd::chown(LOG_FILE_PATH, Some(uid), Some(gid))?;
        }

        println!("pmz daemon started. (PID: {}, Log: {})", pid, LOG_FILE_PATH);
        Ok(())
    } else {
        bail!("Failed to get PID for pmz daemon.");
    }
}

async fn stop_daemon() -> Result<()> {
    let pid_str = match fs::read_to_string(PID_FILE_PATH).await {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("pmz daemon is not running.");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    let pid_val = pid_str
        .parse::<i32>()
        .map_err(|_| anyhow!("Invalid PID file: {}", PID_FILE_PATH))?;

    let pid = nix::unistd::Pid::from_raw(pid_val);

    match nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM) {
        Ok(_) => println!("Sent stop signal to pmz daemon (PID: {})", pid_val),
        Err(nix::errno::Errno::ESRCH) => {
            println!(
                "Daemon process (PID: {}) not found. It might be already stopped.",
                pid_val
            );
        }
        Err(e) => {
            bail!("Failed to send stop signal to daemon: {:?}", e);
        }
    }

    fs::remove_file(PID_FILE_PATH).await?;
    Ok(())
}

async fn send_request_to_daemon(method: Method, uri: &str, body_opt: Option<String>) -> Result<()> {
    let path = Path::new("/tmp/pmz.sock");
    let stream = UnixStream::connect(path).await?;

    let (mut sender, conn) = http1::handshake(TokioIo::new(stream)).await?;
    tokio::task::spawn(async move {
        if let Err(e) = conn.await {
            error!("connection failed: {e:#?}");
        }
    });

    let req_body = match body_opt {
        Some(b) => Full::new(Bytes::from(b)),
        None => Full::new(Bytes::default()),
    };

    let req = http::Request::builder()
        .method(method)
        .uri(uri)
        .body(req_body)?;

    let res = sender.send_request(req).await?;
    let (parts, body) = res.into_parts();
    let body = body.collect().await.unwrap().to_bytes();
    let body = String::from_utf8_lossy(&body);

    println!("{}: {}", parts.status, body);
    Ok(())
}

fn parse_key_val(s: &str) -> Result<(String, String), String> {
    s.split_once('=')
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .ok_or_else(|| format!("'{}' is not valid. Expected format: KEY=VALUE", s))
}
