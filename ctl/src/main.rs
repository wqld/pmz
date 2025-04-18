use std::path::Path;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use http::Method;
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, client::conn::http1};
use hyper_util::rt::TokioIo;
use log::{debug, error};
use serde::Serialize;
use tokio::net::UnixStream;

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
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = Cli::parse();

    match args.command {
        Commands::Run(args) => {
            debug!("pmzctl run with {args:?}");
            run_daemon(&args).await?;
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
                debug!("pmzctl intercept add");
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
    let mut daemon = tokio::process::Command::new("./pmz")
        .args(&["--iface", &args.interface])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()?;

    println!("Running..");
    let _ = daemon.wait().await;

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
