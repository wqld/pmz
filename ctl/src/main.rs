use std::path::Path;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use http::Method;
use http_body_util::Empty;
use hyper::{
    body::{Bytes, Incoming},
    client::conn::http1,
};
use hyper_util::rt::TokioIo;
use log::{debug, error};
use tokio::net::UnixStream;

#[derive(Debug, Parser)]
#[command(name = "pmzctl")]
#[command(about = "pmzctl controls the PMZ daemon", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Agent(AgentArgs),
    Connect,
}

#[derive(Debug, Args)]
struct AgentArgs {
    #[command(subcommand)]
    command: AgentCommands,
}

#[derive(Debug, Subcommand)]
enum AgentCommands {
    Deploy,
    Delete,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = Cli::parse();

    match args.command {
        Commands::Agent(agent) => match agent.command {
            AgentCommands::Deploy => {
                debug!("pmzctl agent deploy");
                send_request_to_daemon(Method::POST, "/agent").await?;
            }
            AgentCommands::Delete => {
                debug!("pmzctl agent delete");
                send_request_to_daemon(Method::DELETE, "/agent").await?;
            }
        },
        Commands::Connect => {
            debug!("pmzctl connect");
            send_request_to_daemon(Method::POST, "/connect").await?;
        }
    };

    Ok(())
}

async fn send_request_to_daemon(method: Method, uri: &str) -> Result<http::Response<Incoming>> {
    let path = Path::new("/tmp/pmz.sock");
    let stream = UnixStream::connect(path).await?;

    let (mut sender, conn) = http1::handshake(TokioIo::new(stream)).await?;
    tokio::task::spawn(async move {
        if let Err(e) = conn.await {
            error!("connection failed: {e:#?}");
        }
    });

    let req = http::Request::builder()
        .method(method)
        .uri(uri)
        .body(Empty::<Bytes>::new())?;

    let res = sender.send_request(req).await?;

    debug!("response: {}", res.status());
    Ok(res)
}
