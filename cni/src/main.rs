use anyhow::Result;
use clap::Parser;

use kube::Client;
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::{discovery::Discovery, k8s::ServiceWatcher, patcher::CniPatcher, server::CniServer};

mod config;
mod discovery;
mod intercept;
mod k8s;
mod netns;
mod patcher;
mod server;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[clap(short, long, default_value = "eth0")]
    iface: String,

    #[arg(short, long, default_value = "/etc/cni/net.d")]
    cni_conf_dir: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let (non_blocking, _guard) = tracing_appender::non_blocking(std::io::stdout());
    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(fmt::layer().with_writer(non_blocking))
        .init();

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap();

    let config = config::Config::load()?;
    let client = Client::try_default().await?;

    let patcher = CniPatcher::new(&config.cni_conf_dir);
    let discovery = Discovery::new(config.clone());
    let service_watcher = ServiceWatcher::new(client.clone());
    let cni_server = CniServer::new(
        config.clone(),
        service_watcher.index(),
        service_watcher.store(),
    );

    patcher.patch().await?;

    let discovery_future = discovery.run();
    let server_future = cni_server.run();
    let watcher_future = service_watcher.run();

    info!("All components are running concurrently.");

    tokio::select! {
        _ = discovery_future => error!("Discovery client task has terminated."),
        _ = watcher_future => error!("Kubernetes service watcher task has terminated."),
        _ = server_future => error!("CNI server task has terminated."),

    }

    info!("PMZ CNI is shutting down due to a critical task failure.");

    Ok(())
}
