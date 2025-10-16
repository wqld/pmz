use std::{collections::HashMap, sync::Arc};

use anyhow::Result;
use clap::Parser;
use cni::ServiceIndex;

use log::{error, info};
use tokio::sync::RwLock;

use crate::{patcher::CniPatcher, server::CniServer};

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
    env_logger::init();

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap();

    let config = config::Config::load()?;
    let service_index: ServiceIndex = Arc::new(RwLock::new(HashMap::new()));

    let patcher = CniPatcher::new(&config.cni_conf_dir);
    let discovery_handle = discovery::run(config.clone()).await?;
    let (watcher_handle, service_store) = k8s::setup_service_watcher(service_index.clone()).await?;
    let cni_server = CniServer::new(config, service_index.clone(), service_store.clone());
    let server_future = cni_server.run();

    // update the existing CNI configuration to enable the invocation of pmz-cni via chaining
    patcher.patch().await?;

    info!("All components are running concurrently.");

    tokio::select! {
        res = discovery_handle => {
            error!("Discovery client task has terminated unexpectedly.");
            if let Err(e) = res {
                error!("JoinError from discovery task: {:?}", e);
            }
        }
        res = watcher_handle => {
            error!("Kubernetes service watcher task has terminated unexpectedly.");
            if let Err(e) = res {
                error!("JoinError from watcher task: {:?}", e);
            }
        }
        res = server_future => {
            error!("CNI server task has terminated unexpectedly.");
            if let Err(e) = res {
                error!("Error from server task: {:?}", e);
            }
        }
    }

    info!("PMZ CNI Agent is shutting down due to a critical task failure.");

    Ok(())
}
