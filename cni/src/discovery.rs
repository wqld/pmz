use std::{net::IpAddr, os::fd::OwnedFd, sync::Arc, time::Duration};

use anyhow::{Result, bail};
use log::{debug, error, info, warn};
use proto::{
    DiscoveryRequest, DiscoveryResponse, intercept_discovery_client::InterceptDiscoveryClient,
};
use tokio::{fs::File, task::JoinHandle, time::sleep};
use tokio_stream::StreamExt;
use tonic::transport;

use crate::{config::Config, intercept::setup_inpod_redirection};

const MAX_RETRIES: u32 = 5;
const INITIAL_DELAY_MS: u64 = 500;
const SELF_NETNS_PATH: &str = "/proc/self/ns/net";

pub async fn run(config: Config) -> Result<JoinHandle<()>> {
    let handle = tokio::spawn(async move {
        if let Err(e) = discovery(&config).await {
            error!("Discovery thread failed: {:?}", e);
        }
    });

    Ok(handle)
}

async fn discovery(config: &Config) -> Result<()> {
    info!(
        "Starting discovery client to connect to {}",
        config.discovery_url
    );

    let mut client = create_discovery_client(&config.discovery_url).await?;

    info!(
        "Requesting intercepts stream for node_ip: {}",
        config.host_ip
    );

    let mut stream = client
        .intercepts(DiscoveryRequest {
            node_ip: config.host_ip.to_owned(),
        })
        .await?
        .into_inner();

    let current_netns = File::open(SELF_NETNS_PATH).await?;
    let current_netns: Arc<OwnedFd> = Arc::new(current_netns.into_std().await.into());

    while let Some(resp) = stream.next().await {
        match resp {
            Ok(resp) => handle_discovery_response(resp, &current_netns).await?,
            Err(e) => error!("Error in discovery stream: {:?}", e),
        }
    }

    Ok(())
}

async fn create_discovery_client(
    url: &str,
) -> Result<InterceptDiscoveryClient<tonic::transport::Channel>> {
    for attempt in 0..MAX_RETRIES {
        match transport::Endpoint::from_shared(url.to_owned())?
            .connect()
            .await
        {
            Ok(ch) => {
                info!("Successfully connected to discovery server");
                return Ok(InterceptDiscoveryClient::new(ch));
            }
            Err(e) => {
                error!(
                    "Connection failed ({}/{}): {:?}",
                    attempt + 1,
                    MAX_RETRIES,
                    e
                );

                if attempt == MAX_RETRIES - 1 {
                    break;
                }

                let delay = Duration::from_millis(INITIAL_DELAY_MS * 2_u64.pow(attempt));
                warn!("Retrying in {:?}", delay);
                sleep(delay).await;
            }
        }
    }

    bail!("Failed to connect after all retries.");
}

async fn handle_discovery_response(
    response: DiscoveryResponse,
    current_netns: &Arc<OwnedFd>,
) -> Result<()> {
    debug!("Handling discovery response: {response:?}");

    let pod_ips = response
        .resources
        .into_iter()
        .flat_map(|endpoint| endpoint.pod_ids.into_iter())
        .map(|identifier| identifier.ip)
        .filter_map(|pod_ip| pod_ip.parse::<IpAddr>().ok());

    for pod_ip in pod_ips {
        if let Err(e) = setup_inpod_redirection(pod_ip, current_netns.clone(), None).await {
            error!("Failed to setup redirection for {}: {:?}", pod_ip, e);
        }
    }

    Ok(())
}
