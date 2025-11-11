use std::{fs::File, io::Write, net::SocketAddr, path::Path, sync::Arc};

use anyhow::{Context, Error, Result, bail};
use futures::StreamExt;
use k8s_openapi::api::core::v1::{Pod, Secret};
use kube::{
    Api,
    runtime::{conditions::is_pod_running, wait::await_condition},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::{
        RwLock,
        broadcast::{self, Receiver},
    },
};
use tokio_stream::wrappers::TcpListenerStream;
use tracing::{Instrument, debug, error, info, instrument};

use crate::{connect::ConnectionStatus, deploy::Deploy};

pub struct Forwarder {
    agent_port: u16,
    tunnel_port: u16,
    shutdown: Receiver<()>,
    client: kube::Client,
}

impl Forwarder {
    pub fn new(
        agent_port: u16,
        tunnel_port: u16,
        shutdown: broadcast::Receiver<()>,
        client: kube::Client,
    ) -> Self {
        Self {
            agent_port,
            tunnel_port,
            shutdown,
            client,
        }
    }

    #[instrument(name = "forward", skip_all, err)]
    pub async fn start(&mut self, conn_stat: Arc<RwLock<ConnectionStatus>>) -> Result<()> {
        let addr = SocketAddr::from(([127, 0, 0, 1], self.tunnel_port));

        let mut stream = match TcpListener::bind(addr).await {
            Ok(listener) => TcpListenerStream::new(listener),
            Err(e) => {
                ConnectionStatus::forward(&conn_stat, true, &e.to_string()).await;
                return Err(Error::new(e));
            }
        };

        ConnectionStatus::forward(&conn_stat, true, "Up").await;
        info!("Listening on {addr:?}");

        loop {
            tokio::select! {
                next = stream.next() => {
                    match next {
                        Some(Ok(conn)) => self.handle_connection(conn).await?,
                        Some(Err(e)) => error!(error = ?e, "Failed to get next connection"),
                        None => {
                            ConnectionStatus::forward(&conn_stat, true, "Down").await;
                            bail!("Forward stream ended unexpectedly")
                        }
                    }
                },
                _ = self.shutdown.recv() => {
                    debug!("Forward shutdown");
                    ConnectionStatus::clear_forward(&conn_stat).await;
                    return Ok(())
                }
            }
        }
    }

    #[instrument(name = "handle", skip_all, err)]
    async fn handle_connection(&self, mut conn: TcpStream) -> Result<()> {
        if let Ok(peer_addr) = conn.peer_addr() {
            debug!("New connection: {peer_addr}");
        }

        let (agent_name, agent_namespace) =
            match Deploy::get_pod_info_by_label(self.client.clone(), "app=pmz-agent").await {
                Ok(pod_info) => pod_info,
                Err(e) => bail!("pmz-agent not found: {e:?}"),
            };

        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), &agent_namespace);

        let pmz_tls = secrets.get("pmz-tls").await?;

        if let Some(data) = pmz_tls.data {
            if let Some(crt) = data.get("tls.crt") {
                let home_dir = std::env::var("HOME")?;
                let cert_dir = Path::new(&home_dir).join(".config/pmz/certs");
                std::fs::create_dir_all(&cert_dir)?;

                let cert_path = cert_dir.join("pmz.crt");
                let mut cert_file = File::create(cert_path)?;
                cert_file.write_all(&crt.0)?;
            } else {
                bail!("pmz-tls secret doesn't have a tls.crt field.");
            }
        } else {
            bail!("pmz-tls secret doesn't have a data attribute.");
        }

        let pods: Api<Pod> = Api::namespaced(self.client.clone(), &agent_namespace);
        let running = await_condition(pods.clone(), &agent_name, is_pod_running());
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), running).await?;

        let agent_name = agent_name.clone();
        let agent_port = self.agent_port;
        tokio::spawn(
            async move {
                if let Err(e) = port_forward(&pods, &agent_name, agent_port, &mut conn).await {
                    error!(error = ?e, "Failed to forward connection");
                }
            }
            .in_current_span(),
        );

        Ok(())
    }
}

#[instrument(skip_all, fields(agent.name = %agent_name, agent.port = %agent_port))]
async fn port_forward(
    pods: &Api<Pod>,
    agent_name: &str,
    agent_port: u16,
    client_conn: &mut (impl AsyncRead + AsyncWrite + Unpin),
) -> Result<()> {
    let mut forwarder = pods.portforward(agent_name, &[agent_port]).await?;
    let mut upstream_conn = forwarder
        .take_stream(agent_port)
        .context("port not found in forwarder")?;

    tokio::io::copy_bidirectional(client_conn, &mut upstream_conn).await?;

    drop(upstream_conn);
    forwarder.join().await?;
    debug!("Connection closed");
    Ok(())
}
