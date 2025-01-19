use std::net::SocketAddr;

use anyhow::{Context, Result};
use futures::StreamExt;
use k8s_openapi::api::core::v1::Pod;
use kube::Api;
use log::{debug, error};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::broadcast,
};
use tokio_stream::wrappers::TcpListenerStream;

pub struct Forward {
    agent_name: String,
    agent_port: u16,
    tunnel_port: u16,
    pods: Api<Pod>,
}

impl Forward {
    pub fn new(agent_name: &str, agent_port: u16, tunnel_port: u16, pods: Api<Pod>) -> Self {
        Self {
            agent_name: agent_name.to_owned(),
            agent_port,
            tunnel_port,
            pods,
        }
    }

    pub async fn start(&self, mut shutdown: broadcast::Receiver<()>) -> Result<()> {
        let addr = SocketAddr::from(([127, 0, 0, 1], self.tunnel_port));

        let listener = TcpListener::bind(addr).await?;
        let mut stream = TcpListenerStream::new(listener);

        loop {
            tokio::select! {
                Some(next) = stream.next() => {
                    match next {
                        Ok(conn) => self.handle_connection(conn),
                        Err(err) => error!("failed to get next connection: {err:?}"),
                    }
                },
                _ = shutdown.recv() => {
                    debug!("forward shutdown");
                    return Ok(())
                }
            }
        }
    }

    fn handle_connection(&self, mut conn: TcpStream) {
        if let Ok(peer_addr) = conn.peer_addr() {
            debug!("new connection: {peer_addr}");
        }

        let pods = self.pods.clone();
        let agent_name = self.agent_name.clone();
        let agent_port = self.agent_port;
        tokio::spawn(async move {
            if let Err(err) = forward_connection(&pods, &agent_name, agent_port, &mut conn).await {
                error!("failed to forward connection: {err:?}");
            }
        });
    }
}

async fn forward_connection(
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
    debug!("connection closed");
    Ok(())
}
