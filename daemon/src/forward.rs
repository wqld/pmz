use std::net::SocketAddr;

use anyhow::{Context, Result};
use futures::TryStreamExt;
use k8s_openapi::api::core::v1::Pod;
use kube::Api;
use log::{debug, error};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
};
use tokio_stream::wrappers::TcpListenerStream;

pub struct Forward {
    tunnel_port: u16,
    pods: Api<Pod>,
}

impl Forward {
    pub fn new(tunnel_port: u16, pods: Api<Pod>) -> Self {
        Self { tunnel_port, pods }
    }

    pub async fn start(&self) -> Result<()> {
        let addr = SocketAddr::from(([127, 0, 0, 1], self.tunnel_port));
        let agent_name = "test";
        let agent_port = 8100; // TODO

        let listener = TcpListener::bind(addr).await?;
        let server = TcpListenerStream::new(listener).try_for_each(|conn| async {
            if let Ok(peer_addr) = conn.peer_addr() {
                debug!("new connection: {peer_addr}");
            }

            let pods = self.pods.clone();
            tokio::spawn(async move {
                if let Err(e) = forward_connection(&pods, &agent_name, agent_port, conn).await {
                    error!("failed to forward connection: {e:?}");
                }
            });

            Ok(())
        });

        if let Err(e) = server.await {
            error!("server error: {e:?}");
        }

        Ok(())
    }
}

async fn forward_connection(
    pods: &Api<Pod>,
    agent_name: &str,
    agent_port: u16,
    mut client_conn: impl AsyncRead + AsyncWrite + Unpin,
) -> Result<()> {
    let mut forwarder = pods.portforward(agent_name, &[agent_port]).await?;
    let mut upstream_conn = forwarder
        .take_stream(agent_port)
        .context("port not found in forwarder")?;
    tokio::io::copy_bidirectional(&mut client_conn, &mut upstream_conn).await?;
    drop(upstream_conn);
    forwarder.join().await?;
    debug!("connection closed");
    Ok(())
}
