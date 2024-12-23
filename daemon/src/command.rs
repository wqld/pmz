use std::{fs, net::SocketAddr, os::unix::fs::PermissionsExt, path::Path};

use anyhow::{Context, Result};
use futures::TryStreamExt;
use http_body_util::Full;
use hyper::{body::Bytes, server::conn::http1, service::service_fn, Method, Response, StatusCode};
use hyper_util::rt::TokioIo;
use ipnet::IpNet;
use k8s_openapi::api::core::v1::Pod;
use kube::{
    api::Api,
    runtime::wait::{await_condition, conditions::is_pod_running},
    Client,
};
use log::debug;
use rsln::{
    netlink::Netlink,
    types::{link::LinkAttrs, routing::RoutingBuilder},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, UnixListener},
};
use tokio_stream::wrappers::TcpListenerStream;

pub struct Command {}

impl Command {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn run(&self) -> Result<()> {
        let path = Path::new("/tmp/pmz.sock");

        if path.exists() {
            fs::remove_file(path)?;
        }

        let listener = UnixListener::bind(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o766))?;
        debug!("Listening for connections at {}.", path.display());

        loop {
            let (stream, _) = listener.accept().await?;

            tokio::task::spawn(async move {
                if let Err(err) = http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |req| async move {
                            match (req.method(), req.uri().path()) {
                                (&Method::POST, "/connect") => connect().await,
                                (&Method::POST, "/disconnect") => {
                                    Ok(Response::new(Full::<Bytes>::from("Disconnected")))
                                }
                                _ => Ok(Response::builder()
                                    .status(StatusCode::NOT_FOUND)
                                    .body(Full::<Bytes>::from("Not Found"))
                                    .unwrap()),
                            }
                        }),
                    )
                    .await
                {
                    debug!("Error serving connection: {:?}", err);
                }
            });
        }
    }
}

async fn connect() -> Result<Response<Full<Bytes>>> {
    let namespace = "default";
    let agent_name = "test";
    let agent_port = 8100; // TODO
    let tunnel_port = 18329;

    let client = Client::try_default().await.unwrap();
    let pods: Api<Pod> = Api::namespaced(client, &namespace);

    debug!("Checking if agent is running");

    let running = await_condition(pods.clone(), &agent_name, is_pod_running());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), running)
        .await
        .unwrap();

    let service_cidr = "10.96.0.0/16";
    let service_cidr_net = service_cidr.parse::<IpNet>()?;
    let mut netlink = Netlink::new();

    let link = netlink.link_get(&LinkAttrs::new("lo"))?;

    let route = RoutingBuilder::default()
        .oif_index(link.attrs().index)
        .dst(Some(service_cidr_net))
        .build()?;

    if let Err(e) = netlink.route_add(&route) {
        if e.to_string().contains("File exists") {
            debug!("route already exists");
        } else {
            return Err(e);
        }
    }

    let addr = SocketAddr::from(([127, 0, 0, 1], tunnel_port));

    let server = TcpListenerStream::new(TcpListener::bind(addr).await.unwrap()).try_for_each(
        |client_conn| async {
            if let Ok(peer_addr) = client_conn.peer_addr() {
                debug!("new connection: {}", peer_addr);
            }

            let pods = pods.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    forward_connection(&pods, &agent_name, agent_port, client_conn).await
                {
                    debug!("failed to forward connection: {:?}", e);
                }
            });

            Ok(())
        },
    );

    if let Err(e) = server.await {
        debug!("server error: {:?}", e);
    }

    Ok(Response::new(Full::<Bytes>::from("Connected")))
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
