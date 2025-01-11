use std::{fs, os::unix::fs::PermissionsExt, path::Path, sync::Arc, time::Duration};

use anyhow::Result;
use aya::maps::{HashMap, MapData};
use common::{DnsQuery, DnsRecordA};
use http::{Method, Request, StatusCode};
use http_body_util::Full;
use hyper::{
    body::{Bytes, Incoming},
    server::conn::http1,
    service::service_fn,
    Response,
};
use hyper_util::rt::TokioIo;
use k8s_openapi::api::core::v1::Pod;
use kube::{
    api::{Api, ListParams},
    runtime::wait::{await_condition, conditions::is_pod_running},
    ResourceExt,
};
use log::{debug, error, info};
use tokio::{
    net::UnixListener,
    sync::{broadcast, mpsc::Receiver, Mutex, RwLock},
    time::sleep,
};

use crate::{
    connect::{Connection, ConnectionManager},
    deploy::Deploy,
    discovery::Discovery,
    forward::Forward,
    route::Route,
    tunnel::Tunnel,
};

pub struct Command {
    req_rx: Arc<Mutex<Receiver<HttpRequest>>>,
    service_registry: Arc<RwLock<HashMap<MapData, DnsQuery, DnsRecordA>>>,
    connection_manager: Arc<Mutex<ConnectionManager>>,
}

impl Command {
    pub fn new(
        req_rx: Receiver<HttpRequest>,
        service_registry: HashMap<MapData, DnsQuery, DnsRecordA>,
    ) -> Self {
        Self {
            req_rx: Arc::new(Mutex::new(req_rx)),
            service_registry: Arc::new(RwLock::new(service_registry)),
            connection_manager: Arc::new(Mutex::new(ConnectionManager::default())),
        }
    }

    pub async fn run(&self) -> Result<()> {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .unwrap();

        let path = Path::new("/tmp/pmz.sock");

        if path.exists() {
            fs::remove_file(path)?;
        }

        let listener = UnixListener::bind(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o766))?;
        debug!("Listening for connections at {}.", path.display());

        loop {
            let (stream, _) = listener.accept().await?;
            let req_rx = self.req_rx.clone();
            let service_registry = self.service_registry.clone();
            let connection_manager = self.connection_manager.clone();

            tokio::task::spawn(async move {
                if let Err(err) = http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |req| {
                            handle_request(
                                req,
                                req_rx.clone(),
                                service_registry.clone(),
                                connection_manager.clone(),
                            )
                        }),
                    )
                    .await
                {
                    error!("Error serving connection: {err:#?}");
                }
            });
        }
    }
}

async fn handle_request(
    req: Request<Incoming>,
    req_rx: Arc<Mutex<Receiver<HttpRequest>>>,
    service_registry: Arc<RwLock<HashMap<MapData, DnsQuery, DnsRecordA>>>,
    connection_manager: Arc<Mutex<ConnectionManager>>,
) -> Result<Response<Full<Bytes>>> {
    match (req.method(), req.uri().path()) {
        (&Method::POST, "/agent") => deploy_agent().await,
        (&Method::DELETE, "/agent") => delete_agent().await,
        (&Method::POST, "/connect") => connect(req_rx, service_registry, connection_manager).await,
        (&Method::DELETE, "/connect") => disconnect(connection_manager).await,
        _ => not_found().await,
    }
}

async fn deploy_agent() -> Result<Response<Full<Bytes>>> {
    let namespace = "default"; // TODO
    let client = kube::Client::try_default().await?;
    let deploy = Deploy::new(client, &namespace);

    deploy.deploy_tls_secret().await?;
    deploy.deploy_agent().await?;

    Ok(Response::new(Full::<Bytes>::from("Agent deployed")))
}

async fn delete_agent() -> Result<Response<Full<Bytes>>> {
    let namespace = "default"; // TODO
    let client = kube::Client::try_default().await?;
    let deploy = Deploy::new(client, &namespace);

    deploy.clean_resources().await?;

    Ok(Response::new(Full::<Bytes>::from("Agent deleted")))
}

async fn connect(
    req_rx: Arc<Mutex<Receiver<HttpRequest>>>,
    service_registry: Arc<RwLock<HashMap<MapData, DnsQuery, DnsRecordA>>>,
    connection_manager: Arc<Mutex<ConnectionManager>>,
) -> Result<Response<Full<Bytes>>> {
    let namespace = "default"; // TODO
    let agent_port = 8100; // TODO
    let tunnel_host = "localhost";
    let tunnel_port = 18329; // if we want to support multi cluster, this should be a range

    let mut connection_manager = connection_manager.lock().await;
    if let Some(_) = connection_manager.connections.get("default") {
        return Ok(Response::new(Full::<Bytes>::from("Already connected")));
    }

    let client = loop {
        match kube::Client::try_default().await {
            Ok(client) => {
                info!("Connected to the cluster");
                break client;
            }
            Err(e) => {
                log::error!("{}", e);
                sleep(Duration::from_secs(5)).await;
            }
        }
    };

    let pods: Api<Pod> = Api::namespaced(client.clone(), &namespace);

    let lp = ListParams::default().labels("app=pmz-agent");
    let agent_name = match pods.list(&lp).await?.iter().last() {
        Some(p) => p.name_any(),
        None => {
            return Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::<Bytes>::from("Not found"))?)
        }
    };

    debug!("Checking if agent is running");

    let running = await_condition(pods.clone(), &agent_name, is_pod_running());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), running).await?;

    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let shutdown_discovery = shutdown_tx.subscribe();
    let shutdown_forward = shutdown_tx.subscribe();
    let shutdown_tunnel = shutdown_tx.subscribe();

    let route = Route::setup_routes().unwrap();
    let discovery = Discovery::new(service_registry);
    let forward = Forward::new(&agent_name, agent_port, tunnel_port, pods);
    let tunnel = Tunnel::new(&tunnel_host, tunnel_port, req_rx);

    tokio::spawn(async move { discovery.watch(client, shutdown_discovery).await });
    tokio::spawn(async move { forward.start(shutdown_forward).await });
    tokio::spawn(async move { tunnel.run(shutdown_tunnel).await });

    let connection = Connection { route, shutdown_tx };

    match connection_manager
        .connections
        .insert("default".to_string(), connection)
    {
        Some(_) => Ok(Response::new(Full::<Bytes>::from("Connected what?!"))),
        None => Ok(Response::new(Full::<Bytes>::from("Connected"))),
    }
}

async fn disconnect(
    connection_manager: Arc<Mutex<ConnectionManager>>,
) -> Result<Response<Full<Bytes>>> {
    let connection = {
        let mut connection_manager = connection_manager.lock().await;
        connection_manager.connections.remove("default")
    };

    match connection {
        Some(conn) => {
            conn.shutdown_tx.send(())?;
            Ok(Response::new(Full::<Bytes>::from("Disconnected")))
        }
        None => Ok(Response::new(Full::<Bytes>::from("No connection"))),
    }
}

async fn not_found() -> Result<Response<Full<Bytes>>> {
    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::<Bytes>::from("Not found"))?)
}

pub struct HttpRequest {
    pub request: String,
    pub source: String,
    pub target: String,
    pub response: tokio::sync::oneshot::Sender<Bytes>,
}
