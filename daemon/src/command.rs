use std::{fs, net::Ipv4Addr, os::unix::fs::PermissionsExt, path::Path, sync::Arc, time::Duration};

use anyhow::Result;
use aya::maps::{HashMap, MapData};
use common::{DnsQuery, DnsRecordA};
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::{
    body::{Buf, Bytes, Incoming},
    server::conn::http1,
    service::service_fn,
    Response,
};
use hyper_util::rt::TokioIo;
use k8s_openapi::api::core::v1::{Pod, Service};
use kube::{
    api::Api,
    runtime::wait::{await_condition, conditions::is_pod_running},
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
        (&Method::POST, "/agent") => deploy_agent(req.into_body()).await,
        (&Method::DELETE, "/agent") => delete_agent().await,
        (&Method::POST, "/connect") => connect(req_rx, service_registry, connection_manager).await,
        (&Method::DELETE, "/connect") => disconnect(connection_manager).await,
        (&Method::POST, "/dns") => {
            add_dns(req.into_body(), service_registry, connection_manager).await
        }
        (&Method::DELETE, "/dns") => {
            remove_dns(req.into_body(), service_registry, connection_manager).await
        }
        (&Method::GET, "/dns") => list_dns(service_registry, connection_manager).await,
        _ => not_found().await,
    }
}

async fn deploy_agent(req: Incoming) -> Result<Response<Full<Bytes>>> {
    let client = kube::Client::try_default().await?;

    let _ = match Deploy::get_pod_info_by_label(client.clone(), "app=pmz-agent").await {
        Ok(_) => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::<Bytes>::from("pmz-agent is already deployed"))?)
        }
        Err(_) => {}
    };

    let body = req.collect().await?.aggregate();
    let props: serde_json::Value = serde_json::from_reader(body.reader())?;
    let namespace = props["namespace"].as_str().unwrap_or("default");

    let deploy = Deploy::new(client, namespace);

    deploy.deploy_tls_secret().await?;
    deploy.deploy_agent().await?;

    Ok(Response::new(Full::<Bytes>::from("Agent deployed")))
}

async fn delete_agent() -> Result<Response<Full<Bytes>>> {
    let client = kube::Client::try_default().await?;

    let (_, agent_namespace) =
        match Deploy::get_pod_info_by_label(client.clone(), "app=pmz-agent").await {
            Ok(pod_info) => pod_info,
            Err(_) => {
                return Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Full::<Bytes>::from("pmz-agent not found"))?)
            }
        };

    let deploy = Deploy::new(client, &agent_namespace);
    deploy.clean_resources().await?;

    Ok(Response::new(Full::<Bytes>::from("Agent deleted")))
}

async fn connect(
    req_rx: Arc<Mutex<Receiver<HttpRequest>>>,
    service_registry: Arc<RwLock<HashMap<MapData, DnsQuery, DnsRecordA>>>,
    connection_manager: Arc<Mutex<ConnectionManager>>,
) -> Result<Response<Full<Bytes>>> {
    let agent_port = 8100; // TODO
    let tunnel_host = "localhost";
    let tunnel_port = 18329; // if we want to support multi cluster, this should be a range

    let mut connection_manager = connection_manager.lock().await;
    if connection_manager.check_connection("default") {
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

    let (agent_name, agent_namespace) =
        match Deploy::get_pod_info_by_label(client.clone(), "app=pmz-agent").await {
            Ok(pod_info) => pod_info,
            Err(_) => {
                return Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Full::<Bytes>::from("pmz-agent not found"))?)
            }
        };

    debug!("Checking if agent is running: {agent_name:?}");

    let pods: Api<Pod> = Api::namespaced(client.clone(), &agent_namespace);
    let running = await_condition(pods.clone(), &agent_name, is_pod_running());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), running).await?;

    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let shutdown_discovery = shutdown_tx.subscribe();
    let shutdown_forward = shutdown_tx.subscribe();
    let shutdown_tunnel = shutdown_tx.subscribe();

    let route = Route::setup_routes().await?;
    let discovery = Discovery::new(service_registry);
    let forward = Forward::new(&agent_name, agent_port, tunnel_port, pods);
    let tunnel = Tunnel::new(&tunnel_host, tunnel_port, req_rx);

    tokio::spawn(async move { discovery.watch(client, shutdown_discovery).await });
    tokio::spawn(async move { forward.start(shutdown_forward).await });
    tokio::spawn(async move { tunnel.run(shutdown_tunnel).await });

    let connection = Connection {
        _route: route,
        shutdown_tx,
    };

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

async fn add_dns(
    req: Incoming,
    service_registry: Arc<RwLock<HashMap<MapData, DnsQuery, DnsRecordA>>>,
    connection_manager: Arc<Mutex<ConnectionManager>>,
) -> Result<Response<Full<Bytes>>> {
    let connection_manager = connection_manager.lock().await;
    if !connection_manager.check_connection("default") {
        return Ok(Response::builder().status(StatusCode::BAD_REQUEST).body(
            Full::<Bytes>::from(
                "Not connected. Please run 'pmzctl connect' to establish a connection.",
            ),
        )?);
    }

    let body = req.collect().await?.aggregate();
    let props: serde_json::Value = serde_json::from_reader(body.reader())?;
    debug!("data: {props:?}");

    let mut registry = service_registry.write().await;

    let mut domain_name: [u8; 256] = [0; 256];
    let domain_from_req = match props["domain"].as_str() {
        Some(domain) => domain.as_bytes(),
        None => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::<Bytes>::from("Please provide the domain name."))?)
        }
    };

    domain_name[..domain_from_req.len()].copy_from_slice(&domain_from_req);

    let dns_query = DnsQuery {
        record_type: 1,
        class: 1,
        name: domain_name,
    };

    let client = kube::Client::try_default().await?;

    let namespace = props["namespace"].as_str().unwrap_or("default");
    let service_name = match props["service"].as_str() {
        Some(service) => service,
        None => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::<Bytes>::from("Please provide the service name."))?)
        }
    };

    let services: Api<Service> = Api::namespaced(client, &namespace);
    let service = match services.get(&service_name).await {
        Ok(service) => service,
        Err(_) => {
            return Ok(Response::builder().status(StatusCode::BAD_REQUEST).body(
                Full::<Bytes>::from(format!("Service {service_name:?} not founds")),
            )?)
        }
    };

    let service_ip = match service.spec {
        Some(spec) => match spec.cluster_ip {
            Some(ip) => ip,
            None => {
                return Ok(Response::builder().status(StatusCode::BAD_REQUEST).body(
                    Full::<Bytes>::from(format!(
                        "Service {service_name:?} doesn't have the cluster ip"
                    )),
                )?)
            }
        },
        None => {
            return Ok(Response::builder().status(StatusCode::BAD_REQUEST).body(
                Full::<Bytes>::from(format!("Service {service_name:?} doesn't have the spec")),
            )?)
        }
    };

    let ipv4: Ipv4Addr = service_ip.parse()?;

    let dns_recard_a = DnsRecordA {
        ip: u32::from(ipv4),
        ttl: 30,
    };

    registry.insert(dns_query, dns_recard_a, 0)?;

    Ok(Response::new(Full::<Bytes>::from("dns added")))
}

async fn remove_dns(
    req: Incoming,
    service_registry: Arc<RwLock<HashMap<MapData, DnsQuery, DnsRecordA>>>,
    connection_manager: Arc<Mutex<ConnectionManager>>,
) -> Result<Response<Full<Bytes>>> {
    let connection_manager = connection_manager.lock().await;
    if !connection_manager.check_connection("default") {
        return Ok(Response::builder().status(StatusCode::BAD_REQUEST).body(
            Full::<Bytes>::from(
                "Not connected. Please run 'pmzctl connect' to establish a connection.",
            ),
        )?);
    }

    let body = req.collect().await?.aggregate();
    let props: serde_json::Value = serde_json::from_reader(body.reader())?;
    debug!("data: {props:?}");

    let mut registry = service_registry.write().await;

    let mut domain_name: [u8; 256] = [0; 256];
    let domain_from_req = match props["domain"].as_str() {
        Some(domain) => domain.as_bytes(),
        None => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::<Bytes>::from("Please provide the domain name."))?)
        }
    };

    domain_name[..domain_from_req.len()].copy_from_slice(&domain_from_req);

    let dns_query = DnsQuery {
        record_type: 1,
        class: 1,
        name: domain_name,
    };

    registry.remove(&dns_query)?;

    Ok(Response::new(Full::<Bytes>::from("dns removed")))
}

async fn list_dns(
    service_registry: Arc<RwLock<HashMap<MapData, DnsQuery, DnsRecordA>>>,
    connection_manager: Arc<Mutex<ConnectionManager>>,
) -> Result<Response<Full<Bytes>>> {
    let connection_manager = connection_manager.lock().await;
    if !connection_manager.check_connection("default") {
        return Ok(Response::builder().status(StatusCode::BAD_REQUEST).body(
            Full::<Bytes>::from(
                "Not connected. Please run 'pmzctl connect' to establish a connection.",
            ),
        )?);
    }

    let registry = service_registry.read().await;
    let services: String = registry
        .iter()
        .filter_map(Result::ok)
        .map(|(query, record)| {
            let name = String::from_utf8_lossy(&query.name);
            let name = name.trim_end_matches('\0');
            let ipv4: Ipv4Addr = Ipv4Addr::from_bits(record.ip);
            format!("\n{} {}", name, ipv4)
        })
        .collect();

    Ok(Response::new(Full::<Bytes>::from(services)))
}

async fn not_found() -> Result<Response<Full<Bytes>>> {
    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::<Bytes>::from("Not found"))?)
}

pub struct HttpRequest {
    pub request: String,
    pub _source: String,
    pub target: String,
    pub response: Option<tokio::sync::oneshot::Sender<Bytes>>,
}
