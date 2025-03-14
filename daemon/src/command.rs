use std::{
    fs::{self, File},
    io::Write,
    net::Ipv4Addr,
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::Arc,
    time::Duration,
};

use anyhow::{Result, anyhow, bail};
use aya::maps::{HashMap, MapData};
use common::{DnsQuery, DnsRecordA};
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::{
    Response,
    body::{Buf, Bytes, Incoming},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use k8s_openapi::api::core::v1::{Pod, Secret, Service};
use kube::{
    api::Api,
    runtime::wait::{await_condition, conditions::is_pod_running},
};
use log::{debug, error, info};
use proxy::tunnel::client::{TunnelClient, TunnelRequest, establish_http2_connection};
use rsln::{handle::sock_diag::DiagFamily, netlink::Netlink};
use serde::Serialize;
use tokio::{
    net::UnixListener,
    sync::{Mutex, RwLock, broadcast, mpsc::Receiver},
    time::sleep,
};

use crate::{
    connect::{Connection, ConnectionManager, ConnectionStatus},
    deploy::Deploy,
    discovery::Discovery,
    forward::Forward,
    route::Route,
};

pub struct Command {
    req_rx: Arc<Mutex<Receiver<TunnelRequest>>>,
    service_registry: Arc<RwLock<HashMap<MapData, DnsQuery, DnsRecordA>>>,
    service_cidr_map: Arc<RwLock<HashMap<MapData, u8, u32>>>,
    connection_manager: Arc<Mutex<ConnectionManager>>,
    connection_status: Arc<RwLock<ConnectionStatus>>,
}

impl Command {
    pub fn new(
        req_rx: Receiver<TunnelRequest>,
        service_registry: HashMap<MapData, DnsQuery, DnsRecordA>,
        service_cidr_map: HashMap<MapData, u8, u32>,
        connection_status: Arc<RwLock<ConnectionStatus>>,
    ) -> Self {
        Self {
            req_rx: Arc::new(Mutex::new(req_rx)),
            service_registry: Arc::new(RwLock::new(service_registry)),
            service_cidr_map: Arc::new(RwLock::new(service_cidr_map)),
            connection_manager: Arc::new(Mutex::new(ConnectionManager::default())),
            connection_status,
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
            let service_cidr_map = self.service_cidr_map.clone();
            let connection_manager = self.connection_manager.clone();
            let connection_status = self.connection_status.clone();

            tokio::task::spawn(async move {
                if let Err(err) = http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |req| {
                            handle_request(
                                req,
                                req_rx.clone(),
                                service_registry.clone(),
                                service_cidr_map.clone(),
                                connection_manager.clone(),
                                connection_status.clone(),
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
    req_rx: Arc<Mutex<Receiver<TunnelRequest>>>,
    service_registry: Arc<RwLock<HashMap<MapData, DnsQuery, DnsRecordA>>>,
    service_cidr_map: Arc<RwLock<HashMap<MapData, u8, u32>>>,
    connection_manager: Arc<Mutex<ConnectionManager>>,
    connection_status: Arc<RwLock<ConnectionStatus>>,
) -> Result<Response<Full<Bytes>>> {
    let tunnel_port = 18329; // if we want to support multi cluster, this should be a range

    match (req.method(), req.uri().path()) {
        (&Method::POST, "/agent") => deploy_agent(req.into_body()).await,
        (&Method::DELETE, "/agent") => delete_agent().await,
        (&Method::POST, "/connect") => {
            connect(
                req_rx,
                service_registry,
                service_cidr_map,
                connection_manager,
                connection_status,
                tunnel_port,
            )
            .await
        }
        (&Method::DELETE, "/connect") => disconnect(connection_manager).await,
        (&Method::POST, "/dns") => {
            add_dns(req.into_body(), service_registry, connection_manager).await
        }
        (&Method::DELETE, "/dns") => {
            remove_dns(req.into_body(), service_registry, connection_manager).await
        }
        (&Method::GET, "/dns") => list_dns(service_registry, connection_manager).await,
        (&Method::POST, "/intercept") => {
            start_intercept(req.into_body(), tunnel_port, service_registry).await
        }
        _ => not_found().await,
    }
}

async fn deploy_agent(req: Incoming) -> Result<Response<Full<Bytes>>> {
    let client = kube::Client::try_default().await?;

    let _ = match Deploy::get_pod_info_by_label(client.clone(), "app=pmz-agent").await {
        Ok(_) => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::from("pmz-agent is already deployed"))?);
        }
        Err(_) => {}
    };

    let body = req.collect().await?.aggregate();
    let props: serde_json::Value = serde_json::from_reader(body.reader())?;
    let namespace = props["namespace"].as_str().unwrap_or("default");

    let deploy = Deploy::new(client, namespace);

    deploy.deploy_tls_secret().await?;
    deploy.deploy_agent().await?;

    Ok(Response::new(Full::from("Agent deployed")))
}

async fn delete_agent() -> Result<Response<Full<Bytes>>> {
    let client = kube::Client::try_default().await?;

    let (_, agent_namespace) =
        match Deploy::get_pod_info_by_label(client.clone(), "app=pmz-agent").await {
            Ok(pod_info) => pod_info,
            Err(_) => {
                return Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Full::from("pmz-agent not found"))?);
            }
        };

    let deploy = Deploy::new(client, &agent_namespace);
    deploy.clean_resources().await?;

    Ok(Response::new(Full::from("Agent deleted")))
}

async fn connect(
    req_rx: Arc<Mutex<Receiver<TunnelRequest>>>,
    service_registry: Arc<RwLock<HashMap<MapData, DnsQuery, DnsRecordA>>>,
    service_cidr_map: Arc<RwLock<HashMap<MapData, u8, u32>>>,
    connection_manager: Arc<Mutex<ConnectionManager>>,
    connection_status: Arc<RwLock<ConnectionStatus>>,
    tunnel_port: u16,
) -> Result<Response<Full<Bytes>>> {
    let agent_port = 8100; // TODO

    let mut connection_manager = connection_manager.lock().await;
    if connection_manager.check_connection("default") {
        return Ok(Response::new(Full::from("Already connected")));
    }

    let client = loop {
        let c = kube::Client::try_default().await;
        match c {
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
                    .body(Full::from("pmz-agent not found"))?);
            }
        };

    debug!("Checking if agent is running: {agent_name:?}");

    let secrets: Api<Secret> = Api::namespaced(client.clone(), &agent_namespace);

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
            return Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::from("pmz-tls secret doesn't have a tls.crt field."))?);
        }
    } else {
        return Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::from("pmz-tls secret doesn't have a data attribute."))?);
    }

    let pods: Api<Pod> = Api::namespaced(client.clone(), &agent_namespace);
    let running = await_condition(pods.clone(), &agent_name, is_pod_running());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), running).await?;

    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let shutdown_discovery = shutdown_tx.subscribe();
    let shutdown_forward = shutdown_tx.subscribe();
    let shutdown_tunnel = shutdown_tx.subscribe();

    // let conn_stat_route = connection_status.clone();
    let conn_stat_discovery = connection_status.clone();
    let conn_stat_forward = connection_status.clone();
    // let conn_stat_tunnel = connection_status.clone();

    let route = Route::setup_routes(service_cidr_map).await?;
    let discovery = Discovery::new(service_registry);
    let forward = Forward::new(&agent_name, agent_port, tunnel_port, pods);
    let tunnel = TunnelClient::new(tunnel_port, req_rx);

    tokio::spawn(async move {
        discovery
            .watch(client, shutdown_discovery, conn_stat_discovery)
            .await
    });
    tokio::spawn(async move {
        if let Err(e) = forward.start(shutdown_forward, conn_stat_forward).await {
            error!("failed to run the forward task: {e:?}");
        }
    });
    tokio::spawn(async move {
        if let Err(e) = tunnel.run(shutdown_tunnel).await {
            error!("failed to run the tunnel task: {e:?}");
        }
    });

    while let None = connection_status.read().await.forward {}

    let connection = Connection {
        _route: route,
        shutdown_tx,
    };

    let res = connection_manager
        .connections
        .insert("default".to_string(), connection);

    match res {
        Some(_) => Ok(Response::new(Full::from("Connected what?!"))),
        None => Ok(Response::new(Full::from(format!(
            "{:#?}",
            connection_status.read().await
        )))),
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
        Some(_) => Ok(Response::new(Full::from("Disconnected"))),
        None => Ok(Response::new(Full::from("No connection"))),
    }
}

async fn add_dns(
    req: Incoming,
    service_registry: Arc<RwLock<HashMap<MapData, DnsQuery, DnsRecordA>>>,
    connection_manager: Arc<Mutex<ConnectionManager>>,
) -> Result<Response<Full<Bytes>>> {
    let connection_manager = connection_manager.lock().await;
    if !connection_manager.check_connection("default") {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Full::from(
                "Not connected. Please run 'pmzctl connect' to establish a connection.",
            ))?);
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
                .body(Full::from("Please provide the domain name."))?);
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
                .body(Full::from("Please provide the service name."))?);
        }
    };

    let services: Api<Service> = Api::namespaced(client, &namespace);
    let service = match services.get(&service_name).await {
        Ok(service) => service,
        Err(_) => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::from(format!("Service {service_name:?} not founds")))?);
        }
    };

    let service_ip =
        match service.spec {
            Some(spec) => match spec.cluster_ip {
                Some(ip) => ip,
                None => {
                    return Ok(Response::builder().status(StatusCode::BAD_REQUEST).body(
                        Full::from(format!(
                            "Service {service_name:?} doesn't have the cluster ip"
                        )),
                    )?);
                }
            },
            None => {
                return Ok(Response::builder().status(StatusCode::BAD_REQUEST).body(
                    Full::from(format!("Service {service_name:?} doesn't have the spec")),
                )?);
            }
        };

    let ipv4: Ipv4Addr = service_ip.parse()?;

    let dns_recard_a = DnsRecordA {
        ip: u32::from(ipv4),
        ttl: 30,
    };

    registry.insert(dns_query, dns_recard_a, 0)?;

    Ok(Response::new(Full::from("dns added")))
}

async fn remove_dns(
    req: Incoming,
    service_registry: Arc<RwLock<HashMap<MapData, DnsQuery, DnsRecordA>>>,
    connection_manager: Arc<Mutex<ConnectionManager>>,
) -> Result<Response<Full<Bytes>>> {
    let connection_manager = connection_manager.lock().await;
    if !connection_manager.check_connection("default") {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Full::from(
                "Not connected. Please run 'pmzctl connect' to establish a connection.",
            ))?);
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
                .body(Full::from("Please provide the domain name."))?);
        }
    };

    domain_name[..domain_from_req.len()].copy_from_slice(&domain_from_req);

    let dns_query = DnsQuery {
        record_type: 1,
        class: 1,
        name: domain_name,
    };

    registry.remove(&dns_query)?;

    Ok(Response::new(Full::from("dns removed")))
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

    Ok(Response::new(Full::from(services)))
}

async fn start_intercept(
    req: Incoming,
    tunnel_port: u16,
    service_registry: Arc<RwLock<HashMap<MapData, DnsQuery, DnsRecordA>>>,
) -> Result<Response<Full<Bytes>>> {
    let body = req.collect().await?.aggregate();
    let props: serde_json::Value = serde_json::from_reader(body.reader())?;
    debug!("data: {props:?}");

    let namespace = props["namespace"].as_str().unwrap_or("default");
    let service_name = match props["service"].as_str() {
        Some(service) => service,
        None => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::from("Please provide the service name."))?);
        }
    };
    let dns_query = Discovery::create_dns_query(service_name, namespace)?;

    let service_registry = service_registry.read().await;
    let cluster_ip =
        match service_registry.get(&dns_query, 0) {
            Ok(record) => record.ip,
            Err(_) => return Ok(Response::builder().status(StatusCode::BAD_REQUEST).body(
                Full::from(
                    "Failed to get the ClusterIp with the specified service name and namespace.",
                ),
            )?),
        };

    let (local_port, service_port) = match parse_ports(props["port"].as_str()) {
        Ok((local, service)) => (local, service),
        Err(e) => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::from(e.to_string()))?);
        }
    };

    debug!("local port: {local_port:?}, service port: {service_port:?}");

    if let Err(e) = is_port_in_use(local_port) {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Full::from(e.to_string()))?);
    }

    let sender = establish_http2_connection("localhost", tunnel_port).await?;
    let mut send_req = sender.ready().await?;

    let body = IntercepRequest {
        cluster_ip,
        service_port,
        target_port: local_port,
    };

    let body = serde_json::to_string(&body)?;

    let req = http::Request::builder()
        .uri("/intercept")
        .method(http::Method::POST)
        .version(http::Version::HTTP_11)
        .body(())?;

    let (resp, mut send) = send_req.send_request(req, false)?;

    debug!("request body: {body:?}");

    send.send_data(Bytes::from(body), true)?;

    let resp = resp.await?;
    let (parts, mut body) = resp.into_parts();
    let body = body.data().await.unwrap()?;
    debug!("{:?}: {:?}", parts.status, body);

    Ok(Response::builder()
        .status(parts.status)
        .body(Full::from(body))
        .unwrap())
}

fn parse_ports(port_input: Option<&str>) -> Result<(u16, u16)> {
    port_input
        .and_then(|v| v.split_once(':'))
        .and_then(|(local, service)| {
            let local = local.parse::<u16>().ok()?;
            let service = service.parse::<u16>().ok()?;
            Some((local, service))
        })
        .ok_or_else(|| {
            anyhow!(
                "Please specify the port information using the --port option.
                The format should be LOCAL_PORT:SERVICE_PORT (e.g., 8080:80)."
            )
        })
}

fn is_port_in_use(port: u16) -> Result<()> {
    let mut netlink = Netlink::new();
    let tcpv4_diags = netlink.tcp_diagnostics(DiagFamily::V4)?;

    for diag in tcpv4_diags {
        if diag.msg.state == 10 && diag.msg.id.src_port == port {
            debug!("match {diag:?}");
            return Ok(());
        }
    }

    bail!("There is no process listening on port {port}");
}

async fn not_found() -> Result<Response<Full<Bytes>>> {
    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::from("Not found"))?)
}

#[derive(Serialize)]
struct IntercepRequest {
    cluster_ip: u32,
    service_port: u16,
    target_port: u16,
}
