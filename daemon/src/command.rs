use std::{
    fs::{self},
    net::Ipv4Addr,
    os::{fd::AsRawFd, unix::fs::PermissionsExt},
    path::Path,
    sync::Arc,
    time::Duration,
};

use anyhow::{Result, anyhow, bail};
use aya::maps::{HashMap, MapData};
use common::{Config, DnsQuery, DnsRecordA};
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::{
    Response,
    body::{Buf, Bytes, Incoming},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use k8s_openapi::api::core::v1::Service;
use kube::api::Api;
use proxy::{
    InterceptContext,
    tunnel::client::{TunnelClient, TunnelRequest},
};
use rsln::{handle::sock_diag::DiagFamily, netlink::Netlink};
use serde::Deserialize;
use tokio::{
    net::UnixListener,
    sync::{
        Mutex, RwLock, broadcast,
        mpsc::{self, Receiver},
    },
    time::sleep,
};
use tracing::{Instrument, debug, error, info, instrument};
use uuid::Uuid;

use crate::{
    connect::{Connection, ConnectionManager, ConnectionStatus},
    deploy::Deploy,
    discovery::Discovery,
    intercept::Interceptor,
    route::Router,
};

pub struct Command {
    req_rx: Arc<Mutex<Receiver<TunnelRequest>>>,
    service_registry: Arc<RwLock<HashMap<MapData, DnsQuery, DnsRecordA>>>,
    service_cidr_map: Arc<RwLock<HashMap<MapData, u8, u32>>>,
    config_map: Arc<RwLock<HashMap<MapData, u8, Config>>>,
    connection_manager: Arc<Mutex<ConnectionManager>>,
    connection_status: Arc<RwLock<ConnectionStatus>>,
    intercept_ctx_tx: Arc<Mutex<mpsc::Sender<InterceptContext>>>,
    intercept_ctx_rx: Arc<Mutex<mpsc::Receiver<InterceptContext>>>,
}

impl Command {
    pub fn new(
        req_rx: Receiver<TunnelRequest>,
        service_registry: HashMap<MapData, DnsQuery, DnsRecordA>,
        service_cidr_map: HashMap<MapData, u8, u32>,
        config_map: HashMap<MapData, u8, Config>,
        connection_status: Arc<RwLock<ConnectionStatus>>,
    ) -> Self {
        let (intercept_ctx_tx, intercept_ctx_rx) = mpsc::channel::<InterceptContext>(1);

        Self {
            req_rx: Arc::new(Mutex::new(req_rx)),
            service_registry: Arc::new(RwLock::new(service_registry)),
            service_cidr_map: Arc::new(RwLock::new(service_cidr_map)),
            config_map: Arc::new(RwLock::new(config_map)),
            connection_manager: Arc::new(Mutex::new(ConnectionManager::default())),
            connection_status,
            intercept_ctx_tx: Arc::new(Mutex::new(intercept_ctx_tx)),
            intercept_ctx_rx: Arc::new(Mutex::new(intercept_ctx_rx)),
        }
    }

    #[instrument(name = "command", skip_all)]
    pub async fn run(&self) -> Result<()> {
        rustls::crypto::ring::default_provider()
            .install_default()
            .unwrap();

        let path = Path::new("/tmp/pmz.sock");

        if path.exists() {
            fs::remove_file(path)?;
        }

        let listener = UnixListener::bind(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o766))?;
        debug!(path = ?path, "Unix socket listening");

        while let Ok((stream, _)) = listener.accept().await {
            let req_rx = self.req_rx.clone();
            let service_registry = self.service_registry.clone();
            let service_cidr_map = self.service_cidr_map.clone();
            let config_map = self.config_map.clone();
            let connection_manager = self.connection_manager.clone();
            let connection_status = self.connection_status.clone();
            let intercept_ctx_tx = self.intercept_ctx_tx.clone();
            let intercept_ctx_rx = self.intercept_ctx_rx.clone();

            tokio::task::spawn(
                async move {
                    if let Err(e) = http1::Builder::new()
                        .serve_connection(
                            TokioIo::new(stream),
                            service_fn(move |req| {
                                handle_request(
                                    req,
                                    req_rx.clone(),
                                    service_registry.clone(),
                                    service_cidr_map.clone(),
                                    config_map.clone(),
                                    connection_manager.clone(),
                                    connection_status.clone(),
                                    intercept_ctx_tx.clone(),
                                    intercept_ctx_rx.clone(),
                                )
                            }),
                        )
                        .await
                    {
                        error!(error = ?e, "Error serving connection");
                    }
                }
                .in_current_span(),
            );
        }

        Ok(())
    }
}

#[instrument(
    name = "handle",
    skip_all,
    fields(
        http.method = %req.method(),
        http.uri = %req.uri(),
    )
)]
async fn handle_request(
    req: Request<Incoming>,
    req_rx: Arc<Mutex<Receiver<TunnelRequest>>>,
    service_registry: Arc<RwLock<HashMap<MapData, DnsQuery, DnsRecordA>>>,
    service_cidr_map: Arc<RwLock<HashMap<MapData, u8, u32>>>,
    config_map: Arc<RwLock<HashMap<MapData, u8, Config>>>,
    connection_manager: Arc<Mutex<ConnectionManager>>,
    connection_status: Arc<RwLock<ConnectionStatus>>,
    intercept_ctx_tx: Arc<Mutex<mpsc::Sender<InterceptContext>>>,
    intercept_ctx_rx: Arc<Mutex<mpsc::Receiver<InterceptContext>>>,
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
                config_map,
                connection_manager,
                connection_status,
                intercept_ctx_rx,
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
            start_intercept(req.into_body(), connection_manager, intercept_ctx_tx).await
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

    deploy.deploy_cni().await?;
    deploy.deploy_tls_secret().await?;
    deploy.add_rbac_to_agent().await?;
    deploy.add_rbac_to_cni().await?;
    deploy.deploy_agent().await?;
    deploy.expose_agent().await?;

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

fn get_netns_cookie() -> Result<u64> {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let fd = socket.as_raw_fd();

    let mut cookie: u64 = 0;
    let mut len = std::mem::size_of::<u64>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_NETNS_COOKIE,
            &mut cookie as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };

    if ret != 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    Ok(cookie)
}

#[instrument(skip_all)]
async fn connect(
    req_rx: Arc<Mutex<Receiver<TunnelRequest>>>,
    service_registry: Arc<RwLock<HashMap<MapData, DnsQuery, DnsRecordA>>>,
    service_cidr_map: Arc<RwLock<HashMap<MapData, u8, u32>>>,
    config_map: Arc<RwLock<HashMap<MapData, u8, Config>>>,
    connection_manager: Arc<Mutex<ConnectionManager>>,
    connection_status: Arc<RwLock<ConnectionStatus>>,
    intercept_ctx_rx: Arc<Mutex<mpsc::Receiver<InterceptContext>>>,
    tunnel_port: u16,
) -> Result<Response<Full<Bytes>>> {
    // let agent_port = 8100; // TODO

    {
        let conn_mgr = connection_manager.lock().await;
        if conn_mgr.check_connection("default") {
            return Ok(Response::new(Full::from("Already connected")));
        }
    }

    let client = loop {
        let c = kube::Client::try_default().await;
        match c {
            Ok(client) => {
                info!("Connected to the cluster");
                break client;
            }
            Err(e) => {
                error!("{}", e);
                sleep(Duration::from_secs(5)).await;
            }
        }
    };

    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let shutdown_intercept = shutdown_tx.subscribe();

    // let conn_stat_route = connection_status.clone();
    let conn_stat_discovery = connection_status.clone();
    // let conn_stat_tunnel = connection_status.clone();

    let router = Router::setup_routes(service_cidr_map).await?;
    let mut discovery = Discovery::new(service_registry, shutdown_tx.subscribe(), client.clone());
    let mut tunnel = TunnelClient::new(tunnel_port, req_rx, shutdown_tx.subscribe());

    let interceptor = Interceptor::new(intercept_ctx_rx, shutdown_intercept, client.clone());

    let cfg = Config {
        host_netns: get_netns_cookie()?,
        service_addr: router.service_cidr_addr,
        subnet_mask: 0xFFFF0000,
        proxy_pid: std::process::id(),
        dummy: 0,
        proxy_port: 18328,
    };

    let mut config_map = config_map.write().await;
    config_map.insert(0, cfg, 0)?;

    tokio::spawn(async move { discovery.watch(conn_stat_discovery).await }.in_current_span());
    tokio::spawn(async move { tunnel.run().await }.in_current_span());
    tokio::spawn(async move { interceptor.launch().await }.in_current_span());

    let connection = Connection {
        _route: router,
        shutdown_tx,
    };

    let mut conn_mgr = connection_manager.lock().await;
    let res = conn_mgr
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
        let mut conn_mgr = connection_manager.lock().await;
        conn_mgr.connections.remove("default")
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
    {
        let conn_mgr = connection_manager.lock().await;
        if !conn_mgr.check_connection("default") {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::from(
                    "Not connected. Please run 'pmzctl connect' to establish a connection.",
                ))?);
        }
    }

    let body = req.collect().await?.aggregate();
    let props: serde_json::Value = serde_json::from_reader(body.reader())?;
    debug!("data: {props:?}");

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

    let mut registry = service_registry.write().await;
    registry.insert(dns_query, dns_recard_a, 0)?;

    Ok(Response::new(Full::from("dns added")))
}

async fn remove_dns(
    req: Incoming,
    service_registry: Arc<RwLock<HashMap<MapData, DnsQuery, DnsRecordA>>>,
    connection_manager: Arc<Mutex<ConnectionManager>>,
) -> Result<Response<Full<Bytes>>> {
    {
        let conn_mgr = connection_manager.lock().await;
        if !conn_mgr.check_connection("default") {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::from(
                    "Not connected. Please run 'pmzctl connect' to establish a connection.",
                ))?);
        }
    }

    let body = req.collect().await?.aggregate();
    let props: serde_json::Value = serde_json::from_reader(body.reader())?;
    debug!("data: {props:?}");

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

    let mut registry = service_registry.write().await;
    registry.remove(&dns_query)?;

    Ok(Response::new(Full::from("dns removed")))
}

async fn list_dns(
    service_registry: Arc<RwLock<HashMap<MapData, DnsQuery, DnsRecordA>>>,
    connection_manager: Arc<Mutex<ConnectionManager>>,
) -> Result<Response<Full<Bytes>>> {
    if let Some(res) = check_connection(connection_manager).await? {
        return Ok(res);
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
    connection_manager: Arc<Mutex<ConnectionManager>>,
    intercept_ctx_tx: Arc<Mutex<mpsc::Sender<InterceptContext>>>,
) -> Result<Response<Full<Bytes>>> {
    if let Some(res) = check_connection(connection_manager).await? {
        return Ok(res);
    }

    #[derive(Deserialize, Debug)]
    struct InterceptStartRequest {
        namespace: String,
        service: String,
        port: String,
        #[serde(default, rename = "header")]
        headers: Vec<(String, String)>,
        uri: Option<String>,
    }

    let body = req.collect().await?.aggregate();
    let req: InterceptStartRequest = serde_json::from_reader(body.reader())?;
    debug!("InterceptStartRequest: {req:?}");

    let (local_port, service_port) = match parse_ports(&req.port) {
        Ok((lo, svc)) => (lo, svc),
        Err(e) => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::from(e.to_string()))?);
        }
    };

    debug!("local port: {local_port:?}, service port: {service_port:?}");

    // ensure that the service requested to intercept traffic exists
    let client = kube::Client::try_default().await?;
    let services: Api<Service> = Api::namespaced(client, &req.namespace);
    let _ = match services.get(&req.service).await {
        Ok(service) => {
            if let None = service
                .spec
                .and_then(|s| s.ports)
                .iter()
                .flatten()
                .find(|p| p.port == service_port as i32)
            {
                return Ok(Response::builder().status(StatusCode::BAD_REQUEST).body(
                    Full::from(format!(
                        "Service '{}' does not expose port {service_port}",
                        req.service
                    )),
                )?);
            }
        }
        Err(_) => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::from(format!("Service {:?} not founds", req.service)))?);
        }
    };

    if let Err(e) = is_port_in_use(local_port) {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Full::from(e.to_string()))?);
    }

    let intercept_ctx = InterceptContext {
        id: Uuid::nil().into_bytes(),
        namespace: req.namespace,
        service_name: req.service,
        service_port,
        local_port,
        headers: req.headers,
        uri: req.uri,
    };

    debug!("send intercept context: {intercept_ctx:?}");
    intercept_ctx_tx.lock().await.send(intercept_ctx).await?;

    Ok(Response::builder()
        // .status(parts.status)
        // .body(Full::from(body))
        .body(Full::from("intercept request processed successfully"))
        .unwrap())
}

fn parse_ports(port_input: &str) -> Result<(u16, u16)> {
    port_input
        .split_once(':')
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

async fn check_connection(
    connection_manager: Arc<Mutex<ConnectionManager>>,
) -> Result<Option<Response<Full<Bytes>>>> {
    let conn_mgr = connection_manager.lock().await;
    if !conn_mgr.check_connection("default") {
        return Ok(Some(
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::<Bytes>::from(
                    "Not connected. Please run 'pmzctl connect' to establish a connection.",
                ))?,
        ));
    }

    Ok(None)
}
