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
use h2::client::SendRequest;
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
use proxy::{
    InterceptContext, InterceptRequest,
    tunnel::{
        client::{TunnelClient, TunnelRequest, establish_h2_connection},
        stream::TunnelStream,
    },
};
use rsln::{handle::sock_diag::DiagFamily, netlink::Netlink};
use tokio::{
    net::{TcpStream, UnixListener},
    sync::{
        Mutex, RwLock, broadcast,
        mpsc::{self, Receiver},
    },
    time::sleep,
};
use uuid::Uuid;

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
    intercept_ctx_tx: Arc<Mutex<mpsc::Sender<InterceptContext>>>,
    intercept_ctx_rx: Arc<Mutex<mpsc::Receiver<InterceptContext>>>,
}

impl Command {
    pub fn new(
        req_rx: Receiver<TunnelRequest>,
        service_registry: HashMap<MapData, DnsQuery, DnsRecordA>,
        service_cidr_map: HashMap<MapData, u8, u32>,
        connection_status: Arc<RwLock<ConnectionStatus>>,
    ) -> Self {
        let (intercept_ctx_tx, intercept_ctx_rx) = mpsc::channel::<InterceptContext>(1);

        Self {
            req_rx: Arc::new(Mutex::new(req_rx)),
            service_registry: Arc::new(RwLock::new(service_registry)),
            service_cidr_map: Arc::new(RwLock::new(service_cidr_map)),
            connection_manager: Arc::new(Mutex::new(ConnectionManager::default())),
            connection_status,
            intercept_ctx_tx: Arc::new(Mutex::new(intercept_ctx_tx)),
            intercept_ctx_rx: Arc::new(Mutex::new(intercept_ctx_rx)),
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
            let intercept_ctx_tx = self.intercept_ctx_tx.clone();
            let intercept_ctx_rx = self.intercept_ctx_rx.clone();

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
                                intercept_ctx_tx.clone(),
                                intercept_ctx_rx.clone(),
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
    deploy.add_rback_to_agent().await?;
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

async fn connect(
    req_rx: Arc<Mutex<Receiver<TunnelRequest>>>,
    service_registry: Arc<RwLock<HashMap<MapData, DnsQuery, DnsRecordA>>>,
    service_cidr_map: Arc<RwLock<HashMap<MapData, u8, u32>>>,
    connection_manager: Arc<Mutex<ConnectionManager>>,
    connection_status: Arc<RwLock<ConnectionStatus>>,
    intercept_ctx_rx: Arc<Mutex<mpsc::Receiver<InterceptContext>>>,
    tunnel_port: u16,
) -> Result<Response<Full<Bytes>>> {
    let agent_port = 8100; // TODO

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
    let mut shutdown_dial = shutdown_tx.subscribe();
    let mut shutdown_intercept = shutdown_tx.subscribe();

    let service_registry_clone = service_registry.clone();

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

    // // TODO: how to get the namespace for pmz-agnet?
    let dns_query = Discovery::create_dns_query("pmz-agent", "default").unwrap();
    let pmz_agent_service_ip: String;

    loop {
        let service_registry = service_registry_clone.read().await;
        if let Ok(ip) = service_registry.get(&dns_query, 0) {
            pmz_agent_service_ip = Ipv4Addr::from(ip.ip).to_string();
            debug!("found IP for pmz-agent: {}", pmz_agent_service_ip);
            break;
        } else {
            drop(service_registry);
            debug!("service 'pmz-agent' not yet available in registry, retrying...");
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    let pmz_agent_service_ip_clone = pmz_agent_service_ip.clone();
    let (intercept_tx, mut intercept_rx) = mpsc::channel::<Bytes>(1);

    // dial & intercept thread
    tokio::spawn(async move {
        let sender = establish_h2_connection(&pmz_agent_service_ip_clone, 8101, false)
            .await
            .unwrap();
        let mut send_req = sender.ready().await.unwrap();
        let send_req_clone = send_req.clone();

        // open a dial stream with agent
        let req = Request::builder().uri("/dial").body(()).unwrap();

        // send the preface
        let (resp, mut send) = send_req.send_request(req, false).unwrap();
        send.send_data("dial-preface-from-agent".into(), false)
            .unwrap();

        let resp = resp.await.unwrap();
        let mut recv = resp.into_body();

        // get an uuid
        let uuid = if let Some(data) = recv.data().await {
            let data = data.unwrap();
            Uuid::from_slice(&data).unwrap()
        } else {
            // TODO need to proceed as an error case
            Uuid::nil()
        };

        debug!("uuid is allocated from agent: {uuid:?}");

        // register an intercept rule from daemon to agent
        tokio::spawn(async move {
            loop {
                if let Some(mut ctx) = intercept_ctx_rx.lock().await.recv().await {
                    ctx.id = uuid.into_bytes();
                    let ctx = serde_json::to_vec(&ctx).unwrap();
                    debug!("request to register an intercept rule {ctx:?}");
                    send.send_data(ctx.into(), false).unwrap();
                }
            }
        });

        // receive target port from agent to initiate dialing
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(data) = recv.data() => {
                        match data {
                            Ok(target_port) => {
                                if let Err(e) = intercept_tx.send(target_port).await {
                                    error!("intercept_tx.send failed: {e:?}")
                                }
                            },
                            Err(e) => error!("recv.data failed: {e:?}"),
                        }
                    }
                    _ = shutdown_dial.recv() => break
                }
            }
        });

        async fn intercept_tunnel(
            mut send_req: SendRequest<Bytes>,
            id: Uuid,
            target_port: u16,
        ) -> Result<()> {
            let req = Request::builder().uri("/intercept").body(()).unwrap();

            let (resp, mut send) = send_req.send_request(req, false).unwrap();
            let intercept_req = InterceptRequest {
                id: id.into_bytes(),
                target_port,
            };
            let intercept_req = serde_json::to_vec(&intercept_req)?;
            send.send_data(intercept_req.into(), false).unwrap();

            let resp = resp.await.unwrap();
            debug!("got response: {:?}", resp);

            let recv = resp.into_body();

            let mut downstream = TunnelStream { recv, send };
            let target_addr = format!("localhost:{}", target_port);
            let mut upstream = TcpStream::connect(target_addr).await?;

            tokio::io::copy_bidirectional(&mut downstream, &mut upstream)
                .await
                .unwrap();

            Ok(())
        }

        // establish a connection with the local process using the target port
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(target_port) = intercept_rx.recv() => {
                        let target_port = {
                            let byte_slice = target_port.as_ref();

                            if byte_slice.len() != 2 {
                                error!("target_port's slice must be 2 bytes");
                                continue
                            }

                            u16::from_be_bytes([byte_slice[0], byte_slice[1]])
                        };

                        intercept_tunnel(send_req_clone.clone(), uuid, target_port).await.unwrap();
                    }
                    _ = shutdown_intercept.recv() => break
                }
            }
        });
    });

    let connection = Connection {
        _route: route,
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

    // let dns_query = Discovery::create_dns_query(service_name, namespace)?;

    // let service_registry = service_registry.read().await;
    // let cluster_ip =
    //     match service_registry.get(&dns_query, 0) {
    //         Ok(record) => record.ip,
    //         Err(_) => return Ok(Response::builder().status(StatusCode::BAD_REQUEST).body(
    //             Full::from(
    //                 "Failed to get the ClusterIp with the specified service name and namespace.",
    //             ),
    //         )?),
    //     };

    let (local_port, service_port) = match parse_ports(props["port"].as_str()) {
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
    let services: Api<Service> = Api::namespaced(client, namespace);
    let _ = match services.get(&service_name).await {
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
                        "Service '{service_name}' does not expose port {service_port}"
                    )),
                )?);
            }
        }
        Err(_) => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::from(format!("Service {service_name:?} not founds")))?);
        }
    };

    if let Err(e) = is_port_in_use(local_port) {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Full::from(e.to_string()))?);
    }

    let intercept_ctx = InterceptContext {
        id: Uuid::nil().into_bytes(),
        service_name: service_name.to_string(),
        namespace: namespace.to_string(),
        port: service_port,
        target_port: local_port,
    };

    debug!("send intercept context: {intercept_ctx:?}");
    intercept_ctx_tx.lock().await.send(intercept_ctx).await?;

    // let sender = establish_h2_connection("localhost", tunnel_port, true).await?;
    // let mut send_req = sender.ready().await?;

    // let body = IntercepRequest {
    //     cluster_ip,
    //     service_port,
    //     target_port: local_port,
    // };

    // let body = serde_json::to_string(&body)?;

    // let req = http::Request::builder()
    //     .uri("/intercept")
    //     .method(http::Method::POST)
    //     .version(http::Version::HTTP_11)
    //     .body(())?;

    // let (resp, mut send) = send_req.send_request(req, false)?;

    // debug!("request body: {body:?}");

    // send.send_data(Bytes::from(body), true)?;

    // let resp = resp.await?;
    // let (parts, mut body) = resp.into_parts();
    // let body = body.data().await.unwrap()?;
    // debug!("{:?}: {:?}", parts.status, body);

    Ok(Response::builder()
        // .status(parts.status)
        // .body(Full::from(body))
        .body(Full::from("intercept request processed successfully"))
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

// #[derive(Serialize)]
// struct IntercepRequest {
//     cluster_ip: u32,
//     service_port: u16,
//     target_port: u16,
// }
