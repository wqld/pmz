use std::{fs, os::unix::fs::PermissionsExt, path::Path, sync::Arc};

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
    api::Api,
    runtime::wait::{await_condition, conditions::is_pod_running},
    Client,
};
use log::{debug, error};
use tokio::{
    join,
    net::UnixListener,
    sync::{mpsc::Receiver, Mutex, RwLock},
};

use crate::{discovery::Discovery, forward::Forward, route::Route, tunnel::Tunnel};

pub struct Command {
    req_rx: Arc<Mutex<Receiver<HttpRequest>>>,
    service_registry: Arc<RwLock<HashMap<MapData, DnsQuery, DnsRecordA>>>,
}

impl Command {
    pub fn new(
        req_rx: Receiver<HttpRequest>,
        service_registry: HashMap<MapData, DnsQuery, DnsRecordA>,
    ) -> Self {
        Self {
            req_rx: Arc::new(Mutex::new(req_rx)),
            service_registry: Arc::new(RwLock::new(service_registry)),
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

            tokio::task::spawn(async move {
                if let Err(err) = http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |req| {
                            handle_request(req, req_rx.clone(), service_registry.clone())
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
) -> Result<Response<Full<Bytes>>> {
    match (req.method(), req.uri().path()) {
        (&Method::POST, "/agent") => deploy_agent().await,
        (&Method::DELETE, "/agent") => delete_agent().await,
        (&Method::POST, "/connect") => connect(req_rx, service_registry).await,
        _ => not_found().await,
    }
}

async fn deploy_agent() -> Result<Response<Full<Bytes>>> {
    // create cert/key
    // apply cert/key secret to cluster
    // deploy agnet deployment
    Ok(Response::new(Full::<Bytes>::from("Agent deployed")))
}

async fn delete_agent() -> Result<Response<Full<Bytes>>> {
    Ok(Response::new(Full::<Bytes>::from("Agent deleted")))
}

async fn connect(
    req_rx: Arc<Mutex<Receiver<HttpRequest>>>,
    service_registry: Arc<RwLock<HashMap<MapData, DnsQuery, DnsRecordA>>>,
) -> Result<Response<Full<Bytes>>> {
    let namespace = "default";
    let agent_name = "test";
    let agent_port = 8100; // TODO
    let tunnel_host = "localhost";
    let tunnel_port = 18329;

    let client = Client::try_default().await.unwrap();
    let pods: Api<Pod> = Api::namespaced(client, &namespace);

    debug!("Checking if agent is running");

    let running = await_condition(pods.clone(), &agent_name, is_pod_running());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), running)
        .await
        .unwrap();

    let discovery = Discovery::new(service_registry);

    // route
    let mut route = Route::new().unwrap();
    route.add_service_route().unwrap();

    // port forward
    let forward = Forward::new(tunnel_port, pods);

    // proxy tunnel
    let tunnel = Tunnel::new(&tunnel_host, tunnel_port, req_rx);

    let (_, _, _) = join!(discovery.watch(), forward.start(), tunnel.run());

    // netlink.route_handle(RtCmd::Delete, &route)?; // TODO
    // TODO clean service map

    Ok(Response::new(Full::<Bytes>::from("Connected")))
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
