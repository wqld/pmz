use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Result, bail};
use clap::Parser;

use ::proxy::tunnel;
use ::proxy::tunnel::server::TunnelServer;
use discovery::DiscoveryServer;
use futures_util::StreamExt;
use k8s_openapi::api::core::v1::Service;
use kube::runtime::{WatchStreamExt, watcher};
use kube::{Api, ResourceExt};
use log::{debug, error};
use proto::intercept_discovery_server::InterceptDiscoveryServer;
use proxy::{
    DialRequest, InterceptRouteKey, InterceptRouteMap, InterceptRuleKey, InterceptRuleMap,
    InterceptValue,
};
use server::InterceptTunnel;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock, mpsc};
use tonic::transport;
use uuid::Uuid;

mod discovery;
mod server;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "127.0.0.1")]
    ip: String,

    #[arg(short, long, default_value_t = 8100)]
    tunnel_port: u16,

    #[arg(short, long, default_value_t = 8101)]
    reverse_port: u16,

    #[arg(short, long, default_value = "/certs/pmz.crt")]
    cert: String,

    #[arg(short, long, default_value = "/certs/pmz.key")]
    key: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap();

    let subs = HashMap::new();
    let subs = Arc::new(RwLock::new(subs));
    let subs_clone = subs.clone();

    // discovery thread
    tokio::spawn(async move {
        debug!("Discovery!");
        let addr = SocketAddr::from(([0, 0, 0, 0], 50018));
        let discovery_server = DiscoveryServer::new(subs_clone);
        debug!("Discovery server is starting with {addr:?}");

        transport::Server::builder()
            .add_service(InterceptDiscoveryServer::new(discovery_server))
            .serve(addr)
            .await
            .unwrap()
    });

    let dial_map: HashMap<Uuid, mpsc::Sender<DialRequest>> = HashMap::new();
    let dial_map = Arc::new(Mutex::new(dial_map));
    let dial_map_for_gate = dial_map.clone();

    let intercept_rule_map = InterceptRuleMap::default();
    let intercept_rule_map = Arc::new(RwLock::new(intercept_rule_map));
    let intercept_rule_map_for_svc = intercept_rule_map.clone();

    let intercept_route_map = InterceptRouteMap::default();
    let intercept_route_map = Arc::new(RwLock::new(intercept_route_map));
    let intercept_route_map_for_svc = intercept_route_map.clone();
    let intercept_route_map_for_gate = intercept_route_map.clone();

    let (intercept_rule_tx, mut intercept_rule_rx) =
        mpsc::channel::<(InterceptRuleKey, InterceptValue)>(1);

    // intercept rule thread
    tokio::spawn(async move {
        loop {
            if let Some((key, value)) = intercept_rule_rx.recv().await {
                debug!("received rule key: {key:?}, value: {value:?}");
                // update intercept rule & route map
                let client = kube::Client::try_default().await.unwrap();
                let api: Api<Service> = Api::namespaced(client, &key.namespace);
                let svc = api.get(&key.service).await.unwrap();
                let spec = svc.spec.unwrap();
                let cluster_ip = spec.cluster_ip.unwrap_or_default();
                debug!("cluster ip: {cluster_ip:?}");

                if let Some(svc_ports) = spec.ports {
                    if svc_ports
                        .iter()
                        .find(|sp| sp.port == key.port as i32)
                        .is_none()
                    {
                        error!(
                            "port {} not found in service {}/{}",
                            key.port, key.namespace, key.service
                        );
                        continue;
                    }
                }

                let ip_addr = Ipv4Addr::from_str(&cluster_ip).unwrap();
                let rkey = InterceptRouteKey {
                    ip: ip_addr.into(),
                    port: key.port,
                };
                let rvalue = InterceptValue {
                    id: value.id,
                    target_port: value.target_port,
                };
                debug!("intercept route key: {rkey:?}, value: {rvalue:?}");

                // TODO: Remove route map. eBPF redirection is not feasible;
                // use CRD for intercept rules, enabling CNI handling
                intercept_rule_map.write().await.insert(key, value);
                intercept_route_map.write().await.insert(rkey, rvalue);
            }
        }
    });

    // TODO Deprecated: we don't need to this anymore.
    // service watcher
    tokio::spawn(async move {
        let client = kube::Client::try_default().await.unwrap();
        let api: Api<Service> = Api::all(client);

        let mut stream = watcher(api, watcher::Config::default())
            .default_backoff()
            .boxed();

        async fn sync_service_intercept_routes<F>(
            svc: Service,
            intercept_rule_map: Arc<RwLock<InterceptRuleMap>>,
            mut intercept_route_action: F,
        ) -> Result<()>
        where
            F: AsyncFnMut(InterceptRouteKey, InterceptValue) -> Result<()>,
        {
            let mut key = InterceptRuleKey {
                service: svc.name_any(),
                namespace: svc.namespace().unwrap_or_default(),
                port: 0,
            };
            let spec = svc.spec.unwrap();
            let cluster_ip = spec.cluster_ip.unwrap_or_default();

            if let Some(svc_ports) = spec.ports {
                for svc_port in svc_ports {
                    let port = svc_port.port;
                    key.port = port.try_into().unwrap_or_default();

                    if let Some(value) = intercept_rule_map.read().await.get(&key) {
                        let ip_addr = Ipv4Addr::from_str(&cluster_ip).unwrap();
                        let key = InterceptRouteKey {
                            ip: ip_addr.into(),
                            port: key.port,
                        };
                        let value = InterceptValue {
                            id: value.id,
                            target_port: value.target_port,
                        };

                        intercept_route_action(key, value).await.unwrap();
                    }
                }
            }
            Ok(())
        }

        // TODO need to update the intercept target table
        async fn handle_service_event(
            event: watcher::Event<Service>,
            intercept_rule_map: Arc<RwLock<InterceptRuleMap>>,
            intercept_route_map: Arc<RwLock<InterceptRouteMap>>,
        ) -> Result<()> {
            match event {
                watcher::Event::Apply(svc) | watcher::Event::InitApply(svc) => {
                    sync_service_intercept_routes(
                        svc,
                        intercept_rule_map,
                        async move |k: InterceptRouteKey, v: InterceptValue| -> Result<()> {
                            intercept_route_map.write().await.insert(k, v);
                            Ok(())
                        },
                    )
                    .await
                    .unwrap();
                }
                watcher::Event::Delete(svc) => {
                    sync_service_intercept_routes(
                        svc,
                        intercept_rule_map,
                        async move |k: InterceptRouteKey, _: InterceptValue| -> Result<()> {
                            intercept_route_map.write().await.remove(&k);
                            Ok(())
                        },
                    )
                    .await
                    .unwrap();
                }
                _ => {}
            }
            Ok(())
        }

        loop {
            let intercept_rule_map = intercept_rule_map_for_svc.clone();
            let intercept_route_map = intercept_route_map_for_svc.clone();
            if let Some(next) = stream.next().await {
                match next {
                    Ok(event) => {
                        handle_service_event(event, intercept_rule_map, intercept_route_map)
                            .await
                            .unwrap()
                    }
                    Err(e) => error!("failed to get next service event: {e:?}"),
                }
            }
        }
    });

    // intercept gate thread
    tokio::spawn(async move {
        let gate_port = 18326;
        let addr = SocketAddr::from(([127, 0, 0, 1], gate_port));

        let listener = TcpListener::bind(addr).await.unwrap();
        debug!("Intercep Gate: Listening on {addr}");

        loop {
            let (stream, peer_addr) = listener.accept().await.unwrap();
            debug!("peer_addr: {peer_addr:?}");

            // TODO retrieve the target ip & port from the header
            let (ip, port) = {
                let target_ip = 174086685; // u32::from_be(0);
                let target_port = 80; // u16::from_be(0);

                (target_ip, target_port)
            };

            // get the uuid associated with the origin from the intercept_route_map
            let key = InterceptRouteKey { ip, port };
            match intercept_route_map_for_gate.read().await.get(&key) {
                Some(InterceptValue { id, target_port }) => {
                    // retrieve the tx for the uuid from dial_map to initiate dialing
                    match dial_map_for_gate.lock().await.get(id) {
                        Some(tx) => {
                            let dial_req = DialRequest {
                                id: *id,
                                target_port: *target_port,
                                stream,
                            };
                            tx.send(dial_req).await.unwrap();
                        }
                        None => todo!(),
                    }
                }
                None => todo!(),
            }
        }
    });

    let intercept = InterceptTunnel::new(args.reverse_port, dial_map, intercept_rule_tx);

    let tunnel = TunnelServer::new(tunnel::server::Args {
        ip: args.ip,
        proxy_port: args.tunnel_port,
        cert: args.cert,
        key: args.key,
    });

    match tokio::join!(intercept.start(), tunnel.start()) {
        (Ok(_), Ok(_)) => Ok(()),
        (Ok(_), Err(e)) | (Err(e), Ok(_)) => Err(e),
        (Err(e1), Err(e2)) => bail!("{:?} + {:?}", e1, e2),
    }
}
