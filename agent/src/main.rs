use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{Result, bail};
use clap::Parser;

use ::ctrl::{ForwardTo, InterceptRule, InterceptRuleSpec, Match};
use ::proxy::tunnel;
use ::proxy::tunnel::server::TunnelServer;
use discovery::DiscoveryServer;
use futures_util::StreamExt;
use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::api::{ListParams, Patch, PatchParams};
use kube::runtime::{WatchStreamExt, watcher};
use kube::{Api, ResourceExt};
use proto::intercept_discovery_server::InterceptDiscoveryServer;
use proxy::{
    DialRequest, InterceptRouteKey, InterceptRouteMap, InterceptRuleKey, InterceptRuleMap,
    InterceptValue,
};
use server::InterceptTunnel;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock, mpsc};
use tonic::{Status, transport};
use tracing::{debug, error, info};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};
use uuid::Uuid;

mod ctrl;
mod discovery;
mod server;

type DiscovertTx = mpsc::Sender<Result<proto::DiscoveryResponse, Status>>;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "127.0.0.1")]
    ip: String,

    #[arg(short, long, default_value_t = 8100)]
    tunnel_port: u16,

    #[arg(short, long, default_value_t = 8101)]
    reverse_port: u16,

    #[arg(short, long, default_value_t = 18326)]
    gate_port: u16,

    #[arg(short, long, default_value = "/certs/pmz.crt")]
    cert: String,

    #[arg(short, long, default_value = "/certs/pmz.key")]
    key: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let (non_blocking, _guard) = tracing_appender::non_blocking(std::io::stdout());
    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(fmt::layer().with_writer(non_blocking))
        .init();

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap();

    let args = Args::parse();
    info!(?args, "Starting pmz-agent with parsed arguments");

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

    let subs_clone = subs.clone();

    // controller thread
    tokio::spawn(async move {
        ctrl::run(subs_clone)
            .await
            .expect("Failed to run InterceptRule controller");
    });

    let dial_map: HashMap<Uuid, mpsc::Sender<DialRequest>> = HashMap::new();
    let dial_map = Arc::new(Mutex::new(dial_map));
    let dial_map_for_gate = dial_map.clone();

    let intercept_rule_map = InterceptRuleMap::default();
    let intercept_rule_map = Arc::new(RwLock::new(intercept_rule_map));
    // let intercept_rule_map_for_svc = intercept_rule_map.clone();
    let intercept_rule_map_for_eps = intercept_rule_map.clone();

    let intercept_route_map = InterceptRouteMap::default();
    let intercept_route_map = Arc::new(RwLock::new(intercept_route_map));
    // let intercept_route_map_for_svc = intercept_route_map.clone();
    let intercept_route_map_for_eps = intercept_route_map.clone();
    let intercept_route_map_for_gate = intercept_route_map.clone();

    let (intercept_rule_tx, mut intercept_rule_rx) =
        mpsc::channel::<(InterceptRuleKey, InterceptValue)>(1);

    // let client = kube::Client::try_default().await?;
    // let ssapply = PatchParams::apply("pmz-agent").force();
    // let crds: Api<CustomResourceDefinition> = Api::all(client.clone());
    // crds.patch(
    //     "interceptrules.pmz.sinabro.io",
    //     &ssapply,
    //     &Patch::Apply(InterceptRule::crd()),
    // )
    // .await?;

    // debug!("Waiting for the api-server to accept the CRD");
    // let establish = await_condition(
    //     crds,
    //     "interceptrules.pmz.sinabro.io",
    //     conditions::is_crd_established(),
    // );
    // let _ = tokio::time::timeout(std::time::Duration::from_secs(10), establish).await?;

    // intercept rule thread
    tokio::spawn(async move {
        loop {
            if let Some((key, value)) = intercept_rule_rx.recv().await {
                debug!("received rule key: {key:?}, value: {value:?}");
                // update intercept rule & route map
                let client = kube::Client::try_default().await.unwrap();
                let svc_api: Api<Service> = Api::namespaced(client.clone(), &key.namespace);
                let svc = svc_api.get(&key.service).await.unwrap();
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

                let eps_api: Api<EndpointSlice> = Api::namespaced(client.clone(), &key.namespace);
                let lp = ListParams::default()
                    .labels(&format!("kubernetes.io/service-name={}", key.service));

                for eps in eps_api.list(&lp).await.unwrap() {
                    for ep in &eps.endpoints {
                        for addr in &ep.addresses {
                            let ip: Ipv4Addr = addr.parse().unwrap();
                            let route_key = InterceptRouteKey {
                                ip: ip.into(),
                                port: key.port,
                            };
                            let route_value = InterceptValue {
                                id: value.id,
                                target_port: value.target_port,
                                // ..Default::default()
                            };
                            debug!("intercept route key: {route_key:?}, value: {route_value:?}");
                            intercept_route_map
                                .write()
                                .await
                                .insert(route_key, route_value);
                        }
                    }
                }

                let ssapply = PatchParams::apply("pmz-agent").force();
                // let crds: Api<CustomResourceDefinition> = Api::all(client.clone());
                // crds.patch(
                //     "interceptrules.pmz.sinabro.io",
                //     &ssapply,
                //     &Patch::Apply(InterceptRule::crd()),
                // )
                // .await
                // .unwrap();

                // debug!("Waiting for the api-server to accept the CRD");
                // let establish = await_condition(
                //     crds,
                //     "interceptrules.pmz.sinabro.io",
                //     conditions::is_crd_established(),
                // );
                // let _ = tokio::time::timeout(std::time::Duration::from_secs(10), establish)
                //     .await
                //     .unwrap();

                let intercept_rule_api: Api<InterceptRule> =
                    Api::namespaced(client.clone(), &key.namespace);

                let intercelt_rule_name = format!("{}-{}", key.service, key.port);
                let mut intercept_rule_cr = InterceptRule::new(
                    &intercelt_rule_name,
                    InterceptRuleSpec {
                        r#match: Match {
                            service: key.service.clone(),
                            port: key.port,
                            http: None,
                        },
                        forward_to: ForwardTo {
                            id: value.id.to_string(),
                            port: value.target_port,
                        },
                    },
                );
                let labels = intercept_rule_cr.labels_mut();
                labels.insert(
                    "pmz.sinabro.io/service-name".to_string(),
                    key.service.clone(),
                );
                labels.insert(
                    "pmz.sinabro.io/namespace".to_string(),
                    key.namespace.clone(),
                );

                intercept_rule_api
                    .patch(
                        &intercelt_rule_name,
                        &ssapply,
                        &Patch::Apply(&intercept_rule_cr),
                    )
                    .await
                    .unwrap();

                intercept_rule_map.write().await.insert(key, value);
            }
        }
    });

    // endpointSlice watcher
    tokio::spawn(async move {
        let client = kube::Client::try_default().await.unwrap();
        let eps: Api<EndpointSlice> = Api::all(client);

        let mut stream = watcher(eps, watcher::Config::default())
            .default_backoff()
            .boxed();

        loop {
            let intercept_rule_map = intercept_rule_map_for_eps.clone();
            let intercept_route_map = intercept_route_map_for_eps.clone();

            if let Some(next) = stream.next().await {
                match next {
                    Ok(event) => match event {
                        watcher::Event::Apply(eps) | watcher::Event::InitApply(eps) => {
                            if let Some(owner) = eps
                                .metadata
                                .owner_references
                                .as_ref()
                                .and_then(|owners| owners.first())
                            {
                                let service_name = &owner.name;
                                let namespace = eps.namespace().unwrap_or_default();

                                if let Some(eps_ports) = eps.ports {
                                    for eps_port in eps_ports {
                                        let port = eps_port.port.unwrap_or(0) as u16;
                                        let rule_key = InterceptRuleKey {
                                            namespace: namespace.clone(),
                                            service: service_name.clone(),
                                            port,
                                        };

                                        if let Some(rule_value) =
                                            intercept_rule_map.read().await.get(&rule_key)
                                        {
                                            for ep in &eps.endpoints {
                                                for addr in &ep.addresses {
                                                    let ip: Ipv4Addr = addr.parse().unwrap();
                                                    let key = InterceptRouteKey {
                                                        ip: ip.into(),
                                                        port: rule_key.port,
                                                    };
                                                    let value = InterceptValue {
                                                        id: rule_value.id,
                                                        target_port: rule_value.target_port,
                                                        // ..Default::default()
                                                    };
                                                    debug!(
                                                        "Try to add route to map with {:?}",
                                                        key
                                                    );

                                                    intercept_route_map
                                                        .write()
                                                        .await
                                                        .insert(key, value);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        watcher::Event::Delete(_eps) => todo!(),
                        _ => {}
                    },
                    Err(e) => {
                        error!("Failed to get next endpointSlice event: {:?}", e);
                    }
                }
            }
        }
    });

    // intercept gate thread
    tokio::spawn(async move {
        let gate_port = 18326;
        let addr = SocketAddr::from(([0, 0, 0, 0], gate_port));

        let listener = TcpListener::bind(addr).await.unwrap();
        debug!("Intercep Gate: Listening on {addr}");

        loop {
            let (mut stream, peer_addr) = listener.accept().await.unwrap();
            debug!("peer_addr: {peer_addr:?}");

            let mut original_dst_heder = [0u8; 6];
            if let Err(e) = stream.read_exact(&mut original_dst_heder).await {
                error!("Failed to read header from interceptor: {}", e);
                continue;
            }

            let target_ip = Ipv4Addr::new(
                original_dst_heder[0],
                original_dst_heder[1],
                original_dst_heder[2],
                original_dst_heder[3],
            );
            let target_port = u16::from_be_bytes([original_dst_heder[4], original_dst_heder[5]]);

            let ip: u32 = u32::from(target_ip);
            let port: u16 = target_port;

            debug!(
                "Received original destination from header: {}:{}",
                target_ip, target_port
            );

            // // TODO retrieve the target ip & port from the header
            // let (ip, port) = {
            //     let target_ip = 174126728; // u32::from_be(echo service's cluster ip);
            //     let target_port = 80; // u16::from_be(0);

            //     (target_ip, target_port)
            // };

            // get the uuid associated with the origin from the intercept_route_map
            let key = InterceptRouteKey { ip, port };
            debug!("Try to get route from map with {:?}", key);
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
