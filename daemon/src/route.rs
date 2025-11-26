use std::{error::Error, sync::Arc};

use anyhow::{Result, bail};
use aya::maps::{HashMap, MapData};
use ipnet::IpNet;
use k8s_openapi::api::{core::v1::Service, networking::v1::ServiceCIDR};
use kube::{
    Api,
    api::{DeleteParams, ListParams, PostParams},
    core::ErrorResponse,
};
use rsln::{
    netlink::Netlink,
    types::{
        link::LinkAttrs,
        routing::{Routing, RoutingBuilder},
    },
};
use serde_json::json;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

pub struct Router {
    netlink: Netlink,
    service_route: Routing,
}

impl Drop for Router {
    fn drop(&mut self) {
        debug!("route dropped");
        self.drop_routes()
    }
}

impl Router {
    pub async fn setup_routes(
        service_cidr_map: Arc<RwLock<HashMap<MapData, u8, u32>>>,
    ) -> Result<Self> {
        let service_cidr = Self::find_service_cidr().await?;
        let service_cidr_net = service_cidr.parse::<IpNet>()?;
        let mut netlink = Netlink::new();

        let link = netlink.link_get(&LinkAttrs::new("lo"))?;

        let service_route = RoutingBuilder::default()
            .oif_index(link.attrs().index)
            .dst(Some(service_cidr_net))
            .build()?;

        if let Err(e) = netlink.route_add(&service_route) {
            if e.to_string().contains("File exists") {
                debug!("route already exists");
            } else {
                return Err(e);
            }
        }

        let service_cidr_u32: u32 = match service_cidr_net.addr() {
            std::net::IpAddr::V4(ipv4_addr) => ipv4_addr.into(),
            std::net::IpAddr::V6(_) => bail!("IPv6 is not supported"),
        };

        let mut cidr_map = service_cidr_map.write().await;
        cidr_map.insert(0, service_cidr_u32, 0)?;

        Ok(Self {
            netlink,
            service_route,
        })
    }

    fn drop_routes(&mut self) {
        if let Err(e) = self.netlink.route_del(&self.service_route) {
            error!("failed to drop routes: {e:#?}");
        }
    }

    async fn find_service_cidr() -> Result<String> {
        let client = kube::Client::try_default().await?;
        let service_cidrs: Api<ServiceCIDR> = Api::all(client.clone());

        if let Ok(list) = service_cidrs.list(&ListParams::default()).await {
            let cidr = list
                .items
                .first()
                .and_then(|sc| sc.spec.as_ref())
                .and_then(|spec| spec.cidrs.as_ref())
                .and_then(|cidrs| cidrs.first());

            if let Some(cidr) = cidr {
                info!("Found Service CIDR via API: {}", cidr);
                return Ok(cidr.clone());
            }
        }

        let services: Api<Service> = Api::default_namespaced(client.clone());
        let dummy: Service = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "pmz-dummy" },
            "spec": {
                "clusterIP": "1.1.1.1",
                "ports": [{ "port": 443 }]
            }
        }))?;

        match services.create(&PostParams::default(), &dummy).await {
            Ok(_) => {
                let _ = services.delete("pmz-dummy", &DeleteParams::default()).await;
                bail!("Unexpectedly succeeded to create service with 1.1.1.1");
            }
            Err(err) => {
                if let Some(e) = err.source().and_then(|s| s.downcast_ref::<ErrorResponse>()) {
                    if let Some(cidr) = e.message.split("The range of valid IPs is ").nth(1) {
                        let cidr = cidr.trim().to_owned();
                        info!("Found Service CIDR via legacy error parsing: {cidr}");
                        return Ok(cidr);
                    }

                    info!("Error message does not contain CIDR hint: {}", e.message);
                }
            }
        }

        bail!("failed to find service cidr via both API and legacy methods");
    }
}
