use std::error::Error;

use anyhow::{bail, Result};
use ipnet::IpNet;
use k8s_openapi::api::core::v1::Service;
use kube::{
    api::{DeleteParams, PostParams},
    core::ErrorResponse,
    Api,
};
use log::{debug, error, info};
use rsln::{
    netlink::Netlink,
    types::{
        link::LinkAttrs,
        routing::{Routing, RoutingBuilder},
    },
};
use serde_json::json;

pub struct Route {
    netlink: Netlink,
    service_route: Routing,
}

impl Drop for Route {
    fn drop(&mut self) {
        debug!("route dropped");
        self.drop_routes()
    }
}

impl Route {
    pub async fn setup_routes() -> Result<Self> {
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
        let services: Api<Service> = Api::default_namespaced(client);

        let dummy: Service = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": "pmz-dummy"
            },
            "spec": {
                "clusterIP": "1.1.1.1",
                "ports": [{ "port": 443 }]
            }
        }))?;

        match services.create(&PostParams::default(), &dummy).await {
            Ok(_) => {
                services
                    .delete("pmz-dummy", &DeleteParams::default())
                    .await?;
            }
            Err(err) => {
                if let Some(e) = err.source().unwrap().downcast_ref::<ErrorResponse>() {
                    if let Some(cidr) = e.message.split("The range of valid IPs is ").nth(1) {
                        info!("service cidr: {cidr}");
                        let cidr = cidr.trim().to_owned();
                        return Ok(cidr);
                    }
                }
            }
        }

        bail!("failed to find service cidr");
    }
}
