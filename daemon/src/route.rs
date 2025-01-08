use anyhow::{bail, Result};
use ipnet::IpNet;
use log::{debug, error, info};
use rsln::{
    netlink::Netlink,
    types::{
        link::LinkAttrs,
        routing::{Routing, RoutingBuilder},
    },
};

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
    pub fn setup_routes() -> Result<Self> {
        let service_cidr = Self::find_service_cidr()?;
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

    fn find_service_cidr() -> Result<String> {
        let output = std::process::Command::new("kubectl")
            .arg("cluster-info")
            .arg("dump")
            .output()
            .expect("failed to execute kubectl command");

        if !output.status.success() {
            bail!("kubectl cluster-info dump command failed");
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(line) = stdout
            .lines()
            .find(|line| line.contains("service-cluster-ip-range"))
        {
            if let Some(cidr) = line.split("--service-cluster-ip-range=").nth(1) {
                if let Some(cidr) = cidr.split(',').next() {
                    let cidr = cidr.trim_matches('"').to_owned();
                    info!("service cidr: {cidr}");
                    return Ok(cidr);
                }
            }
        }

        bail!("failed to find service cidr");
    }
}
