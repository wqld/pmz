use anyhow::{bail, Result};
use ipnet::IpNet;
use log::{debug, info};
use rsln::{
    netlink::Netlink,
    types::{link::LinkAttrs, routing::RoutingBuilder},
};

pub struct Route {
    netlink: Netlink,
    oif_index: i32,
    dst: IpNet,
}

impl Route {
    pub fn new() -> Result<Self> {
        let service_cidr = Self::find_service_cidr()?;
        let service_cidr_net = service_cidr.parse::<IpNet>()?;
        let mut netlink = Netlink::new();

        let link = netlink.link_get(&LinkAttrs::new("lo"))?;

        Ok(Self {
            netlink,
            oif_index: link.attrs().index,
            dst: service_cidr_net,
        })
    }

    pub fn add_service_route(&mut self) -> Result<()> {
        let route = RoutingBuilder::default()
            .oif_index(self.oif_index)
            .dst(Some(self.dst))
            .build()?;

        if let Err(e) = self.netlink.route_add(&route) {
            if e.to_string().contains("File exists") {
                debug!("route already exists");
            } else {
                return Err(e);
            }
        }

        Ok(())
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
