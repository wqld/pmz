use std::{net::Ipv4Addr, sync::Arc};

use anyhow::Result;
use aya::maps::{HashMap, MapData};
use common::{DnsQuery, DnsRecordA, MAX_DNS_NAME_LENGTH};
use futures::StreamExt;
use k8s_openapi::api::core::v1::Service;
use kube::{
    Api, ResourceExt,
    runtime::{
        WatchStreamExt,
        watcher::{self, Event, watcher},
    },
};
use tokio::sync::{RwLock, broadcast};
use tracing::{debug, error, info, instrument};

use crate::connect::ConnectionStatus;

pub struct Discovery {
    service_registry: Arc<RwLock<HashMap<MapData, DnsQuery, DnsRecordA>>>,
}

impl Discovery {
    pub fn new(service_registry: Arc<RwLock<HashMap<MapData, DnsQuery, DnsRecordA>>>) -> Self {
        Self { service_registry }
    }

    #[instrument(name = "discovery", skip_all)]
    pub async fn watch(
        &self,
        client: kube::Client,
        mut shutdown: broadcast::Receiver<()>,
        connection_status: Arc<RwLock<ConnectionStatus>>,
    ) -> Result<()> {
        let api: Api<Service> = Api::all(client);

        let mut stream = watcher(api, watcher::Config::default())
            .default_backoff()
            .boxed();

        ConnectionStatus::discovery(&connection_status, true, "Up").await;

        loop {
            tokio::select! {
                Some(next) = stream.next() => {
                    match next {
                        Ok(event) => self.handle_service_event(event).await?,
                        Err(e) => error!(error = ?e, "failed to get next event"),
                    }
                },
                _ = shutdown.recv() => {
                    debug!("discovery shutdown");
                    self.clean_registry().await?;
                    ConnectionStatus::clear_discovery(&connection_status).await;
                    return Ok(())
                }
            }
        }
    }

    #[instrument(name = "handle", skip_all)]
    async fn handle_service_event(&self, event: Event<Service>) -> Result<()> {
        match event {
            watcher::Event::Apply(svc) | watcher::Event::InitApply(svc) => {
                let name = svc.name_any();
                let namespace = svc.namespace().unwrap_or_default();
                let cluster_ip = svc.spec.unwrap().cluster_ip.unwrap_or_default();

                let a_record = match Self::create_a_record(&cluster_ip) {
                    Ok(record) => record,
                    Err(_) => return Ok(()),
                };
                let dns_query = Self::create_dns_query(&name, &namespace);

                let mut registry = self.service_registry.write().await;
                registry.insert(dns_query, a_record, 0).unwrap();

                info!("Apply {}.{}.svc: {}", name, namespace, cluster_ip);
            }
            watcher::Event::Delete(svc) => {
                let name = svc.name_any();
                let namespace = svc.namespace().unwrap_or_default();
                let cluster_ip = svc.spec.unwrap().cluster_ip.unwrap_or_default();

                let dns_query = Self::create_dns_query(&name, &namespace);

                let mut registry = self.service_registry.write().await;
                registry.remove(&dns_query).unwrap();

                info!("Delete {}.{}.svc: {}", name, namespace, cluster_ip);
            }
            _ => {}
        }

        Ok(())
    }

    fn create_a_record(cluster_ip: &str) -> Result<DnsRecordA> {
        let ipv4: Ipv4Addr = cluster_ip.parse()?;

        Ok(DnsRecordA {
            ip: u32::from(ipv4),
            ttl: 30,
        })
    }

    pub fn create_dns_query(name: &str, namespace: &str) -> DnsQuery {
        let mut dns_name = [0u8; MAX_DNS_NAME_LENGTH];
        let combined = format!("{}.{}.svc", name, namespace);
        let bytes = combined.as_bytes();
        let len = bytes.len().min(256);

        dns_name[..len].copy_from_slice(&bytes[..len]);

        DnsQuery {
            record_type: 1,
            class: 1,
            name: dns_name,
        }
    }

    async fn clean_registry(&self) -> Result<()> {
        let registry = self.service_registry.read().await;
        let dns_queries: Vec<Option<DnsQuery>> =
            registry.keys().map(|map_key| map_key.ok()).collect();

        drop(registry);

        let mut registry = self.service_registry.write().await;

        for dns_query_opt in dns_queries {
            if let Some(dns_query) = dns_query_opt {
                registry.remove(&dns_query)?;
            }
        }

        Ok(())
    }
}
