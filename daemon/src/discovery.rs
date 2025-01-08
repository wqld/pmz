use std::{net::Ipv4Addr, sync::Arc};

use anyhow::Result;
use aya::maps::{HashMap, MapData};
use common::{DnsQuery, DnsRecordA, MAX_DNS_NAME_LENGTH};
use futures::StreamExt;
use k8s_openapi::api::core::v1::Service;
use kube::{
    runtime::{
        watcher::{self, watcher, Event},
        WatchStreamExt,
    },
    Api, ResourceExt,
};
use log::{debug, error, info};
use tokio::sync::{broadcast, RwLock};

pub struct Discovery {
    service_registry: Arc<RwLock<HashMap<MapData, DnsQuery, DnsRecordA>>>,
}

impl Discovery {
    pub fn new(service_registry: Arc<RwLock<HashMap<MapData, DnsQuery, DnsRecordA>>>) -> Self {
        Self { service_registry }
    }

    pub async fn watch(
        &self,
        client: kube::Client,
        mut shutdown: broadcast::Receiver<()>,
    ) -> Result<()> {
        let api: Api<Service> = Api::all(client);

        let mut stream = watcher(api, watcher::Config::default())
            .default_backoff()
            .boxed();

        loop {
            tokio::select! {
                Some(next) = stream.next() => {
                    match next {
                        Ok(event) => self.handle_service_event(event).await,
                        Err(err) => error!("failed to get next event {err:?}"),
                    }
                },
                _ = shutdown.recv() => {
                    debug!("discovery shutdown");
                    self.clean_registry().await?;
                    return Ok(())
                }
            }
        }
    }

    async fn handle_service_event(&self, event: Event<Service>) {
        match event {
            watcher::Event::Apply(svc) | watcher::Event::InitApply(svc) => {
                let name = svc.name_any();
                let namespace = svc.namespace().unwrap_or_default();
                let cluster_ip = svc.spec.unwrap().cluster_ip.unwrap_or_default();

                let a_record = Self::create_a_record(&cluster_ip).unwrap();
                let dns_query = Self::create_dns_query(&name, &namespace).unwrap();

                let mut registry = self.service_registry.write().await;
                registry.insert(dns_query, a_record, 0).unwrap();

                info!("Apply {}.{}.svc: {}", name, namespace, cluster_ip);
            }
            watcher::Event::Delete(svc) => {
                let name = svc.name_any();
                let namespace = svc.namespace().unwrap_or_default();
                let cluster_ip = svc.spec.unwrap().cluster_ip.unwrap_or_default();

                let dns_query = Self::create_dns_query(&name, &namespace).unwrap();

                let mut registry = self.service_registry.write().await;
                registry.remove(&dns_query).unwrap();

                info!("Delete {}.{}.svc: {}", name, namespace, cluster_ip);
            }
            _ => {}
        }
    }

    fn create_a_record(cluster_ip: &str) -> Result<DnsRecordA> {
        let ipv4: Ipv4Addr = cluster_ip.parse().unwrap();

        Ok(DnsRecordA {
            ip: u32::from(ipv4),
            ttl: 30,
        })
    }

    fn create_dns_query(name: &str, namespace: &str) -> Result<DnsQuery> {
        let mut dns_name = [0u8; MAX_DNS_NAME_LENGTH];
        let combined = format!("{}.{}.svc", name, namespace);
        let bytes = combined.as_bytes();
        let len = bytes.len().min(256);

        dns_name[..len].copy_from_slice(&bytes[..len]);

        Ok(DnsQuery {
            record_type: 1,
            class: 1,
            name: dns_name,
        })
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
