use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use anyhow::Result;
use aya::maps::{HashMap, MapData};
use common::{DnsQuery, DnsRecordA, MAX_DNS_NAME_LENGTH};
use futures::TryStreamExt;
use k8s_openapi::api::core::v1::Service;
use kube::{
    runtime::{watcher, WatchStreamExt},
    Api, ResourceExt,
};
use tokio::{sync::RwLock, time::sleep};

pub struct Discovery {
    service_registry: Arc<RwLock<HashMap<MapData, DnsQuery, DnsRecordA>>>,
}

impl Discovery {
    pub fn new(service_registry: HashMap<MapData, DnsQuery, DnsRecordA>) -> Self {
        Self {
            service_registry: Arc::new(RwLock::new(service_registry)),
        }
    }

    pub async fn watch(&self) -> Result<()> {
        let client = loop {
            match kube::Client::try_default().await {
                Ok(client) => {
                    log::info!("Connected to the cluster");
                    break client;
                }
                Err(e) => {
                    log::error!("{}", e);
                    sleep(Duration::from_secs(5)).await;
                }
            }
        };

        let api: Api<Service> = Api::all(client);

        let stream = watcher(api, watcher::Config::default())
            .default_backoff()
            .try_for_each(|event| async move {
                match event {
                    watcher::Event::Apply(svc) | watcher::Event::InitApply(svc) => {
                        let name = svc.name_any();
                        let namespace = svc.namespace().unwrap_or_default();
                        let cluster_ip = svc.spec.unwrap().cluster_ip.unwrap_or_default();

                        let a_record = Self::create_a_record(&cluster_ip).unwrap();
                        let dns_query = Self::create_dns_query(&name, &namespace).unwrap();

                        let mut registry = self.service_registry.write().await;
                        registry.insert(dns_query, a_record, 0).unwrap();

                        log::info!("Apply {}.{}.svc: {}", name, namespace, cluster_ip);
                    }
                    watcher::Event::Delete(svc) => {
                        let name = svc.name_any();
                        let namespace = svc.namespace().unwrap_or_default();
                        let cluster_ip = svc.spec.unwrap().cluster_ip.unwrap_or_default();

                        let dns_query = Self::create_dns_query(&name, &namespace).unwrap();

                        let mut registry = self.service_registry.write().await;
                        registry.remove(&dns_query).unwrap();

                        log::info!("Delete {}.{}.svc: {}", name, namespace, cluster_ip);
                    }
                    _ => {}
                }

                Ok(())
            });

        tokio::select! {
            _ = stream => {}
        }

        Ok(())
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
}
