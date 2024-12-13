use std::time::Duration;

use anyhow::Result;
use futures::TryStreamExt;
use k8s_openapi::api::core::v1::Service;
use kube::{
    runtime::{watcher, WatchStreamExt},
    Api, ResourceExt,
};
use tokio::time::sleep;

pub struct Discovery {}

impl Discovery {
    pub async fn watch() -> Result<()> {
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

                        log::info!("Apply {}.{}.svc: {}", name, namespace, cluster_ip);
                    }
                    watcher::Event::Delete(svc) => {
                        let name = svc.name_any();
                        let namespace = svc.namespace().unwrap_or_default();
                        let cluster_ip = svc.spec.unwrap().cluster_ip.unwrap_or_default();

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
}
