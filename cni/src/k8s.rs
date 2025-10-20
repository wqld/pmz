use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use anyhow::Result;
use cni::{NamespacedName, ServiceIndex};
use futures_util::StreamExt;
use k8s_openapi::api::core::v1::{Pod, Service};
use kube::{
    Api, Client, ResourceExt,
    runtime::{
        WatchStreamExt,
        reflector::{self, ObjectRef, Store, store::Writer},
        watcher,
    },
};
use tokio::sync::RwLock;
use tracing::{debug, info, instrument, warn};

pub struct ServiceWatcher {
    client: Client,
    store: Store<Service>,
    writer: Writer<Service>,
    index: ServiceIndex,
}

impl ServiceWatcher {
    pub fn new(client: Client) -> Self {
        let index = Arc::new(RwLock::new(HashMap::new()));
        let (store, writer) = reflector::store();

        Self {
            client,
            store,
            writer,
            index,
        }
    }

    pub fn store(&self) -> reflector::Store<Service> {
        self.store.clone()
    }

    pub fn index(&self) -> ServiceIndex {
        self.index.clone()
    }

    #[instrument(name = "watcher", skip_all, err)]
    pub async fn run(self) -> Result<()> {
        let api: Api<Service> = Api::all(self.client);

        let mut reflector =
            reflector::reflector(self.writer, watcher(api, watcher::Config::default()))
                .default_backoff()
                .boxed();

        info!("Service reflector started.");

        while let Some(event) = reflector.next().await {
            match event {
                Ok(event) => Self::handle_event(event, &self.store, &self.index).await,
                Err(e) => warn!(error = ?e, "Watcher stream produced an error"),
            }
        }

        Ok(())
    }

    #[instrument(
        skip_all,
        fields(event_type = tracing::field::Empty)
    )]
    async fn handle_event(
        event: watcher::Event<Service>,
        store: &Store<Service>,
        index: &ServiceIndex,
    ) {
        let event_type = match &event {
            watcher::Event::Apply(_) => "Apply",
            watcher::Event::InitApply(_) => "InitApply",
            watcher::Event::Delete(_) => "Delete",
            watcher::Event::Init => "Init",
            watcher::Event::InitDone => "InitDone",
        };
        tracing::Span::current().record("event_type", &event_type);

        let mut index = index.write().await;

        match event {
            watcher::Event::Apply(svc) | watcher::Event::InitApply(svc) => {
                let ns_name = NamespacedName::from(&svc);
                let svc_ref = ObjectRef::from_obj(&svc);

                if let Some(old_svc) = store.get(&svc_ref) {
                    if let Some(selector) = old_svc.spec.as_ref().and_then(|s| s.selector.as_ref())
                    {
                        debug!(service = %ns_name, "Removing old indexes for updated service");
                        for (k, v) in selector {
                            let label_key = format!("{k}={v}");
                            if let Some(services) = index.get_mut(&label_key) {
                                services.remove(&ns_name);
                                if services.is_empty() {
                                    index.remove(&label_key);
                                }
                            }
                        }
                    }
                }

                if let Some(selector) = svc.spec.as_ref().and_then(|s| s.selector.as_ref()) {
                    debug!(service = %ns_name, ?selector, "Applying new indexes for service");
                    for (k, v) in selector {
                        let label_key = format!("{k}={v}");
                        index.entry(label_key).or_default().insert(ns_name.clone());
                    }
                }
            }
            watcher::Event::Delete(svc) => {
                let ns_name = NamespacedName::from(&svc);
                if let Some(selector) = svc.spec.as_ref().and_then(|s| s.selector.as_ref()) {
                    debug!(service = %ns_name, "Deleting indexes for service");
                    for (k, v) in selector {
                        let label_key = format!("{k}={v}");
                        if let Some(services) = index.get_mut(&label_key) {
                            services.remove(&ns_name);
                            if services.is_empty() {
                                index.remove(&label_key);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

#[instrument(
    skip_all,
    err,
    fields(
        pod_name = %pod.name_any()
    )
)]
pub async fn find_services_for_pod(
    pod: &Pod,
    svc_index: ServiceIndex,
    svc_store: Store<Service>,
) -> Result<Vec<Arc<Service>>> {
    svc_store.wait_until_ready().await?;
    let pod_labels = pod.labels();
    let index = svc_index.read().await;

    Ok(pod_labels
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .filter_map(|k| index.get(&k))
        .flatten()
        .map(|nn| reflector::ObjectRef::<Service>::new(&nn.name).within(&nn.namespace))
        .filter_map(|obj_ref| svc_store.get(&obj_ref))
        .filter(|svc| selector_matches(svc, pod_labels))
        .collect::<Vec<_>>())
}

fn selector_matches(service: &Arc<Service>, labels: &BTreeMap<String, String>) -> bool {
    if let Some(selector) = service.spec.as_ref().and_then(|s| s.selector.as_ref()) {
        selector
            .iter()
            .all(|(k, v)| labels.get(k).map_or(false, |lv| lv == v))
    } else {
        false
    }
}
