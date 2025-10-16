use std::{collections::BTreeMap, sync::Arc};

use anyhow::Result;
use cni::{NamespacedName, ServiceIndex};
use futures_util::StreamExt;
use k8s_openapi::api::core::v1::{Pod, Service};
use kube::{
    Api, Client, ResourceExt,
    runtime::{WatchStreamExt, reflector, watcher},
};
use log::{debug, warn};
use tokio::task::JoinHandle;

pub async fn setup_service_watcher(
    service_index: ServiceIndex,
) -> Result<(JoinHandle<()>, reflector::Store<Service>)> {
    let client = Client::try_default().await?;
    let service_api: Api<Service> = Api::all(client.clone());
    let (service_store, service_writer) = reflector::store();
    let mut service_reflector = reflector::reflector(
        service_writer,
        watcher(service_api, watcher::Config::default()),
    )
    .default_backoff()
    .boxed();

    let handle = tokio::spawn(async move {
        while let Some(Ok(event)) = service_reflector.next().await {
            if let Err(e) = handle_service_event(event, &service_index.clone()).await {
                warn!("Failed to handle service event: {:?}", e);
            }
        }
    });

    Ok((handle, service_store))
}

async fn handle_service_event(
    event: watcher::Event<Service>,
    service_index: &ServiceIndex,
) -> Result<()> {
    match event {
        watcher::Event::Apply(svc) | watcher::Event::InitApply(svc) => {
            let ns_name = NamespacedName {
                name: svc.name_any(),
                namespace: svc.namespace().unwrap_or_default(),
            };

            let mut index = service_index.write().await;

            // TODO: Consider removing old selectors if service is updated.
            // get the previous selector from the store(reader) and remove the previous index
            // let svc_ref = reflector::ObjectRef::from_obj(&svc);

            // svc_store_for_reflector.wait_until_ready().await.unwrap();
            // if let Some(old_svc) = svc_store_for_reflector.get(&svc_ref) {
            //     if let Some(selector) =
            //         old_svc.spec.as_ref().and_then(|s| s.selector.as_ref())
            //     {
            //         debug!("Previous selector: {selector:?}");
            //         for (k, v) in selector {
            //             let label_key = format!("{k}={v}");
            //             index.entry(label_key).or_default().remove(&namespace_name);
            //         }
            //     }
            // }

            if let Some(selector) = svc.spec.as_ref().and_then(|s| s.selector.as_ref()) {
                debug!(
                    "Indexing service {:?} with selector {:?}",
                    ns_name, selector
                );
                // let mut index = svc_index_for_reflector.write().await;
                for (k, v) in selector {
                    let label_key = format!("{k}={v}");
                    index.entry(label_key).or_default().insert(ns_name.clone());
                }
            }
        }
        watcher::Event::Delete(svc) => {
            // TODO: Implement deletion logic to clean up the index.
            debug!("Service deleted: {:?}", svc.name_any());
        }
        _ => {}
    }

    Ok(())
}

pub async fn find_services_for_pod(
    pod: &Pod,
    svc_index: ServiceIndex,
    svc_store: reflector::Store<Service>,
) -> Result<Vec<Arc<Service>>> {
    debug!("Try to find services for pod {}", pod.name_any());
    svc_store.wait_until_ready().await?;
    let pod_labels = pod.labels();
    let index = svc_index.read().await;

    // let candidate_ns_names: Vec<NamespacedName> = {
    //     debug!("Read lock for service index - a");
    //     let index = svc_index.read().await;
    //     debug!("Read lock for service index");

    //     pod_labels
    //         .iter()
    //         .map(|(k, v)| format!("{k}={v}"))
    //         .filter_map(|k| index.get(&k))
    //         .flatten()
    //         .cloned()
    //         .collect()
    // };

    // debug!(
    //     "Found {} candidate namespaced names.",
    //     candidate_ns_names.len()
    // );

    // Ok(candidate_ns_names
    //     .into_iter()
    //     .map(|nn| reflector::ObjectRef::<Service>::new(&nn.name).within(&nn.namespace))
    //     .filter_map(|obj_ref| svc_store.get(&obj_ref))
    //     .filter(|svc| selector_matches(svc, pod_labels))
    //     .collect::<Vec<_>>())

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
