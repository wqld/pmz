use anyhow::Context;
use ctrl::{Error, InterceptRule, InterceptRuleStatus, Result};

use futures::StreamExt;
use k8s_openapi::{
    api::core::v1::Service, apimachinery::pkg::apis::meta::v1::OwnerReference, chrono::Utc,
};
use kube::{
    Api, Client, Resource, ResourceExt,
    api::{Patch, PatchParams},
    runtime::{
        controller::{Action, Controller},
        watcher,
    },
};
use proxy::InterceptRuleMap;
use serde_json::json;
use std::{sync::Arc, time::Duration};
use tokio::sync::RwLock;
use tracing::{debug, error, info};

#[derive(Clone)]
struct State {
    client: Client,
    intercept_rule_map: Arc<RwLock<InterceptRuleMap>>,
}

pub async fn run(intercept_rule_map: Arc<RwLock<InterceptRuleMap>>) -> Result<(), kube::Error> {
    let client = Client::try_default().await?;
    let intercept_rules = Api::<InterceptRule>::all(client.clone());

    let state = State {
        client: client.clone(),
        intercept_rule_map,
        // subscribers,
        // intercept_cache,
    };

    Controller::new(intercept_rules, watcher::Config::default())
        .run(reconcile, error_policy, Arc::new(state))
        .for_each(|_| futures::future::ready(()))
        .await;

    debug!("started");

    Ok(())
}

async fn reconcile(rule: Arc<InterceptRule>, ctx: Arc<State>) -> Result<Action> {
    // TODO logic to handle events that delete interceptRule must also be added.
    // TODO notify the CNI pod so that inpod traffic redirection can be cleared.
    let start_time = std::time::Instant::now();

    let namespace = rule.namespace().unwrap_or("default".to_owned());
    let rule_name = rule.name_any();
    info!("Reconcile request received for InterceptRule '{namespace}/{rule_name}'");

    let result = try_reconcile(rule.clone(), ctx.clone(), &namespace, &rule_name).await;

    let duration = start_time.elapsed();

    match result {
        Ok(action) => {
            info!(
                "Rule: {}/{}, Action: {:?}, Duration: {:?}, Reconciliation successful.",
                namespace, rule_name, action, duration
            );
            Ok(action)
        }
        Err(error) => {
            error!(
                "Rule: {}/{}, Error: {}, Duration: {:?}, Reconciliation failed.",
                namespace, rule_name, error, duration
            );

            Ok(Action::requeue(Duration::from_secs(30)))
        }
    }
}

// Core reconciliation logic extracted into a helper function.
// Performs the actual steps to reconcile the InterceptRule state.
async fn try_reconcile(
    rule: Arc<InterceptRule>,
    ctx: Arc<State>,
    namespace: &str,
    rule_name: &str,
) -> anyhow::Result<Action> {
    let rule_id = format!("{}/{}", namespace, rule_name);

    if rule.metadata.deletion_timestamp.is_some() {
        info!("Rule: {rule_id}, Deletion detected. Processing removal.");

        let labels = rule.labels();
        let service_namespace = labels.get("pmz.sinabro.io/namespace");
        let service_name = labels.get("pmz.sinabro.io/service-name");
        let port = rule.spec.r#match.port;

        // let rule_key = InterceptRuleKey {
        //     namespace: namespace.clone(),
        //     service: service_name.clone(),
        //     port,
        // };

        // let mut affected_nodes = Vec::new();
        // {
        //     let mut cache = ctx.intercept_cache.write().await;
        //     for (node_ip, rules) in cache.iter_mut() {
        //         if rules.remove(&rule_id).is_some() {
        //             affected_nodes.push(node_ip.clone());
        //         }
        //     }
        // }

        // let remove_msg = DiscoveryResponse {
        //     payload: Some(RespPayload::Remove(RemoveIntercept {
        //         uid: rule_id.clone(),
        //     })),
        // };

        // let subs = ctx.subscribers.read().await;
        // for node_ip in affected_nodes {
        //     if let Some(tx) = subs.get(&node_ip) {
        //         if tx.send(Ok(remove_msg.clone())).await.is_err() {
        //             debug!(
        //                 "Subscriber {node_ip} disconnected before remove update (already handled by server)"
        //             );
        //         }
        //     }
        // }

        let finalizer_name = "pmz.sinabro.io";
        info!("Rule: {rule_id}, Removing finalizer '{finalizer_name}'.");
        let rules_api: Api<InterceptRule> = Api::namespaced(ctx.client.clone(), namespace);

        let new_finalizers: Vec<String> = rule
            .metadata
            .finalizers
            .as_ref()
            .map_or_else(Vec::new, |v| {
                v.iter().filter(|&s| s != finalizer_name).cloned().collect()
            });

        let patch = json!({
            "metadata": {
                "finalizers": new_finalizers
            }
        });

        rules_api
            .patch(rule_name, &PatchParams::default(), &Patch::Merge(&patch))
            .await?;

        return Ok(Action::await_change());
    }

    // let services = Api::<Service>::namespaced(ctx.client.clone(), namespace);

    // let service_name = &rule.spec.r#match.service;
    // let requested_port = rule.spec.r#match.port;

    // debug!(
    //     "Rule: {}/{}, Service: {}, Port: {}, Processing rule details",
    //     namespace, rule_name, service_name, requested_port
    // );

    // // Get the target Service
    // let service = services
    //     .get(service_name)
    //     .await
    //     .with_context(|| format!("Getting target Service '{}/{}'", namespace, service_name))?;

    // debug!(
    //     "Rule: {}/{}, Found target Service: {}",
    //     namespace, rule_name, service_name
    // );

    // //  Ensure OwnerReference exists (or add it)
    // let owner_ref =
    //     create_owner_reference(&service).context("Creating OwnerReference from Service")?;

    // let mut owner_refs = rule.metadata.owner_references.clone().unwrap_or_default();
    // let needs_update = !owner_refs.iter().any(|or| or.uid == owner_ref.uid);

    // if needs_update {
    //     info!("Rule: {}/{}, Adding OwnerReference", namespace, rule_name);

    //     update_owner_reference(&ctx, &mut owner_refs, owner_ref, namespace, rule_name).await?;
    //     update_status_last_updated(&ctx, namespace, rule_name).await?;
    // } else {
    //     debug!(
    //         "Rule: {}/{}, OwnerReference already exists",
    //         namespace, rule_name
    //     );
    // }

    // // Get the targetPort field
    // let target_port = service
    //     .spec
    //     .as_ref()
    //     .and_then(|spec| spec.ports.as_ref())
    //     .and_then(|ports| ports.iter().find(|&p| p.port == requested_port as i32))
    //     .and_then(|port| port.target_port.clone())
    //     .ok_or_else(|| {
    //         anyhow!(
    //             "Port {} in Service '{}/{}' is missing the 'targetPort' field.",
    //             requested_port,
    //             namespace,
    //             service_name
    //         )
    //     })?;

    // debug!(
    //     "Rule: {}/{}, Service Port: {}, Found targetPort: {:?}",
    //     namespace, rule_name, requested_port, target_port
    // );

    // // Resolve the intercept endpoint
    // let intercept_endpoint = resolve_intercept_endpoint(&ctx, namespace, &service, &target_port)
    //     .await
    //     .with_context(|| {
    //         format!(
    //             "Resolving intercept endpoint for Service '{}/{}' targetPort {:?}",
    //             namespace, service_name, target_port
    //         )
    //     })?;

    // debug!(
    //     "Rule: {}/{}, Resolved intercept endpoint: {:?}",
    //     namespace, rule_name, intercept_endpoint
    // );

    // let mut pods_by_node_ip: HashMap<String, Vec<PodIdentifier>> = HashMap::new();

    // for pod_identifier in intercept_endpoint.pod_ids.iter() {
    //     let key = pod_identifier.host_ip.clone();
    //     pods_by_node_ip
    //         .entry(key)
    //         .or_default()
    //         .push(pod_identifier.clone());
    // }

    // let subs = ctx.subscribers.read().await;
    // let mut cache = ctx.intercept_cache.write().await;

    // let mut nodes_sent = HashSet::new();

    // for (node_ip, pods_from_node) in pods_by_node_ip {
    //     let resource_for_subscriber = InterceptEndpoint {
    //         pod_ids: pods_from_node,
    //         namespace: intercept_endpoint.namespace.clone(),
    //         target_port: intercept_endpoint.target_port,
    //     };

    //     let add_msg = AddIntercept {
    //         uid: rule_id.clone(),
    //         endpoint: Some(resource_for_subscriber),
    //     };

    //     cache
    //         .entry(node_ip.clone())
    //         .or_default()
    //         .insert(rule_id.clone(), add_msg.clone());

    //     nodes_sent.insert(node_ip.clone());

    //     if let Some(subscriber_tx) = subs.get(&node_ip) {
    //         let resp = DiscoveryResponse {
    //             payload: Some(RespPayload::Add(add_msg)),
    //         };

    //         if subscriber_tx.send(Ok(resp.clone())).await.is_err() {
    //             debug!(
    //                 "Subscriber {node_ip} disconnected before add update (already handled by server)"
    //             );
    //         }
    //     } else {
    //         debug!("No active subscriber for {node_ip}. Update cached for next connection.");
    //     }
    // }

    // let mut nodes_to_remove = Vec::new();
    // for (node_ip, rules) in cache.iter_mut() {
    //     if !nodes_sent.contains(node_ip) && rules.remove(&rule_id).is_some() {
    //         nodes_to_remove.push(node_ip.clone());
    //     }
    // }

    // if !nodes_to_remove.is_empty() {
    //     let remove_msg = DiscoveryResponse {
    //         payload: Some(RespPayload::Remove(RemoveIntercept {
    //             uid: rule_id.clone(),
    //         })),
    //     };

    //     for node_ip in nodes_to_remove {
    //         debug!("Rule: {rule_id}, Removing from node {node_ip} (no longer matches).");
    //         if let Some(tx) = subs.get(&node_ip) {
    //             if tx.send(Ok(remove_msg.clone())).await.is_err() {
    //                 debug!(
    //                     "Subscriber {node_ip} disconnected before diff remove update (already handled by server)"
    //                 );
    //             }
    //         }
    //     }
    // }

    // debug!("Rule: {rule_id}, Reconciliation complete.");

    Ok(Action::requeue(Duration::from_secs(3600)))
}

fn create_owner_reference(svc: &Service) -> Result<OwnerReference> {
    Ok(OwnerReference {
        api_version: Service::api_version(&()).to_string(),
        kind: Service::kind(&()).to_string(),
        name: (&svc.metadata).name.clone().expect("name failed"),
        uid: (&svc.metadata).uid.clone().expect("uid failed"),
        controller: Some(true),
        block_owner_deletion: Some(false),
    })
}

async fn update_owner_reference(
    ctx: &Arc<State>,
    owner_refs: &mut Vec<OwnerReference>,
    owner_ref: OwnerReference,
    namespace: &str,
    rule_name: &str,
) -> anyhow::Result<()> {
    owner_refs.push(owner_ref);

    let patch = json!({
        "metadata": {
            "ownerReferences": owner_refs
        }
    });

    let rules = Api::<InterceptRule>::namespaced(ctx.client.clone(), namespace);

    rules
        .patch(rule_name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
        .with_context(|| {
            format!(
                "Failed to patch InterceptRule '{}/{}' to update OwnerReferences",
                namespace, rule_name
            )
        })?;

    info!(
        "Successfully updated OwnerReferences for InterceptRule '{}/{}'",
        namespace, rule_name
    );

    Ok(())
}

async fn update_status_last_updated(
    ctx: &Arc<State>,
    namespace: &str,
    rule_name: &str,
) -> anyhow::Result<()> {
    let now = Utc::now();

    let status_patch = json!({
        "status": InterceptRuleStatus {
            last_updated: Some(now),
        }
    });

    let rules_api = Api::<InterceptRule>::namespaced(ctx.client.clone(), namespace);

    rules_api
        .patch_status(
            rule_name,
            &PatchParams::default(),
            &Patch::Merge(&status_patch),
        )
        .await
        .with_context(|| {
            format!(
                "Failed to patch status for InterceptRule '{}/{}' to update last_updated",
                namespace, rule_name
            )
        })?;

    info!(
        "Successfully updated status.last_updated for InterceptRule '{}/{}'",
        namespace, rule_name
    );

    Ok(())
}

// async fn resolve_intercept_endpoint(
//     ctx: &Arc<State>,
//     namespace: &str,
//     svc: &Service,
//     target_port: &IntOrString,
// ) -> anyhow::Result<InterceptEndpoint> {
//     // Get the service selector from the service spec
//     let selector = svc
//         .spec
//         .as_ref()
//         .and_then(|s| s.selector.as_ref())
//         .ok_or_else(|| {
//             anyhow!(
//                 "Service '{}/{}' is missing spec or selector.",
//                 namespace,
//                 svc.name_any(),
//             )
//         })?;

//     // Create the label selector string from the selector map
//     // e.g., "app=myapp,tier=frontend"
//     let label_selector = selector
//         .iter()
//         .map(|(k, v)| format!("{}={}", k, v))
//         .collect::<Vec<_>>()
//         .join(",");

//     // Retrieve the list of Pods matching the label selector
//     let pods = Api::<Pod>::namespaced(ctx.client.clone(), &namespace);
//     let list_params = ListParams::default().labels(&label_selector);
//     let target_pods = pods.list(&list_params).await.with_context(|| {
//         format!(
//             "Failed to list pods with selector '{}' for service '{}/{}'",
//             label_selector,
//             namespace,
//             svc.name_any(),
//         )
//     })?;

//     // Resolve the target port (Int or String) to i32
//     let resolved_target_port = match target_port {
//         IntOrString::Int(tp) => Ok(*tp),
//         IntOrString::String(np) => match target_pods
//             .iter()
//             .find_map(|p| find_named_port_in_pod(p, np))
//         {
//             Some(p) => Ok(p),
//             None => Err(anyhow!(
//                 "Named port '{}' specified for service '{}/{}' was not found in any backing pods.",
//                 np,
//                 namespace,
//                 svc.name_any()
//             )),
//         },
//     }?;

//     // Create a list of valid PodIdentifiers,
//     // filtering for Pods that have both podIP and hostIP
//     let pod_ids: Vec<PodIdentifier> = target_pods
//         .iter()
//         .filter_map(|p| {
//             let pod_name = p.name_any();
//             let pod_status = p.status.as_ref();

//             let pod_ip = pod_status
//                 .and_then(|s| s.pod_ip.as_ref())
//                 .filter(|ip| !ip.is_empty());

//             let host_ip = pod_status.and_then(|s| s.host_ip.clone());

//             if let (Some(pod_ip), Some(host_ip)) = (pod_ip, host_ip) {
//                 Some(PodIdentifier {
//                     name: pod_name,
//                     ip: pod_ip.clone(),
//                     host_ip,
//                 })
//             } else {
//                 None
//             }
//         })
//         .collect();

//     // Return an error if no valid Pods were found
//     if pod_ids.is_empty() {
//         bail!(
//             "No valid pods found for service '{}' in namespace '{}' matching the selector and having both required IPs (podIP, hostIP).",
//             svc.name_any(),
//             namespace
//         );
//     }

//     Ok(InterceptEndpoint {
//         pod_ids,
//         namespace: namespace.to_owned(),
//         target_port: resolved_target_port,
//     })
// }

// fn find_named_port_in_pod(pod: &Pod, named_port: &str) -> Option<i32> {
//     pod.spec
//         .as_ref()
//         .map(|spec| &spec.containers)
//         .into_iter()
//         .flatten()
//         .flat_map(|container| container.ports.iter().flatten())
//         .find(|port| port.name.as_deref() == Some(named_port))
//         .map(|port| port.container_port)
// }

fn error_policy(object: Arc<InterceptRule>, err: &Error, _ctx: Arc<State>) -> Action {
    error!("{err:?} occured with {object:?}");
    Action::requeue(Duration::from_secs(5))
}
