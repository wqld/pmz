use anyhow::{Context, anyhow, bail};
use ctrl::{Error, InterceptRule, InterceptRuleStatus, Result};

use futures::StreamExt;
use k8s_openapi::{
    api::core::v1::{Pod, Service},
    apimachinery::pkg::{apis::meta::v1::OwnerReference, util::intstr::IntOrString},
    chrono::Utc,
};
use kube::{
    Api, Client, Resource, ResourceExt,
    api::{ListParams, Patch, PatchParams},
    runtime::{
        controller::{Action, Controller},
        watcher,
    },
};
use log::{debug, error, info, warn};
use proto::{InterceptEndpoint, PodIdentifier};
use serde_json::json;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::RwLock;

use crate::DiscovertTx;

#[derive(Clone)]
struct State {
    client: Client,
    subscribers: Arc<RwLock<HashMap<String, DiscovertTx>>>,
}

pub async fn run(
    subscribers: Arc<RwLock<HashMap<String, DiscovertTx>>>,
) -> Result<(), kube::Error> {
    let client = Client::try_default().await?;
    let intercept_rules = Api::<InterceptRule>::all(client.clone());

    let state = State {
        client: client.clone(),
        subscribers,
    };

    Controller::new(intercept_rules, watcher::Config::default())
        .run(reconcile, error_policy, Arc::new(state))
        .for_each(|_| futures::future::ready(()))
        .await;

    debug!("started");

    Ok(())
}

async fn reconcile(rule: Arc<InterceptRule>, ctx: Arc<State>) -> Result<Action> {
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
    let services = Api::<Service>::namespaced(ctx.client.clone(), namespace);

    let service_name = &rule.spec.service;
    let requested_port = rule.spec.port;

    debug!(
        "Rule: {}/{}, Service: {}, Port: {}, Processing rule details",
        namespace, rule_name, service_name, requested_port
    );

    // Get the target Service
    let service = services
        .get(service_name)
        .await
        .with_context(|| format!("Getting target Service '{}/{}'", namespace, service_name))?;

    debug!(
        "Rule: {}/{}, Found target Service: {}",
        namespace, rule_name, service_name
    );

    //  Ensure OwnerReference exists (or add it)
    let owner_ref =
        create_owner_reference(&service).context("Creating OwnerReference from Service")?;

    let mut owner_refs = rule.metadata.owner_references.clone().unwrap_or_default();
    let needs_update = !owner_refs.iter().any(|or| or.uid == owner_ref.uid);

    if needs_update {
        info!("Rule: {}/{}, Adding OwnerReference", namespace, rule_name);

        update_owner_reference(&ctx, &mut owner_refs, owner_ref, namespace, rule_name).await?;
        update_status_last_updated(&ctx, namespace, rule_name).await?;
    } else {
        debug!(
            "Rule: {}/{}, OwnerReference already exists",
            namespace, rule_name
        );
    }

    // Get the targetPort field
    let target_port = service
        .spec
        .as_ref()
        .and_then(|spec| spec.ports.as_ref())
        .and_then(|ports| ports.iter().find(|&p| p.port == requested_port as i32))
        .and_then(|port| port.target_port.clone())
        .ok_or_else(|| {
            anyhow!(
                "Port {} in Service '{}/{}' is missing the 'targetPort' field.",
                requested_port,
                namespace,
                service_name
            )
        })?;

    debug!(
        "Rule: {}/{}, Service Port: {}, Found targetPort: {:?}",
        namespace, rule_name, requested_port, target_port
    );

    // Resolve the intercept endpoint
    let intercept_endpoint = resolve_intercept_endpoint(&ctx, namespace, &service, &target_port)
        .await
        .with_context(|| {
            format!(
                "Resolving intercept endpoint for Service '{}/{}' targetPort {:?}",
                namespace, service_name, target_port
            )
        })?;

    debug!(
        "Rule: {}/{}, Resolved intercept endpoint: {:?}",
        namespace, rule_name, intercept_endpoint
    );

    process_and_notify(&ctx, &intercept_endpoint).await
}

async fn process_and_notify(
    ctx: &Arc<State>,
    intercept_endpoint: &proto::InterceptEndpoint,
) -> anyhow::Result<Action> {
    let mut pods_by_host_ip: HashMap<String, Vec<PodIdentifier>> = HashMap::new();

    for pod_identifier in intercept_endpoint.pod_ids.iter() {
        let key = pod_identifier.host_ip.clone();
        pods_by_host_ip
            .entry(key)
            .or_default()
            .push(pod_identifier.clone());
    }

    let subs = ctx.subscribers.read().await;
    let mut any_subscriber_missing = false;

    for (host_ip_key, pods_for_this_host) in pods_by_host_ip {
        if let Some(subscriber_tx) = subs.get(&host_ip_key) {
            let resource_for_subscriber = proto::InterceptEndpoint {
                pod_ids: pods_for_this_host,
                namespace: intercept_endpoint.namespace.clone(),
                target_port: intercept_endpoint.target_port,
            };

            let resp = proto::DiscoveryResponse {
                version_info: "v1.0-alpha".to_string(),
                resources: vec![resource_for_subscriber],
            };

            debug!(
                "Sending update to subscriber at {}: {:?}",
                host_ip_key, resp
            );

            if let Err(e) = subscriber_tx.send(Ok(resp.clone())).await {
                error!(
                    "Failed to send message to subscriber {}: {}",
                    host_ip_key, e
                );
            }
        } else {
            warn!(
                "No active subscriber found for host IP: {}. Update not delivered.",
                host_ip_key
            );
            any_subscriber_missing = true;
        }
    }

    if any_subscriber_missing {
        debug!("One or more subscribers were missing for this endpoint, requesting short requeue.");
        Ok(Action::requeue(Duration::from_secs(5)))
    } else {
        debug!("All found subscribers notified (or send attempted). Requesting long requeue.");
        Ok(Action::requeue(Duration::from_secs(3600)))
    }
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

async fn resolve_intercept_endpoint(
    ctx: &Arc<State>,
    namespace: &str,
    svc: &Service,
    target_port: &IntOrString,
) -> anyhow::Result<InterceptEndpoint> {
    // Get the service selector from the service spec
    let selector = svc
        .spec
        .as_ref()
        .and_then(|s| s.selector.as_ref())
        .ok_or_else(|| {
            anyhow!(
                "Service '{}/{}' is missing spec or selector.",
                namespace,
                svc.name_any(),
            )
        })?;

    // Create the label selector string from the selector map
    // e.g., "app=myapp,tier=frontend"
    let label_selector = selector
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join(",");

    // Retrieve the list of Pods matching the label selector
    let pods = Api::<Pod>::namespaced(ctx.client.clone(), &namespace);
    let list_params = ListParams::default().labels(&label_selector);
    let target_pods = pods.list(&list_params).await.with_context(|| {
        format!(
            "Failed to list pods with selector '{}' for service '{}/{}'",
            label_selector,
            namespace,
            svc.name_any(),
        )
    })?;

    // Resolve the target port (Int or String) to i32
    let resolved_target_port = match target_port {
        IntOrString::Int(tp) => Ok(*tp),
        IntOrString::String(np) => match target_pods
            .iter()
            .find_map(|p| find_named_port_in_pod(p, np))
        {
            Some(p) => Ok(p),
            None => Err(anyhow!(
                "Named port '{}' specified for service '{}/{}' was not found in any backing pods.",
                np,
                namespace,
                svc.name_any()
            )),
        },
    }?;

    // Create a list of valid PodIdentifiers,
    // filtering for Pods that have both podIP and hostIP
    let pod_ids: Vec<PodIdentifier> = target_pods
        .iter()
        .filter_map(|p| {
            let pod_name = p.name_any();
            let pod_status = p.status.as_ref();

            let pod_ip = pod_status
                .and_then(|s| s.pod_ip.as_ref())
                .filter(|ip| !ip.is_empty());

            let host_ip = pod_status.and_then(|s| s.host_ip.clone());

            if let (Some(pod_ip), Some(host_ip)) = (pod_ip, host_ip) {
                Some(PodIdentifier {
                    name: pod_name,
                    ip: pod_ip.clone(),
                    host_ip,
                })
            } else {
                None
            }
        })
        .collect();

    // Return an error if no valid Pods were found
    if pod_ids.is_empty() {
        bail!(
            "No valid pods found for service '{}' in namespace '{}' matching the selector and having both required IPs (podIP, hostIP).",
            svc.name_any(),
            namespace
        );
    }

    Ok(InterceptEndpoint {
        pod_ids,
        namespace: namespace.to_owned(),
        target_port: resolved_target_port,
    })
}

fn find_named_port_in_pod(pod: &Pod, named_port: &str) -> Option<i32> {
    pod.spec
        .as_ref()
        .map(|spec| &spec.containers)
        .into_iter()
        .flatten()
        .flat_map(|container| container.ports.iter().flatten())
        .find(|port| port.name.as_deref() == Some(named_port))
        .map(|port| port.container_port)
}

fn error_policy(object: Arc<InterceptRule>, err: &Error, _ctx: Arc<State>) -> Action {
    error!("{err:?} occured with {object:?}");
    Action::requeue(Duration::from_secs(5))
}
