use ctrl::{Error, InterceptRule, Result};

use futures::StreamExt;
use k8s_openapi::{
    api::core::v1::{Pod, Service},
    apimachinery::pkg::{apis::meta::v1::OwnerReference, util::intstr::IntOrString},
};
use kube::{
    Api, Client, Resource, ResourceExt,
    api::{ListParams, Patch, PatchParams},
    runtime::controller::{Action, Controller},
};
use log::{debug, error, info, warn};
use serde_json::json;
use std::{sync::Arc, time::Duration};

#[derive(Clone)]
struct State {
    client: Client,
}

#[derive(Default, Debug)]
pub struct ServiceEndpoint {
    pub pod_ips: Vec<String>,
    pub target_port: Option<i32>,
}

#[tokio::main]
async fn main() -> Result<(), kube::Error> {
    env_logger::init();

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap();

    let client = Client::try_default().await?;
    let intercept_rules = Api::<InterceptRule>::all(client.clone());

    let state = State {
        client: client.clone(),
    };

    Controller::new(intercept_rules, Default::default())
        // TODO .watches(endpoint_slices, Default::default(), mapper)
        .run(reconcile, error_policy, Arc::new(state))
        .for_each(|_| futures::future::ready(()))
        .await;

    debug!("started");

    Ok(())
}

async fn reconcile(obj: Arc<InterceptRule>, ctx: Arc<State>) -> Result<Action> {
    let start_time = std::time::Instant::now();

    let namespace = obj.namespace().unwrap_or("default".to_owned());
    let rule_name = obj.name_any();
    info!("Reconcile request received for InterceptRule '{namespace}/{rule_name}'");

    let services = Api::<Service>::namespaced(ctx.client.clone(), &namespace);

    let service_name = &obj.spec.service;
    let port = &obj.spec.port;

    debug!(
        "Processing InterceptRule details for '{namespace}/{rule_name}': Service='{service_name}', Port='{port}'"
    );

    match services.get(&service_name).await {
        Ok(service) => {
            debug!("Target Service '{service_name}' for InterceptRule '{namespace}/{rule_name}'");

            let owner_ref = create_owner_reference(&service)?;
            debug!(
                "Created OwnerReference for InterceptRule '{namespace}/{rule_name}': {owner_ref:?}"
            );

            let mut owner_refs = obj.metadata.owner_references.clone().unwrap_or_default();
            let needs_update = !owner_refs.iter().any(|or| or.uid == owner_ref.uid);

            if needs_update {
                if let Err(_) =
                    update_owner_reference(&ctx, &mut owner_refs, owner_ref, &namespace, &rule_name)
                        .await
                {
                    return Ok(Action::requeue(Duration::from_secs(15)));
                }
            } else {
                debug!(
                    "OwnerReference already exists for InterceptRule '{namespace}/{rule_name}', no update needed"
                );
            }

            let target_port = service
                .spec
                .as_ref()
                .and_then(|spec| spec.ports.as_ref())
                .and_then(|ports| ports.iter().find(|&p| p.port == *port as i32))
                .and_then(|port| port.target_port.clone());

            let service_endpoint = match target_port {
                Some(target_port) => {
                    debug!("Found targetPort: {target_port:?} for Service port {port}");

                    resolve_service_endpoint(&ctx, &namespace, &service, &target_port).await
                }
                None => {
                    warn!(
                        "Could not find targetPort mapping for Service port {port} in Service '{service_name}'"
                    );
                    Ok(ServiceEndpoint::default())
                }
            };

            // TODO send endpoints to cni
            debug!("service endpoint: {service_endpoint:?}");
        }
        Err(e) => {
            error!(
                "Failed to get target Service '{service_name}' for InterceptRule '{namespace}/{rule_name}': {e:?}"
            );
            return Ok(Action::requeue(Duration::from_secs(30)));
        }
    }

    let reconcile_duration = start_time.elapsed();
    info!("Reconciliation finished. {namespace}/{rule_name}, duration={reconcile_duration:?}");
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

    match rules
        .patch(rule_name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
    {
        Ok(_) => {
            info!("Added OwnerReference to InterceptRule '{namespace}/{rule_name}'");
            Ok(())
        }
        Err(e) => {
            error!(
                "Failed to patch InterceptRule '{namespace}/{rule_name}' to add OwnerReference: {e:?}"
            );
            Err(e.into())
        }
    }
}

async fn resolve_service_endpoint(
    ctx: &Arc<State>,
    ns: &str,
    svc: &Service,
    target_port: &IntOrString,
) -> Result<ServiceEndpoint> {
    if let Some(selector) = svc.spec.as_ref().and_then(|spec| spec.selector.as_ref()) {
        let label_selector = selector
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(",");
        let pods = Api::<Pod>::namespaced(ctx.client.clone(), &ns);
        let list_params = ListParams::default().labels(&label_selector);

        match pods.list(&list_params).await {
            Ok(pod_list) => {
                let target_port = match target_port {
                    IntOrString::Int(tp) => Some(*tp),
                    IntOrString::String(np) => pod_list
                        .iter()
                        .find_map(|pod| find_named_port_in_pod(pod, &np)),
                };

                let pod_ips: Vec<String> = pod_list
                    .iter()
                    .filter_map(|pod| pod.status.as_ref())
                    .filter_map(|status| status.pod_ip.clone())
                    .collect();

                return Ok(ServiceEndpoint {
                    pod_ips,
                    target_port,
                });
            }
            _ => {}
        }
    }

    Ok(ServiceEndpoint::default())
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
