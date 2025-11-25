use std::{collections::HashSet, net::IpAddr, os::fd::OwnedFd, sync::Arc};

use anyhow::{Context, Result, anyhow};
use cni::InterceptRuleCache;
use ctrl::InterceptRule;
use futures::StreamExt;
use k8s_openapi::{
    api::core::v1::{Pod, Service},
    apimachinery::pkg::util::intstr::IntOrString,
};
use kube::{
    Api, ResourceExt,
    api::ListParams,
    runtime::{WatchStreamExt, watcher},
};
use tokio::{fs::File, sync::RwLock};
use tracing::{debug, error, info, instrument};

use crate::{
    config::Config,
    intercept::{setup_inpod_redirection, stop_inpod_redirection},
};

const SELF_NETNS_PATH: &str = "/proc/self/ns/net";

pub struct Discovery {
    config: Config,
    client: kube::Client,
    intercept_rule_cache: Arc<RwLock<InterceptRuleCache>>,
}

impl Discovery {
    pub fn new(
        config: Config,
        client: kube::Client,
        intercept_rule_cache: Arc<RwLock<InterceptRuleCache>>,
    ) -> Self {
        Self {
            config,
            client,
            intercept_rule_cache,
        }
    }

    #[instrument(
            name = "discovery", skip_all, err,
            fields(host_ip = %self.config.host_ip)
        )]
    pub async fn run(&self) -> Result<()> {
        let intercept_rules = Api::<InterceptRule>::all(self.client.clone());
        let current_netns = File::open(SELF_NETNS_PATH).await?;
        let current_netns: Arc<OwnedFd> = Arc::new(current_netns.into_std().await.into());

        let mut stream = watcher::watcher(intercept_rules, Default::default())
            .default_backoff()
            .boxed();

        loop {
            if let Some(next) = stream.next().await {
                match next {
                    Ok(event) => match event {
                        watcher::Event::Apply(rule) | watcher::Event::InitApply(rule) => {
                            let namespace = rule.namespace().unwrap_or_default();
                            let rule_name = rule.name_any();
                            let service_name = rule.spec.r#match.service;
                            let service_port = rule.spec.r#match.port;
                            let rule_id = format!("{}/{}", namespace, rule_name);

                            debug!(
                                ?namespace,
                                ?rule_name,
                                ?service_name,
                                ?service_port,
                                "InterceptRule applied"
                            );

                            let services =
                                Api::<Service>::namespaced(self.client.clone(), &namespace);
                            if let Some(service) = services.get_opt(&service_name).await? {
                                debug!(?namespace, ?rule_name, ?service_name, "Service found");

                                let target_port = match service
                                    .spec
                                    .as_ref()
                                    .and_then(|spec| spec.ports.as_ref())
                                    .and_then(|ports| {
                                        ports.iter().find(|&p| p.port == service_port as i32)
                                    })
                                    .and_then(|port| port.target_port.clone())
                                {
                                    Some(p) => p,
                                    None => continue,
                                };

                                debug!(
                                    ?namespace,
                                    ?rule_name,
                                    ?service_name,
                                    ?service_port,
                                    ?target_port,
                                    "TartgetPort found"
                                );

                                let intercept_endpoints = resolve_intercept_endpoints(
                                    self.client.clone(),
                                    &namespace,
                                    &service,
                                    &target_port,
                                    &self.config.host_ip,
                                )
                                .await?;

                                debug!(?intercept_endpoints, "Endpoints found");

                                let new_ip_set: HashSet<IpAddr> = intercept_endpoints
                                    .iter()
                                    .map(|(ip, _, _)| ip.clone())
                                    .collect();

                                let mut cache = self.intercept_rule_cache.write().await;
                                let old_ip_set = cache.get(&rule_id).cloned().unwrap_or_default();

                                debug!(
                                    ?rule_id,
                                    old_count = old_ip_set.len(),
                                    new_count = new_ip_set.len(),
                                    "Reconciling redirection rules"
                                );

                                for ip_to_remove in old_ip_set.difference(&new_ip_set) {
                                    debug!(?ip_to_remove, "Stopping stale redirection");
                                    if let Err(e) =
                                        stop_inpod_redirection(*ip_to_remove, current_netns.clone())
                                            .await
                                    {
                                        error!(?e, ?ip_to_remove, "Failed to stop redirection");
                                    }
                                }

                                for (ip, _port, _protoo) in intercept_endpoints {
                                    if !old_ip_set.contains(&ip) {
                                        info!(?ip, "Setting up new redirection");
                                        if let Err(e) = setup_inpod_redirection(
                                            ip,
                                            &self.config.intercept_gate_addr,
                                            current_netns.clone(),
                                            None,
                                        )
                                        .await
                                        {
                                            error!(?e, ?ip, "Failed to setup redirection");
                                        }
                                    } else {
                                        debug!(?ip, "Redirection already active, skipping");
                                    }
                                }

                                cache.insert(rule_id, new_ip_set);
                            }
                        }
                        watcher::Event::Delete(rule) => {
                            let rule_id = format!(
                                "{}/{}",
                                rule.namespace().unwrap_or_default(),
                                rule.name_any()
                            );

                            let mut cache = self.intercept_rule_cache.write().await;
                            if let Some(old_ips) = cache.remove(&rule_id) {
                                info!(
                                    ?rule_id,
                                    count = old_ips.len(),
                                    "Rule deleted, cleaning up all redirections"
                                );
                                for ip in old_ips {
                                    if let Err(e) =
                                        stop_inpod_redirection(ip, current_netns.clone()).await
                                    {
                                        error!(?e, ?ip, "Failed to stop redirection on delete");
                                    }
                                }
                            }
                        }
                        _ => {}
                    },
                    Err(e) => error!(?e, "Watcher error"),
                }
            }
        }
    }
}

async fn resolve_intercept_endpoints(
    client: kube::Client,
    namespace: &str,
    svc: &Service,
    target_port: &IntOrString,
    host_ip: &str,
) -> Result<Vec<(IpAddr, i32, String)>> {
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
    let pods = Api::<Pod>::namespaced(client.clone(), &namespace);
    let list_params = ListParams::default().labels(&label_selector);
    let target_pods = pods.list(&list_params).await.with_context(|| {
        format!(
            "Failed to list pods with selector '{}' for service '{}/{}'",
            label_selector,
            namespace,
            svc.name_any(),
        )
    })?;

    let endpoints = target_pods
        .iter()
        .filter(|pod| {
            pod.status
                .as_ref()
                .and_then(|s| s.host_ip.as_ref())
                .map(|i| i == host_ip)
                .unwrap_or(false)
        })
        .filter_map(|pod| {
            let status = pod.status.as_ref()?;
            let pod_ip_str = status.pod_ip.as_ref()?;
            let pod_ip: IpAddr = pod_ip_str.parse().ok()?;
            let (port_num, protocol) = find_port_info(pod, target_port)?;

            Some((pod_ip, port_num, protocol))
        })
        .collect();

    // if endpoints.is_empty() {}

    Ok(endpoints)
}

fn find_port_info(pod: &Pod, target_port: &IntOrString) -> Option<(i32, String)> {
    pod.spec
        .as_ref()?
        .containers
        .iter()
        .flat_map(|c| c.ports.iter().flatten())
        .find(|p| match target_port {
            IntOrString::Int(num) => p.container_port == *num,
            IntOrString::String(name) => p.name.as_deref() == Some(name),
        })
        .map(|p| (p.container_port, p.protocol.clone().unwrap_or_default()))
}
