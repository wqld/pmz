use std::{
    fs::Permissions,
    os::{fd::OwnedFd, unix::fs::PermissionsExt},
    path::Path,
    sync::Arc,
};

use anyhow::Result;
use cni::{CniAddEvent, ServiceIndex};
use ctrl::InterceptRule;
use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use hyper::{
    body::{Buf, Bytes, Incoming},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use k8s_openapi::api::core::v1::{Pod, Service};
use kube::{Api, Client, ResourceExt, api::ListParams, runtime::reflector::Store};
use tokio::{
    fs::{File, create_dir_all, remove_file, set_permissions},
    net::UnixListener,
};
use tracing::{Instrument, debug, error, info, instrument};

use crate::{config::Config, intercept::setup_inpod_redirection, k8s};

pub struct CniServer {
    config: Config,
    service_index: ServiceIndex,
    service_store: Store<Service>,
}

impl CniServer {
    pub fn new(config: Config, service_index: ServiceIndex, service_store: Store<Service>) -> Self {
        Self {
            config,
            service_index,
            service_store,
        }
    }

    #[instrument(
        name = "server",
        skip_all,
        err,
        fields(socket_path = %self.config.cni_socket_path)
    )]
    pub async fn run(&self) -> Result<()> {
        let path = Path::new(&self.config.cni_socket_path);

        if path.exists() {
            remove_file(path).await?;
        }

        if let Some(parent) = path.parent() {
            create_dir_all(parent).await?;
        }

        let listener = UnixListener::bind(path)?;
        set_permissions(path, Permissions::from_mode(0o700)).await?;

        info!("CNI server listening");

        loop {
            let (stream, _) = listener.accept().await?;
            let service_index = self.service_index.clone();
            let service_store = self.service_store.clone();
            let intercept_gate_url = self.config.intercept_gate_addr.clone();

            tokio::spawn(
                async move {
                    if let Err(e) = http1::Builder::new()
                        .serve_connection(
                            TokioIo::new(stream),
                            service_fn(move |req| {
                                Self::handle_request(
                                    req,
                                    service_index.clone(),
                                    service_store.clone(),
                                    intercept_gate_url.clone(),
                                )
                            }),
                        )
                        .await
                    {
                        error!(error = ?e, "Error serving connection");
                    }
                }
                .in_current_span(),
            );
        }
    }

    #[instrument(
        skip_all,
        err,
        fields(
            pod_name = tracing::field::Empty,
            namespace = tracing::field::Empty
        )
    )]
    async fn handle_request(
        req: Request<Incoming>,
        svc_index: ServiceIndex,
        svc_store: Store<Service>,
        intercept_gate_addr: String,
    ) -> Result<Response<Full<Bytes>>> {
        let body = req.collect().await?.aggregate();
        let event: CniAddEvent = serde_json::from_reader(body.reader())?;

        tracing::Span::current()
            .record("pod.name", &event.pod_name.as_str())
            .record("pod.namespace", &event.pod_namespace.as_str());

        debug!("Received CNI ADD event");

        let pod_name = event.pod_name;
        let namespace = event.pod_namespace;

        let client = Client::try_default().await?;
        let pod_api: Api<Pod> = Api::namespaced(client.clone(), &namespace);

        let pod = pod_api.get(&pod_name).await?;
        let services = k8s::find_services_for_pod(&pod, svc_index, svc_store).await?;

        let ir_api: Api<InterceptRule> = Api::all(client.clone());
        let mut intercept_rules = vec![];

        debug!(
            services = services.len(),
            "Now searching for intercept rules"
        );

        for svc in services {
            let label_selector = format!(
                "pmz.sinabro.io/service-name={},pmz.sinabro.io/namespace={}",
                svc.name_any(),
                svc.namespace().unwrap_or("default".to_string())
            );
            let lp = ListParams::default().labels(&label_selector);

            if let Ok(obj_list) = ir_api.list(&lp).await {
                intercept_rules.extend(obj_list);
            }
        }

        if !intercept_rules.is_empty() {
            debug!(
                count = intercept_rules.len(),
                "Found matching intercept rules"
            );

            let self_netns_path = "/proc/self/ns/net";
            let current_netns = File::open(self_netns_path).await?;
            let current_netns: Arc<OwnedFd> = Arc::new(current_netns.into_std().await.into());

            for ip_config in event.ips {
                let addr_str = ip_config.address.split('/').next().unwrap_or_default();
                let pod_ip = addr_str.parse()?;
                let target_netns_path = format!("/host{}", event.netns);
                let target_netns = File::open(target_netns_path).await?;
                let target_netns_fd = target_netns.into_std().await.into();

                setup_inpod_redirection(
                    pod_ip,
                    &intercept_gate_addr,
                    current_netns.clone(),
                    Some(target_netns_fd),
                )
                .await?;
            }
        }

        Ok(Response::new(Full::from("handle requested")))
    }
}
