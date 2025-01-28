use anyhow::{bail, Result};
use k8s_openapi::api::{
    apps::v1::Deployment,
    core::v1::{Pod, Secret},
};
use kube::{
    api::{DeleteParams, ListParams, Patch, PatchParams},
    Api, Client, Resource, ResourceExt,
};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use serde_json::json;

static TLS_SECRET_NAME: &str = "pmz-tls";
static AGENT_APP_NAME: &str = "pmz-agent";

pub struct Deploy<'a> {
    client: kube::Client,
    namespace: &'a str,
}

impl<'a> Deploy<'a> {
    pub fn new(client: Client, namespace: &'a str) -> Self {
        Self { client, namespace }
    }

    pub async fn get_pod_info_by_label(client: Client, label: &str) -> Result<(String, String)> {
        let pods: Api<Pod> = Api::all(client);

        let lp = ListParams::default().labels(label);
        match pods.list(&lp).await?.iter().last() {
            Some(p) => Ok((
                p.name_any(),
                p.meta().namespace.clone().unwrap_or("default".to_owned()),
            )),
            None => bail!("failed to get resource"),
        }
    }

    pub async fn deploy_tls_secret(&self) -> Result<()> {
        let (crt, key) = Self::generate_self_signed()?;

        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), self.namespace);

        let tls_secret: Secret = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": TLS_SECRET_NAME,
                "namespace": self.namespace
            },
            "type": "kubernetes.io/tls",
            "stringData": {
                "tls.crt": &crt,
                "tls.key": &key
            },
        }))?;

        let ss_apply = PatchParams::apply("pmz");
        secrets
            .patch(TLS_SECRET_NAME, &ss_apply, &Patch::Apply(tls_secret))
            .await?;

        Ok(())
    }

    pub async fn deploy_agent(&self) -> Result<()> {
        let deployments: Api<Deployment> = Api::namespaced(self.client.clone(), self.namespace);

        let ss_apply = PatchParams::apply("pmz");
        let pmz_agent: Deployment = serde_json::from_value(json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": AGENT_APP_NAME,
                "namespace": self.namespace,
                "labels": {
                    "app": AGENT_APP_NAME
                }
            },
            "spec": {
                "replicas": 1,
                "selector": {
                    "matchLabels": {
                        "app": AGENT_APP_NAME
                    }
                },
                "template": {
                    "metadata": {
                        "labels": {
                            "app": AGENT_APP_NAME
                        }
                    },
                    "spec": {
                        "containers": [{
                            "name": AGENT_APP_NAME,
                            "image": "ghcr.io/wqld/pmz-agent:0.0.1",
                            "ports": [{ "containerPort": 8100 }],
                            "volumeMounts": [
                                {
                                    "name": TLS_SECRET_NAME,
                                    "readOnly": true,
                                    "mountPath": "/certs/pmz.crt",
                                    "subPath": "tls.crt"
                                },
                                {
                                    "name": TLS_SECRET_NAME,
                                    "readOnly": true,
                                    "mountPath": "/certs/pmz.key",
                                    "subPath": "tls.key"
                                }
                            ]
                        }],
                        "volumes": [{
                            "name": TLS_SECRET_NAME,
                            "secret": {
                                "secretName": "pmz-tls"
                            }
                        }]
                    }
                }
            }
        }))?;

        deployments
            .patch(AGENT_APP_NAME, &ss_apply, &Patch::Apply(pmz_agent))
            .await?;

        Ok(())
    }

    pub async fn clean_resources(&self) -> Result<()> {
        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), self.namespace);
        let deployments: Api<Deployment> = Api::namespaced(self.client.clone(), self.namespace);

        secrets
            .delete(TLS_SECRET_NAME, &DeleteParams::default())
            .await?;

        deployments
            .delete(AGENT_APP_NAME, &DeleteParams::default())
            .await?;

        Ok(())
    }

    fn generate_self_signed() -> Result<(String, String)> {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".to_string()])?;

        Ok((cert.pem(), key_pair.serialize_pem()))
    }
}
