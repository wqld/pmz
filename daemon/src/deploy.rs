use anyhow::{Result, bail};
use k8s_openapi::api::{
    apps::v1::Deployment,
    core::v1::{Pod, Secret, Service, ServiceAccount},
    rbac::v1::{ClusterRole, ClusterRoleBinding, PolicyRule, RoleRef, Subject},
};
use kube::{
    Api, Client, Resource, ResourceExt,
    api::{DeleteParams, ListParams, ObjectMeta, Patch, PatchParams},
};
use rcgen::{CertifiedKey, generate_simple_self_signed};
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
        let res = pods.list(&lp).await?;
        match res.iter().last() {
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
                        "serviceAccountName": "pmz-agent",
                        "hostNetwork": true,
                        "containers": [{
                            "name": AGENT_APP_NAME,
                            "image": "ghcr.io/wqld/pmz-agent:0.1.0",
                            "ports": [{ "containerPort": 8100 }],
                            "env": [{
                                "name": "RUST_LOG",
                                "value": "debug"
                            }],
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
                            ],
                            "securityContext": {
                                "privileged": true
                            }
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

    pub async fn expose_agent(&self) -> Result<()> {
        let services: Api<Service> = Api::namespaced(self.client.clone(), self.namespace);
        let ss_apply = PatchParams::apply("pmz");
        let pmz_service: Service = serde_json::from_value(json!( {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": AGENT_APP_NAME,
                "namespace": self.namespace,
                "labels": {
                    "app": AGENT_APP_NAME
                }

            },
            "spec": {
                "selector": {
                    "app": AGENT_APP_NAME
                },
                "ports": [{
                    "protocol": "TCP",
                    "port": 8101
                }]
            }

        }))?;

        services
            .patch(AGENT_APP_NAME, &ss_apply, &Patch::Apply(pmz_service))
            .await?;

        Ok(())
    }

    pub async fn add_rback_to_agent(&self) -> Result<()> {
        let service_accounts: Api<ServiceAccount> =
            Api::namespaced(self.client.clone(), &self.namespace);
        let cluster_roles: Api<ClusterRole> = Api::all(self.client.clone());
        let clsuter_role_bindings: Api<ClusterRoleBinding> = Api::all(self.client.clone());
        let ss_apply = PatchParams::apply("pmz");

        let pmz_service_account = ServiceAccount {
            metadata: ObjectMeta {
                name: Some(AGENT_APP_NAME.to_owned()),
                ..Default::default()
            },
            ..Default::default()
        };

        let pmz_cluster_role = ClusterRole {
            aggregation_rule: None,
            metadata: ObjectMeta {
                name: Some(AGENT_APP_NAME.to_owned()),
                ..Default::default()
            },
            rules: Some({
                vec![PolicyRule {
                    api_groups: Some(vec!["".to_owned()]),
                    resources: Some(vec!["services".to_owned()]),
                    verbs: vec!["get".to_owned(), "watch".to_owned(), "list".to_owned()],
                    ..Default::default()
                }]
            }),
        };

        let pmz_cluster_role_binding = ClusterRoleBinding {
            metadata: ObjectMeta {
                name: Some(AGENT_APP_NAME.to_owned()),
                ..Default::default()
            },
            role_ref: RoleRef {
                api_group: "rbac.authorization.k8s.io".to_owned(),
                kind: "ClusterRole".to_owned(),
                name: AGENT_APP_NAME.to_owned(),
            },
            subjects: Some(vec![Subject {
                kind: "ServiceAccount".to_owned(),
                name: AGENT_APP_NAME.to_owned(),
                namespace: Some(self.namespace.to_owned()),
                ..Default::default()
            }]),
        };

        service_accounts
            .patch(
                AGENT_APP_NAME,
                &ss_apply,
                &Patch::Apply(pmz_service_account),
            )
            .await?;
        cluster_roles
            .patch(AGENT_APP_NAME, &ss_apply, &Patch::Apply(pmz_cluster_role))
            .await?;
        clsuter_role_bindings
            .patch(
                AGENT_APP_NAME,
                &ss_apply,
                &Patch::Apply(pmz_cluster_role_binding),
            )
            .await?;

        Ok(())
    }

    pub async fn clean_resources(&self) -> Result<()> {
        let deployments: Api<Deployment> = Api::namespaced(self.client.clone(), self.namespace);
        let services: Api<Service> = Api::namespaced(self.client.clone(), self.namespace);
        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), self.namespace);
        let clsuter_role_bindings: Api<ClusterRoleBinding> = Api::all(self.client.clone());
        let cluster_roles: Api<ClusterRole> = Api::all(self.client.clone());
        let service_accounts: Api<ServiceAccount> =
            Api::namespaced(self.client.clone(), &self.namespace);

        deployments
            .delete(AGENT_APP_NAME, &DeleteParams::default())
            .await?;
        services
            .delete(AGENT_APP_NAME, &DeleteParams::default())
            .await?;
        secrets
            .delete(TLS_SECRET_NAME, &DeleteParams::default())
            .await?;
        clsuter_role_bindings
            .delete(AGENT_APP_NAME, &DeleteParams::default())
            .await?;
        cluster_roles
            .delete(AGENT_APP_NAME, &DeleteParams::default())
            .await?;
        service_accounts
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
