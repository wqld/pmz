use std::collections::BTreeMap;

use anyhow::{Result, bail};
use k8s_openapi::{
    api::{
        apps::v1::{DaemonSet, DaemonSetSpec, Deployment},
        core::v1::{
            Capabilities, Container, EnvVar, EnvVarSource, HostPathVolumeSource,
            ObjectFieldSelector, Pod, PodSpec, PodTemplateSpec, Secret, SecurityContext, Service,
            ServiceAccount, ServicePort, ServiceSpec, Toleration, Volume, VolumeMount,
        },
        rbac::v1::{ClusterRole, ClusterRoleBinding, PolicyRule, RoleRef, Subject},
    },
    apimachinery::pkg::apis::meta::v1::LabelSelector,
};
use kube::{
    Api, Client, Resource, ResourceExt,
    api::{DeleteParams, ListParams, ObjectMeta, Patch, PatchParams},
};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use serde_json::json;

static TLS_SECRET_NAME: &str = "pmz-tls";
static AGENT_APP_NAME: &str = "pmz-agent";
static CNI_APP_NAME: &str = "pmz-cni";

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

    pub async fn deploy_cni(&self) -> Result<()> {
        let daemon_sets: Api<DaemonSet> = Api::namespaced(self.client.clone(), &self.namespace);
        let ss_apply = PatchParams::apply("pmz");

        let pmz_cni: DaemonSet = DaemonSet {
            metadata: ObjectMeta {
                name: Some(CNI_APP_NAME.to_string()),
                namespace: Some(self.namespace.to_string()),
                ..Default::default()
            },
            spec: Some(DaemonSetSpec {
                selector: LabelSelector {
                    match_labels: Some(Self::build_label_map("name", CNI_APP_NAME)),
                    ..Default::default()
                },
                template: PodTemplateSpec {
                    metadata: Some(ObjectMeta {
                        labels: Some(Self::build_label_map("name", CNI_APP_NAME)),
                        ..Default::default()
                    }),
                    spec: Some(PodSpec {
                        service_account_name: Some(CNI_APP_NAME.to_string()),
                        host_network: Some(true),
                        dns_policy: Some("ClusterFirstWithHostNet".to_string()),
                        volumes: Some(vec![
                            Volume {
                                name: "cni-bin".to_string(),
                                host_path: Some(HostPathVolumeSource {
                                    path: "/opt/cni/bin".to_string(),
                                    type_: Some("DirectoryOrCreate".to_string()),
                                }),
                                ..Default::default()
                            },
                            Volume {
                                name: "cni-cfg".to_string(),
                                host_path: Some(HostPathVolumeSource {
                                    path: "/etc/cni/net.d".to_string(),
                                    type_: Some("DirectoryOrCreate".to_string()),
                                }),
                                ..Default::default()
                            },
                            Volume {
                                name: "pmz-dir".to_string(),
                                host_path: Some(HostPathVolumeSource {
                                    path: "/var/run/pmz".to_string(),
                                    type_: Some("DirectoryOrCreate".to_string()),
                                }),
                                ..Default::default()
                            },
                            Volume {
                                name: "host-proc".to_string(),
                                host_path: Some(HostPathVolumeSource {
                                    path: "/proc".to_string(),
                                    type_: Some("Directory".to_string())
                                }),
                                ..Default::default()
                            },
                            Volume {
                                name: "host-netns".to_string(),
                                host_path: Some(HostPathVolumeSource {
                                    path: "/var/run/netns".to_string(),
                                    type_: Some("DirectoryOrCreate".to_string())
                                }),
                                ..Default::default()
                            }
                        ]),
                        init_containers: Some(vec![Container {
                            name: "install-cni".to_string(),
                            image: Some("ghcr.io/wqld/pmz-cni:0.1.0".to_string()),
                            image_pull_policy: Some("IfNotPresent".to_string()),
                            command: Some(vec![
                                "sh".to_string(),
                                "-c".to_string(),
                                "chmod +x /app/pmz-cni-plugin && cp /app/pmz-cni-plugin /cni/pmz-cni".to_string(),
                            ]),
                            volume_mounts: Some(vec![
                                VolumeMount {
                                    name: "cni-bin".to_string(),
                                    mount_path: "/cni".to_string(),
                                    ..Default::default()
                                },
                                VolumeMount {
                                    name: "pmz-dir".to_string(),
                                    mount_path: "/var/run/pmz".to_string(),
                                    ..Default::default()
                                }
                            ]),
                            ..Default::default()
                        }]),
                        containers: vec![Container {
                            name: "pmz-cni".to_string(),
                            image: Some("ghcr.io/wqld/pmz-cni:0.1.0".to_string()),
                            image_pull_policy: Some("IfNotPresent".to_string()),
                            env: Some(vec![
                                EnvVar {
                                    name: "CNI_NAMESPACE".to_string(),
                                    value: None,
                                    value_from: Some(EnvVarSource {
                                        field_ref: Some(ObjectFieldSelector {
                                            api_version: None,
                                            field_path: "metadata.namespace".to_string()
                                        }),
                                        ..Default::default()
                                    }),
                                },
                                EnvVar {
                                    name: "HOST_IP".to_string(),
                                    value: None,
                                    value_from: Some(EnvVarSource {
                                        field_ref: Some(ObjectFieldSelector {
                                            api_version: None,
                                            field_path: "status.hostIP".to_string()
                                        }),
                                        ..Default::default()
                                    })
                                },
                                EnvVar {
                                    name: "RUST_LOG".to_string(),
                                    value: Some("debug".to_string()),
                                    ..Default::default()
                                }
                            ]),
                            volume_mounts: Some(vec![
                                VolumeMount {
                                    name: "cni-cfg".to_string(),
                                    mount_path: "/etc/cni/net.d".to_string(),
                                    ..Default::default()
                                },
                                VolumeMount {
                                    name: "pmz-dir".to_string(),
                                    mount_path: "/var/run/pmz".to_string(),
                                    ..Default::default()
                                },
                                VolumeMount {
                                    name: "host-proc".to_string(),
                                    mount_path: "/host/proc".to_string(),
                                    read_only: Some(true),
                                    ..Default::default()
                                },
                                VolumeMount {
                                    name: "host-netns".to_string(),
                                    mount_path: "/host/var/run/netns".to_string(),
                                    mount_propagation: Some("HostToContainer".to_string()),
                                    read_only: Some(true),
                                    ..Default::default()
                                }
                            ]),
                            security_context: Some(SecurityContext {
                                privileged: Some(true),
                                capabilities: Some(Capabilities {
                                    add: Some(vec!["NET_RAW".to_string(), "NET_ADMIN".to_string()]),
                                    drop: None,
                                }),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }],
                        tolerations: Some(vec![
                            Toleration {
                                effect: Some("NoSchedule".to_string()),
                                operator: Some("Exists".to_string()),
                                ..Default::default()
                            },
                            
                            Toleration {
                                effect: Some("NoExecute".to_string()),
                                operator: Some("Exists".to_string()),
                                ..Default::default()
                            },
                            Toleration {
                                key: Some("CriticalAddonsOnly".to_string()),
                                operator: Some("Exists".to_string()),
                                ..Default::default()
                            }
                        ]),
                        ..Default::default()
                    }),
                },
                ..Default::default()
            }),
            ..Default::default()
        };

        daemon_sets
            .patch(CNI_APP_NAME, &ss_apply, &Patch::Apply(pmz_cni))
            .await?;

        Ok(())
    }

    pub async fn deploy_agent(&self) -> Result<()> {
        let deployments: Api<Deployment> = Api::namespaced(self.client.clone(), &self.namespace);
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
        let pmz_service = Service {
            metadata: ObjectMeta {
                name: Some(AGENT_APP_NAME.to_string()),
                namespace: Some(self.namespace.to_string()),
                labels: Some(Self::build_label_map("app", AGENT_APP_NAME)),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                selector: Some(Self::build_label_map("app", AGENT_APP_NAME)),
                ports: Some(vec![
                    ServicePort {
                        name: Some("reverse".to_string()),
                        protocol: Some("TCP".to_string()),
                        port: 8101,
                        ..Default::default()
                    },
                    ServicePort {
                        name: Some("grpc".to_string()),
                        protocol: Some("TCP".to_string()),
                        port: 50018,
                        ..Default::default()
                    },
                ]),
                ..Default::default()
            }),
            ..Default::default()
        };

        services
            .patch(AGENT_APP_NAME, &ss_apply, &Patch::Apply(pmz_service))
            .await?;

        Ok(())
    }

    pub async fn add_rbac_to_agent(&self) -> Result<()> {
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
                vec![
                    PolicyRule {
                        api_groups: Some(vec!["".to_owned()]),
                        resources: Some(vec!["pods".to_owned(), "services".to_owned()]),
                        verbs: vec!["get".to_owned(), "watch".to_owned(), "list".to_owned()],
                        ..Default::default()
                    },
                    PolicyRule {
                        api_groups: Some(vec!["discovery.k8s.io".to_owned()]),
                        resources: Some(vec!["endpointslices".to_owned()]),
                        verbs: vec!["get".to_owned(), "watch".to_owned(), "list".to_owned()],
                        ..Default::default()
                    },
                    PolicyRule {
                        api_groups: Some(vec!["pmz.sinabro.io".to_owned()]),
                        resources: Some(vec!["interceptrules".to_owned()]),
                        verbs: vec![
                            "create".to_owned(),
                            "get".to_owned(),
                            "watch".to_owned(),
                            "list".to_owned(),
                            "patch".to_owned(),
                        ],
                        ..Default::default()
                    },
                    PolicyRule {
                        api_groups: Some(vec!["pmz.sinabro.io".to_owned()]),
                        resources: Some(vec!["interceptrules/status".to_owned()]),
                        verbs: vec!["get".to_owned(), "patch".to_owned()],
                        ..Default::default()
                    },
                    PolicyRule {
                        api_groups: Some(vec!["apiextensions.k8s.io".to_owned()]),
                        resources: Some(vec!["customresourcedefinitions".to_owned()]),
                        verbs: vec![
                            "get".to_owned(),
                            "watch".to_owned(),
                            "list".to_owned(),
                            "patch".to_owned(),
                        ],
                        ..Default::default()
                    },
                ]
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

    pub async fn add_rbac_to_cni(&self) -> Result<()> {
        let service_accounts: Api<ServiceAccount> =
            Api::namespaced(self.client.clone(), &self.namespace);
        let cluster_roles: Api<ClusterRole> = Api::all(self.client.clone());
        let clsuter_role_bindings: Api<ClusterRoleBinding> = Api::all(self.client.clone());
        let ss_apply = PatchParams::apply("pmz");

        let pmz_service_account = ServiceAccount {
            metadata: ObjectMeta {
                name: Some(CNI_APP_NAME.to_owned()),
                ..Default::default()
            },
            ..Default::default()
        };

        let pmz_cluster_role = ClusterRole {
            aggregation_rule: None,
            metadata: ObjectMeta {
                name: Some(CNI_APP_NAME.to_owned()),
                ..Default::default()
            },
            rules: Some({
                vec![
                    PolicyRule {
                        api_groups: Some(vec!["".to_owned()]),
                        resources: Some(vec!["pods".to_owned(), "services".to_owned()]),
                        verbs: vec!["get".to_owned(), "watch".to_owned(), "list".to_owned()],
                        ..Default::default()
                    },
                    PolicyRule {
                        api_groups: Some(vec!["pmz.sinabro.io".to_owned()]),
                        resources: Some(vec!["interceptrules".to_owned()]),
                        verbs: vec!["get".to_owned(), "watch".to_owned(), "list".to_owned()],
                        ..Default::default()
                    },
                    PolicyRule {
                        api_groups: Some(vec!["apiextensions.k8s.io".to_owned()]),
                        resources: Some(vec!["customresourcedefinitions".to_owned()]),
                        verbs: vec!["get".to_owned(), "watch".to_owned(), "list".to_owned(), "create".to_owned(), "patch".to_owned()],
                        ..Default::default()
                    }
                ]
            }),
        };

        let pmz_cluster_role_binding = ClusterRoleBinding {
            metadata: ObjectMeta {
                name: Some(CNI_APP_NAME.to_owned()),
                ..Default::default()
            },
            role_ref: RoleRef {
                api_group: "rbac.authorization.k8s.io".to_owned(),
                kind: "ClusterRole".to_owned(),
                name: CNI_APP_NAME.to_owned(),
            },
            subjects: Some(vec![Subject {
                kind: "ServiceAccount".to_owned(),
                name: CNI_APP_NAME.to_owned(),
                namespace: Some(self.namespace.to_owned()),
                ..Default::default()
            }]),
        };

        service_accounts
            .patch(CNI_APP_NAME, &ss_apply, &Patch::Apply(pmz_service_account))
            .await?;
        cluster_roles
            .patch(CNI_APP_NAME, &ss_apply, &Patch::Apply(pmz_cluster_role))
            .await?;
        clsuter_role_bindings
            .patch(
                CNI_APP_NAME,
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
        let daemon_sets: Api<DaemonSet> = Api::namespaced(self.client.clone(), &self.namespace);

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
        clsuter_role_bindings
            .delete(CNI_APP_NAME, &DeleteParams::default())
            .await?;
        cluster_roles
            .delete(CNI_APP_NAME, &DeleteParams::default())
            .await?;
        service_accounts
            .delete(CNI_APP_NAME, &DeleteParams::default())
            .await?;
        daemon_sets
            .delete(CNI_APP_NAME, &DeleteParams::default())
            .await?;

        Ok(())
    }

    fn generate_self_signed() -> Result<(String, String)> {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_string()])?;

        Ok((cert.pem(), signing_key.serialize_pem()))
    }

    fn build_label_map(key: &str, value: &str) -> BTreeMap<String, String> {
        [(key, value)]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }
}
