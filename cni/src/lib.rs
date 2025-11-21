use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Display, Formatter},
    net::IpAddr,
    sync::Arc,
};

use kube::ResourceExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::{RwLock, broadcast};

pub type InterceptRuleCache = HashMap<String, (Vec<IpAddr>, broadcast::Sender<()>)>;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Interface {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socket_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pci_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IpConfig {
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Route {
    pub dst: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gw: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adv_mss: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Dns {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nameservers: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CniResult {
    pub cni_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interfaces: Option<Vec<Interface>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ips: Option<Vec<IpConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routes: Option<Vec<Route>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<Dns>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CniConfig {
    pub cni_version: String,
    pub name: String,
    #[serde(rename = "type")]
    pub plugin_type: String,
    #[serde(rename = "prevResult")]
    pub raw_prev_result: Option<Value>,
    #[serde(skip)]
    pub prev_result: Option<CniResult>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CniAddEvent {
    pub netns: String,
    pub pod_name: String,
    pub pod_namespace: String,
    pub ips: Vec<IpConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NamespacedName {
    pub name: String,
    pub namespace: String,
}

impl From<&k8s_openapi::api::core::v1::Service> for NamespacedName {
    fn from(svc: &k8s_openapi::api::core::v1::Service) -> Self {
        Self {
            name: svc.name_any(),
            namespace: svc.namespace().unwrap_or_default(),
        }
    }
}

impl Display for NamespacedName {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.namespace, self.name)
    }
}

pub type ServiceIndex = Arc<RwLock<HashMap<String, HashSet<NamespacedName>>>>;
