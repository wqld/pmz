use k8s_openapi::chrono::{DateTime, Utc};
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(thiserror::Error, Debug)]
pub enum Error {}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq, Eq, Hash)]
#[kube(
    kind = "InterceptRule",
    group = "pmz.sinabro.io",
    version = "v1alpha1",
    shortname = "irs",
    namespaced
)]
#[kube(status = "InterceptRuleStatus")]
pub struct InterceptRuleSpec {
    pub service: String,
    pub port: u16,
    #[serde(rename = "localPort")]
    pub local_port: u16,
    pub id: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct InterceptRuleStatus {
    pub last_updated: Option<DateTime<Utc>>,
}
