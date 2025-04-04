use k8s_openapi::chrono::{DateTime, Utc};
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(thiserror::Error, Debug)]
pub enum Error {}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    kind = "InterceptRule",
    group = "pmz.sinabro",
    version = "v1alpha1",
    shortname = "irs",
    namespaced
)]
#[kube(status = "InterceptRuleStatus")]
pub struct InterceptRuleSpec {
    pub service: String,
    pub port: u16,
    pub target_port: u16,
    pub id: uuid::Bytes,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct InterceptRuleStatus {
    last_updated: Option<DateTime<Utc>>,
}
