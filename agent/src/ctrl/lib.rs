use std::collections::BTreeMap;

use k8s_openapi::chrono::{DateTime, Utc};
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(thiserror::Error, Debug)]
pub enum Error {}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(CustomResource, JsonSchema, Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
#[kube(
    group = "pmz.sinabro.io",
    version = "v1alpha1",
    kind = "InterceptRule",
    shortname = "irs",
    namespaced
)]
#[kube(status = "InterceptRuleStatus")]
#[serde(rename_all = "camelCase")]
pub struct InterceptRuleSpec {
    pub r#match: Match,
    pub forward_to: ForwardTo,
}

#[derive(JsonSchema, Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Match {
    pub service: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<Vec<HttpMatchRule>>,
}

#[derive(JsonSchema, Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct ForwardTo {
    pub id: String,
    pub port: u16,
}

#[derive(JsonSchema, Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct HttpMatchRule {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<BTreeMap<String, StringMatch>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<StringMatch>,
}

#[derive(JsonSchema, Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct StringMatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
}

#[derive(Deserialize, JsonSchema, Serialize, Debug, Clone)]
pub struct InterceptRuleStatus {
    pub last_updated: Option<DateTime<Utc>>,
}
