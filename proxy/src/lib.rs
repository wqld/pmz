use std::{
    collections::HashMap,
    ops::{Deref, DerefMut},
};

use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use uuid::Uuid;

pub mod tunnel;

#[derive(Debug, Serialize, Deserialize)]
pub struct InterceptContext {
    pub id: uuid::Bytes,
    pub service_name: String,
    pub namespace: String,
    pub port: u16,
    pub target_port: u16,
}

pub struct DialRequest {
    pub id: Uuid,
    pub target_port: u16,
    pub stream: TcpStream,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct InterceptRequest {
    pub id: uuid::Bytes,
    pub target_port: u16,
}

#[derive(Default)]
pub struct InterceptRuleMap(HashMap<InterceptRuleKey, InterceptValue>);

impl Deref for InterceptRuleMap {
    type Target = HashMap<InterceptRuleKey, InterceptValue>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for InterceptRuleMap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[derive(Default)]
pub struct InterceptRouteMap(HashMap<InterceptRouteKey, InterceptValue>);

impl Deref for InterceptRouteMap {
    type Target = HashMap<InterceptRouteKey, InterceptValue>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for InterceptRouteMap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[derive(Debug, Default, PartialEq, Eq, Hash)]
pub struct InterceptRuleKey {
    pub service: String,
    pub namespace: String,
    pub port: u16,
}

#[derive(Debug, Default, PartialEq, Eq, Hash)]
pub struct InterceptRouteKey {
    pub ip: u32,
    pub port: u16,
}

#[derive(Debug, Default)]
pub struct InterceptValue {
    pub id: Uuid,
    pub target_port: u16,
}
