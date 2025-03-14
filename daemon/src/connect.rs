use std::{collections::HashMap, sync::Arc};

use tokio::sync::{RwLock, broadcast};

use crate::route::Route;

pub struct Connection {
    pub _route: Route,
    pub shutdown_tx: broadcast::Sender<()>,
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.shutdown_tx.send(()).unwrap();
    }
}

#[derive(Default)]
pub struct ConnectionManager {
    pub connections: HashMap<String, Connection>,
}

impl ConnectionManager {
    pub fn check_connection(&self, name: &str) -> bool {
        self.connections.contains_key(name)
    }
}

#[derive(Debug, Default)]
pub struct ConnectionStatus {
    pub proxy: Option<ConnectionCondition>,
    pub discovery: Option<ConnectionCondition>,
    pub forward: Option<ConnectionCondition>,
}

impl ConnectionStatus {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn proxy(conn_stat: &Arc<RwLock<Self>>, status: bool, reason: &str) {
        let mut guard = conn_stat.write().await;
        guard.proxy = Some(ConnectionCondition::new(status, reason));
    }

    pub async fn discovery(conn_stat: &Arc<RwLock<Self>>, status: bool, reason: &str) {
        let mut guard = conn_stat.write().await;
        guard.discovery = Some(ConnectionCondition::new(status, reason));
    }

    pub async fn clear_discovery(conn_stat: &Arc<RwLock<Self>>) {
        let mut guard = conn_stat.write().await;
        guard.discovery = None;
    }

    pub async fn forward(conn_stat: &Arc<RwLock<Self>>, status: bool, reason: &str) {
        let mut guard = conn_stat.write().await;
        guard.forward = Some(ConnectionCondition::new(status, reason));
    }

    pub async fn clear_forward(conn_stat: &Arc<RwLock<Self>>) {
        let mut guard = conn_stat.write().await;
        guard.forward = None;
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct ConnectionCondition {
    status: bool,
    reason: String,
}

impl ConnectionCondition {
    pub fn new(status: bool, reason: &str) -> Self {
        Self {
            status,
            reason: reason.to_owned(),
        }
    }
}
