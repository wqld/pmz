use std::collections::HashMap;

use tokio::sync::broadcast;

use crate::route::Route;

pub struct Connection {
    pub _route: Route,
    pub shutdown_tx: broadcast::Sender<()>,
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
