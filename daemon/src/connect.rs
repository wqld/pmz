use std::collections::HashMap;

use tokio::sync::broadcast;

use crate::route::Route;

pub struct Connection {
    pub route: Route,
    pub shutdown_tx: broadcast::Sender<()>,
}

#[derive(Default)]
pub struct ConnectionManager {
    pub connections: HashMap<String, Connection>,
}
