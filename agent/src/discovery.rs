use std::{collections::HashMap, pin::Pin, sync::Arc};

use proto::{DiscoveryRequest, DiscoveryResponse, intercept_discovery_server::InterceptDiscovery};
use tokio::sync::{RwLock, mpsc};
use tokio_stream::{Stream, wrappers::ReceiverStream};
use tonic::{Request, Response, Status};
use tracing::{debug, info};

use crate::DiscovertTx;

type InterceptResult<T> = Result<Response<T>, Status>;
type ResponseStream = Pin<Box<dyn Stream<Item = Result<DiscoveryResponse, Status>> + Send>>;

pub struct DiscoveryServer {
    pub subscribers: Arc<RwLock<HashMap<String, DiscovertTx>>>,
}

impl DiscoveryServer {
    pub fn new(subscribers: Arc<RwLock<HashMap<String, DiscovertTx>>>) -> Self {
        Self { subscribers }
    }
}

#[tonic::async_trait]
impl InterceptDiscovery for DiscoveryServer {
    type InterceptsStream = ResponseStream;

    async fn intercepts(
        &self,
        req: Request<DiscoveryRequest>,
    ) -> InterceptResult<Self::InterceptsStream> {
        let data = req.into_inner();
        let node_ip = data.node_ip;

        debug!("Subscription is requested from {node_ip}");

        let (tx, rx) = mpsc::channel(1);

        {
            let mut subs = self.subscribers.write().await;
            subs.insert(node_ip.clone(), tx.clone());
            info!("Subscription for {node_ip} is completed");
        }

        let subs_clone = self.subscribers.clone();
        let node_ip_clone = node_ip.clone();

        tokio::spawn(async move {
            tx.closed().await;

            let mut subs = subs_clone.write().await;
            subs.remove(&node_ip_clone);
        });

        let receiver_stream = Box::pin(ReceiverStream::new(rx));
        Ok(Response::new(receiver_stream))
    }
}
