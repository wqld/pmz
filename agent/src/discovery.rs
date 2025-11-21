use std::{collections::HashMap, pin::Pin, sync::Arc};

use futures::StreamExt;
use proto::{
    AddIntercept, DiscoveryRequest, DiscoveryResponse, SnapshotSent,
    discovery_request::Payload as ReqPayload, discovery_response::Payload as RespPayload,
    intercept_discovery_server::InterceptDiscovery,
};
use tokio::sync::{RwLock, mpsc};
use tokio_stream::{Stream, wrappers::ReceiverStream};
use tonic::{Request, Response, Status, Streaming};
use tracing::{debug, error, info, warn};

use crate::DiscovertTx;

type InterceptResult<T> = Result<Response<T>, Status>;
type ResponseStream = Pin<Box<dyn Stream<Item = Result<DiscoveryResponse, Status>> + Send>>;

#[tonic::async_trait]
trait AckStreamExt {
    async fn wait_ack(&mut self, node_ip: &str) -> Result<(), ()>;
}

#[tonic::async_trait]
impl<T> AckStreamExt for T
where
    T: Stream<Item = Result<DiscoveryRequest, Status>> + Unpin + Send,
{
    async fn wait_ack(&mut self, node_ip: &str) -> Result<(), ()> {
        match self.next().await {
            Some(Ok(DiscoveryRequest {
                payload: Some(ReqPayload::Ack(ack)),
            })) => {
                if !ack.error.is_empty() {
                    error!("Client {node_ip} reported error within Ack: {}", ack.error);
                    Err(())
                } else {
                    Ok(())
                }
            }
            _ => {
                error!("Client {node_ip} disconnected waiting for Ack");
                Err(())
            }
        }
    }
}

pub struct DiscoveryServer {
    pub subscribers: Arc<RwLock<HashMap<String, DiscovertTx>>>,
    pub intercept_cache: Arc<RwLock<HashMap<String, HashMap<String, AddIntercept>>>>,
}

impl DiscoveryServer {
    pub fn new(
        subscribers: Arc<RwLock<HashMap<String, DiscovertTx>>>,
        intercept_cache: Arc<RwLock<HashMap<String, HashMap<String, AddIntercept>>>>,
    ) -> Self {
        Self {
            subscribers,
            intercept_cache,
        }
    }
}

#[tonic::async_trait]
impl InterceptDiscovery for DiscoveryServer {
    type InterceptsStream = ResponseStream;

    async fn intercepts(
        &self,
        req: Request<Streaming<DiscoveryRequest>>,
    ) -> InterceptResult<Self::InterceptsStream> {
        let (tx, rx) = mpsc::channel(10);
        let out_stream = Box::pin(ReceiverStream::new(rx));

        let cache_clone = self.intercept_cache.clone();
        let subs_clone = self.subscribers.clone();

        tokio::spawn(async move {
            let mut in_stream = req.into_inner();

            let hello = match in_stream.next().await {
                Some(Ok(DiscoveryRequest {
                    payload: Some(ReqPayload::Hello(hello)),
                })) => hello,
                _ => {
                    error!("Client failed to send Hello as first message.");
                    return;
                }
            };

            let node_ip = hello.node_ip;

            debug!("Subscription is requested from {node_ip}");

            let target_rules = {
                let cache = cache_clone.read().await;
                cache
                    .get(&node_ip)
                    .map_or_else(Vec::new, |b| b.values().cloned().collect())
            };

            for add_msg in target_rules {
                let payload = RespPayload::Add(add_msg);
                let resp = DiscoveryResponse {
                    payload: Some(payload),
                };

                tx.send(Ok(resp)).await.unwrap();
                in_stream.wait_ack(&node_ip).await.unwrap();
            }

            let revision = "1".to_owned(); // TODO
            let snapshot = SnapshotSent { revision };
            let payload = RespPayload::SnapshotSent(snapshot);
            let resp = DiscoveryResponse {
                payload: Some(payload),
            };

            tx.send(Ok(resp)).await.unwrap();
            in_stream.wait_ack(&node_ip).await.unwrap();
            debug!("Snapshot sent and Acked by {node_ip}");

            {
                let mut subs = subs_clone.write().await;
                subs.insert(node_ip.clone(), tx);
                info!("Subscription for {node_ip} is completed (live updates enabled)");
            }

            while let Some(req) = in_stream.next().await {
                match req {
                    Ok(DiscoveryRequest {
                        payload: Some(ReqPayload::Ack(ack)),
                    }) => {
                        error!(
                            "Client {node_ip} reported NACK (live update failure) for rule [{}]: {}",
                            ack.uid, ack.error
                        );

                        // TODO
                    }
                    Ok(DiscoveryRequest {
                        payload: Some(ReqPayload::Hello(_)),
                    }) => {
                        error!("Client {node_ip} sent unexpected Hello after snapshot");
                        break;
                    }
                    Ok(DiscoveryRequest { payload: None }) => {
                        warn!("Client {node_ip} sent empty payload");
                    }
                    Err(e) => {
                        info!("Client {node_ip} request stream error: {}", e);
                        break;
                    }
                }
            }

            info!("Client {node_ip} disconnected. Removing subscriber.");
            let mut subs = subs_clone.write().await;
            subs.remove(&node_ip);
        });

        Ok(Response::new(out_stream))
    }
}
