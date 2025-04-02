use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use anyhow::{Result, anyhow};
use bytes::Bytes;
use h2::{RecvStream, server::SendResponse};
use http::Request;
use log::{debug, error, info};
use proxy::{
    DialRequest, InterceptContext, InterceptRequest, InterceptRuleKey, InterceptValue,
    tunnel::stream::TunnelStream,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Mutex, mpsc},
};
use uuid::Uuid;

pub struct InterceptTunnel {
    port: u16,
    dial_map: Arc<Mutex<HashMap<Uuid, mpsc::Sender<DialRequest>>>>,
    intercept_rule_tx: Arc<Mutex<mpsc::Sender<(InterceptRuleKey, InterceptValue)>>>,
}

impl InterceptTunnel {
    pub fn new(
        port: u16,
        dial_map: Arc<Mutex<HashMap<Uuid, mpsc::Sender<DialRequest>>>>,
        intercept_rule_tx: mpsc::Sender<(InterceptRuleKey, InterceptValue)>,
    ) -> Self {
        Self {
            port,
            dial_map,
            intercept_rule_tx: Arc::new(Mutex::new(intercept_rule_tx)),
        }
    }

    pub async fn start(&self) -> Result<()> {
        let addr = SocketAddr::from(([0, 0, 0, 0], self.port));
        let listener = TcpListener::bind(addr).await?;
        info!("listening on {}", addr);

        let stream_map = Arc::new(Mutex::new(HashMap::new()));

        loop {
            if let Ok((stream, _)) = listener.accept().await {
                let req_rx = self.dial_map.clone();
                let intercept_rule_tx = self.intercept_rule_tx.clone();
                let stream_map = stream_map.clone();

                tokio::spawn(async move {
                    if let Err(e) = serve(stream, req_rx, intercept_rule_tx, stream_map).await {
                        error!("  -> err={:?}", e);
                    }
                });
            }
        }
    }
}

async fn serve(
    stream: TcpStream,
    dial_map: Arc<Mutex<HashMap<Uuid, mpsc::Sender<DialRequest>>>>,
    intercept_rule_tx: Arc<Mutex<mpsc::Sender<(InterceptRuleKey, InterceptValue)>>>,
    stream_map: Arc<Mutex<HashMap<InterceptRequest, TcpStream>>>,
) -> Result<()> {
    debug!("accepted");
    let mut connection = h2::server::handshake(stream).await?;
    debug!("h2 connection bound");

    while let Some(result) = connection.accept().await {
        let (resp, send) = result?;
        let dial_map = dial_map.clone();
        let intercept_rule_tx = intercept_rule_tx.clone();
        let stream_map = stream_map.clone();

        tokio::spawn(async move {
            if let Err(e) =
                handle_request(resp, send, dial_map, intercept_rule_tx, stream_map).await
            {
                error!("error while handling request: {}", e);
            }
        });
    }

    debug!("h2 connection closed");
    Ok(())
}

async fn handle_request(
    req: Request<RecvStream>,
    send: SendResponse<Bytes>,
    dial_map: Arc<Mutex<HashMap<Uuid, mpsc::Sender<DialRequest>>>>,
    intercept_rule_tx: Arc<Mutex<mpsc::Sender<(InterceptRuleKey, InterceptValue)>>>,
    stream_map: Arc<Mutex<HashMap<InterceptRequest, TcpStream>>>,
) -> Result<()> {
    debug!("got request: {:?}", req);

    match req.uri().path() {
        "/dial" => dial(req, send, dial_map, intercept_rule_tx, stream_map).await,
        "/intercept" => intercept(req, send, stream_map).await,
        _ => todo!(),
    }
}

async fn dial(
    req: Request<RecvStream>,
    mut send: SendResponse<Bytes>,
    dial_map: Arc<Mutex<HashMap<Uuid, mpsc::Sender<DialRequest>>>>,
    intercept_rule_tx: Arc<Mutex<mpsc::Sender<(InterceptRuleKey, InterceptValue)>>>,
    stream_map: Arc<Mutex<HashMap<InterceptRequest, TcpStream>>>,
) -> Result<()> {
    debug!("call dial");
    let mut body = req.into_body();

    // check the preface
    if let Some(preface) = body.data().await {
        match preface {
            Ok(p) if p == Bytes::from_static(b"dial-preface-from-agent") => {
                debug!("<<<< server dial {:?}", p);
            }
            Ok(_) => return Err(anyhow!("Preface mismatch")),
            Err(e) => return Err(e.into()),
        }
    }

    let response = http::Response::new(());
    let mut send = send.send_response(response, false).unwrap();

    // generate an uuid and store a channel for this seesion,
    // keyed by the generated uuid
    let uuid = Uuid::now_v7();
    let (dial_tx, mut dial_rx) = mpsc::channel::<DialRequest>(1);
    {
        dial_map.lock().await.insert(uuid, dial_tx);
        debug!("create uuid({uuid:?}) and insert it with dial_tx to dial_map");
    }
    // respond to the daemon with the generated uuid
    send.send_data(Bytes::copy_from_slice(&uuid.into_bytes()), false)?;
    debug!(">>>> server dial send uuid as bytes {uuid:?}");

    // TODO shutdown
    // let (_shutdown_tx, mut shutdown_rx) = broadcast::channel::<()>(1);

    // register an intercept rule
    tokio::spawn(async move {
        loop {
            if let Some(data) = body.data().await {
                let bytes = data.unwrap();
                let intercept_ctx: InterceptContext =
                    serde_json::from_slice(bytes.as_ref()).unwrap();
                debug!("receive an intercept rule from daemon: {intercept_ctx:?}");

                fn parse_rule_from_slice(
                    intercept_ctx: InterceptContext,
                ) -> Result<(InterceptRuleKey, InterceptValue)> {
                    let key = InterceptRuleKey {
                        service: intercept_ctx.service_name,
                        namespace: intercept_ctx.namespace,
                        port: intercept_ctx.port,
                    };

                    let value = InterceptValue {
                        id: Uuid::from_bytes(intercept_ctx.id),
                        target_port: intercept_ctx.target_port,
                    };

                    Ok((key, value))
                }

                let (key, value) = parse_rule_from_slice(intercept_ctx).unwrap();
                debug!("parsed rule key: {key:?}, value: {value:?}");
                intercept_rule_tx
                    .lock()
                    .await
                    .send((key, value))
                    .await
                    .unwrap();
            }
        }
    });

    // initiate dialing to daemon
    tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(DialRequest { id,  target_port, stream }) = dial_rx.recv() => {
                    debug!(">>>> server dial send {}: {}", id,  target_port);
                    let data = Bytes::copy_from_slice(&target_port.to_be_bytes());
                    send.send_data(data, false).unwrap();

                    let key = InterceptRequest {
                        id: id.into_bytes(),
                        target_port
                    };

                    stream_map.lock().await.insert(key, stream);
                }
                // _ = shutdown_rx.recv() => {
                //     debug!("shutdown write_handle");
                //     break;
                // }
            }
        }
    });

    Ok(())
}

async fn intercept(
    req: Request<RecvStream>,
    mut send: SendResponse<Bytes>,
    stream_map: Arc<Mutex<HashMap<InterceptRequest, TcpStream>>>,
) -> Result<()> {
    debug!("call intercept");
    let mut recv = req.into_body();

    if let Some(data) = recv.data().await {
        let bytes = data?;
        let intercept_req: InterceptRequest = serde_json::from_slice(&bytes.as_ref())?;
        debug!("<<<< intercept_req: {intercept_req:?}");
        let _ = recv.flow_control().release_capacity(bytes.len());

        let response = http::Response::new(());
        let send = send.send_response(response, false).unwrap();

        let mut downstream = TunnelStream { recv, send };
        let mut upstream = match stream_map.lock().await.remove(&intercept_req) {
            Some(stream) => stream,
            None => todo!(),
        };

        tokio::io::copy_bidirectional(&mut downstream, &mut upstream)
            .await
            .unwrap();
    }

    Ok(())
}
