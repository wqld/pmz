use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use anyhow::{Result, anyhow};
use bytes::Bytes;
use h2::{RecvStream, SendStream, server::SendResponse};
use http::Request;
use proxy::{
    DialRequest, InterceptContext, InterceptRequest, InterceptRuleKey, InterceptValue,
    tunnel::stream::TunnelStream,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Mutex, mpsc},
};
use tracing::{Instrument, debug, error, info, info_span, instrument, warn};
use uuid::Uuid;

const DIAL_PREFACE: &[u8] = b"dial-preface-from-agent";

#[derive(Clone)]
struct AppState {
    dial_map: Arc<Mutex<HashMap<Uuid, mpsc::Sender<DialRequest>>>>,
    stream_map: Arc<Mutex<HashMap<InterceptRequest, TcpStream>>>,
    intercept_rule_tx: mpsc::Sender<(InterceptRuleKey, InterceptValue)>,
}

impl AppState {
    fn new(
        dial_map: Arc<Mutex<HashMap<Uuid, mpsc::Sender<DialRequest>>>>,
        intercept_rule_tx: mpsc::Sender<(InterceptRuleKey, InterceptValue)>,
    ) -> Self {
        Self {
            dial_map,
            stream_map: Arc::new(Mutex::new(HashMap::new())),
            intercept_rule_tx,
        }
    }
}

pub struct InterceptTunnel {
    port: u16,
    state: AppState,
    // dial_map: Arc<Mutex<HashMap<Uuid, mpsc::Sender<DialRequest>>>>,
    // intercept_rule_tx: Arc<Mutex<mpsc::Sender<(InterceptRuleKey, InterceptValue)>>>,
}

impl InterceptTunnel {
    pub fn new(
        port: u16,
        dial_map: Arc<Mutex<HashMap<Uuid, mpsc::Sender<DialRequest>>>>,
        intercept_rule_tx: mpsc::Sender<(InterceptRuleKey, InterceptValue)>,
    ) -> Self {
        Self {
            port,
            state: AppState::new(dial_map, intercept_rule_tx),
        }
    }

    #[instrument(name = "intercept_tunnel", skip_all, fields(port = self.port))]
    pub async fn start(&self) -> Result<()> {
        let addr = SocketAddr::from(([0, 0, 0, 0], self.port));
        let listener = TcpListener::bind(addr).await?;
        info!("Listening on {}", addr);

        // let stream_map = Arc::new(Mutex::new(HashMap::new()));

        loop {
            if let Ok((stream, peer_addr)) = listener.accept().await {
                let state = self.state.clone();

                // let req_rx = self.dial_map.clone();
                // let intercept_rule_tx = self.intercept_rule_tx.clone();
                // let stream_map = stream_map.clone();

                tokio::spawn(
                    async move {
                        debug!("Accepted");
                        if let Err(e) = serve(stream, state).await {
                            error!(?e, "h2 connection error");
                        }
                    }
                    .instrument(info_span!("connection", peer=%peer_addr)),
                );
            }
        }
    }
}

#[instrument(skip_all)]
async fn serve(
    stream: TcpStream,
    state: AppState,
    // dial_map: Arc<Mutex<HashMap<Uuid, mpsc::Sender<DialRequest>>>>,
    // intercept_rule_tx: Arc<Mutex<mpsc::Sender<(InterceptRuleKey, InterceptValue)>>>,
    // stream_map: Arc<Mutex<HashMap<InterceptRequest, TcpStream>>>,
) -> Result<()> {
    let mut connection = h2::server::handshake(stream).await?;
    debug!("h2 connection bound");

    while let Some(result) = connection.accept().await {
        let (resp, send) = result?;
        let state = state.clone();

        // let dial_map = dial_map.clone();
        // let intercept_rule_tx = intercept_rule_tx.clone();
        // let stream_map = stream_map.clone();

        tokio::spawn(
            async move {
                if let Err(e) = handle_request(resp, send, state).await {
                    error!(?e, "Error while handling request");
                }
            }
            .in_current_span(),
        );
    }

    debug!("h2 connection closed");
    Ok(())
}

#[instrument(
    name = "handle",
    skip_all,
    fields(
        method = %req.method(),
        path = %req.uri().path()
    )
)]
async fn handle_request(
    req: Request<RecvStream>,
    mut send: SendResponse<Bytes>,
    state: AppState,
    // dial_map: Arc<Mutex<HashMap<Uuid, mpsc::Sender<DialRequest>>>>,
    // intercept_rule_tx: Arc<Mutex<mpsc::Sender<(InterceptRuleKey, InterceptValue)>>>,
    // stream_map: Arc<Mutex<HashMap<InterceptRequest, TcpStream>>>,
) -> Result<()> {
    debug!("Got request");

    match req.uri().path() {
        "/dial" => dial(req, send, state).await,
        "/intercept" => intercept(req, send, state).await,
        _ => {
            warn!("Unhandled path");
            let response = http::Response::builder()
                .status(http::StatusCode::NOT_FOUND)
                .body(())?;
            send.send_response(response, true)?;
            Ok(())
        }
    }
}

#[instrument(skip_all)]
async fn dial(
    req: Request<RecvStream>,
    mut send: SendResponse<Bytes>,
    state: AppState,
    // dial_map: Arc<Mutex<HashMap<Uuid, mpsc::Sender<DialRequest>>>>,
    // intercept_rule_tx: Arc<Mutex<mpsc::Sender<(InterceptRuleKey, InterceptValue)>>>,
    // stream_map: Arc<Mutex<HashMap<InterceptRequest, TcpStream>>>,
) -> Result<()> {
    debug!("Call dial");
    let mut body = req.into_body();

    // check the preface
    if let Some(preface) = body.data().await {
        match preface {
            Ok(p) if p == Bytes::from_static(DIAL_PREFACE) => {
                debug!("<<< server dial preface ok");
            }
            Ok(_) => return Err(anyhow!("Preface mismatch")),
            Err(e) => return Err(e.into()),
        }
    }

    let response = http::Response::new(());
    let mut send = send.send_response(response, false)?;

    // generate an uuid and store a channel for this seesion,
    // keyed by the generated uuid
    let uuid = Uuid::now_v7();
    let (dial_tx, dial_rx) = mpsc::channel::<DialRequest>(1);
    {
        state.dial_map.lock().await.insert(uuid, dial_tx);
        debug!("Create uuid({uuid:?}) and insert it with dial_tx to dial_map");
    }

    // respond to the daemon with the generated uuid
    send.send_data(Bytes::copy_from_slice(&uuid.into_bytes()), false)?;
    debug!(">>> server dial send uuid as bytes {uuid:?}");

    // TODO shutdown
    // let (_shutdown_tx, mut shutdown_rx) = broadcast::channel::<()>(1);

    let intercept_task = handle_intercept_rules(body, state.intercept_rule_tx.clone());
    let dial_task = handle_dial_requests(send, dial_rx, state.stream_map.clone());

    tokio::select! {
        res = intercept_task => {
            match res {
                Ok(_) => debug!("Intercept rule task finished gracefully"),
                Err(e) => error!("Intercept rule task failed: {:?}", e),
            }
        }
        res = dial_task => {
            match res {
                Ok(_) => debug!("Dial request task finished gracefully"),
                Err(e) => error!("Dial request task failed: {:?}", e),
            }
        }
    }

    debug!(
        "Dial session ended. Cleaning up dial_map for UUID: {:?}",
        uuid
    );
    state.dial_map.lock().await.remove(&uuid);

    Ok(())
}

// register an intercept rule
#[instrument(skip_all)]
async fn handle_intercept_rules(
    mut body: RecvStream,
    intercept_rule_tx: mpsc::Sender<(InterceptRuleKey, InterceptValue)>,
) -> Result<()> {
    info!("Starting intercept rule receiver task");

    while let Some(data) = body.data().await {
        let bytes = match data {
            Ok(b) => b,
            Err(e) => {
                error!("Failed to read data from body stream: {e:?}");
                continue;
            }
        };

        let intercept_ctx: InterceptContext = match serde_json::from_slice(bytes.as_ref()) {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to deserialize intercept context: {e:?}");
                continue;
            }
        };

        debug!("Receive an intercept rule from daemon: {intercept_ctx:?}");

        let (key, value) = parse_rule_from_slice(intercept_ctx);
        debug!("Parsed rule key: {key:?}, value: {value:?}");

        if let Err(e) = intercept_rule_tx.send((key, value)).await {
            error!("Failed to send parsed rule. Receiver is gone. Stopping task: {e:?}");
            break;
        }
    }

    info!("Body data stream finished. Shutting down task.");
    Ok(())
}

// initiate dialing to daemon
#[instrument(skip_all)]
async fn handle_dial_requests(
    mut send: SendStream<Bytes>,
    mut dial_rx: mpsc::Receiver<DialRequest>,
    stream_map: Arc<Mutex<HashMap<InterceptRequest, TcpStream>>>,
    // mut shutdown_rx: broadcast::Receiver<()>,
) -> Result<()> {
    loop {
        tokio::select! {
            Some(DialRequest { id, target_port, stream }) = dial_rx.recv() => {
                debug!(">>> server dial send {}: {}", id, target_port);
                let data = Bytes::copy_from_slice(&target_port.to_be_bytes());

                if let Err(e) = send.send_data(data, false) {
                    error!("Failed to send dial request to agent: {e:?}");
                    break;
                }

                let key = InterceptRequest {
                    id: id.into_bytes(),
                    target_port,
                };

                stream_map.lock().await.insert(key, stream);
            }
            // _ = shutdown_rx.recv() => {
            //     debug!("shutdown write_handle");
            //     break;
            // }
        }
    }

    Ok(())
}

#[instrument(skip_all)]
async fn intercept(
    req: Request<RecvStream>,
    mut send: SendResponse<Bytes>,
    state: AppState,
    // stream_map: Arc<Mutex<HashMap<InterceptRequest, TcpStream>>>,
) -> Result<()> {
    debug!("Call intercept");
    let mut recv = req.into_body();

    if let Some(data) = recv.data().await {
        let bytes = data?;
        let intercept_req: InterceptRequest = serde_json::from_slice(&bytes.as_ref())?;
        debug!("<<< intercept_req: {intercept_req:?}");
        let _ = recv.flow_control().release_capacity(bytes.len());

        let mut upstream = match state.stream_map.lock().await.remove(&intercept_req) {
            Some(stream) => stream,
            None => {
                error!("Stream not found for intercept request: {intercept_req:?}");
                let response = http::Response::builder()
                    .status(http::StatusCode::NOT_FOUND)
                    .body(())?;
                send.send_response(response, true)?;
                return Ok(());
            }
        };

        let response = http::Response::new(());
        let send_stream = send.send_response(response, false).unwrap();

        let mut downstream = TunnelStream {
            recv,
            send: send_stream,
        };
        // let mut upstream = match state.stream_map.lock().await.remove(&intercept_req) {
        //     Some(stream) => stream,
        //     None => todo!(),
        // };

        debug!("Starting bidirectional copy");

        match tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await {
            Ok((up, down)) => debug!("copy_bidirectional finished: {up} up, {down} down"),
            Err(e) => error!("copy_bidirectional finished with error: {e:?}"),
        }
    }

    Ok(())
}

fn parse_rule_from_slice(intercept_ctx: InterceptContext) -> (InterceptRuleKey, InterceptValue) {
    let key = InterceptRuleKey {
        namespace: intercept_ctx.namespace,
        service: intercept_ctx.service_name,
        port: intercept_ctx.service_port,
    };

    let value = InterceptValue {
        id: Uuid::from_bytes(intercept_ctx.id),
        target_port: intercept_ctx.local_port,
    };

    (key, value)
}
