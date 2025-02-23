use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;
use aya::maps::{HashMap, MapData};
use bytes::{Buf, Bytes};
use common::SockAddr;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use log::{debug, error, info};
use tokio::{net::TcpListener, sync::RwLock};

pub struct Server {
    port: u16,
    intercept_rule: Arc<RwLock<HashMap<MapData, SockAddr, SockAddr>>>,
}

impl Server {
    pub fn new(port: u16, intercept_rule: HashMap<MapData, SockAddr, SockAddr>) -> Self {
        Self {
            port,
            intercept_rule: Arc::new(RwLock::new(intercept_rule)),
        }
    }

    pub async fn start(&self) -> Result<()> {
        let api_addr = SocketAddr::from(([0, 0, 0, 0], self.port));
        let api_listener = TcpListener::bind(api_addr).await?;
        info!("Health check listening on {}", api_addr);

        loop {
            let (stream, peer_addr) = api_listener.accept().await.unwrap();
            let intercept_rule = self.intercept_rule.clone();
            debug!("peer addr: {peer_addr:?}");

            tokio::spawn(async move {
                if let Err(e) = http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |req| handle(req, intercept_rule.clone())),
                    )
                    .await
                {
                    error!("Error serving connection: {:?}", e);
                }
            });
        }
    }
}

async fn handle(
    req: Request<Incoming>,
    intercept_rule: Arc<RwLock<HashMap<MapData, SockAddr, SockAddr>>>,
) -> Result<Response<Full<Bytes>>> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/health") => Ok(Response::new(Full::from("healthy"))),
        (&Method::POST, "/intercept") => start_intercept(req.into_body(), intercept_rule).await,
        _ => not_found(),
    }
}

async fn start_intercept(
    req: Incoming,
    intercept_rule: Arc<RwLock<HashMap<MapData, SockAddr, SockAddr>>>,
) -> Result<Response<Full<Bytes>>> {
    debug!("start_intercept with {req:?}");
    let body = req.collect().await?.aggregate();
    let props: serde_json::Value = serde_json::from_reader(body.reader())?;
    debug!("data: {props:?}");

    Ok(Response::new(Full::from("intercept started")))
}

fn not_found() -> Result<Response<Full<Bytes>>> {
    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::from("Not found"))?)
}
