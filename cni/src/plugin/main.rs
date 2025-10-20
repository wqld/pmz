use std::{collections::HashMap, path::Path};

use anyhow::Result;
use cni::{CniAddEvent, CniConfig, CniResult};
use http_body_util::Full;
use hyper::{body::Bytes, client::conn::http1};
use hyper_util::rt::TokioIo;
use tokio::{io::AsyncReadExt, net::UnixStream};
use tracing::{Instrument, debug, error, info, info_span};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    let file_appender = tracing_appender::rolling::never("/var/log", "pmz-cni.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(fmt::layer().with_writer(non_blocking))
        .init();

    let top_span = info_span!(
        "cni",
        cni.command = tracing::field::Empty,
        k8s.pod.name = tracing::field::Empty,
        k8s.pod.namespace = tracing::field::Empty,
        cni.netns = tracing::field::Empty,
    );
    let _enter = top_span.enter();

    let cmd = std::env::var("CNI_COMMAND")?;
    tracing::Span::current().record("cni.command", &cmd);

    info!("CNI command started");

    match cmd.as_str() {
        "ADD" => {
            let netns = std::env::var("CNI_NETNS")?;
            let netdev = std::env::var("CNI_IFNAME")?;
            let cni_args_str = std::env::var("CNI_ARGS").unwrap_or_default();
            let cni_args_map = parse_cni_args(&cni_args_str);

            let namespace = cni_args_map.get("K8S_POD_NAMESPACE").unwrap();
            let pod_name = cni_args_map.get("K8S_POD_NAME").unwrap();

            tracing::Span::current()
                .record("k8s.pod.name", &pod_name)
                .record("k8s.pod.namespace", &namespace)
                .record("cni.netns", &netns);

            let mut buf = vec![];
            tokio::io::stdin().read_to_end(&mut buf).await?;

            let mut conf: CniConfig = serde_json::from_slice(&buf)?;
            let mut output = None;

            if let Some(value) = conf.raw_prev_result.take() {
                let prev_result: CniResult = serde_json::from_value(value)?;
                output = Some(serde_json::to_string(&prev_result)?);
                conf.prev_result = Some(prev_result);
            }

            debug!(?netdev, ?conf, "Processing ADD command");

            let ips = conf.prev_result.and_then(|r| r.ips).unwrap();

            let cni_sock_path = Path::new("/var/run/pmz/cni.sock");
            info!(path = %cni_sock_path.display(), "Connecting to CNI daemon socket");
            let cni_stream = UnixStream::connect(cni_sock_path).await?;

            let (mut sender, conn) = http1::handshake(TokioIo::new(cni_stream)).await?;

            tokio::spawn(
                async move {
                    if let Err(e) = conn.await {
                        error!(error = ?e, "CNI daemon connection failed");
                    }
                }
                .instrument(tracing::debug_span!("cni_daemon_connection")),
            );

            let add_event = CniAddEvent {
                netns: netns.to_owned(),
                pod_name: pod_name.to_owned(),
                pod_namespace: namespace.to_owned(),
                ips,
            };

            let json_string = serde_json::to_string(&add_event)?;
            let req_body = Full::new(Bytes::from(json_string));
            let req = http::Request::builder()
                .method(http::Method::POST)
                .uri("/")
                .body(req_body)?;

            info!("Sending ADD event to daemon");
            let _ = sender.send_request(req).await?;

            if let Some(result) = output {
                println!("{}", result);
            } else {
                println!("{{}}")
            }
        }
        _ => {
            debug!("Ignoring CNI command");
        }
    }

    Ok(())
}

fn parse_cni_args(cni_args: &str) -> HashMap<String, String> {
    cni_args
        .split(';')
        .filter(|s| !s.is_empty())
        .filter_map(|arg_pair| {
            let mut parts = arg_pair.splitn(2, '=');

            match (parts.next(), parts.next()) {
                (Some(key), Some(value)) => {
                    Some((key.trim().to_string(), value.trim().to_string()))
                }
                _ => None,
            }
        })
        .collect()
}
