use std::{collections::HashMap, io::Write, path::Path};

use anyhow::Result;
use cni::{CniAddEvent, CniConfig, CniResult};
use http_body_util::Full;
use hyper::{body::Bytes, client::conn::http1};
use hyper_util::rt::TokioIo;
use log::{debug, error};
use tokio::{io::AsyncReadExt, net::UnixStream};

#[tokio::main]
async fn main() -> Result<()> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .write(true)
        .open("/var/log/pmz-cni.log")?;
    let log_file = Box::new(file);
    env_logger::Builder::new()
        .target(env_logger::Target::Pipe(log_file))
        .filter(None, log::LevelFilter::Debug)
        .format(|buf, record| {
            writeln!(
                buf,
                "{} [{}] {}: {}",
                chrono::Local::now(),
                record.level(),
                record.module_path().unwrap_or("<unknown>"),
                record.args()
            )
        })
        .init();

    let cmd = std::env::var("CNI_COMMAND")?;
    debug!("command: {cmd:?}");

    match cmd.as_str() {
        "ADD" => {
            let netns = std::env::var("CNI_NETNS")?;
            let netdev = std::env::var("CNI_IFNAME")?;
            let cni_args_str = std::env::var("CNI_ARGS").unwrap_or_default();
            let cni_args_map = parse_cni_args(&cni_args_str);

            let namespace = cni_args_map.get("K8S_POD_NAMESPACE").unwrap();
            let pod_name = cni_args_map.get("K8S_POD_NAME").unwrap();

            let mut buf = vec![];
            tokio::io::stdin().read_to_end(&mut buf).await?;

            let mut conf: CniConfig = serde_json::from_slice(&buf)?;
            let mut output = None;

            if let Some(value) = conf.raw_prev_result.take() {
                let prev_result: CniResult = serde_json::from_value(value)?;
                output = Some(serde_json::to_string(&prev_result)?);
                conf.prev_result = Some(prev_result);
            }

            debug!("{namespace:?}/{pod_name:?} (ADD) netns {netns:?}, netdev {netdev:?}: {conf:?}");

            let ips = conf.prev_result.and_then(|r| r.ips).unwrap();

            let cni_sock_path = Path::new("/var/run/pmz/cni.sock");
            let cni_stream = UnixStream::connect(cni_sock_path).await?;

            let (mut sender, conn) = http1::handshake(TokioIo::new(cni_stream)).await?;
            tokio::spawn(async move {
                if let Err(e) = conn.await {
                    error!("connection failed: {e:#?}");
                }
            });

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

            let _ = sender.send_request(req).await?;

            if let Some(result) = output {
                println!("{}", result);
            } else {
                println!("{{}}")
            }
        }
        _ => {}
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
