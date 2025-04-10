use std::{collections::HashMap, io::Write};

use anyhow::Result;
use log::debug;
use tokio::io::AsyncReadExt;

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

            let namespace = cni_args_map.get("K8S_POD_NAMESPACE");
            let pod_name = cni_args_map.get("K8S_POD_NAME");

            let mut buf = String::new();
            tokio::io::stdin().read_to_string(&mut buf).await?;

            debug!("{namespace:?}/{pod_name:?} (ADD) netns {netns:?}, netdev {netdev:?}: {buf:?}");

            let config: serde_json::Value = serde_json::from_str(&buf)?;
            let prev_result = config.get("prevResult").unwrap();
            let output = serde_json::to_string(prev_result)?;
            println!("{}", output);
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
