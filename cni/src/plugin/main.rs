use std::io::Write;

use anyhow::Result;
use log::debug;

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
            let stdin = std::io::read_to_string(std::io::stdin())?;
            debug!("(ADD) netns {netns:?}, netdev {netdev:?}");
            debug!("stdin: {stdin:?}");

            let config: serde_json::Value = serde_json::from_str(&stdin)?;
            let prev_result = config.get("prevResult").unwrap();
            let output = serde_json::to_string(prev_result)?;
            println!("{}", output);
        }
        _ => {}
    }

    Ok(())
}
