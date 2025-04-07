use std::{
    ffi::OsStr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use anyhow::Result;
use clap::Parser;
use http_body_util::Full;
use hyper::{
    Request, Response,
    body::{Bytes, Incoming},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use log::{debug, error};
use serde::{Deserialize, Serialize};
use tokio::net::UnixListener;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "/etc/cni/net.d")]
    cni_conf_dir: String,
}

#[derive(Serialize)]
struct CniPluginConfig {
    #[serde(rename = "type")]
    plugin_type: String,
}

#[derive(Deserialize)]
struct CniConfList {
    plugins: Vec<serde_json::Value>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();

    // update the existing CNI configuration to enable the invocation of pmz-cni via chaining
    let dir_path = Path::new(&args.cni_conf_dir);
    debug!("cni conf dir: {dir_path:?}");
    if let Some(conflist_path) = get_first_lexicographical_conflist(dir_path).await? {
        update_cni_conflist(&conflist_path).await?;
    } else {
        error!("no conflist exists");
    }

    let unix_sock_path = Path::new("/var/run/pmz/cni.sock");

    if unix_sock_path.exists() {
        tokio::fs::remove_file(unix_sock_path).await?;
    }

    let listener = UnixListener::bind(unix_sock_path)?;
    tokio::fs::set_permissions(unix_sock_path, std::fs::Permissions::from_mode(0o766)).await?;

    loop {
        let (stream, _) = listener.accept().await?;

        tokio::spawn(async move {
            if let Err(e) = http1::Builder::new()
                .serve_connection(
                    TokioIo::new(stream),
                    service_fn(move |req| handle_request(req)),
                )
                .await
            {
                error!("Error serving connection: {e:#?}");
            }
        });
    }
}

// If there are multiple CNI configuration files in the directory,
// the kubelet uses the configuration file that comes first by name in lexicographic order.
async fn get_first_lexicographical_conflist(dir_path: &Path) -> Result<Option<PathBuf>> {
    let mut conflist_paths: Vec<PathBuf> = Vec::new();
    let mut entries = tokio::fs::read_dir(dir_path).await?;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let metadata = tokio::fs::metadata(&path).await?;

        if metadata.is_file() && path.extension() == Some(&OsStr::new("conflist")) {
            conflist_paths.push(path);
        }
    }

    conflist_paths.sort_unstable();

    for path in conflist_paths {
        let content = match tokio::fs::read(&path).await {
            Ok(c) => c,
            Err(_) => continue,
        };

        match serde_json::from_slice::<CniConfList>(&content) {
            Ok(conflist) => {
                if conflist.plugins.is_empty() {
                    continue;
                }
                return Ok(Some(path));
            }
            Err(_) => continue,
        }
    }

    Ok(None)
}

// Reads a CNI conflist file, adds or updates the pmz-cni plugin configuration,
// and atomically writes the modified contents back to the same file path.
async fn update_cni_conflist(conflist_path: &Path) -> Result<()> {
    let content = tokio::fs::read(&conflist_path).await?;

    let mut root_value: serde_json::Value = serde_json::from_slice(&content)?;
    if let Some(plugins) = root_value.get_mut("plugins").and_then(|v| v.as_array_mut()) {
        upsert_plugin_config(plugins)?;

        let updated_content = serde_json::to_vec_pretty(&root_value)?;
        let temp_name = format!(
            "{}.tmp.{}",
            conflist_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy(),
            std::process::id()
        );
        let temp_path = conflist_path.with_file_name(temp_name);
        tokio::fs::write(&temp_path, &updated_content).await?;
        tokio::fs::rename(&temp_path, &conflist_path).await?;
    }

    Ok(())
}

fn upsert_plugin_config(plugins: &mut Vec<serde_json::Value>) -> Result<()> {
    let pmz_cni_plugin_config = CniPluginConfig {
        plugin_type: "pmz-cni".to_owned(),
    };
    let pmz_cni_plugin_config = serde_json::to_value(&pmz_cni_plugin_config)?;

    for plugin in plugins.iter_mut() {
        if let Some(plugin_type) = plugin.get("type").and_then(|v| v.as_str()) {
            if plugin_type == "pmz-cni" {
                *plugin = pmz_cni_plugin_config.clone();
                return Ok(());
            }
        }
    }

    plugins.push(pmz_cni_plugin_config);
    Ok(())
}

async fn handle_request(_req: Request<Incoming>) -> Result<Response<Full<Bytes>>> {
    Ok(Response::new(Full::from("handle requested")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    async fn create_file(dir: &Path, name: &str, content: &str) -> Result<PathBuf> {
        let path = dir.join(name);
        tokio::fs::write(&path, content).await?;
        Ok(path)
    }

    #[tokio::test]
    async fn test_get_first_lexicographical_conflist() -> Result<()> {
        let dir = tempdir()?;
        let valid_content = r#"{"plugins": [{"type": "bridge"}]}"#;
        create_file(dir.path(), "99-last.conflist", valid_content).await?;
        let expected_path = create_file(dir.path(), "10-first.conflist", valid_content).await?;
        create_file(dir.path(), "05-other.conf", "{}").await?;

        let result = get_first_lexicographical_conflist(dir.path()).await?;
        assert_eq!(result, Some(expected_path));
        Ok(())
    }

    #[test]
    fn test_upsert_plugin_config() -> Result<()> {
        let mut plugins: Vec<serde_json::Value> = vec![serde_json::json!({"type": "bridge"})];
        upsert_plugin_config(&mut plugins)?;

        assert_eq!(plugins.len(), 2);
        assert_eq!(plugins[0]["type"], "bridge");
        assert_eq!(plugins[1]["type"], "pmz-cni");
        Ok(())
    }

    #[tokio::test]
    async fn test_update_cni_conflist() -> Result<()> {
        let dir = tempdir()?;
        let initial_content = serde_json::json!({
            "name": "testnet_add",
            "cniVersion": "0.4.0",
            "plugins": [
                {"type": "bridge"},
                {"type": "pmz-cni"},
                {"type": "portmap"}
            ]
        });
        let file_path = create_file(
            dir.path(),
            "test-add.conflist",
            &initial_content.to_string(),
        )
        .await?;

        update_cni_conflist(&file_path).await?;

        let updated_content_bytes = tokio::fs::read(&file_path).await?;
        let updated_value: serde_json::Value = serde_json::from_slice(&updated_content_bytes)?;

        let plugins = updated_value["plugins"].as_array().unwrap();
        assert_eq!(plugins.len(), 3);
        assert_eq!(plugins[1]["type"], "pmz-cni");
        Ok(())
    }
}
