use anyhow::{Result, anyhow};
use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
};
use tracing::{error, info, instrument};

use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct CniPluginConfig {
    #[serde(rename = "type")]
    plugin_type: String,
}

#[derive(Deserialize)]
struct CniConfList {
    plugins: Vec<serde_json::Value>,
}

pub struct CniPatcher {
    conf_dir: PathBuf,
}

impl CniPatcher {
    pub fn new(cni_conf_dir: &str) -> Self {
        Self {
            conf_dir: PathBuf::from(cni_conf_dir),
        }
    }

    #[instrument(skip_all, fields(conf_dir = %self.conf_dir.display()))]
    pub async fn patch(&self) -> Result<()> {
        if let Some(conflist_path) = self.find_primary_conflist().await? {
            info!(path = ?conflist_path, "Found primary CNI config, starting patch");
            Self::update_conflist_file(&conflist_path).await?;
            info!("Successfully patched CNI configuration.");
        } else {
            error!(path = %self.conf_dir.display(), "No valid CNI .conflist file found.");
        }
        Ok(())
    }

    // If there are multiple CNI configuration files in the directory,
    // the kubelet uses the configuration file that comes first by name in lexicographic order.
    async fn find_primary_conflist(&self) -> Result<Option<PathBuf>> {
        let mut entries = tokio::fs::read_dir(&self.conf_dir).await?;
        let mut conflist_paths: Vec<PathBuf> = Vec::new();

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();

            if path.is_file() && path.extension() == Some(&OsStr::new("conflist")) {
                conflist_paths.push(path);
            }
        }

        conflist_paths.sort_unstable();

        for path in conflist_paths {
            if let Ok(content) = tokio::fs::read(&path).await {
                if let Ok(conflist) = serde_json::from_slice::<CniConfList>(&content) {
                    if !conflist.plugins.is_empty() {
                        return Ok(Some(path));
                    }
                }
            }
        }

        Ok(None)
    }

    // Reads a CNI conflist file, adds or updates the pmz-cni plugin configuration,
    // and atomically writes the modified contents back to the same file path.
    async fn update_conflist_file(conflist_path: &Path) -> Result<()> {
        let content = tokio::fs::read(conflist_path).await?;
        let mut root: serde_json::Value = serde_json::from_slice(&content)?;

        let plugins = root
            .get_mut("plugins")
            .and_then(|v| v.as_array_mut())
            .ok_or_else(|| anyhow!("'plugins' array not found in CNI config"))?;

        Self::upsert_pmz_plugin(plugins)?;

        let updated_content = serde_json::to_vec_pretty(&root)?;
        let temp_path = conflist_path.with_extension("conflist.tmp");
        tokio::fs::write(&temp_path, &updated_content).await?;
        tokio::fs::rename(&temp_path, conflist_path).await?;

        Ok(())
    }

    fn upsert_pmz_plugin(plugins: &mut Vec<serde_json::Value>) -> Result<()> {
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

        let patcher = CniPatcher::new(dir.path().to_str().unwrap());

        let result = patcher.find_primary_conflist().await?;
        assert_eq!(result, Some(expected_path));
        Ok(())
    }

    #[test]
    fn test_upsert_plugin_config() -> Result<()> {
        let mut plugins: Vec<serde_json::Value> = vec![serde_json::json!({"type": "bridge"})];
        CniPatcher::upsert_pmz_plugin(&mut plugins)?;

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

        CniPatcher::update_conflist_file(&file_path).await?;

        let updated_content_bytes = tokio::fs::read(&file_path).await?;
        let updated_value: serde_json::Value = serde_json::from_slice(&updated_content_bytes)?;

        let plugins = updated_value["plugins"].as_array().unwrap();
        assert_eq!(plugins.len(), 3);
        assert_eq!(plugins[1]["type"], "pmz-cni");
        Ok(())
    }
}
