use eyre::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// How to combine user-specified items with the built-in defaults.
#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ListMode {
    /// Append user items after the built-in defaults.
    #[default]
    Extend,
    /// Ignore defaults entirely; use only user items.
    Replace,
}

/// A configurable list that can either extend or replace the built-in defaults.
#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct ListConfig {
    pub mode: ListMode,
    pub items: Vec<String>,
}

/// Configuration for claude-permit, loaded from YAML.
#[derive(Debug, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct Config {
    /// Min observations to trigger a suggestion.
    pub suggest_threshold: u32,
    /// Min distinct sessions for a suggestion.
    pub suggest_sessions: u32,
    /// Days after which events are eligible for cleanup.
    pub clean_older_than: u32,
    /// Whether the log command should enforce deny patterns. Default: false.
    pub enforce_deny: bool,
    /// Bash patterns that are permanently denied (blocks execution).
    pub deny_patterns: ListConfig,
    /// Bash commands classified as safe risk.
    pub safe_commands: ListConfig,
    /// Bash commands classified as moderate risk.
    pub moderate_commands: ListConfig,
    /// MCP tools classified as dangerous (write/mutation operations).
    pub mcp_write_tools: ListConfig,
    /// Rule patterns considered overly broad (triggers Narrow recommendation).
    pub broad_patterns: ListConfig,
    /// Pager command for paginated output (e.g. "less -F -X"). None disables paging.
    pub pager: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            suggest_threshold: 3,
            suggest_sessions: 2,
            clean_older_than: 90,
            enforce_deny: false,
            deny_patterns: ListConfig::default(),
            safe_commands: ListConfig::default(),
            moderate_commands: ListConfig::default(),
            mcp_write_tools: ListConfig::default(),
            broad_patterns: ListConfig::default(),
            pager: None,
        }
    }
}

impl Config {
    /// Load configuration with fallback chain: explicit path > ~/.config > defaults.
    pub fn load(config_path: Option<&PathBuf>) -> Result<Self> {
        if let Some(path) = config_path {
            return Self::load_from_file(path).context(format!("Failed to load config from {}", path.display()));
        }

        if let Some(config_dir) = dirs::config_dir() {
            let primary = config_dir.join("claude-permit").join("claude-permit.yml");
            if primary.exists() {
                match Self::load_from_file(&primary) {
                    Ok(config) => return Ok(config),
                    Err(e) => {
                        log::warn!("Failed to load config from {}: {e}", primary.display());
                    }
                }
            }
        }

        // Fallback: ./claude-permit.yml
        let local = PathBuf::from("claude-permit.yml");
        if local.exists() {
            match Self::load_from_file(&local) {
                Ok(config) => return Ok(config),
                Err(e) => {
                    log::warn!("Failed to load config from {}: {e}", local.display());
                }
            }
        }

        Ok(Self::default())
    }

    fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(&path).context("Failed to read config file")?;
        let config: Self = serde_yaml::from_str(&content).context("Failed to parse config file")?;
        log::info!("Loaded config from: {}", path.as_ref().display());
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn default_config() {
        let config = Config::default();
        assert_eq!(config.suggest_threshold, 3);
        assert_eq!(config.suggest_sessions, 2);
        assert_eq!(config.clean_older_than, 90);
        assert!(!config.enforce_deny);
    }

    #[test]
    fn load_from_yaml() {
        let dir = TempDir::new().expect("temp");
        let path = dir.path().join("config.yml");
        std::fs::write(&path, "suggest-threshold: 5\nsuggest-sessions: 3\nenforce-deny: true\n").expect("write");

        let config = Config::load(Some(&path)).expect("load");
        assert_eq!(config.suggest_threshold, 5);
        assert_eq!(config.suggest_sessions, 3);
        assert!(config.enforce_deny);
    }

    #[test]
    fn load_partial_yaml() {
        let dir = TempDir::new().expect("temp");
        let path = dir.path().join("config.yml");
        std::fs::write(&path, "suggest-threshold: 10\n").expect("write");

        let config = Config::load(Some(&path)).expect("load");
        assert_eq!(config.suggest_threshold, 10);
        // Others should be defaults
        assert_eq!(config.suggest_sessions, 2);
        assert!(!config.enforce_deny);
    }

    #[test]
    fn load_missing_file_uses_defaults() {
        let path = PathBuf::from("/nonexistent/config.yml");
        // Explicit path that doesn't exist should error
        assert!(Config::load(Some(&path)).is_err());
    }

    #[test]
    fn load_no_path_uses_defaults() {
        let config = Config::load(None).expect("load");
        assert_eq!(config.suggest_threshold, 3);
    }

    #[test]
    fn list_config_extend_mode() {
        let dir = TempDir::new().expect("temp");
        let path = dir.path().join("config.yml");
        std::fs::write(
            &path,
            "deny-patterns:\n  mode: extend\n  items:\n    - \"shutdown\"\n    - \"reboot\"\n",
        )
        .expect("write");

        let config = Config::load(Some(&path)).expect("load");
        assert_eq!(config.deny_patterns.mode, ListMode::Extend);
        assert_eq!(config.deny_patterns.items, vec!["shutdown", "reboot"]);
    }

    #[test]
    fn list_config_replace_mode() {
        let dir = TempDir::new().expect("temp");
        let path = dir.path().join("config.yml");
        std::fs::write(&path, "deny-patterns:\n  mode: replace\n  items:\n    - \"rm \"\n").expect("write");

        let config = Config::load(Some(&path)).expect("load");
        assert_eq!(config.deny_patterns.mode, ListMode::Replace);
        assert_eq!(config.deny_patterns.items, vec!["rm "]);
    }

    #[test]
    fn list_config_items_only_defaults_to_extend() {
        let dir = TempDir::new().expect("temp");
        let path = dir.path().join("config.yml");
        std::fs::write(&path, "deny-patterns:\n  items:\n    - \"custom\"\n").expect("write");

        let config = Config::load(Some(&path)).expect("load");
        assert_eq!(config.deny_patterns.mode, ListMode::Extend);
        assert_eq!(config.deny_patterns.items, vec!["custom"]);
    }
}
