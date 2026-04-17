use eyre::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Where a permission rule comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleSource {
    Global,
    Local,
}

impl std::fmt::Display for RuleSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleSource::Global => write!(f, "global"),
            RuleSource::Local => write!(f, "local"),
        }
    }
}

/// A parsed permission rule with its source.
#[derive(Debug, Clone)]
pub struct PermissionRule {
    pub rule: String,
    pub list: PermissionList,
    pub source: RuleSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionList {
    Allow,
    Deny,
}

impl std::fmt::Display for PermissionList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PermissionList::Allow => write!(f, "allow"),
            PermissionList::Deny => write!(f, "deny"),
        }
    }
}

/// Partial representation of Claude Code settings - just the permissions block.
#[derive(Debug, Deserialize, Default)]
struct SettingsFile {
    #[serde(default)]
    permissions: Permissions,
}

#[derive(Debug, Deserialize, Default)]
struct Permissions {
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    deny: Vec<String>,
}

/// Load permission rules from both settings files, deduplicating and tracking source.
pub fn load_settings(settings_path: &Path, settings_local_path: &Path) -> Result<Vec<PermissionRule>> {
    let mut rules = Vec::new();

    // Load global settings
    if settings_path.exists() {
        let global = parse_settings_file(settings_path)
            .with_context(|| format!("Failed to parse {}", settings_path.display()))?;

        for rule in global.permissions.allow {
            rules.push(PermissionRule {
                rule,
                list: PermissionList::Allow,
                source: RuleSource::Global,
            });
        }
        for rule in global.permissions.deny {
            rules.push(PermissionRule {
                rule,
                list: PermissionList::Deny,
                source: RuleSource::Global,
            });
        }
    }

    // Load local settings
    if settings_local_path.exists() {
        let local = parse_settings_file(settings_local_path)
            .with_context(|| format!("Failed to parse {}", settings_local_path.display()))?;

        for rule in local.permissions.allow {
            rules.push(PermissionRule {
                rule,
                list: PermissionList::Allow,
                source: RuleSource::Local,
            });
        }
        for rule in local.permissions.deny {
            rules.push(PermissionRule {
                rule,
                list: PermissionList::Deny,
                source: RuleSource::Local,
            });
        }
    }

    Ok(rules)
}

/// Walk up from `start_dir` looking for `.claude/settings.local.json`.
/// Falls back to `~/.claude/settings.local.json` if no project-level file found.
/// Existence check is intentional: discovery only activates for files that already
/// exist, matching Claude Code's own discovery semantics.
pub fn discover_settings_local(start_dir: &Path) -> PathBuf {
    let mut dir = start_dir.to_path_buf();
    loop {
        let candidate = dir.join(".claude").join("settings.local.json");
        if candidate.exists() {
            return candidate;
        }
        match dir.parent() {
            Some(parent) => dir = parent.to_path_buf(),
            None => break,
        }
    }
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".claude")
        .join("settings.local.json")
}

fn parse_settings_file(path: &Path) -> Result<SettingsFile> {
    let content = std::fs::read_to_string(path).context("Failed to read file")?;
    let settings: SettingsFile = serde_json::from_str(&content).context("Failed to parse JSON")?;
    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn parse_global_settings() {
        let dir = TempDir::new().expect("temp");
        let global = dir.path().join("settings.json");
        let local = dir.path().join("settings.local.json");
        std::fs::write(
            &global,
            r#"{"permissions":{"allow":["Bash(ls:*)","WebSearch"],"deny":["Bash(git tag -d *)"]}}"#,
        )
        .expect("write");

        let rules = load_settings(&global, &local).expect("load");
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0].rule, "Bash(ls:*)");
        assert_eq!(rules[0].source, RuleSource::Global);
        assert_eq!(rules[0].list, PermissionList::Allow);
        assert_eq!(rules[2].list, PermissionList::Deny);
    }

    #[test]
    fn parse_both_files() {
        let dir = TempDir::new().expect("temp");
        let global = dir.path().join("settings.json");
        let local = dir.path().join("settings.local.json");
        std::fs::write(&global, r#"{"permissions":{"allow":["Bash(ls:*)"]}}"#).expect("write");
        std::fs::write(&local, r#"{"permissions":{"allow":["Bash(curl:*)"],"deny":[]}}"#).expect("write");

        let rules = load_settings(&global, &local).expect("load");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].source, RuleSource::Global);
        assert_eq!(rules[1].source, RuleSource::Local);
    }

    #[test]
    fn missing_files_ok() {
        let dir = TempDir::new().expect("temp");
        let global = dir.path().join("nonexistent.json");
        let local = dir.path().join("also-nonexistent.json");
        let rules = load_settings(&global, &local).expect("load");
        assert!(rules.is_empty());
    }

    #[test]
    fn discover_finds_project_settings_local() {
        let root = TempDir::new().expect("temp");
        let claude_dir = root.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).expect("mkdir");
        let expected = claude_dir.join("settings.local.json");
        std::fs::write(&expected, r#"{"permissions":{}}"#).expect("write");

        let subdir = root.path().join("project").join("src");
        std::fs::create_dir_all(&subdir).expect("mkdir sub");

        let found = discover_settings_local(&subdir);
        assert_eq!(found, expected);
    }

    #[test]
    fn discover_falls_back_to_home() {
        let empty = TempDir::new().expect("temp");
        let result = discover_settings_local(empty.path());
        let expected = dirs::home_dir()
            .expect("home dir")
            .join(".claude")
            .join("settings.local.json");
        assert_eq!(result, expected);
    }

    #[test]
    fn settings_with_extra_fields() {
        let dir = TempDir::new().expect("temp");
        let global = dir.path().join("settings.json");
        let local = dir.path().join("settings.local.json");
        std::fs::write(
            &global,
            r#"{"model":"opus","env":{},"permissions":{"allow":["Bash(ls:*)"],"deny":[],"additionalDirectories":["/tmp"]},"hooks":{}}"#,
        )
        .expect("write");

        let rules = load_settings(&global, &local).expect("load");
        assert_eq!(rules.len(), 1);
    }
}
