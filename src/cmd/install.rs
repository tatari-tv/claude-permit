use colored::*;
use eyre::{Context, Result};
use serde_json::{Map, Value, json};
use std::path::Path;

/// Install the claude-permit PreToolUse hook into a Claude Code settings file.
///
/// Returns Ok(true) if the hook was installed, Ok(false) if already present.
pub fn run_install(settings_path: &Path, yes: bool) -> Result<bool> {
    // Read or create settings
    let mut root: Map<String, Value> = if settings_path.exists() {
        let content = std::fs::read_to_string(settings_path).context("Failed to read settings file")?;
        serde_json::from_str(&content).context("Failed to parse settings JSON")?
    } else {
        if !yes {
            println!(
                "{} {} does not exist. Pass --yes to create it.",
                "SKIP".yellow().bold(),
                settings_path.display()
            );
            return Ok(false);
        }
        if let Some(parent) = settings_path.parent() {
            std::fs::create_dir_all(parent).context("Failed to create settings directory")?;
        }
        Map::new()
    };

    // Check if hook already exists
    if has_permit_hook(&root) {
        println!(
            "{} claude-permit hook already installed in {}",
            "OK".green().bold(),
            settings_path.display()
        );
        return Ok(false);
    }

    if !yes {
        println!("Would add claude-permit PreToolUse hook to {}", settings_path.display());
        println!("Pass --yes to apply.");
        return Ok(false);
    }

    // Insert the hook
    insert_hook(&mut root);

    // Write back
    let output = serde_json::to_string_pretty(&root).context("Failed to serialize settings")?;
    std::fs::write(settings_path, format!("{output}\n")).context("Failed to write settings file")?;

    println!(
        "{} Installed claude-permit hook in {}",
        "OK".green().bold(),
        settings_path.display()
    );
    Ok(true)
}

/// Check if any PreToolUse hook already references claude-permit.
fn has_permit_hook(root: &Map<String, Value>) -> bool {
    let Some(hooks) = root.get("hooks") else {
        return false;
    };
    let Some(hooks_obj) = hooks.as_object() else {
        return false;
    };
    let Some(pre) = hooks_obj.get("PreToolUse") else {
        return false;
    };
    let Some(entries) = pre.as_array() else {
        return false;
    };
    entries.iter().any(|entry| {
        let s = serde_json::to_string(entry).unwrap_or_default();
        s.contains("claude-permit")
    })
}

/// Insert the claude-permit PreToolUse hook entry, preserving existing hooks.
fn insert_hook(root: &mut Map<String, Value>) {
    let hook_entry = json!({
        "matcher": "",
        "hooks": [
            {
                "type": "command",
                "command": "claude-permit log"
            }
        ]
    });

    let hooks = root
        .entry("hooks")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .expect("hooks must be an object");

    let pre = hooks
        .entry("PreToolUse")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .expect("PreToolUse must be an array");

    pre.push(hook_entry);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn install_into_empty_settings() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, "{}").unwrap();

        let installed = run_install(&path, true).unwrap();
        assert!(installed);

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("claude-permit log"));
        assert!(content.contains("PreToolUse"));
    }

    #[test]
    fn install_preserves_existing_hooks() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            r#"{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{"type": "command", "command": "echo hello"}]
      }
    ]
  }
}"#,
        )
        .unwrap();

        let installed = run_install(&path, true).unwrap();
        assert!(installed);

        let content = std::fs::read_to_string(&path).unwrap();
        // Both hooks present
        assert!(content.contains("echo hello"));
        assert!(content.contains("claude-permit log"));
    }

    #[test]
    fn install_idempotent() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            r#"{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [{"type": "command", "command": "claude-permit log"}]
      }
    ]
  }
}"#,
        )
        .unwrap();

        let installed = run_install(&path, true).unwrap();
        assert!(!installed);
    }

    #[test]
    fn install_preserves_other_fields() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, r#"{"model": "opus", "permissions": {"allow": ["Bash(ls:*)"]}}"#).unwrap();

        run_install(&path, true).unwrap();

        let root: Map<String, Value> = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(root.get("model").and_then(|v| v.as_str()), Some("opus"));
        assert!(root.get("permissions").is_some());
        assert!(root.get("hooks").is_some());
    }

    #[test]
    fn install_dry_run_no_write() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, "{}").unwrap();

        let installed = run_install(&path, false).unwrap();
        assert!(!installed);

        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "{}");
    }

    #[test]
    fn install_creates_file_when_missing() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("subdir").join("settings.json");

        let installed = run_install(&path, true).unwrap();
        assert!(installed);
        assert!(path.exists());

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("claude-permit log"));
    }

    #[test]
    fn install_skips_missing_without_yes() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nonexistent.json");

        let installed = run_install(&path, false).unwrap();
        assert!(!installed);
        assert!(!path.exists());
    }
}
