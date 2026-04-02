use colored::*;
use eyre::{Context, Result};
use serde_json::Value;
use std::collections::HashSet;
use std::path::Path;

use crate::cmd::audit::{AuditEntry, audit};
use crate::risk::Recommendation;

/// Which recommendation types to apply.
pub struct ApplyFilter {
    pub promote: bool,
    pub remove: bool,
    pub deny: bool,
}

/// Summary of what was (or would be) applied.
pub struct ApplySummary {
    pub promoted: Vec<String>,
    pub removed: Vec<String>,
    pub denied: Vec<String>,
    pub narrow_skipped: usize,
}

/// Run the apply command.
pub fn run_apply(
    settings_path: &Path,
    settings_local_path: &Path,
    filter: &ApplyFilter,
    write: bool,
    backup: bool,
) -> Result<()> {
    // Run audit to get recommendations
    let entries = audit(settings_path, settings_local_path, None)?;

    // Partition entries by recommendation
    let summary = build_summary(&entries, filter);

    let total = summary.promoted.len() + summary.removed.len() + summary.denied.len();

    if total == 0 {
        println!("No actionable recommendations match the selected filters.");
        if summary.narrow_skipped > 0 {
            println!("Skipped: {} narrow (requires manual review)", summary.narrow_skipped);
        }
        return Ok(());
    }

    // Display what will happen
    print_plan(&summary, write);

    if !write {
        println!("\n{}", "Pass --yes to apply these changes.".yellow().bold());
        return Ok(());
    }

    // Load raw JSON values
    let global_content = std::fs::read_to_string(settings_path).context("Failed to read settings.json")?;
    let local_content = if settings_local_path.exists() {
        std::fs::read_to_string(settings_local_path).context("Failed to read settings.local.json")?
    } else {
        String::from("{}")
    };

    let mut global: Value = serde_json::from_str(&global_content).context("Failed to parse settings.json")?;
    let mut local: Value = serde_json::from_str(&local_content).context("Failed to parse settings.local.json")?;

    // Create backups
    if backup {
        let mut args = vec![settings_path.to_str().expect("valid path")];
        if settings_local_path.exists() {
            args.push(settings_local_path.to_str().expect("valid path"));
        }
        let status = std::process::Command::new("rkvr")
            .arg("bkup")
            .args(&args)
            .status()
            .context("Failed to run rkvr bkup")?;
        if !status.success() {
            eyre::bail!("rkvr bkup failed");
        }
    }

    // Apply operations
    let global_allow = get_allow_array(&mut global);
    let local_allow = get_allow_array(&mut local);

    // Build a set of what's already in global allow for dedup
    let global_existing: HashSet<String> = global_allow
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();

    // Promote: add to global (if not already there), remove from local
    for rule in &summary.promoted {
        if !global_existing.contains(rule) {
            global_allow.push(Value::String(rule.clone()));
        }
        remove_from_array(local_allow, rule);
    }

    // Remove: delete from local allow
    for rule in &summary.removed {
        remove_from_array(local_allow, rule);
    }

    // Deny: remove from whichever allow list contains it
    for rule in &summary.denied {
        remove_from_array(global_allow, rule);
        remove_from_array(local_allow, rule);
    }

    // Write back
    let global_out = serde_json::to_string_pretty(&global)?;
    let local_out = serde_json::to_string_pretty(&local)?;

    std::fs::write(settings_path, format!("{global_out}\n")).context("Failed to write settings.json")?;
    std::fs::write(settings_local_path, format!("{local_out}\n")).context("Failed to write settings.local.json")?;

    println!();
    println!(
        "{} Applied {} promote, {} remove, {} deny operations.",
        "Done.".green().bold(),
        summary.promoted.len(),
        summary.removed.len(),
        summary.denied.len(),
    );

    if !summary.denied.is_empty() {
        println!(
            "\n{} Denied rules were removed from allow lists only. Add explicit deny entries to settings.json if desired.",
            "Note:".yellow()
        );
    }

    Ok(())
}

fn build_summary(entries: &[AuditEntry], filter: &ApplyFilter) -> ApplySummary {
    let mut promoted = Vec::new();
    let mut removed = Vec::new();
    let mut denied = Vec::new();
    let mut narrow_skipped = 0;

    for entry in entries {
        if entry.list != "allow" {
            continue;
        }
        match entry.recommendation {
            Recommendation::Promote if filter.promote => {
                promoted.push(entry.rule.clone());
            }
            Recommendation::Remove if filter.remove => {
                removed.push(entry.rule.clone());
            }
            Recommendation::Deny if filter.deny => {
                denied.push(entry.rule.clone());
            }
            Recommendation::Narrow => {
                narrow_skipped += 1;
            }
            _ => {}
        }
    }

    ApplySummary {
        promoted,
        removed,
        denied,
        narrow_skipped,
    }
}

fn print_plan(summary: &ApplySummary, write: bool) {
    let verb = if write { "Applying" } else { "Would apply" };
    println!(
        "{} {} promote, {} remove, {} deny operations:",
        verb,
        summary.promoted.len(),
        summary.removed.len(),
        summary.denied.len(),
    );

    if !summary.promoted.is_empty() {
        println!(
            "\n{} {} rules",
            "PROMOTE (local -> global):".cyan().bold(),
            summary.promoted.len()
        );
        print_rules(&summary.promoted, "+", 10);
    }

    if !summary.removed.is_empty() {
        println!(
            "\n{} {} rules",
            "REMOVE (from local):".red().bold(),
            summary.removed.len()
        );
        print_rules(&summary.removed, "-", 10);
    }

    if !summary.denied.is_empty() {
        println!(
            "\n{} {} rules",
            "DENY (remove from allow):".red().bold(),
            summary.denied.len()
        );
        print_rules(&summary.denied, "x", 10);
    }

    if summary.narrow_skipped > 0 {
        println!("\nSkipped: {} narrow (requires manual review)", summary.narrow_skipped);
    }
}

fn print_rules(rules: &[String], prefix: &str, max_show: usize) {
    for rule in rules.iter().take(max_show) {
        println!("  {prefix} {rule}");
    }
    if rules.len() > max_show {
        println!("  ... ({} more)", rules.len() - max_show);
    }
}

fn get_allow_array(value: &mut Value) -> &mut Vec<Value> {
    value
        .as_object_mut()
        .and_then(|obj| {
            obj.entry("permissions")
                .or_insert_with(|| Value::Object(serde_json::Map::new()))
                .as_object_mut()
        })
        .and_then(|perms| {
            if !perms.contains_key("allow") {
                perms.insert("allow".to_string(), Value::Array(Vec::new()));
            }
            perms.get_mut("allow").and_then(|v| v.as_array_mut())
        })
        .expect("permissions.allow should be an array")
}

fn remove_from_array(arr: &mut Vec<Value>, rule: &str) {
    arr.retain(|v| v.as_str() != Some(rule));
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_settings(dir: &Path, global: &str, local: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let gp = dir.join("settings.json");
        let lp = dir.join("settings.local.json");
        std::fs::write(&gp, global).expect("write global");
        std::fs::write(&lp, local).expect("write local");
        (gp, lp)
    }

    #[test]
    fn promote_moves_rule_to_global() {
        let dir = TempDir::new().expect("temp");
        let (gp, lp) = write_settings(
            dir.path(),
            r#"{"permissions":{"allow":["Bash(git status:*)"],"deny":[]}}"#,
            r#"{"permissions":{"allow":["Bash(ls:*)","Bash(tree:*)"]}}"#,
        );

        let filter = ApplyFilter {
            promote: true,
            remove: false,
            deny: false,
        };
        run_apply(&gp, &lp, &filter, true, false).expect("apply");

        let global: Value = serde_json::from_str(&std::fs::read_to_string(&gp).expect("read")).expect("parse");
        let local: Value = serde_json::from_str(&std::fs::read_to_string(&lp).expect("read")).expect("parse");

        let global_allow: Vec<&str> = global["permissions"]["allow"]
            .as_array()
            .expect("array")
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        let local_allow: Vec<&str> = local["permissions"]["allow"]
            .as_array()
            .expect("array")
            .iter()
            .filter_map(|v| v.as_str())
            .collect();

        // ls and tree are safe -> should be promoted to global
        assert!(global_allow.contains(&"Bash(ls:*)"));
        assert!(global_allow.contains(&"Bash(tree:*)"));
        // and removed from local
        assert!(!local_allow.contains(&"Bash(ls:*)"));
        assert!(!local_allow.contains(&"Bash(tree:*)"));
    }

    #[test]
    fn remove_deletes_dangerous_from_local() {
        let dir = TempDir::new().expect("temp");
        let (gp, lp) = write_settings(
            dir.path(),
            r#"{"permissions":{"allow":[]}}"#,
            r#"{"permissions":{"allow":["Bash(sudo rm:*)","Bash(ls:*)"]}}"#,
        );

        let filter = ApplyFilter {
            promote: false,
            remove: true,
            deny: false,
        };
        run_apply(&gp, &lp, &filter, true, false).expect("apply");

        let local: Value = serde_json::from_str(&std::fs::read_to_string(&lp).expect("read")).expect("parse");
        let local_allow: Vec<&str> = local["permissions"]["allow"]
            .as_array()
            .expect("array")
            .iter()
            .filter_map(|v| v.as_str())
            .collect();

        // sudo rm should be removed
        assert!(!local_allow.contains(&"Bash(sudo rm:*)"));
        // ls should remain (it's safe, not dangerous)
        assert!(local_allow.contains(&"Bash(ls:*)"));
    }

    #[test]
    fn promote_dedup_already_in_global() {
        let dir = TempDir::new().expect("temp");
        let (gp, lp) = write_settings(
            dir.path(),
            r#"{"permissions":{"allow":["Bash(ls:*)"]}}"#,
            r#"{"permissions":{"allow":["Bash(ls:*)"]}}"#,
        );

        let filter = ApplyFilter {
            promote: true,
            remove: false,
            deny: false,
        };
        run_apply(&gp, &lp, &filter, true, false).expect("apply");

        let global: Value = serde_json::from_str(&std::fs::read_to_string(&gp).expect("read")).expect("parse");
        let local: Value = serde_json::from_str(&std::fs::read_to_string(&lp).expect("read")).expect("parse");

        // Should not duplicate in global
        let global_allow = global["permissions"]["allow"].as_array().expect("array");
        let count = global_allow.iter().filter(|v| v.as_str() == Some("Bash(ls:*)")).count();
        assert_eq!(count, 1);

        // Should be removed from local
        let local_allow = local["permissions"]["allow"].as_array().expect("array");
        assert!(!local_allow.iter().any(|v| v.as_str() == Some("Bash(ls:*)")));
    }

    #[test]
    fn dry_run_does_not_modify_files() {
        let dir = TempDir::new().expect("temp");
        let global_json = r#"{"permissions":{"allow":[]}}"#;
        let local_json = r#"{"permissions":{"allow":["Bash(ls:*)"]}}"#;
        let (gp, lp) = write_settings(dir.path(), global_json, local_json);

        let filter = ApplyFilter {
            promote: true,
            remove: true,
            deny: true,
        };
        // write=false means dry run
        run_apply(&gp, &lp, &filter, false, false).expect("apply");

        // Files should be unchanged
        assert_eq!(std::fs::read_to_string(&gp).expect("read"), global_json);
        assert_eq!(std::fs::read_to_string(&lp).expect("read"), local_json);
    }

    #[test]
    fn backup_runs_without_error() {
        let dir = TempDir::new().expect("temp");
        let (gp, lp) = write_settings(
            dir.path(),
            r#"{"permissions":{"allow":[]}}"#,
            r#"{"permissions":{"allow":["Bash(sudo rm:*)"]}}"#,
        );

        let filter = ApplyFilter {
            promote: false,
            remove: true,
            deny: false,
        };
        // rkvr must be available in PATH; this is an integration smoke test
        run_apply(&gp, &lp, &filter, true, true).expect("apply");
    }

    #[test]
    fn preserves_non_permission_fields() {
        let dir = TempDir::new().expect("temp");
        let (gp, lp) = write_settings(
            dir.path(),
            r#"{"env":{"FOO":"bar"},"model":"opus","permissions":{"allow":[],"deny":[]},"hooks":{}}"#,
            r#"{"permissions":{"allow":["Bash(ls:*)"]},"enableAllProjectMcpServers":true}"#,
        );

        let filter = ApplyFilter {
            promote: true,
            remove: false,
            deny: false,
        };
        run_apply(&gp, &lp, &filter, true, false).expect("apply");

        let global: Value = serde_json::from_str(&std::fs::read_to_string(&gp).expect("read")).expect("parse");
        assert_eq!(global["env"]["FOO"], "bar");
        assert_eq!(global["model"], "opus");
        assert!(global["hooks"].is_object());

        let local: Value = serde_json::from_str(&std::fs::read_to_string(&lp).expect("read")).expect("parse");
        assert_eq!(local["enableAllProjectMcpServers"], true);
    }

    #[test]
    fn no_filters_selected_no_ops() {
        let dir = TempDir::new().expect("temp");
        let (gp, lp) = write_settings(
            dir.path(),
            r#"{"permissions":{"allow":[]}}"#,
            r#"{"permissions":{"allow":["Bash(sudo rm:*)","Bash(ls:*)"]}}"#,
        );

        let filter = ApplyFilter {
            promote: false,
            remove: false,
            deny: false,
        };
        run_apply(&gp, &lp, &filter, true, false).expect("apply");

        // Nothing should change
        let local: Value = serde_json::from_str(&std::fs::read_to_string(&lp).expect("read")).expect("parse");
        let local_allow = local["permissions"]["allow"].as_array().expect("array");
        assert_eq!(local_allow.len(), 2);
    }

    #[test]
    fn deny_list_rules_not_acted_on() {
        let dir = TempDir::new().expect("temp");
        let (gp, lp) = write_settings(
            dir.path(),
            r#"{"permissions":{"allow":[],"deny":["Bash(git tag -d *)","Bash(rm -rf:*)"]}}"#,
            r#"{"permissions":{"allow":[]}}"#,
        );

        let filter = ApplyFilter {
            promote: true,
            remove: true,
            deny: true,
        };
        run_apply(&gp, &lp, &filter, true, false).expect("apply");

        // Deny-list rules should not be touched - they're already denied
        let global: Value = serde_json::from_str(&std::fs::read_to_string(&gp).expect("read")).expect("parse");
        let deny = global["permissions"]["deny"].as_array().expect("array");
        assert_eq!(deny.len(), 2, "deny list should be unchanged");
    }

    #[test]
    fn missing_local_file_handled() {
        let dir = TempDir::new().expect("temp");
        let gp = dir.path().join("settings.json");
        let lp = dir.path().join("settings.local.json");
        std::fs::write(&gp, r#"{"permissions":{"allow":["Bash(ls:*)"]}}"#).expect("write");
        // local file does not exist

        let filter = ApplyFilter {
            promote: true,
            remove: true,
            deny: true,
        };
        run_apply(&gp, &lp, &filter, true, false).expect("apply");
        // Should not panic
    }
}
