use colored::*;
use eyre::{Context, Result, bail};
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
    pub dupe: bool,
}

impl ApplyFilter {
    /// All actionable recommendations.
    pub fn all() -> Self {
        Self { promote: true, remove: true, deny: true, dupe: true }
    }
}

/// Parse action words from CLI into an ApplyFilter.
/// Empty slice means all actionable.
pub fn parse_apply_filter(actions: &[String]) -> Result<ApplyFilter> {
    if actions.is_empty() {
        return Ok(ApplyFilter::all());
    }
    for action in actions {
        match action.as_str() {
            "promote" | "remove" | "deny" | "dupe" => {}
            other => bail!("Unknown apply action '{}'. Valid: promote, remove, deny, dupe", other),
        }
    }
    Ok(ApplyFilter {
        promote: actions.iter().any(|a| a == "promote"),
        remove: actions.iter().any(|a| a == "remove"),
        deny: actions.iter().any(|a| a == "deny"),
        dupe: actions.iter().any(|a| a == "dupe"),
    })
}

/// Summary of what was (or would be) applied.
pub struct ApplySummary {
    pub promoted: Vec<String>,
    pub removed: Vec<String>,
    pub denied: Vec<String>,
    pub duped: Vec<(String, String)>, // (rule, source)
    pub narrow_skipped: usize,
}

/// Apply recommendations from already-audited entries.
pub fn apply_entries(
    entries: &[AuditEntry],
    filter: &ApplyFilter,
    settings_path: &Path,
    settings_local_path: &Path,
    backup: bool,
    write: bool,
) -> Result<()> {
    let summary = build_summary(entries, filter);
    let total = summary.promoted.len() + summary.removed.len() + summary.denied.len() + summary.duped.len();

    if total == 0 {
        println!("No actionable recommendations match the selected filters.");
        if summary.narrow_skipped > 0 {
            println!("Skipped: {} narrow (requires manual review)", summary.narrow_skipped);
        }
        return Ok(());
    }

    print_plan(&summary, write);

    if !write {
        println!("\n{}", "Pass --apply to write these changes.".yellow().bold());
        return Ok(());
    }

    let global_content = std::fs::read_to_string(settings_path).context("Failed to read settings.json")?;
    let local_content = if settings_local_path.exists() {
        std::fs::read_to_string(settings_local_path).context("Failed to read settings.local.json")?
    } else {
        String::from("{}")
    };

    let mut global: Value = serde_json::from_str(&global_content).context("Failed to parse settings.json")?;
    let mut local: Value = serde_json::from_str(&local_content).context("Failed to parse settings.local.json")?;

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
            bail!("rkvr bkup failed");
        }
    }

    let global_allow = get_allow_array(&mut global);
    let local_allow = get_allow_array(&mut local);

    let global_existing: HashSet<String> = global_allow
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();

    for rule in &summary.promoted {
        if !global_existing.contains(rule) {
            global_allow.push(Value::String(rule.clone()));
        }
        remove_from_array(local_allow, rule);
    }

    for rule in &summary.removed {
        remove_from_array(local_allow, rule);
    }

    for rule in &summary.denied {
        remove_from_array(global_allow, rule);
        remove_from_array(local_allow, rule);
    }

    for (rule, source) in &summary.duped {
        if source == "global" {
            remove_from_array(global_allow, rule);
        } else {
            remove_from_array(local_allow, rule);
        }
    }

    let global_out = serde_json::to_string_pretty(&global)?;
    let local_out = serde_json::to_string_pretty(&local)?;

    std::fs::write(settings_path, format!("{global_out}\n")).context("Failed to write settings.json")?;
    std::fs::write(settings_local_path, format!("{local_out}\n")).context("Failed to write settings.local.json")?;

    println!();
    println!(
        "{} Applied {} promote, {} remove, {} deny, {} dupe.",
        "Done.".green().bold(),
        summary.promoted.len(),
        summary.removed.len(),
        summary.denied.len(),
        summary.duped.len(),
    );

    if !summary.denied.is_empty() {
        println!(
            "\n{} Denied rules were removed from allow lists only. Add explicit deny entries to settings.json if desired.",
            "Note:".yellow()
        );
    }

    Ok(())
}

/// Convenience wrapper used by tests: re-audits then applies.
pub fn run_apply(
    settings_path: &Path,
    settings_local_path: &Path,
    filter: &ApplyFilter,
    write: bool,
    backup: bool,
) -> Result<()> {
    let entries = audit(settings_path, settings_local_path, &[], None)?;
    apply_entries(&entries, filter, settings_path, settings_local_path, backup, write)
}

fn build_summary(entries: &[AuditEntry], filter: &ApplyFilter) -> ApplySummary {
    let mut promoted = Vec::new();
    let mut removed = Vec::new();
    let mut denied = Vec::new();
    let mut duped = Vec::new();
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
            Recommendation::Dupe if filter.dupe => {
                duped.push((entry.rule.clone(), entry.source.clone()));
            }
            Recommendation::Narrow => {
                narrow_skipped += 1;
            }
            _ => {}
        }
    }

    ApplySummary { promoted, removed, denied, duped, narrow_skipped }
}

fn print_plan(summary: &ApplySummary, write: bool) {
    let verb = if write { "Applying" } else { "Would apply" };
    println!(
        "{} {} promote, {} remove, {} deny, {} dupe:",
        verb,
        summary.promoted.len(),
        summary.removed.len(),
        summary.denied.len(),
        summary.duped.len(),
    );

    if !summary.promoted.is_empty() {
        println!("\n{} {} rules", "PROMOTE (local -> global):".cyan().bold(), summary.promoted.len());
        print_rules(&summary.promoted, "+", 10);
    }

    if !summary.removed.is_empty() {
        println!("\n{} {} rules", "REMOVE (from local):".red().bold(), summary.removed.len());
        print_rules(&summary.removed, "-", 10);
    }

    if !summary.denied.is_empty() {
        println!("\n{} {} rules", "DENY (remove from allow):".red().bold(), summary.denied.len());
        print_rules(&summary.denied, "x", 10);
    }

    if !summary.duped.is_empty() {
        println!("\n{} {} rules", "DUPE (covered by broader rule):".yellow().bold(), summary.duped.len());
        for (rule, source) in summary.duped.iter().take(10) {
            println!("  - {rule}  [{source}]");
        }
        if summary.duped.len() > 10 {
            println!("  ... ({} more)", summary.duped.len() - 10);
        }
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

        run_apply(&gp, &lp, &ApplyFilter { promote: true, remove: false, deny: false, dupe: false }, true, false).expect("apply");

        let global: Value = serde_json::from_str(&std::fs::read_to_string(&gp).expect("read")).expect("parse");
        let local: Value = serde_json::from_str(&std::fs::read_to_string(&lp).expect("read")).expect("parse");

        let global_allow: Vec<&str> = global["permissions"]["allow"].as_array().expect("array").iter().filter_map(|v| v.as_str()).collect();
        let local_allow: Vec<&str> = local["permissions"]["allow"].as_array().expect("array").iter().filter_map(|v| v.as_str()).collect();

        assert!(global_allow.contains(&"Bash(ls:*)"));
        assert!(global_allow.contains(&"Bash(tree:*)"));
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

        run_apply(&gp, &lp, &ApplyFilter { promote: false, remove: true, deny: false, dupe: false }, true, false).expect("apply");

        let local: Value = serde_json::from_str(&std::fs::read_to_string(&lp).expect("read")).expect("parse");
        let local_allow: Vec<&str> = local["permissions"]["allow"].as_array().expect("array").iter().filter_map(|v| v.as_str()).collect();

        assert!(!local_allow.contains(&"Bash(sudo rm:*)"));
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

        run_apply(&gp, &lp, &ApplyFilter { promote: true, remove: false, deny: false, dupe: false }, true, false).expect("apply");

        let global: Value = serde_json::from_str(&std::fs::read_to_string(&gp).expect("read")).expect("parse");
        let local: Value = serde_json::from_str(&std::fs::read_to_string(&lp).expect("read")).expect("parse");

        let count = global["permissions"]["allow"].as_array().expect("array").iter().filter(|v| v.as_str() == Some("Bash(ls:*)")).count();
        assert_eq!(count, 1);
        assert!(!local["permissions"]["allow"].as_array().expect("array").iter().any(|v| v.as_str() == Some("Bash(ls:*)")));
    }

    #[test]
    fn dry_run_does_not_modify_files() {
        let dir = TempDir::new().expect("temp");
        let global_json = r#"{"permissions":{"allow":[]}}"#;
        let local_json = r#"{"permissions":{"allow":["Bash(ls:*)"]}}"#;
        let (gp, lp) = write_settings(dir.path(), global_json, local_json);

        run_apply(&gp, &lp, &ApplyFilter::all(), false, false).expect("apply");

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

        run_apply(&gp, &lp, &ApplyFilter { promote: false, remove: true, deny: false, dupe: false }, true, true).expect("apply");
    }

    #[test]
    fn preserves_non_permission_fields() {
        let dir = TempDir::new().expect("temp");
        let (gp, lp) = write_settings(
            dir.path(),
            r#"{"env":{"FOO":"bar"},"model":"opus","permissions":{"allow":[],"deny":[]},"hooks":{}}"#,
            r#"{"permissions":{"allow":["Bash(ls:*)"]},"enableAllProjectMcpServers":true}"#,
        );

        run_apply(&gp, &lp, &ApplyFilter { promote: true, remove: false, deny: false, dupe: false }, true, false).expect("apply");

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

        run_apply(&gp, &lp, &ApplyFilter { promote: false, remove: false, deny: false, dupe: false }, true, false).expect("apply");

        let local: Value = serde_json::from_str(&std::fs::read_to_string(&lp).expect("read")).expect("parse");
        assert_eq!(local["permissions"]["allow"].as_array().expect("array").len(), 2);
    }

    #[test]
    fn deny_list_rules_not_acted_on() {
        let dir = TempDir::new().expect("temp");
        let (gp, lp) = write_settings(
            dir.path(),
            r#"{"permissions":{"allow":[],"deny":["Bash(git tag -d *)","Bash(rm -rf:*)"]}}"#,
            r#"{"permissions":{"allow":[]}}"#,
        );

        run_apply(&gp, &lp, &ApplyFilter::all(), true, false).expect("apply");

        let global: Value = serde_json::from_str(&std::fs::read_to_string(&gp).expect("read")).expect("parse");
        assert_eq!(global["permissions"]["deny"].as_array().expect("array").len(), 2, "deny list should be unchanged");
    }

    #[test]
    fn missing_local_file_handled() {
        let dir = TempDir::new().expect("temp");
        let gp = dir.path().join("settings.json");
        let lp = dir.path().join("settings.local.json");
        std::fs::write(&gp, r#"{"permissions":{"allow":["Bash(ls:*)"]}}"#).expect("write");

        run_apply(&gp, &lp, &ApplyFilter::all(), true, false).expect("apply");
    }

    #[test]
    fn dupe_removed_from_correct_file() {
        let dir = TempDir::new().expect("temp");
        // Edit(**) is broader - Edit(**/*.rs) is a dupe, lives in global
        let (gp, lp) = write_settings(
            dir.path(),
            r#"{"permissions":{"allow":["Edit(**)", "Edit(**/*.rs)"]}}"#,
            r#"{"permissions":{"allow":[]}}"#,
        );

        run_apply(&gp, &lp, &ApplyFilter { promote: false, remove: false, deny: false, dupe: true }, true, false).expect("apply");

        let global: Value = serde_json::from_str(&std::fs::read_to_string(&gp).expect("read")).expect("parse");
        let global_allow: Vec<&str> = global["permissions"]["allow"].as_array().expect("array").iter().filter_map(|v| v.as_str()).collect();

        assert!(global_allow.contains(&"Edit(**)"));
        assert!(!global_allow.contains(&"Edit(**/*.rs)"), "dupe should be removed");
    }

    #[test]
    fn parse_apply_filter_empty_is_all() {
        let f = parse_apply_filter(&[]).expect("parse");
        assert!(f.promote && f.remove && f.deny && f.dupe);
    }

    #[test]
    fn parse_apply_filter_specific() {
        let f = parse_apply_filter(&["promote".to_string(), "dupe".to_string()]).expect("parse");
        assert!(f.promote);
        assert!(!f.remove);
        assert!(!f.deny);
        assert!(f.dupe);
    }

    #[test]
    fn parse_apply_filter_unknown_errors() {
        assert!(parse_apply_filter(&["foo".to_string()]).is_err());
    }
}
