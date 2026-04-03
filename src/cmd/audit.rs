use eyre::Result;
use serde::Serialize;
use std::path::Path;

use crate::cmd::apply::{apply_entries, parse_apply_filter};
use crate::filter::filter_by_patterns;
use crate::pager::page_output;
use crate::risk::{Recommendation, RiskTier, classify_rule, recommend, subsumes};
use crate::settings::load_settings;

/// A single row in the audit output.
#[derive(Debug, Serialize)]
pub struct AuditEntry {
    pub rule: String,
    pub list: String,
    pub source: String,
    pub risk: RiskTier,
    pub recommendation: Recommendation,
}

/// Run the audit: load settings, classify each rule, produce entries.
pub fn audit(
    settings_path: &Path,
    settings_local_path: &Path,
    patterns: &[String],
    risk_filter: Option<RiskTier>,
) -> Result<Vec<AuditEntry>> {
    let rules = load_settings(settings_path, settings_local_path)?;
    let mut entries: Vec<AuditEntry> = rules
        .into_iter()
        .map(|r| {
            let tier = classify_rule(&r.rule);
            let source_str = r.source.to_string();
            let rec = recommend(tier, &source_str, &r.rule);
            AuditEntry {
                rule: r.rule,
                list: r.list.to_string(),
                source: source_str,
                risk: tier,
                recommendation: rec,
            }
        })
        .collect();

    // Mark rules made redundant by a broader rule in the same list (allow or deny).
    // Cross-list matches are intentional: deny rules carve out from a broad allow.
    // Permanent-deny rules (Recommendation::Deny) are never overridden.
    let snapshots: Vec<(String, String)> = entries
        .iter()
        .map(|e| (e.list.clone(), e.rule.clone()))
        .collect();
    for i in 0..entries.len() {
        if entries[i].recommendation == Recommendation::Deny {
            continue;
        }
        let covered = snapshots.iter().enumerate().any(|(j, (list, rule))| {
            j != i && *list == entries[i].list && subsumes(rule, &entries[i].rule)
        });
        if covered {
            entries[i].recommendation = Recommendation::Dupe;
        }
    }

    // Apply pattern filter (exact -> prefix -> substring cascade)
    let entries = filter_by_patterns(entries, patterns, |e| e.rule.as_str());

    // Apply risk filter on the already-narrowed set
    let entries = if let Some(filter) = risk_filter {
        entries.into_iter().filter(|e| e.risk == filter).collect()
    } else {
        entries
    };

    Ok(entries)
}

/// Format audit entries as a table string.
pub fn format_table(entries: &[AuditEntry]) -> String {
    if entries.is_empty() {
        return "No rules found.".to_string();
    }

    let source_width = 6;
    let risk_width = 9;
    let action_width = 7; // "promote" is the longest value
    let list_width = 5;

    let mut out = String::new();

    // Header — Rule is last so it needs no padding
    out.push_str(&format!(
        "{:<source_width$}  {:<risk_width$}  {:<action_width$}  {:<list_width$}  {}\n",
        "Source", "Risk", "Action", "List", "Rule"
    ));
    out.push_str(&format!(
        "{:-<source_width$}  {:-<risk_width$}  {:-<action_width$}  {:-<list_width$}  {:-<4}\n",
        "", "", "", "", ""
    ));

    // Rows
    for entry in entries {
        out.push_str(&format!(
            "{:<source_width$}  {:<risk_width$}  {:<action_width$}  {:<list_width$}  {}\n",
            entry.source, entry.risk, entry.recommendation, entry.list, entry.rule
        ));
    }

    out
}

/// Format audit entries as JSON.
pub fn format_json(entries: &[AuditEntry]) -> Result<String> {
    Ok(serde_json::to_string_pretty(entries)?)
}

/// Run the full audit command with output formatting.
pub fn run_audit(
    settings_path: &Path,
    settings_local_path: &Path,
    patterns: &[String],
    format: &str,
    risk_filter: Option<RiskTier>,
    apply: Option<&[String]>,
    pager: Option<&str>,
) -> Result<()> {
    let entries = audit(settings_path, settings_local_path, patterns, risk_filter)?;

    match format {
        "json" => println!("{}", format_json(&entries)?),
        "markdown" => {
            let mut out = String::new();
            for entry in &entries {
                out.push_str(&format!(
                    "| {} | {} | {} | {} | {} |\n",
                    entry.source, entry.risk, entry.recommendation, entry.list, entry.rule
                ));
            }
            page_output(&out, pager);
        }
        _ => page_output(&format_table(&entries), pager),
    }

    let total = entries.len();
    let deny_count = entries.iter().filter(|e| e.recommendation == Recommendation::Deny).count();
    let narrow_count = entries.iter().filter(|e| e.recommendation == Recommendation::Narrow).count();
    let promote_count = entries.iter().filter(|e| e.recommendation == Recommendation::Promote).count();
    let remove_count = entries.iter().filter(|e| e.recommendation == Recommendation::Remove).count();
    let dupe_count = entries.iter().filter(|e| e.recommendation == Recommendation::Dupe).count();

    eprintln!(
        "\n{total} rules audited: {promote_count} promote, {narrow_count} narrow, {remove_count} remove, {deny_count} deny, {dupe_count} dupe"
    );

    if let Some(actions) = apply {
        let filter = parse_apply_filter(actions)?;
        apply_entries(&entries, &filter, settings_path, settings_local_path, true, true)?;
    }

    Ok(())
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
    fn audit_classifies_rules() {
        let dir = TempDir::new().expect("temp");
        let (gp, lp) = write_settings(
            dir.path(),
            r#"{"permissions":{"allow":["Bash(ls:*)","Bash(git tag:*)"],"deny":["Bash(git tag -d *)"]}}"#,
            r#"{"permissions":{"allow":["Bash(sudo rm:*)","WebSearch"]}}"#,
        );

        let entries = audit(&gp, &lp, &[], None).expect("audit");
        assert_eq!(entries.len(), 5);

        // ls is safe
        let ls = entries.iter().find(|e| e.rule == "Bash(ls:*)").expect("ls");
        assert_eq!(ls.risk, RiskTier::Safe);

        // sudo rm is dangerous
        let sudo = entries.iter().find(|e| e.rule == "Bash(sudo rm:*)").expect("sudo");
        assert_eq!(sudo.risk, RiskTier::Dangerous);
        assert_eq!(sudo.recommendation, Recommendation::Remove);

        // WebSearch is safe and local - should promote
        let ws = entries.iter().find(|e| e.rule == "WebSearch").expect("ws");
        assert_eq!(ws.risk, RiskTier::Safe);
        assert_eq!(ws.recommendation, Recommendation::Promote);
    }

    #[test]
    fn audit_risk_filter() {
        let dir = TempDir::new().expect("temp");
        let (gp, lp) = write_settings(
            dir.path(),
            r#"{"permissions":{"allow":["Bash(ls:*)","Bash(sudo rm:*)"]}}"#,
            r#"{"permissions":{}}"#,
        );

        let entries = audit(&gp, &lp, &[], Some(RiskTier::Dangerous)).expect("audit");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].rule, "Bash(sudo rm:*)");
    }

    #[test]
    fn format_table_empty() {
        let result = format_table(&[]);
        assert_eq!(result, "No rules found.");
    }

    #[test]
    fn format_table_has_header() {
        let entries = vec![AuditEntry {
            rule: "Bash(ls:*)".to_string(),
            list: "allow".to_string(),
            source: "global".to_string(),
            risk: RiskTier::Safe,
            recommendation: Recommendation::Keep,
        }];
        let table = format_table(&entries);
        assert!(table.contains("Rule"));
        assert!(table.contains("Risk"));
        assert!(table.contains("Bash(ls:*)"));
    }

    #[test]
    fn format_json_valid() {
        let entries = vec![AuditEntry {
            rule: "Bash(ls:*)".to_string(),
            list: "allow".to_string(),
            source: "global".to_string(),
            risk: RiskTier::Safe,
            recommendation: Recommendation::Keep,
        }];
        let json = format_json(&entries).expect("json");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert!(parsed.is_array());
    }

    #[test]
    fn narrow_recommendation_for_broad_patterns() {
        let dir = TempDir::new().expect("temp");
        let (gp, lp) = write_settings(
            dir.path(),
            r#"{"permissions":{"allow":["Bash(git:*)"]}}"#,
            r#"{"permissions":{}}"#,
        );

        let entries = audit(&gp, &lp, &[], None).expect("audit");
        assert_eq!(entries[0].recommendation, Recommendation::Narrow);
    }

    #[test]
    fn redundant_when_broader_rule_exists() {
        let dir = TempDir::new().expect("temp");
        // Edit(**) is broader than Edit(**/*.rs) — the specific one should be redundant
        let (gp, lp) = write_settings(
            dir.path(),
            r#"{"permissions":{"allow":["Edit(**)", "Edit(**/*.rs)", "Bash(git:*)", "Bash(git status:*)"]}}"#,
            r#"{"permissions":{}}"#,
        );

        let entries = audit(&gp, &lp, &[], None).expect("audit");

        let edit_specific = entries.iter().find(|e| e.rule == "Edit(**/*.rs)").expect("edit specific");
        assert_eq!(edit_specific.recommendation, Recommendation::Dupe);

        let git_specific = entries.iter().find(|e| e.rule == "Bash(git status:*)").expect("git status");
        assert_eq!(git_specific.recommendation, Recommendation::Dupe);

        // The broader rules keep their own recommendations
        let edit_broad = entries.iter().find(|e| e.rule == "Edit(**)").expect("edit broad");
        assert_ne!(edit_broad.recommendation, Recommendation::Dupe);
    }
}
