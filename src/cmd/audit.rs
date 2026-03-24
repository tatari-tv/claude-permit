use eyre::Result;
use serde::Serialize;
use std::path::Path;

use crate::risk::{Recommendation, RiskTier, classify_rule, recommend};
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

    // Apply risk filter if specified
    if let Some(filter) = risk_filter {
        entries.retain(|e| e.risk == filter);
    }

    Ok(entries)
}

/// Format audit entries as a table string.
pub fn format_table(entries: &[AuditEntry]) -> String {
    if entries.is_empty() {
        return "No rules found.".to_string();
    }

    // Column widths
    let rule_width = entries.iter().map(|e| e.rule.len()).max().unwrap_or(4).clamp(4, 60);
    let list_width = 5;
    let source_width = 6;
    let risk_width = 9;
    let rec_width = 14;

    let mut out = String::new();

    // Header
    out.push_str(&format!(
        "{:<rule_width$}  {:<list_width$}  {:<source_width$}  {:<risk_width$}  {:<rec_width$}\n",
        "Rule", "List", "Source", "Risk", "Recommendation"
    ));
    out.push_str(&format!(
        "{:-<rule_width$}  {:-<list_width$}  {:-<source_width$}  {:-<risk_width$}  {:-<rec_width$}\n",
        "", "", "", "", ""
    ));

    // Rows
    for entry in entries {
        let rule_display = if entry.rule.len() > rule_width {
            format!("{}...", &entry.rule[..rule_width - 3])
        } else {
            entry.rule.clone()
        };
        out.push_str(&format!(
            "{:<rule_width$}  {:<list_width$}  {:<source_width$}  {:<risk_width$}  {:<rec_width$}\n",
            rule_display, entry.list, entry.source, entry.risk, entry.recommendation
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
    format: &str,
    risk_filter: Option<RiskTier>,
) -> Result<()> {
    let entries = audit(settings_path, settings_local_path, risk_filter)?;

    match format {
        "json" => println!("{}", format_json(&entries)?),
        "markdown" => {
            // Markdown uses same table format with pipes
            for entry in &entries {
                println!(
                    "| {} | {} | {} | {} | {} |",
                    entry.rule, entry.list, entry.source, entry.risk, entry.recommendation
                );
            }
        }
        _ => print!("{}", format_table(&entries)),
    }

    // Summary
    let total = entries.len();
    let deny_count = entries
        .iter()
        .filter(|e| e.recommendation == Recommendation::Deny)
        .count();
    let narrow_count = entries
        .iter()
        .filter(|e| e.recommendation == Recommendation::Narrow)
        .count();
    let promote_count = entries
        .iter()
        .filter(|e| e.recommendation == Recommendation::Promote)
        .count();
    let remove_count = entries
        .iter()
        .filter(|e| e.recommendation == Recommendation::Remove)
        .count();

    eprintln!(
        "\n{total} rules audited: {promote_count} promote, {narrow_count} narrow, {remove_count} remove, {deny_count} deny"
    );

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

        let entries = audit(&gp, &lp, None).expect("audit");
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

        let entries = audit(&gp, &lp, Some(RiskTier::Dangerous)).expect("audit");
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

        let entries = audit(&gp, &lp, None).expect("audit");
        assert_eq!(entries[0].recommendation, Recommendation::Narrow);
    }
}
