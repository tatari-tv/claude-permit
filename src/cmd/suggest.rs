use std::collections::HashMap;

use eyre::Result;
use serde::Serialize;

use crate::db::EventStore;
use crate::risk::{RiskTier, classify_tool_input};

/// Internal Claude mechanics tools - not relevant for permission rules.
const SKIP_TOOLS: &[&str] = &[
    "TaskCreate",
    "TaskUpdate",
    "TaskGet",
    "TaskList",
    "TaskStop",
    "TaskOutput",
    "ExitPlanMode",
    "EnterPlanMode",
    "SendMessage",
    "ToolSearch",
    "Skill",
    "Agent",
];

/// A suggestion row for output.
#[derive(Debug, Serialize)]
pub struct SuggestEntry {
    pub pattern: String,
    pub count: i64,
    pub sessions: i64,
    pub suggested_rule: String,
    pub risk: RiskTier,
}

/// Generate suggestions from the event database.
pub fn suggest(store: &EventStore, threshold: u32, min_sessions: u32) -> Result<Vec<SuggestEntry>> {
    let patterns = store.suggest_patterns(threshold, min_sessions)?;

    // Compute suggested rules, filtering noise tools.
    // DB returns rows ordered by count DESC, so first hit per rule is highest-frequency.
    let raw: Vec<(String, String, i64, i64, RiskTier)> = patterns
        .into_iter()
        .filter(|p| !SKIP_TOOLS.contains(&p.tool_name.as_str()))
        .map(|p| {
            let risk = classify_tool_input(&p.tool_name, &p.tool_input);
            let suggested_rule = make_rule(&p.tool_name, &p.tool_input);
            let pattern = format_pattern(&p.tool_name, &p.tool_input);
            (pattern, suggested_rule, p.count, p.sessions, risk)
        })
        .collect();

    // Deduplicate by suggested_rule: sum counts, take max sessions.
    // Multiple raw inputs can normalize to the same rule (e.g. "otto ci --flag1"
    // and "otto ci --flag2" both become Bash(otto ci:*)).
    let mut deduped: HashMap<String, (String, i64, i64, RiskTier)> = HashMap::new();
    for (pattern, rule, count, sessions, risk) in raw {
        let entry = deduped
            .entry(rule.clone())
            .or_insert_with(|| (pattern, 0, 0, risk));
        entry.1 += count;
        if sessions > entry.2 {
            entry.2 = sessions;
        }
    }

    let mut entries: Vec<SuggestEntry> = deduped
        .into_iter()
        .map(|(rule, (pattern, count, sessions, risk))| SuggestEntry {
            pattern,
            count,
            sessions,
            suggested_rule: rule,
            risk,
        })
        .collect();

    entries.sort_by(|a, b| b.count.cmp(&a.count));

    Ok(entries)
}

/// Build a Claude Code permission rule string from a tool invocation.
fn make_rule(tool_name: &str, tool_input: &str) -> String {
    match tool_name {
        "Bash" => {
            let prefix = command_prefix(tool_input);
            format!("Bash({prefix}:*)")
        }
        "Edit" | "Write" | "Read" | "Glob" | "Grep" => {
            tool_name.to_string()
        }
        "WebFetch" => {
            if let Some(domain) = extract_domain(tool_input) {
                format!("WebFetch(domain:{domain})")
            } else {
                format!("WebFetch({tool_input})")
            }
        }
        name if name.starts_with("mcp__") => name.to_string(),
        _ => format!("{tool_name}({tool_input})"),
    }
}

/// Extract the command prefix (first word or two-word compound like "git status").
fn command_prefix(cmd: &str) -> String {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    match parts.as_slice() {
        [] => String::new(),
        [single] => (*single).to_string(),
        [first, second, ..] => {
            let compound = ["git", "docker", "cargo", "gh", "otto", "sudo", "systemctl", "apt"];
            if compound.contains(first) {
                format!("{first} {second}")
            } else {
                (*first).to_string()
            }
        }
    }
}

/// Format a short human-readable pattern label.
fn format_pattern(tool_name: &str, tool_input: &str) -> String {
    match tool_name {
        "Bash" => command_prefix(tool_input),
        "Read" | "Edit" | "Write" | "Glob" | "Grep" => {
            tool_name.to_string()
        }
        _ => {
            let input = collapse_home(tool_input);
            format!("{tool_name} {input}")
        }
    }
}

/// Replace $HOME prefix with `~`.
fn collapse_home(path: &str) -> String {
    if let Some(home) = dirs::home_dir() {
        let home_str = home.to_string_lossy();
        if let Some(rest) = path.strip_prefix(home_str.as_ref()) {
            return format!("~{rest}");
        }
    }
    path.to_string()
}

/// Truncate a string to `max` chars, appending `...` if cut.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut = s.char_indices().nth(max - 3).map(|(i, _)| i).unwrap_or(s.len());
        format!("{}...", &s[..cut])
    }
}

/// Extract domain from a URL.
fn extract_domain(url: &str) -> Option<String> {
    url.split("//")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .map(|s| s.to_string())
}

/// Run the suggest command with output formatting.
pub fn run_suggest(store: &EventStore, threshold: u32, min_sessions: u32, format: &str) -> Result<()> {
    let entries = suggest(store, threshold, min_sessions)?;

    if entries.is_empty() {
        println!("No patterns meet the threshold ({threshold} observations, {min_sessions} sessions).");
        return Ok(());
    }

    match format {
        "json" => println!("{}", serde_json::to_string_pretty(&entries)?),
        _ => {
            const PAT_MAX: usize = 36;
            const RULE_MAX: usize = 48;

            println!(
                "{:<PAT_MAX$}  {:>5}  {:>8}  {:<RULE_MAX$}  {}",
                "Pattern", "Count", "Sessions", "Suggested Rule", "Risk"
            );
            println!(
                "{:-<PAT_MAX$}  {:->5}  {:->8}  {:-<RULE_MAX$}  {:-<8}",
                "", "", "", "", ""
            );

            for entry in &entries {
                println!(
                    "{:<PAT_MAX$}  {:>5}  {:>8}  {:<RULE_MAX$}  {}",
                    truncate(&entry.pattern, PAT_MAX),
                    entry.count,
                    entry.sessions,
                    truncate(&entry.suggested_rule, RULE_MAX),
                    entry.risk
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_prefix_single() {
        assert_eq!(command_prefix("ls -la"), "ls");
    }

    #[test]
    fn command_prefix_compound() {
        assert_eq!(command_prefix("git status --short"), "git status");
        assert_eq!(command_prefix("cargo build --release"), "cargo build");
        assert_eq!(command_prefix("docker compose up"), "docker compose");
    }

    #[test]
    fn command_prefix_non_compound() {
        assert_eq!(command_prefix("mkdir -p src"), "mkdir");
        assert_eq!(command_prefix("chmod 755 foo"), "chmod");
    }

    #[test]
    fn make_rule_bash() {
        assert_eq!(make_rule("Bash", "git status --short"), "Bash(git status:*)");
        assert_eq!(make_rule("Bash", "ls -la"), "Bash(ls:*)");
    }

    #[test]
    fn make_rule_webfetch() {
        assert_eq!(
            make_rule("WebFetch", "https://docs.rs/clap"),
            "WebFetch(domain:docs.rs)"
        );
    }

    #[test]
    fn make_rule_mcp() {
        assert_eq!(
            make_rule("mcp__atlassian__getJiraIssue", "{}"),
            "mcp__atlassian__getJiraIssue"
        );
    }

    #[test]
    fn truncate_short() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn truncate_long() {
        let s = "abcdefghijklmnop";
        let result = truncate(s, 10);
        assert_eq!(result, "abcdefg...");
        assert_eq!(result.chars().count(), 10);
    }

    #[test]
    fn suggest_deduplicates_bash_variants() {
        let dir = tempfile::TempDir::new().expect("temp");
        let store = crate::db::EventStore::open(&dir.path().join("test.db")).expect("open");

        // Two variants of "otto ci" with different flags, across enough sessions
        for i in 0..5 {
            let session = format!("s{i}");
            store
                .insert_event(
                    "2026-03-24T12:00:00Z",
                    &session,
                    "Bash",
                    "otto ci --fast",
                    None,
                    None,
                    None,
                )
                .expect("insert");
            store
                .insert_event(
                    "2026-03-24T12:01:00Z",
                    &session,
                    "Bash",
                    "otto ci",
                    None,
                    None,
                    None,
                )
                .expect("insert");
        }

        let entries = suggest(&store, 3, 2).expect("suggest");
        // Both variants normalize to Bash(otto ci:*) - should be one entry
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].suggested_rule, "Bash(otto ci:*)");
        assert_eq!(entries[0].count, 10); // summed
    }

    #[test]
    fn suggest_filters_task_tools() {
        let dir = tempfile::TempDir::new().expect("temp");
        let store = crate::db::EventStore::open(&dir.path().join("test.db")).expect("open");

        for i in 0..5 {
            let session = format!("s{i}");
            store
                .insert_event(
                    "2026-03-24T12:00:00Z",
                    &session,
                    "TaskUpdate",
                    r#"{"status":"completed","taskId":"1"}"#,
                    None,
                    None,
                    None,
                )
                .expect("insert");
        }

        let entries = suggest(&store, 3, 2).expect("suggest");
        assert!(entries.is_empty(), "TaskUpdate should be filtered out");
    }

    #[test]
    fn suggest_with_db() {
        let dir = tempfile::TempDir::new().expect("temp");
        let store = crate::db::EventStore::open(&dir.path().join("test.db")).expect("open");

        for i in 0..5 {
            let session = format!("s{}", i % 3);
            store
                .insert_event(
                    "2026-03-24T12:00:00Z",
                    &session,
                    "Bash",
                    "git status --short",
                    None,
                    None,
                    None,
                )
                .expect("insert");
        }

        let entries = suggest(&store, 3, 2).expect("suggest");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].pattern, "git status");
        assert_eq!(entries[0].count, 5);
        assert_eq!(entries[0].suggested_rule, "Bash(git status:*)");
    }
}
