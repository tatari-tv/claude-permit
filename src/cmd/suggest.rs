use eyre::Result;
use serde::Serialize;

use crate::db::EventStore;
use crate::risk::{RiskTier, classify_tool_input};

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

    let entries: Vec<SuggestEntry> = patterns
        .into_iter()
        .map(|p| {
            let risk = classify_tool_input(&p.tool_name, &p.tool_input);
            let suggested_rule = make_rule(&p.tool_name, &p.tool_input);
            let pattern = format_pattern(&p.tool_name, &p.tool_input);
            SuggestEntry {
                pattern,
                count: p.count,
                sessions: p.sessions,
                suggested_rule,
                risk,
            }
        })
        .collect();

    Ok(entries)
}

/// Build a Claude Code permission rule string from a tool invocation.
fn make_rule(tool_name: &str, tool_input: &str) -> String {
    match tool_name {
        "Bash" => {
            let prefix = command_prefix(tool_input);
            format!("Bash({prefix}:*)")
        }
        "Edit" | "Write" | "Read" => {
            // Derive a glob from the file path
            format!("{tool_name}({tool_input})")
        }
        "WebFetch" => {
            // Extract domain from URL
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
            // Two-word prefixes for common compound commands
            let compound = ["git", "docker", "cargo", "gh", "otto", "sudo", "systemctl", "apt"];
            if compound.contains(first) {
                format!("{first} {second}")
            } else {
                (*first).to_string()
            }
        }
    }
}

/// Format a human-readable pattern description.
fn format_pattern(tool_name: &str, tool_input: &str) -> String {
    match tool_name {
        "Bash" => command_prefix(tool_input),
        _ => format!("{tool_name}:{tool_input}"),
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
            let pattern_width = entries.iter().map(|e| e.pattern.len()).max().unwrap_or(7).clamp(7, 30);
            let rule_width = entries
                .iter()
                .map(|e| e.suggested_rule.len())
                .max()
                .unwrap_or(14)
                .clamp(14, 40);

            println!(
                "{:<pattern_width$}  {:>5}  {:>8}  {:<rule_width$}  Risk",
                "Pattern", "Count", "Sessions", "Suggested Rule"
            );
            println!(
                "{:-<pattern_width$}  {:->5}  {:->8}  {:-<rule_width$}  {:-<9}",
                "", "", "", "", ""
            );

            for entry in &entries {
                println!(
                    "{:<pattern_width$}  {:>5}  {:>8}  {:<rule_width$}  {}",
                    entry.pattern, entry.count, entry.sessions, entry.suggested_rule, entry.risk
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
    fn extract_domain_basic() {
        assert_eq!(extract_domain("https://docs.rs/clap"), Some("docs.rs".into()));
        assert_eq!(extract_domain("http://example.com/path"), Some("example.com".into()));
    }

    #[test]
    fn suggest_with_db() {
        let dir = tempfile::TempDir::new().expect("temp");
        let store = EventStore::open(&dir.path().join("test.db")).expect("open");

        // Insert events across multiple sessions
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
