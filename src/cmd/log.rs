use eyre::Result;
use serde_json::json;
use std::io::Read;

use crate::db::EventStore;
use crate::hook::{HookPayload, normalize_tool_input};
use crate::risk::Rules;

/// The result of running the log command - either passthrough or deny.
pub enum LogResult {
    /// Passthrough: output `{}` to not affect the hook pipeline.
    Passthrough,
    /// Deny: output a deny decision with a reason.
    Deny(String),
}

impl LogResult {
    /// Serialize to the JSON string to output on stdout.
    pub fn to_json(&self) -> String {
        match self {
            LogResult::Passthrough => "{}".to_string(),
            LogResult::Deny(reason) => {
                let output = json!({
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": reason
                    }
                });
                output.to_string()
            }
        }
    }
}

/// Run the `log` subcommand: read hook JSON from stdin, write event to DB.
///
/// If `rules.enforce_deny` is true and the command matches a deny pattern,
/// returns a Deny result instead of Passthrough.
pub fn run_log(store: &EventStore, rules: &Rules) -> Result<LogResult> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;

    let payload: HookPayload = serde_json::from_str(&input)?;

    let normalized = normalize_tool_input(&payload.tool_name, &payload.tool_input);
    let raw_input = serde_json::to_string(&payload.tool_input)?;
    let session_id = payload.session_id.as_deref().unwrap_or("unknown");
    let timestamp = chrono::Utc::now().to_rfc3339();
    let tier = rules.classify_tool_input(&payload.tool_name, &normalized);

    store.insert_event(
        &timestamp,
        session_id,
        &payload.tool_name,
        &normalized,
        Some(&raw_input),
        Some(&tier.to_string()),
        Some(&input),
    )?;

    // Check deny enforcement
    if rules.enforce_deny && payload.tool_name == "Bash" && rules.matches_deny_list(&normalized) {
        return Ok(LogResult::Deny(deny_reason(&normalized)));
    }

    Ok(LogResult::Passthrough)
}

fn deny_reason(cmd: &str) -> String {
    if cmd.starts_with("rm ") {
        format!("'{cmd}' is permanently denied; rm is dangerous")
    } else if cmd.starts_with("cd ") && cmd.contains("&&") {
        format!("'{cmd}' is permanently denied; compound cd commands are a security risk")
    } else if cmd.starts_with("git tag -d") {
        format!("'{cmd}' is permanently denied; git tag deletion is not allowed")
    } else if cmd.contains(":refs/tags/") || (cmd.contains("--delete") && cmd.contains("tag")) {
        format!("'{cmd}' is permanently denied; remote tag deletion is not allowed")
    } else {
        format!("'{cmd}' matches a permanent deny pattern")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_result_passthrough_json() {
        let result = LogResult::Passthrough;
        assert_eq!(result.to_json(), "{}");
    }

    #[test]
    fn log_result_deny_json() {
        let result = LogResult::Deny("test reason".to_string());
        let json = result.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed["hookSpecificOutput"]["permissionDecision"], "deny");
        assert_eq!(parsed["hookSpecificOutput"]["permissionDecisionReason"], "test reason");
    }

    #[test]
    fn deny_reason_rm() {
        assert!(deny_reason("rm -rf /tmp").contains("rm is dangerous"));
        assert!(deny_reason("rm /tmp/file").contains("rm is dangerous"));
    }

    #[test]
    fn deny_reason_cd_and() {
        let reason = deny_reason("cd /tmp && rm -rf .");
        assert!(reason.contains("security risk"));
    }

    #[test]
    fn deny_reason_git_tag() {
        let reason = deny_reason("git tag -d v1.0");
        assert!(reason.contains("not allowed"));
    }

    #[test]
    fn log_inserts_event_with_tier() {
        use crate::hook::HookPayload;
        use crate::hook::normalize_tool_input;

        let dir = tempfile::TempDir::new().expect("temp dir");
        let store = EventStore::open(&dir.path().join("test.db")).expect("open");
        let rules = Rules::default();

        let json = r#"{"tool_name":"Bash","tool_input":{"command":"git status"},"session_id":"s1"}"#;

        let payload: HookPayload = serde_json::from_str(json).expect("parse");
        let normalized = normalize_tool_input(&payload.tool_name, &payload.tool_input);
        let raw_input = serde_json::to_string(&payload.tool_input).expect("serialize");
        let session_id = payload.session_id.as_deref().unwrap_or("unknown");
        let timestamp = chrono::Utc::now().to_rfc3339();
        let tier = rules.classify_tool_input(&payload.tool_name, &normalized);

        store
            .insert_event(
                &timestamp,
                session_id,
                &payload.tool_name,
                &normalized,
                Some(&raw_input),
                Some(&tier.to_string()),
                Some(json),
            )
            .expect("insert");

        assert_eq!(store.count_events().expect("count"), 1);
    }
}
