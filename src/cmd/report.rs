use eyre::Result;
use serde::Serialize;

use crate::db::EventStore;
use crate::pager::page_output;
use crate::risk::{RiskTier, classify_tool_input};

/// Summary of a session's permission activity.
#[derive(Debug, Serialize)]
pub struct SessionReport {
    pub session_id: String,
    pub total_events: usize,
    pub safe_count: usize,
    pub moderate_count: usize,
    pub dangerous_count: usize,
    pub tool_counts: Vec<ToolCount>,
    pub dangerous_events: Vec<DangerousEvent>,
}

#[derive(Debug, Serialize)]
pub struct ToolCount {
    pub tool_name: String,
    pub count: usize,
}

#[derive(Debug, Serialize)]
pub struct DangerousEvent {
    pub tool_name: String,
    pub tool_input: String,
    pub timestamp: String,
}

/// Generate a session report.
pub fn report(store: &EventStore, session_id: Option<&str>) -> Result<SessionReport> {
    let events = store.session_events(session_id)?;

    if events.is_empty() {
        return Ok(SessionReport {
            session_id: session_id.unwrap_or("(none)").to_string(),
            total_events: 0,
            safe_count: 0,
            moderate_count: 0,
            dangerous_count: 0,
            tool_counts: Vec::new(),
            dangerous_events: Vec::new(),
        });
    }

    let sid = events[0].session_id.clone();
    let mut safe = 0;
    let mut moderate = 0;
    let mut dangerous = 0;
    let mut tool_map: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut dangerous_events = Vec::new();

    for event in &events {
        let tier = classify_tool_input(&event.tool_name, &event.tool_input);
        match tier {
            RiskTier::Safe => safe += 1,
            RiskTier::Moderate => moderate += 1,
            RiskTier::Dangerous => {
                dangerous += 1;
                dangerous_events.push(DangerousEvent {
                    tool_name: event.tool_name.clone(),
                    tool_input: event.tool_input.clone(),
                    timestamp: event.timestamp.clone(),
                });
            }
        }
        *tool_map.entry(event.tool_name.clone()).or_default() += 1;
    }

    let mut tool_counts: Vec<ToolCount> = tool_map
        .into_iter()
        .map(|(tool_name, count)| ToolCount { tool_name, count })
        .collect();
    tool_counts.sort_by(|a, b| b.count.cmp(&a.count));

    Ok(SessionReport {
        session_id: sid,
        total_events: events.len(),
        safe_count: safe,
        moderate_count: moderate,
        dangerous_count: dangerous,
        tool_counts,
        dangerous_events,
    })
}

/// Run the report command with output formatting.
pub fn run_report(store: &EventStore, session_id: Option<&str>, format: &str, pager: Option<&str>) -> Result<()> {
    let rep = report(store, session_id)?;

    if rep.total_events == 0 {
        println!("No events found for session {}.", rep.session_id);
        return Ok(());
    }

    match format {
        "json" => println!("{}", serde_json::to_string_pretty(&rep)?),
        _ => {
            let mut out = String::new();
            out.push_str(&format!("Session: {}\n", rep.session_id));
            out.push_str(&format!(
                "Events: {} total ({} safe, {} moderate, {} dangerous)\n",
                rep.total_events, rep.safe_count, rep.moderate_count, rep.dangerous_count
            ));
            out.push('\n');

            if !rep.tool_counts.is_empty() {
                out.push_str("Tool usage:\n");
                for tc in &rep.tool_counts {
                    out.push_str(&format!("  {:<20} {}\n", tc.tool_name, tc.count));
                }
                out.push('\n');
            }

            if !rep.dangerous_events.is_empty() {
                out.push_str("Dangerous activity:\n");
                for de in &rep.dangerous_events {
                    out.push_str(&format!("  {} {} ({})\n", de.tool_name, de.tool_input, de.timestamp));
                }
            }

            page_output(&out, pager);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_empty_session() {
        let dir = tempfile::TempDir::new().expect("temp");
        let store = EventStore::open(&dir.path().join("test.db")).expect("open");
        let rep = report(&store, Some("nonexistent")).expect("report");
        assert_eq!(rep.total_events, 0);
    }

    #[test]
    fn report_counts_tiers() {
        let dir = tempfile::TempDir::new().expect("temp");
        let store = EventStore::open(&dir.path().join("test.db")).expect("open");

        store
            .insert_event("2026-03-24T12:00:00Z", "s1", "Bash", "ls -la", None, None, None)
            .expect("insert");
        store
            .insert_event(
                "2026-03-24T12:01:00Z",
                "s1",
                "Bash",
                "git commit -m test",
                None,
                None,
                None,
            )
            .expect("insert");
        store
            .insert_event("2026-03-24T12:02:00Z", "s1", "Bash", "sudo rm /tmp/x", None, None, None)
            .expect("insert");

        let rep = report(&store, Some("s1")).expect("report");
        assert_eq!(rep.total_events, 3);
        assert_eq!(rep.safe_count, 1);
        assert_eq!(rep.moderate_count, 1);
        assert_eq!(rep.dangerous_count, 1);
        assert_eq!(rep.dangerous_events.len(), 1);
        assert_eq!(rep.dangerous_events[0].tool_input, "sudo rm /tmp/x");
    }

    #[test]
    fn report_latest_session() {
        let dir = tempfile::TempDir::new().expect("temp");
        let store = EventStore::open(&dir.path().join("test.db")).expect("open");

        store
            .insert_event("2026-03-24T10:00:00Z", "old", "Bash", "ls", None, None, None)
            .expect("insert");
        store
            .insert_event("2026-03-24T12:00:00Z", "new", "Bash", "tree", None, None, None)
            .expect("insert");

        let rep = report(&store, None).expect("report");
        assert_eq!(rep.session_id, "new");
        assert_eq!(rep.total_events, 1);
    }
}
