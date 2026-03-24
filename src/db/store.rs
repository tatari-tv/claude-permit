use eyre::{Context, Result};
use rusqlite::Connection;
use std::path::{Path, PathBuf};

/// Manages the SQLite event database.
pub struct EventStore {
    conn: Connection,
}

impl EventStore {
    /// Open (or create) the database at the given path, with WAL mode and schema init.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("Failed to create database directory")?;
        }

        let conn = Connection::open(path).context("Failed to open SQLite database")?;
        conn.execute_batch("PRAGMA journal_mode=WAL;")
            .context("Failed to set WAL mode")?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT NOT NULL,
                session_id  TEXT NOT NULL,
                tool_name   TEXT NOT NULL,
                tool_input  TEXT NOT NULL,
                raw_input   TEXT,
                risk_tier   TEXT,
                raw_json    TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
            CREATE INDEX IF NOT EXISTS idx_events_tool ON events(tool_name, tool_input);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);",
        )
        .context("Failed to initialize database schema")?;

        Ok(Self { conn })
    }

    /// Default database path: ~/.local/share/claude-permit/events.db
    pub fn default_path() -> Result<PathBuf> {
        let data_dir = dirs::data_local_dir().ok_or_else(|| eyre::eyre!("Could not determine local data directory"))?;
        Ok(data_dir.join("claude-permit").join("events.db"))
    }

    /// Insert a new event.
    pub fn insert_event(
        &self,
        timestamp: &str,
        session_id: &str,
        tool_name: &str,
        tool_input: &str,
        raw_input: Option<&str>,
        risk_tier: Option<&str>,
        raw_json: Option<&str>,
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO events (timestamp, session_id, tool_name, tool_input, raw_input, risk_tier, raw_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    timestamp, session_id, tool_name, tool_input, raw_input, risk_tier, raw_json
                ],
            )
            .context("Failed to insert event")?;
        Ok(())
    }

    /// Count total events in the database.
    pub fn count_events(&self) -> Result<i64> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .context("Failed to count events")?;
        Ok(count)
    }

    /// Check if the database is writable by performing a test write and rollback.
    pub fn is_writable(&self) -> bool {
        self.conn.execute_batch("BEGIN; ROLLBACK;").is_ok()
    }

    /// Query tool invocation patterns grouped by (tool_name, command_prefix),
    /// returning patterns that meet the threshold and session count requirements.
    pub fn suggest_patterns(&self, min_count: u32, min_sessions: u32) -> Result<Vec<PatternSuggestion>> {
        let mut stmt = self.conn.prepare(
            "SELECT tool_name, tool_input, COUNT(*) as cnt, COUNT(DISTINCT session_id) as sessions
             FROM events
             GROUP BY tool_name, tool_input
             HAVING cnt >= ?1 AND sessions >= ?2
             ORDER BY cnt DESC",
        )?;

        let rows = stmt.query_map(rusqlite::params![min_count, min_sessions], |row| {
            Ok(PatternSuggestion {
                tool_name: row.get(0)?,
                tool_input: row.get(1)?,
                count: row.get(2)?,
                sessions: row.get(3)?,
            })
        })?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row.context("Failed to read pattern row")?);
        }
        Ok(results)
    }

    /// Get events for a specific session (or the latest session if None).
    pub fn session_events(&self, session_id: Option<&str>) -> Result<Vec<EventRow>> {
        let rows = if let Some(sid) = session_id {
            let mut stmt = self.conn.prepare(
                "SELECT id, timestamp, session_id, tool_name, tool_input, risk_tier
                 FROM events WHERE session_id = ?1 ORDER BY timestamp",
            )?;
            let rows = stmt.query_map([sid], map_event_row)?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        } else {
            // Get latest session
            let latest: Option<String> = self
                .conn
                .query_row(
                    "SELECT session_id FROM events ORDER BY timestamp DESC LIMIT 1",
                    [],
                    |row| row.get(0),
                )
                .ok();

            match latest {
                Some(sid) => {
                    let mut stmt = self.conn.prepare(
                        "SELECT id, timestamp, session_id, tool_name, tool_input, risk_tier
                         FROM events WHERE session_id = ?1 ORDER BY timestamp",
                    )?;
                    let rows = stmt.query_map([&sid], map_event_row)?;
                    rows.collect::<std::result::Result<Vec<_>, _>>()?
                }
                None => Vec::new(),
            }
        };
        Ok(rows)
    }

    /// Delete events older than the given number of days. Returns count deleted.
    pub fn clean_older_than(&self, days: u32) -> Result<usize> {
        let deleted = self.conn.execute(
            "DELETE FROM events WHERE timestamp < datetime('now', ?1)",
            [format!("-{days} days")],
        )?;
        Ok(deleted)
    }

    /// Count events that would be deleted by clean_older_than.
    pub fn count_older_than(&self, days: u32) -> Result<i64> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM events WHERE timestamp < datetime('now', ?1)",
            [format!("-{days} days")],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Get all distinct session IDs.
    pub fn distinct_sessions(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare("SELECT DISTINCT session_id FROM events")?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }
}

/// A suggested pattern from the database.
#[derive(Debug)]
pub struct PatternSuggestion {
    pub tool_name: String,
    pub tool_input: String,
    pub count: i64,
    pub sessions: i64,
}

/// A row from the events table.
#[derive(Debug)]
pub struct EventRow {
    pub id: i64,
    pub timestamp: String,
    pub session_id: String,
    pub tool_name: String,
    pub tool_input: String,
    pub risk_tier: Option<String>,
}

fn map_event_row(row: &rusqlite::Row) -> rusqlite::Result<EventRow> {
    Ok(EventRow {
        id: row.get(0)?,
        timestamp: row.get(1)?,
        session_id: row.get(2)?,
        tool_name: row.get(3)?,
        tool_input: row.get(4)?,
        risk_tier: row.get(5)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    struct TestDb {
        store: EventStore,
        // Kept alive so the temp dir isn't deleted while tests run.
        // Accessed via path() in tests that need the directory.
        dir: TempDir,
    }

    impl TestDb {
        fn new() -> Self {
            let dir = TempDir::new().expect("create temp dir");
            let db_path = dir.path().join("test.db");
            let store = EventStore::open(&db_path).expect("open store");
            Self { store, dir }
        }

        fn path(&self) -> &Path {
            self.dir.path()
        }
    }

    #[test]
    fn open_creates_db_and_tables() {
        let t = TestDb::new();
        assert!(t.store.is_writable());
        assert_eq!(t.store.count_events().expect("count"), 0);
    }

    #[test]
    fn insert_and_count() {
        let t = TestDb::new();
        t.store
            .insert_event(
                "2026-03-24T12:00:00Z",
                "session-1",
                "Bash",
                "git status",
                Some(r#"{"command":"git status"}"#),
                Some("safe"),
                None,
            )
            .expect("insert");
        assert_eq!(t.store.count_events().expect("count"), 1);

        t.store
            .insert_event(
                "2026-03-24T12:01:00Z",
                "session-1",
                "Edit",
                "/tmp/foo.rs",
                None,
                Some("moderate"),
                None,
            )
            .expect("insert");
        assert_eq!(t.store.count_events().expect("count"), 2);
    }

    #[test]
    fn open_idempotent() {
        let t = TestDb::new();
        let db_path = t.path().join("reopen.db");
        let store1 = EventStore::open(&db_path).expect("open 1");
        store1
            .insert_event("2026-03-24T12:00:00Z", "s1", "Bash", "ls", None, None, None)
            .expect("insert");
        drop(store1);

        // Re-opening should not lose data
        let store2 = EventStore::open(&db_path).expect("open 2");
        assert_eq!(store2.count_events().expect("count"), 1);
    }

    #[test]
    fn creates_parent_directories() {
        let t = TestDb::new();
        let db_path = t.path().join("nested").join("dirs").join("test.db");
        let store = EventStore::open(&db_path).expect("open");
        assert!(store.is_writable());
    }
}
