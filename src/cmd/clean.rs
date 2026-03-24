use colored::*;
use eyre::Result;

use crate::db::EventStore;

/// Run the clean command: prune old events.
pub fn run_clean(store: &EventStore, older_than_days: u32, dry_run: bool) -> Result<()> {
    if dry_run {
        let count = store.count_older_than(older_than_days)?;
        println!("Would delete {count} events older than {older_than_days} days (dry run, no changes made).");
    } else {
        let deleted = store.clean_older_than(older_than_days)?;
        println!(
            "{} Deleted {deleted} events older than {older_than_days} days.",
            "Done.".green()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_dry_run_no_panic() {
        let dir = tempfile::TempDir::new().expect("temp");
        let store = EventStore::open(&dir.path().join("test.db")).expect("open");
        store
            .insert_event("2020-01-01T00:00:00Z", "s1", "Bash", "ls", None, None, None)
            .expect("insert");

        // Dry run should not fail
        run_clean(&store, 1, true).expect("dry run");
        // Event should still be there
        assert_eq!(store.count_events().expect("count"), 1);
    }

    #[test]
    fn clean_deletes_old_events() {
        let dir = tempfile::TempDir::new().expect("temp");
        let store = EventStore::open(&dir.path().join("test.db")).expect("open");

        // Insert an event from 2020 (very old)
        store
            .insert_event("2020-01-01T00:00:00Z", "s1", "Bash", "old-command", None, None, None)
            .expect("insert");
        // Insert a recent event
        store
            .insert_event(
                &chrono::Utc::now().to_rfc3339(),
                "s2",
                "Bash",
                "new-command",
                None,
                None,
                None,
            )
            .expect("insert");

        assert_eq!(store.count_events().expect("count"), 2);
        run_clean(&store, 1, false).expect("clean");
        assert_eq!(store.count_events().expect("count"), 1);
    }
}
