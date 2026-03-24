#![deny(clippy::unwrap_used)]

use clap::Parser;
use eyre::{Context, Result};
use log::info;
use std::fs;
use std::path::PathBuf;

mod cli;

use claude_permit::cmd;
use claude_permit::db::EventStore;
use cli::{Cli, Command};

fn setup_logging() -> Result<()> {
    let log_dir = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("claude-permit")
        .join("logs");

    fs::create_dir_all(&log_dir).context("Failed to create log directory")?;

    let log_file = log_dir.join("claude-permit.log");

    let target = Box::new(
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file)
            .context("Failed to open log file")?,
    );

    env_logger::Builder::from_default_env()
        .target(env_logger::Target::Pipe(target))
        .init();

    info!("Logging initialized, writing to: {}", log_file.display());
    Ok(())
}

fn settings_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".claude")
        .join("settings.json")
}

fn settings_local_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".claude")
        .join("settings.local.json")
}

fn main() {
    // For the `log` subcommand we must ALWAYS output valid JSON, even on error.
    // So we catch everything and handle it gracefully.
    if let Err(e) = run() {
        // Check if we were running the log subcommand by inspecting args
        let is_log = std::env::args().nth(1).as_deref() == Some("log");
        if is_log {
            // Never block the hook pipeline
            println!("{{}}");
            log::error!("log command failed: {e:?}");
        } else {
            eprintln!("Error: {e:?}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<()> {
    setup_logging().context("Failed to setup logging")?;

    let cli = Cli::parse();

    match cli.command {
        Command::Log => {
            let db_path = EventStore::default_path()?;
            let store = EventStore::open(&db_path)?;
            cmd::run_log(&store)?;
            // Always output valid JSON for the hook pipeline
            println!("{{}}");
        }
        Command::Check => {
            let db_path = EventStore::default_path()?;
            let all_passed = cmd::run_check(&db_path, &settings_path(), &settings_local_path())?;
            if !all_passed {
                std::process::exit(1);
            }
        }
        Command::Audit {
            settings,
            settings_local,
            format,
            risk,
        } => {
            let sp = settings.unwrap_or_else(settings_path);
            let slp = settings_local.unwrap_or_else(settings_local_path);
            let risk_filter = risk.and_then(|r| claude_permit::risk::RiskTier::from_str_opt(&r));
            cmd::run_audit(&sp, &slp, &format, risk_filter)?;
        }
        Command::Suggest { .. } => {
            eprintln!("suggest command not yet implemented (Phase 3)");
        }
        Command::Report { .. } => {
            eprintln!("report command not yet implemented (Phase 3)");
        }
        Command::Clean { .. } => {
            eprintln!("clean command not yet implemented (Phase 3)");
        }
    }

    Ok(())
}
