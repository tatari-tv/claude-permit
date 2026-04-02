#![deny(clippy::unwrap_used)]

use clap::Parser;
use eyre::{Context, Result};
use log::info;
use std::fs;
use std::path::PathBuf;

mod cli;

use claude_permit::cmd;
use claude_permit::config::Config;
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
    let config = Config::load(None).unwrap_or_default();

    match cli.command {
        Command::Log => {
            let db_path = EventStore::default_path()?;
            let store = EventStore::open(&db_path)?;
            let result = cmd::run_log(&store, config.enforce_deny, &config.extra_deny_patterns)?;
            print!("{}", result.to_json());
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
            cmd::run_audit(&sp, &slp, &format, risk_filter, config.pager.as_deref())?;
        }
        Command::Suggest {
            threshold,
            sessions,
            format,
        } => {
            let db_path = EventStore::default_path()?;
            let store = EventStore::open(&db_path)?;
            cmd::run_suggest(&store, threshold, sessions, &format, config.pager.as_deref())?;
        }
        Command::Report { session, format } => {
            let db_path = EventStore::default_path()?;
            let store = EventStore::open(&db_path)?;
            cmd::run_report(&store, session.as_deref(), &format, config.pager.as_deref())?;
        }
        Command::Clean { older_than, dry_run } => {
            let db_path = EventStore::default_path()?;
            let store = EventStore::open(&db_path)?;
            cmd::run_clean(&store, older_than, dry_run)?;
        }
        Command::Apply {
            promote,
            remove,
            deny,
            all,
            settings,
            settings_local,
            yes,
            no_backup,
        } => {
            let do_promote = promote || all;
            let do_remove = remove || all;
            let do_deny = deny || all;

            if !do_promote && !do_remove && !do_deny {
                eprintln!("No filter specified. Use --promote, --remove, --deny, or --all.");
                std::process::exit(1);
            }

            let sp = settings.unwrap_or_else(settings_path);
            let slp = settings_local.unwrap_or_else(settings_local_path);
            let filter = claude_permit::cmd::apply::ApplyFilter {
                promote: do_promote,
                remove: do_remove,
                deny: do_deny,
            };
            cmd::run_apply(&sp, &slp, &filter, yes, !no_backup)?;
        }
    }

    Ok(())
}
