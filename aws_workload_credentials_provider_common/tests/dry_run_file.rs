//! A dry run's records go to their own file, or to the console, whatever
//! `log_level` is. This test binary installs the provider's logger, which a
//! process can do only once.

use std::fs;
use std::process::Command;

use aws_workload_credentials_provider_common::config::types::{LogLevel, LoggingConfig};
use aws_workload_credentials_provider_common::logging::init_logger;
use tempfile::TempDir;

#[test]
fn a_dry_runs_records_go_to_their_own_file() {
    let dir = TempDir::new().unwrap();
    // Logging to a file is the default.
    let mut logging = LoggingConfig::default();
    logging.log_level = LogLevel::Warn;
    logging.telemetry_dry_run = true;
    init_logger(&logging, "provider", dir.path()).unwrap();
    log::info!(target: "telemetry_dryrun", r#"{{"name":"record"}}"#);
    log::warn!("a warning");
    log::info!("an info line");

    let records = fs::read_to_string(dir.path().join("provider_telemetry_dryrun.log")).unwrap();
    assert_eq!(
        records.lines().collect::<Vec<_>>(),
        [r#"{"name":"record"}"#]
    );
    let log = fs::read_to_string(dir.path().join("provider.log")).unwrap();
    assert!(log.contains("a warning"), "{log}");
    assert!(
        !log.contains("record") && !log.contains("an info line"),
        "{log}"
    );

    // Without a dry run there's no such file. The logger is already installed,
    // but init_logger still opens the files it would log to.
    let dir = TempDir::new().unwrap();
    logging.telemetry_dry_run = false;
    init_logger(&logging, "provider", dir.path()).unwrap();
    assert!(dir.path().join("provider.log").exists());
    assert!(!dir.path().join("provider_telemetry_dryrun.log").exists());
}

/// Set in the child process that `on_the_console_a_dry_runs_records_ignore_log_level` starts.
const CHILD: &str = "DRY_RUN_CONSOLE_CHILD";

#[test]
fn on_the_console_a_dry_runs_records_ignore_log_level() {
    // The console logger writes to the real stdout, which the test harness
    // doesn't capture, and this process may already have a logger. So the
    // test reruns itself in a child process and reads its stdout.
    if std::env::var_os(CHILD).is_some() {
        let dir = std::env::current_dir().unwrap();
        let mut logging = LoggingConfig::default();
        logging.log_level = LogLevel::None;
        logging.log_to_file = false;
        logging.telemetry_dry_run = true;
        init_logger(&logging, "provider", &dir).unwrap();
        log::info!(target: "telemetry_dryrun", r#"{{"name":"record"}}"#);
        log::error!("an error");
        return;
    }
    let dir = TempDir::new().unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "on_the_console_a_dry_runs_records_ignore_log_level",
        ])
        .env(CHILD, "1")
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(r#"{"name":"record"}"#), "{stdout}");
    assert!(!stdout.contains("an error"), "{stdout}");
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}
