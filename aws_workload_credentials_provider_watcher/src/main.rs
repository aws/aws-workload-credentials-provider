//! `wcp-watcher`: a sidecar in a customer's TLS container that runs the
//! configured reload command when the ACM provider drops a refresh request
//! for a certificate into this watcher's `inbox/`.
//!
//! # Configuration
//!
//! | Variable | Required | Default |
//! | --- | --- | --- |
//! | `WCP_WATCHER_ID` | yes | — |
//! | `WCP_WATCHER_CONFIG_DIR` | no | `/shared/wcp-watchers/config`, `C:\shared\wcp-watchers\config` |
//! | `WCP_WATCHER_REQUESTS_DIR` | no | `/shared/wcp-watchers/requests`, `C:\shared\wcp-watchers\requests` |
//! | `WCP_WATCHER_STARTUP_HOLD_MS` | no | `30000` |
//!
//! `WCP_WATCHER_ID` selects `<config_dir>/<id>/watcher.config.toml` and
//! `<requests_dir>/<id>/{inbox,pending}/`. It has no default: a wrong guess
//! would reload another watcher's certificates. See [`env::WATCHER_ID_VAR`]
//! and [`env::STARTUP_HOLD_MS_VAR`].
//!
//! # What it does
//!
//! 1. Verify the roots ([`env::WatcherEnv::verify_roots_present`]: config
//!    read-only, requests read-write), then load and validate the
//!    configuration. Any failure refuses to start.
//! 2. Prepare `inbox/`, `pending/`, and `outbox/`, and recover what a previous run left in
//!    `pending/` ([`inbox::prepare_startup_state`]).
//! 3. Watch and scan `inbox/`, holding reloads for the startup hold window
//!    ([`run::STARTUP_HOLD_WINDOW`]); then each distinct command runs once.
//! 4. Per request: claim it into `pending/`, run its command (at most one
//!    reload per command at a time), delete it when the reload completes,
//!    successfully or not, and write one atomic status file per request
//!    ([`inbox`] and [`status`]). Windows runs the command through
//!    `powershell.exe -EncodedCommand`, as EC2 installs do ([`reload`]).
//! 5. Rescan every [`run::PERIODIC_RESCAN_INTERVAL`], re-verifying the
//!    directories first ([`env::WatcherEnv::verify_inbox`]). A lost watch is
//!    re-established with backoff; only [`run::SCAN_FAILURE_EXIT_WINDOW`]
//!    without a successful scan exits.
//!
//! # Not implemented
//!
//! - No heartbeat file: a non-zero exit is the liveness signal.
//! - The configuration is not watched; a change needs a container restart.
//! - No retry of a failed reload, and no poison-request handling ([`inbox`]).

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use aws_workload_credentials_provider_common::config::types::{LogLevel, LoggingConfig};
use aws_workload_credentials_provider_common::filesystem::{FileSystem, RealFileSystem};
use aws_workload_credentials_provider_common::logging::init_logger;
use log::{error, info};

mod env;
mod error;
mod inbox;
mod plan;
mod reload;
mod run;
mod status;
mod types;
mod watch;

use crate::env::{FileSystemValidator, WatcherEnv};
use crate::error::{RunError, StartupError};
use crate::plan::ReloadPlan;
use crate::reload::DirectReloadSink;
use crate::status::FileStatusSink;
use crate::watch::InboxWatch;

#[tokio::main]
async fn main() -> ExitCode {
    // Console, not a file: this runs in a container, where stdout and stderr
    // are the log. `log_to_file = false` takes log4rs's console appender and
    // touches no filesystem, so the log directory argument is never used.
    let mut log_conf = LoggingConfig::default();
    log_conf.log_to_file = false;
    if let Err(e) = init_logger(&log_conf, "wcp_watcher", Path::new(".")) {
        eprintln!("wcp-watcher: failed to initialize logging: {e}");
        return ExitCode::FAILURE;
    }

    match start().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // The log for whoever is collecting logs, stderr for whoever
            // is reading `docker logs` on a container that would not start.
            error!("{e}");
            eprintln!("wcp-watcher: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The startup sequence. Any error here is fatal by design.
async fn start() -> Result<(), Box<dyn std::error::Error>> {
    let env = WatcherEnv::from_process_env()?;

    // The production filesystem is fixed here at compile time: no environment
    // variable, flag, file or feature selects another one, so the directory
    // and mount-mode checks always run against the real disk. The
    // `ReadOnlyConfigFileSystem` the unit tests pass to `prepare` is
    // `#[cfg(test)]` and is never compiled into this binary.
    let (plan, mut watch, recovered) = prepare(&env, &RealFileSystem)?;

    let sink = Arc::new(DirectReloadSink::new());
    let status = Arc::new(FileStatusSink::new(env.outbox_dir()));

    let result = run::run(
        &env,
        &FileSystemValidator(&RealFileSystem),
        plan,
        sink,
        status,
        &mut watch,
        recovered,
        wait_for_shutdown(),
    )
    .await;

    // A closed event channel means `notify`'s thread is gone, and dropping
    // its watcher would then panic on a send to that thread, replacing the
    // error below with a panic. The process is about to exit, so leak it.
    if let Err(RunError::WatchChannelClosed { .. }) = result {
        std::mem::forget(watch);
    }

    result?;
    Ok(())
}

/// Everything before the event loop: verify the roots, load the plan, check
/// the inbox, prepare the pending directory and recover its requests, and
/// start the watch.
///
/// Takes the filesystem the directory checks run against so that the unit
/// tests can drive this exact sequence; [`start`] always
/// passes [`RealFileSystem`].
fn prepare<F: FileSystem>(
    env: &WatcherEnv,
    filesystem: &F,
) -> Result<(Arc<ReloadPlan>, InboxWatch, Vec<inbox::Claimed>), StartupError> {
    info!(
        "Starting wcp-watcher for '{}' (config '{}', requests '{}')",
        env.watcher_id(),
        env.config_dir().display(),
        env.requests_dir().display()
    );

    // Both shared roots must exist, be symlink-free and be mounted with the
    // right access mode before anything is read from them. This is the
    // watcher's own enforcement point: the ACM provider validates the same
    // directories in its own container, with its own mounts, so its result
    // says nothing about this container's.
    env.verify_roots_present(filesystem)?;

    let config_file = env.config_file();
    let plan = Arc::new(ReloadPlan::load(&config_file, env.watcher_id())?);
    info!(
        "Loaded '{}': {} certificate(s), {} distinct reload command(s)",
        config_file.display(),
        plan.certificate_count(),
        plan.command_count()
    );

    let recovered = inbox::prepare_startup_state(env, filesystem)?;

    // Started before the first scan and kept alive for the whole run: dropping
    // the watch stops the watching.
    let watch = InboxWatch::start(&env.inbox_dir())?;
    info!("Watching '{}'", env.inbox_dir().display());

    Ok((plan, watch, recovered))
}

/// Waits for the platform's stop signal.
#[cfg(unix)]
async fn wait_for_shutdown() {
    aws_workload_credentials_provider_common::shutdown_signal().await
}

/// Waits for the platform's stop signal, then returns
///
/// - `CTRL_SHUTDOWN_EVENT`: what `docker stop` sends a Windows container.
/// - `CTRL_CLOSE_EVENT`: the console the watcher is attached to was closed.
/// - `CTRL_C_EVENT`: Ctrl+C on an attached console.
///
/// A listener that cannot be installed panics, as `common::shutdown_signal`
/// does on Unix: the watcher would otherwise run unable to stop cleanly.
#[cfg(windows)]
async fn wait_for_shutdown() {
    use tokio::signal::windows::{ctrl_c, ctrl_close, ctrl_shutdown};

    let mut interrupt = ctrl_c().expect("failed to install CTRL_C_EVENT handler");
    let mut close = ctrl_close().expect("failed to install CTRL_CLOSE_EVENT handler");
    let mut shutdown = ctrl_shutdown().expect("failed to install CTRL_SHUTDOWN_EVENT handler");

    let event = tokio::select! {
        _ = interrupt.recv() => "CTRL_C_EVENT",
        _ = close.recv() => "CTRL_CLOSE_EVENT",
        _ = shutdown.recv() => "CTRL_SHUTDOWN_EVENT",
    };
    info!("Received {event}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use aws_workload_credentials_provider_common::config::ValidationErrorCode;
    use aws_workload_credentials_provider_common::filesystem::RealFileSystem;
    use tempfile::TempDir;

    use crate::env::tests_support::{canonical_root, ReadOnlyConfigFileSystem, TEST_WATCHER_ID};
    use crate::env::{CONFIG_DIR_VAR, REQUESTS_DIR_VAR, WATCHER_ID_VAR};
    use crate::error::InboxCheckError;

    const CERTIFICATE_ARN: &str = "arn:aws:acm:us-west-2:123456789012:certificate/aaaa";

    #[cfg(unix)]
    const RELOAD_PROGRAM: &str = "/bin/true";
    #[cfg(windows)]
    const RELOAD_PROGRAM: &str = r"C:\Windows\System32\cmd.exe";

    struct PrepareFixture {
        _tmp: TempDir,
        env: WatcherEnv,
        filesystem: ReadOnlyConfigFileSystem,
    }

    impl PrepareFixture {
        fn new() -> Self {
            let tmp = TempDir::new().unwrap();
            let root = canonical_root(tmp.path());
            let config_dir = root.join("config");
            let requests_dir = root.join("requests");
            fs::create_dir_all(config_dir.join(TEST_WATCHER_ID)).unwrap();
            let inbox = requests_dir.join(TEST_WATCHER_ID).join("inbox");
            fs::create_dir_all(&inbox).unwrap();

            let config_value = config_dir.to_string_lossy().into_owned();
            let requests_value = requests_dir.to_string_lossy().into_owned();
            let env = WatcherEnv::resolve(move |var| match var {
                WATCHER_ID_VAR => Some(TEST_WATCHER_ID.to_string()),
                CONFIG_DIR_VAR => Some(config_value.clone()),
                REQUESTS_DIR_VAR => Some(requests_value.clone()),
                _ => None,
            })
            .unwrap();
            let filesystem = ReadOnlyConfigFileSystem::for_env(&env);

            Self {
                _tmp: tmp,
                env,
                filesystem,
            }
        }

        fn write_config(&self, text: &str) {
            fs::write(self.env.config_file(), text).unwrap();
        }

        fn valid_config(&self) -> String {
            format!(
                "schema_version = 1\n\
                 watcher_id = \"{}\"\n\
                 \n\
                 [[reload]]\n\
                 command = [\"{}\"]\n\
                 certificate_arns = [\"{}\"]\n",
                TEST_WATCHER_ID,
                RELOAD_PROGRAM.escape_default(),
                CERTIFICATE_ARN,
            )
        }
    }

    fn prepare_error<F: FileSystem>(env: &WatcherEnv, filesystem: &F) -> StartupError {
        match prepare(env, filesystem) {
            Ok(_) => panic!("prepare unexpectedly succeeded"),
            Err(err) => err,
        }
    }

    fn assert_directories_invalid(err: StartupError) {
        let StartupError::DirectoriesInvalid { source } = err else {
            panic!("expected DirectoriesInvalid, got {err}");
        };
        assert_eq!(source.errors.len(), 1);
        assert_eq!(source.errors[0].field, REQUESTS_DIR_VAR);
        assert_eq!(source.errors[0].code, ValidationErrorCode::ConflictingPaths);
    }

    #[test]
    fn prepare_rejects_invalid_shared_roots_before_reading_config() {
        let tmp = TempDir::new().unwrap();
        let root = canonical_root(tmp.path());
        let root_value = root.to_string_lossy().into_owned();
        let env = WatcherEnv::resolve(move |var| match var {
            WATCHER_ID_VAR => Some(TEST_WATCHER_ID.to_string()),
            CONFIG_DIR_VAR | REQUESTS_DIR_VAR => Some(root_value.clone()),
            _ => None,
        })
        .unwrap();
        fs::create_dir_all(env.inbox_dir()).unwrap();

        let err = prepare_error(&env, &RealFileSystem);
        assert_directories_invalid(err);
    }

    #[test]
    fn prepare_reports_a_missing_config_file() {
        let fixture = PrepareFixture::new();

        let err = prepare_error(&fixture.env, &fixture.filesystem);
        let StartupError::ConfigRead { path, source } = err else {
            panic!("expected ConfigRead, got {err}");
        };
        assert_eq!(path, fixture.env.config_file());
        assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn prepare_reports_an_oversized_config_file() {
        let fixture = PrepareFixture::new();
        fixture.write_config(&"x".repeat(crate::plan::MAX_CONFIG_BYTES as usize + 1));

        let err = prepare_error(&fixture.env, &fixture.filesystem);
        let StartupError::ConfigTooLarge { path, size, limit } = err else {
            panic!("expected ConfigTooLarge, got {err}");
        };
        assert_eq!(path, fixture.env.config_file());
        assert_eq!(size, crate::plan::MAX_CONFIG_BYTES + 1);
        assert_eq!(limit, crate::plan::MAX_CONFIG_BYTES);
    }

    #[test]
    fn prepare_reports_malformed_config_toml() {
        let fixture = PrepareFixture::new();
        fixture.write_config("schema_version = [");

        let err = prepare_error(&fixture.env, &fixture.filesystem);
        let StartupError::ConfigParse { path, source } = err else {
            panic!("expected ConfigParse, got {err}");
        };
        assert_eq!(path, fixture.env.config_file());
        assert_eq!(source.code, ValidationErrorCode::TomlSyntaxError);
    }

    #[test]
    fn prepare_reports_invalid_config_values() {
        let fixture = PrepareFixture::new();
        fixture.write_config(
            &fixture
                .valid_config()
                .replace(TEST_WATCHER_ID, "another_watcher"),
        );

        let err = prepare_error(&fixture.env, &fixture.filesystem);
        let StartupError::ConfigInvalid { path, source } = err else {
            panic!("expected ConfigInvalid, got {err}");
        };
        assert_eq!(path, fixture.env.config_file());
        assert_eq!(source.errors.len(), 1);
        assert_eq!(source.errors[0].field, "watcher_id");
        assert_eq!(source.errors[0].code, ValidationErrorCode::InvalidWatcherId);
    }

    /// A missing inbox is created, and the watch is started on it.
    #[test]
    fn prepare_creates_a_missing_inbox_and_watches_it() {
        let fixture = PrepareFixture::new();
        fixture.write_config(&fixture.valid_config());
        fs::remove_dir(fixture.env.inbox_dir()).unwrap();

        let (_, _watch, recovered) = prepare(&fixture.env, &fixture.filesystem).unwrap();

        assert!(recovered.is_empty());
        assert!(fixture.env.inbox_dir().is_dir());
        assert!(fixture.env.pending_dir().is_dir());
        assert!(fixture.env.outbox_dir().is_dir());
    }

    /// A missing `<watcher_id>/` is created, with the inbox and the pending
    /// directory in it, and the watch is started.
    #[test]
    fn prepare_creates_a_missing_watcher_directory() {
        let fixture = PrepareFixture::new();
        fixture.write_config(&fixture.valid_config());
        fs::remove_dir_all(fixture.env.watcher_requests_dir()).unwrap();

        let (_, _watch, recovered) = prepare(&fixture.env, &fixture.filesystem).unwrap();

        assert!(recovered.is_empty());
        assert!(fixture.env.inbox_dir().is_dir());
        assert!(fixture.env.pending_dir().is_dir());
        assert!(fixture.env.outbox_dir().is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn prepare_creates_a_missing_pending_directory_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = PrepareFixture::new();
        fixture.write_config(&fixture.valid_config());

        let (_, _watch, recovered) = prepare(&fixture.env, &fixture.filesystem).unwrap();

        assert!(recovered.is_empty());
        let mode = fs::metadata(fixture.env.pending_dir())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "{mode:o}");
    }

    #[cfg(unix)]
    #[test]
    fn prepare_refuses_a_symlinked_outbox_directory() {
        let fixture = PrepareFixture::new();
        fixture.write_config(&fixture.valid_config());
        let elsewhere = fixture.env.requests_dir().join("elsewhere-outbox");
        fs::create_dir(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, fixture.env.outbox_dir()).unwrap();

        let err = prepare_error(&fixture.env, &fixture.filesystem);
        assert!(
            matches!(
                &err,
                StartupError::RequestDirInvalid {
                    source: InboxCheckError::NotCanonical { path, .. },
                } if *path == fixture.env.outbox_dir()
            ),
            "{err}"
        );
    }

    #[test]
    fn prepare_reuses_an_existing_pending_directory_and_recovers_it() {
        let fixture = PrepareFixture::new();
        fixture.write_config(&fixture.valid_config());
        fs::create_dir(fixture.env.pending_dir()).unwrap();
        let left = fixture.env.pending_dir().join("left.cmd");
        fs::write(
            &left,
            format!(
                r#"{{"command_id":"5d1c0a4e-2b7f-4c3a-9e8d-6f0b1a2c3d4e","certificate_arn":"{CERTIFICATE_ARN}","created_at":"2024-05-01T12:00:00Z"}}"#
            ),
        )
        .unwrap();

        let (_, _watch, recovered) = prepare(&fixture.env, &fixture.filesystem).unwrap();

        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].name, "left.cmd");
        assert!(left.is_file(), "recovered, not deleted");
    }

    #[test]
    fn prepare_refuses_a_file_in_place_of_the_pending_directory() {
        let fixture = PrepareFixture::new();
        fixture.write_config(&fixture.valid_config());
        fs::write(fixture.env.pending_dir(), "not a directory").unwrap();

        let err = prepare_error(&fixture.env, &fixture.filesystem);
        assert!(
            matches!(
                &err,
                StartupError::RequestDirInvalid {
                    source: InboxCheckError::NotADirectory { path },
                } if *path == fixture.env.pending_dir()
            ),
            "{err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn prepare_refuses_a_symlinked_pending_directory() {
        let fixture = PrepareFixture::new();
        fixture.write_config(&fixture.valid_config());
        let elsewhere = fixture.env.requests_dir().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, fixture.env.pending_dir()).unwrap();

        let err = prepare_error(&fixture.env, &fixture.filesystem);
        assert!(
            matches!(
                &err,
                StartupError::RequestDirInvalid {
                    source: InboxCheckError::NotCanonical { path, .. },
                } if *path == fixture.env.pending_dir()
            ),
            "{err}"
        );
    }

    #[tokio::test]
    async fn prepare_loads_the_plan_keeps_inbox_files_and_starts_watching() {
        let fixture = PrepareFixture::new();
        fixture.write_config(&fixture.valid_config());
        let leftover = fixture.env.inbox_dir().join("leftover.cmd");
        fs::write(&leftover, "a request from a previous run").unwrap();

        let (plan, watch, recovered) = prepare(&fixture.env, &fixture.filesystem).unwrap();

        assert_eq!(plan.certificate_count(), 1);
        assert_eq!(plan.command_count(), 1);
        assert_eq!(plan.command(0), &[RELOAD_PROGRAM.to_string()]);
        assert!(recovered.is_empty());
        assert!(leftover.is_file(), "left for the event loop's first scan");

        #[cfg(unix)]
        {
            use std::time::Duration;

            use crate::watch::{InboxWatcher, WatchEvent};

            let mut watch = watch;
            let destination = fixture.env.inbox_dir().join("fresh.cmd");
            let temporary = fixture.env.inbox_dir().join("fresh.cmd.tmp");
            fs::write(&temporary, "fresh request").unwrap();
            fs::rename(&temporary, &destination).unwrap();

            let mut seen = Vec::new();
            tokio::time::timeout(Duration::from_secs(10), async {
                while let Some(event) = watch.events().recv().await {
                    if let WatchEvent::Paths(paths) = event {
                        seen.extend(paths);
                        if seen.contains(&destination) {
                            return;
                        }
                    }
                }
                panic!("watch channel closed; saw {seen:?}");
            })
            .await
            .unwrap_or_else(|_| panic!("no event named the renamed file; saw {seen:?}"));
        }

        #[cfg(windows)]
        drop(watch);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn wait_for_shutdown_returns_for_sigint_and_sigterm() {
        use std::time::Duration;

        use rustix::process::{getpid, kill_process, Signal};
        use tokio::signal::unix::{signal, SignalKind};

        // This is the only signal test in this process. Install both handlers
        // before raising either signal so the test process cannot take the
        // default terminating action while the spawned waiter is starting.
        let _interrupt_listener =
            signal(SignalKind::interrupt()).expect("failed to install SIGINT listener");
        let _terminate_listener =
            signal(SignalKind::terminate()).expect("failed to install SIGTERM listener");

        for signal in [Signal::INT, Signal::TERM] {
            // Keep this test on the current-thread runtime and yield after
            // spawning so wait_for_shutdown has registered both listeners
            // before delivery.
            let waiter = tokio::spawn(wait_for_shutdown());
            tokio::task::yield_now().await;
            assert!(
                !waiter.is_finished(),
                "wait_for_shutdown returned before any signal"
            );

            kill_process(getpid(), signal).unwrap();

            tokio::time::timeout(Duration::from_secs(5), waiter)
                .await
                .expect("wait_for_shutdown did not return after the signal")
                .expect("wait_for_shutdown task panicked");
        }
    }

    /// Set in the environment of the child process that
    /// [`wait_for_shutdown_returns_for_ctrl_c`] starts. Its presence makes the
    /// test run the child's half.
    #[cfg(windows)]
    const CTRL_C_CHILD_VAR: &str = "WCP_WATCHER_TEST_CTRL_C_CHILD";

    /// A real `CTRL_C_EVENT` ends `wait_for_shutdown`.
    ///
    /// `CTRL_C_EVENT` cannot be aimed at one process: `GenerateConsoleCtrlEvent`
    /// delivers it to every process on the caller's console, which here
    /// includes cargo and the test harness. So the test re-runs itself, this
    /// test only, in a child process with a console of its own
    /// (`CREATE_NEW_CONSOLE`), and the child raises the event on that
    /// console. The parent only checks how the child exited.
    ///
    /// `CTRL_CLOSE_EVENT` and `CTRL_SHUTDOWN_EVENT` are not tested:
    /// `GenerateConsoleCtrlEvent` raises only `CTRL_C_EVENT` and
    /// `CTRL_BREAK_EVENT`.
    #[cfg(windows)]
    #[test]
    fn wait_for_shutdown_returns_for_ctrl_c() {
        if std::env::var_os(CTRL_C_CHILD_VAR).is_some() {
            ctrl_c_child();
        } else {
            ctrl_c_parent();
        }
    }

    /// Starts this test in a child process on a new console and waits for it
    /// to pass.
    #[cfg(windows)]
    fn ctrl_c_parent() {
        use std::os::windows::process::CommandExt;
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        /// `CREATE_NEW_CONSOLE` from `Win32::System::Threading`, which this
        /// crate does not otherwise need.
        const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
        const CHILD_TIMEOUT: Duration = Duration::from_secs(60);

        let tmp = TempDir::new().unwrap();
        let stdout_path = tmp.path().join("stdout.txt");
        let stderr_path = tmp.path().join("stderr.txt");

        // `--exact` with the full path runs this one test, so the child never
        // raises the event while any other test is running.
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "tests::wait_for_shutdown_returns_for_ctrl_c",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CTRL_C_CHILD_VAR, "1")
            .stdin(Stdio::null())
            .stdout(fs::File::create(&stdout_path).unwrap())
            .stderr(fs::File::create(&stderr_path).unwrap())
            .creation_flags(CREATE_NEW_CONSOLE)
            .spawn()
            .expect("failed to start the child test process");

        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break Some(status);
            }
            if started.elapsed() > CHILD_TIMEOUT {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            std::thread::sleep(Duration::from_millis(50));
        };

        let output = format!(
            "--- child stdout ---\n{}\n--- child stderr ---\n{}",
            fs::read_to_string(&stdout_path).unwrap_or_default(),
            fs::read_to_string(&stderr_path).unwrap_or_default()
        );
        // A child killed by the console's default handler, because no
        // listener was installed, exits with STATUS_CONTROL_C_EXIT
        // (0xC000013A).
        match status {
            Some(status) if status.success() => {}
            Some(status) => panic!("the child test process failed ({status})\n{output}"),
            None => panic!("the child test process ran over {CHILD_TIMEOUT:?}\n{output}"),
        }
    }

    /// The child's half: start `wait_for_shutdown`, raise `CTRL_C_EVENT` on
    /// this process's own console, and require the wait to end.
    #[cfg(windows)]
    fn ctrl_c_child() {
        use std::time::Duration;

        use windows::Win32::System::Console::{
            GenerateConsoleCtrlEvent, SetConsoleCtrlHandler, CTRL_C_EVENT,
        };

        // A process can inherit "ignore Ctrl+C" from its parent, and then
        // its handlers are never called for `CTRL_C_EVENT`. A null handler
        // with `false` turns that attribute off.
        // SAFETY: plain Win32 call with no pointers.
        unsafe { SetConsoleCtrlHandler(None, false) }.expect("failed to enable Ctrl+C handling");

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            // On the current-thread runtime, one yield runs the waiter up to
            // its first await, so all three listeners are installed before
            // the event is raised.
            let waiter = tokio::spawn(wait_for_shutdown());
            tokio::task::yield_now().await;
            assert!(
                !waiter.is_finished(),
                "wait_for_shutdown returned before any event"
            );

            // Group 0: every process on this console, which `CREATE_NEW_CONSOLE`
            // made this process's own.
            // SAFETY: plain Win32 call with no pointers.
            unsafe { GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0) }
                .expect("failed to raise CTRL_C_EVENT");

            tokio::time::timeout(Duration::from_secs(10), waiter)
                .await
                .expect("wait_for_shutdown did not return after CTRL_C_EVENT")
                .expect("wait_for_shutdown task panicked");
        });
    }
}
