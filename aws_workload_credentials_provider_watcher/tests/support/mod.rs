//! Helpers for the `wcp-watcher` e2e tests: the test-local configuration and
//! request constants, the on-disk layout, request writing, and the child's
//! guarded process and captured transcript. `namespace` (Linux only) runs
//! the binary on real tmpfs mounts.
//!
//! Every path here is a host path. The Linux reload test maps its paths into
//! the child's mount namespace before calling the wait helpers.
//!
//! The tests launch the binary from `CARGO_BIN_EXE_wcp-watcher`, which Cargo
//! sets when it builds integration tests, one per `[[bin]]` name in
//! `Cargo.toml`. `env!` bakes that absolute path in at compile time, so the
//! tests must be built and run on the same host: a test executable
//! cross-compiled with `cargo xwin test --no-run` cannot be run elsewhere.
#![allow(dead_code)]

#[cfg(target_os = "linux")]
pub mod namespace;

use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub use aws_workload_credentials_provider_common::config::watcher_config::WATCHER_CONFIG_FILE_NAME;
use aws_workload_credentials_provider_common::watcher_request::inbox_path;

/// The watcher's environment variable names.
///
/// Spelled out rather than imported: they are `pub const`s in the watcher's
/// `env` module, and a `[[bin]]`'s modules are not importable from an
/// integration test. If they are renamed, a test fails at the readiness
/// timeout with the child's transcript, which names the missing variable.
pub const WATCHER_ID_VAR: &str = "WCP_WATCHER_ID";
pub const CONFIG_DIR_VAR: &str = "WCP_WATCHER_CONFIG_DIR";
pub const REQUESTS_DIR_VAR: &str = "WCP_WATCHER_REQUESTS_DIR";
pub const STARTUP_HOLD_MS_VAR: &str = "WCP_WATCHER_STARTUP_HOLD_MS";

/// Mirrors the in-crate unit tests' `env::tests_support::TEST_WATCHER_ID`.
pub const TEST_WATCHER_ID: &str = "watcher_id_1";

/// The one certificate the test configuration routes to a reload command.
/// The request's `certificate_arn` must equal it, or the watcher never reloads.
pub const ARN: &str = "arn:aws:acm:us-west-2:123456789012:certificate/e2ereload";

/// The request's `command_id`, also the `{command_id}` segment of its
/// filename, kept equal so the watcher's name/contents cross-check is quiet.
pub const COMMAND_ID: &str = "e2e00000-0000-4000-8000-000000000001";

/// The `{epoch_millis}-{sequence}-` half of the request's filename.
pub const REQUEST_NAME_PREFIX: &str = "1728331740000-001-";

/// Suffix of the temp file a request is written through. The watcher reads
/// only names ending in `.cmd`, so the request is never read half-written.
/// Mirrors `types::REQUEST_TEMP_SUFFIX`.
pub const REQUEST_TEMP_SUFFIX: &str = ".tmp";

/// Shortens the watcher's 30-second production startup hold window.
pub const STARTUP_HOLD_MS: u64 = 250;

/// What the watcher logs at startup when it recovers the one request a
/// recovery test left in `pending/`.
pub const RECOVERED_ONE_LINE: &str = "Recovered 1 request(s)";

pub const READY_TIMEOUT: Duration = Duration::from_secs(20);
pub const MARKER_TIMEOUT: Duration = Duration::from_secs(20);
pub const MARKER_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// How long after the marker appears the request may stay in `pending/`.
pub const PENDING_TIMEOUT: Duration = Duration::from_secs(20);

/// How many leading and trailing transcript lines a rendered transcript
/// keeps. The rest is elided so a failure message stays readable however much
/// the watcher logs.
pub const TRANSCRIPT_EDGE_LINES: usize = 60;

/// The host-side paths, all under the canonical temp root.
pub struct Layout {
    pub marker: PathBuf,
    pub config_dir: PathBuf,
    pub requests_dir: PathBuf,
    pub watcher_config_dir: PathBuf,
    pub watcher_requests_dir: PathBuf,
    pub config_file: PathBuf,
    pub inbox: PathBuf,
    pub outbox: PathBuf,
    pub pending: PathBuf,
}

impl Layout {
    pub fn under(root: PathBuf) -> Self {
        let config_dir = root.join("config");
        let requests_dir = root.join("requests");
        let watcher_config_dir = config_dir.join(TEST_WATCHER_ID);
        let watcher_requests_dir = requests_dir.join(TEST_WATCHER_ID);
        Self {
            marker: root.join("reloaded.marker"),
            config_file: watcher_config_dir.join(WATCHER_CONFIG_FILE_NAME),
            inbox: inbox_path(&requests_dir, TEST_WATCHER_ID),
            outbox: watcher_requests_dir.join("outbox"),
            pending: watcher_requests_dir.join("pending"),
            config_dir,
            requests_dir,
            watcher_config_dir,
            watcher_requests_dir,
        }
    }
}

/// The watcher configuration that routes [`ARN`] to `command`.
pub fn watcher_config(command: &[String]) -> String {
    format!(
        "schema_version = 1\n\
         watcher_id = \"{TEST_WATCHER_ID}\"\n\
         \n\
         [[reload]]\n\
         command = {command}\n\
         certificate_arns = [\"{ARN}\"]\n",
        command = toml_command_array(command),
    )
}

/// Writes one request into `inbox` via a `.tmp` file and a rename, and
/// returns its final path.
///
/// The watcher reads only `.cmd` files, so the temp name and the rename are
/// what make the request appear whole. The body is a hardcoded literal of
/// the three wire fields, in the field order and key names the WCP writer
/// (`aws_certificatemanager_provider/src/watcher_request.rs`) uses, so the
/// tests do not depend on the ACM provider's writer.
pub fn write_request(inbox: &Path) -> io::Result<PathBuf> {
    let name = request_name();
    let destination = inbox.join(&name);
    let temp = inbox.join(format!("{name}{REQUEST_TEMP_SUFFIX}"));
    std::fs::write(&temp, request_body())?;
    std::fs::rename(&temp, &destination)?;
    Ok(destination)
}

/// The request's file name, `{epoch_millis}-{sequence}-{command_id}.cmd`.
pub fn request_name() -> String {
    format!("{REQUEST_NAME_PREFIX}{COMMAND_ID}.cmd")
}

/// The request's body. See [`write_request`].
pub fn request_body() -> String {
    format!(
        r#"{{"command_id":"{COMMAND_ID}","certificate_arn":"{ARN}","created_at":"2024-05-01T12:00:00Z"}}"#
    )
}

/// Formats an argv as a TOML array of literal (single-quoted) strings.
pub fn toml_command_array(argv: &[String]) -> String {
    let elements: Vec<String> = argv.iter().map(|element| format!("'{element}'")).collect();
    format!("[{}]", elements.join(", "))
}

/// Blocks until `marker` exists, or fails the test with the configuration
/// and transcript.
pub fn wait_for_marker(marker: &Path, config: &str, log: &Transcript) {
    let deadline = Instant::now() + MARKER_TIMEOUT;
    while !marker.exists() {
        if Instant::now() >= deadline {
            panic!(
                "the reload command's marker '{}' did not appear within {:?}.\n\
                 --- watcher.config.toml ---\n{}\n{}",
                marker.display(),
                MARKER_TIMEOUT,
                config,
                log.render()
            );
        }
        std::thread::sleep(MARKER_POLL_INTERVAL);
    }
}

/// Blocks until `pending` exists and is empty, or fails the test. The
/// reload's requests are deleted just after it completes, which is just
/// after the marker appears.
pub fn wait_for_empty_pending(pending: &Path, log: &Transcript) {
    let deadline = Instant::now() + PENDING_TIMEOUT;
    loop {
        let entries: Vec<_> = match std::fs::read_dir(pending) {
            Ok(entries) => entries
                .filter_map(|e| e.ok())
                .map(|e| e.file_name())
                .collect(),
            Err(error) => panic!(
                "the pending directory '{}' should exist: {error}\n{}",
                pending.display(),
                log.render()
            ),
        };
        if entries.is_empty() {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "'{}' still held {entries:?} {:?} after the reload ran.\n{}",
                pending.display(),
                PENDING_TIMEOUT,
                log.render()
            );
        }
        std::thread::sleep(MARKER_POLL_INTERVAL);
    }
}

/// Kills and reaps the watcher on drop, including while unwinding.
pub struct ChildGuard(pub Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        // Best-effort: the child may already have exited, and a failure to
        // reap must not mask the assertion that is unwinding.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The child's captured stdout and stderr, plus a readiness signal.
///
/// Both streams are drained to EOF for the whole run: a child whose pipe
/// buffer fills up blocks on its next log line instead of reloading.
pub struct Transcript {
    lines: Arc<Mutex<Vec<String>>>,
    ready: Receiver<()>,
    readers: Vec<JoinHandle<()>>,
}

impl Transcript {
    pub fn capture(child: &mut Child, ready_marker: &str) -> Self {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let (ready_tx, ready) = mpsc::channel();
        let stdout = child.stdout.take().expect("stdout was piped");
        let stderr = child.stderr.take().expect("stderr was piped");
        let readers = vec![
            drain(
                stdout,
                "stdout",
                Arc::clone(&lines),
                ready_tx.clone(),
                ready_marker.to_string(),
            ),
            drain(
                stderr,
                "stderr",
                Arc::clone(&lines),
                ready_tx,
                ready_marker.to_string(),
            ),
        ];
        Self {
            lines,
            ready,
            readers,
        }
    }

    /// Blocks until the readiness line is seen, or fails the test.
    pub fn wait_for_ready(&self, timeout: Duration, child: &mut ChildGuard) {
        let outcome = match self.ready.recv_timeout(timeout) {
            Ok(()) => return,
            Err(RecvTimeoutError::Timeout) => format!("did not log readiness within {timeout:?}"),
            // Both readers hit EOF without the line: the child exited during
            // startup.
            Err(RecvTimeoutError::Disconnected) => "exited before watching the inbox".to_string(),
        };
        let status = child.0.try_wait().ok().flatten();
        panic!(
            "wcp-watcher {outcome} (exit status: {status:?}).\n{}",
            self.render()
        );
    }

    /// The captured output, with the middle elided past
    /// [`TRANSCRIPT_EDGE_LINES`] lines at each end.
    pub fn render(&self) -> String {
        let lines = self.lines.lock().unwrap();
        let body = if lines.len() <= 2 * TRANSCRIPT_EDGE_LINES {
            lines.join("\n")
        } else {
            format!(
                "{}\n... {} lines elided ...\n{}",
                lines[..TRANSCRIPT_EDGE_LINES].join("\n"),
                lines.len() - 2 * TRANSCRIPT_EDGE_LINES,
                lines[lines.len() - TRANSCRIPT_EDGE_LINES..].join("\n")
            )
        };
        format!("--- wcp-watcher output ---\n{body}\n---")
    }

    /// How many captured lines so far contain `needle`.
    pub fn count(&self, needle: &str) -> usize {
        self.lines
            .lock()
            .unwrap()
            .iter()
            .filter(|line| line.contains(needle))
            .count()
    }

    /// Joins the reader threads once the child is gone and the pipes closed.
    pub fn join(self) {
        for reader in self.readers {
            let _ = reader.join();
        }
    }
}

/// Reads `stream` to EOF, recording every line and signalling the marker.
fn drain<R: io::Read + Send + 'static>(
    stream: R,
    label: &'static str,
    lines: Arc<Mutex<Vec<String>>>,
    ready: Sender<()>,
    marker: String,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        for line in BufReader::new(stream).lines() {
            let Ok(line) = line else { break };
            if line.contains(&marker) {
                // The receiver is gone once the test has moved on.
                let _ = ready.send(());
            }
            lines.lock().unwrap().push(format!("[{label}] {line}"));
        }
    })
}
