//! End-to-end reload tests for the `wcp-watcher` binary on Windows, the
//! counterpart of `tests/e2e_reload.rs`.
//!
//! Windows cannot read a mount's access mode, so the watcher accepts plain
//! temp directories with one warning per root and no mount harness is needed.
//! The reload runs through the real `powershell.exe -EncodedCommand`, and the
//! inbox request is written after the startup scan so that the
//! `ReadDirectoryChangesW` watch reports it.
#![cfg(windows)]

mod support;

use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use tempfile::TempDir;

use support::{
    request_body, request_name, wait_for_empty_pending, wait_for_marker, watcher_config,
    write_request, ChildGuard, Layout, Transcript, CONFIG_DIR_VAR, READY_TIMEOUT,
    RECOVERED_ONE_LINE, REQUESTS_DIR_VAR, STARTUP_HOLD_MS, STARTUP_HOLD_MS_VAR, TEST_WATCHER_ID,
    WATCHER_ID_VAR,
};

/// Characters, besides ASCII alphanumerics, a reload command element may
/// contain for this test: `common::config::watcher_config`'s Windows
/// `COMMAND_ELEMENT_RE` without `"`, which the validator rejects anyway.
const SAFE_COMMAND_CHARS: &str = r" -_.\/:=+@~";

/// The stable part of the warning logged for a root whose mount mode Windows
/// cannot read. Each line starts `<variable>: ` and then this.
const UNVERIFIABLE_MOUNT_MODE_WARNING: &str = "could not verify the mount access mode";

/// How long the test waits after readiness before writing the inbox request,
/// so the startup scan, which runs just after the readiness line, has listed
/// an empty inbox and the watch reports the request. Timing-based: if the scan
/// is slower, it claims the request instead and the test still passes.
const STARTUP_SCAN_WINDOW: Duration = Duration::from_millis(500);

#[test]
fn a_request_in_the_inbox_makes_the_watcher_binary_run_the_reload_command_on_windows(
) -> Result<(), Box<dyn Error>> {
    let watcher = Watcher::start(false)?;

    std::thread::sleep(STARTUP_SCAN_WINDOW);
    let request = write_request(&watcher.layout.inbox)?;

    watcher.wait_for_marker();

    // Claimed on pickup: the file leaves the inbox before the reload starts.
    assert!(
        !request.exists(),
        "a picked-up request should have left the inbox: {}",
        request.display()
    );
    // Deleted on complete: gone from `pending/` once the reload has finished.
    watcher.wait_for_empty_pending();

    // At least the startup scan's per-scan directory check has run by now. It
    // repeats the root check and must not log the warning again.
    watcher.assert_mount_mode_warned_once();

    watcher.finish();
    Ok(())
}

/// Startup recovery: a request a previous run claimed and never completed is
/// left in `pending/`. The watcher reloads it once its hold window closes and
/// then deletes it.
#[test]
fn a_request_left_in_pending_is_reloaded_and_deleted_at_startup_on_windows(
) -> Result<(), Box<dyn Error>> {
    let watcher = Watcher::start(true)?;

    watcher.wait_for_marker();
    watcher.wait_for_empty_pending();
    assert_eq!(
        watcher.log.count(RECOVERED_ONE_LINE),
        1,
        "the watcher should have logged '{RECOVERED_ONE_LINE}' once.\n{}",
        watcher.log.render()
    );

    watcher.finish();
    Ok(())
}

/// A running `wcp-watcher`, past its readiness line.
///
/// Fields drop in declaration order: the child is killed and reaped first, on
/// every path out of a test, so it no longer holds the inbox open when the
/// temp root is removed.
struct Watcher {
    child: ChildGuard,
    log: Transcript,
    layout: Layout,
    config: String,
    _tmp: TempDir,
}

impl Watcher {
    /// Starts the watcher on a fresh temp layout, with one request already in
    /// `pending/` when `with_pending_request` is set.
    fn start(with_pending_request: bool) -> Result<Self, Box<dyn Error>> {
        let tmp = TempDir::new()?;
        // The watcher refuses a root that does not canonicalize to itself, so
        // every path is derived from the canonical temp root.
        let layout = Layout::under(canonical_root(tmp.path()));

        let command = vec![
            path_arg(&cmd_exe()),
            "/c".to_string(),
            "mkdir".to_string(),
            path_arg(&layout.marker),
        ];
        for element in &command {
            assert_command_element(element);
        }
        let config = watcher_config(&command);

        std::fs::create_dir_all(&layout.watcher_config_dir)?;
        std::fs::create_dir_all(&layout.inbox)?;
        std::fs::create_dir_all(&layout.outbox)?;
        std::fs::write(&layout.config_file, &config)?;
        if with_pending_request {
            std::fs::create_dir(&layout.pending)?;
            std::fs::write(layout.pending.join(request_name()), request_body())?;
        }

        // Set by Cargo for integration tests; see tests/support/mod.rs.
        let mut child = Command::new(env!("CARGO_BIN_EXE_wcp-watcher"))
            .env(WATCHER_ID_VAR, TEST_WATCHER_ID)
            .env(CONFIG_DIR_VAR, &layout.config_dir)
            .env(REQUESTS_DIR_VAR, &layout.requests_dir)
            .env(STARTUP_HOLD_MS_VAR, STARTUP_HOLD_MS.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("the wcp-watcher binary should spawn: {error}"))?;

        let log = Transcript::capture(
            &mut child,
            &format!("Watching '{}'", layout.inbox.display()),
        );
        let mut child = ChildGuard(child);

        // `Watching '<inbox>'` is logged after the directory check, the
        // pending directory's recovery and the watch start, so an inbox
        // request written after it is reported by the watch.
        log.wait_for_ready(READY_TIMEOUT, &mut child);

        Ok(Self {
            child,
            log,
            layout,
            config,
            _tmp: tmp,
        })
    }

    fn wait_for_marker(&self) {
        wait_for_marker(&self.layout.marker, &self.config, &self.log);
    }

    fn wait_for_empty_pending(&self) {
        wait_for_empty_pending(&self.layout.pending, &self.log);
    }

    /// Each root's unverifiable-mount-mode warning appears exactly once.
    fn assert_mount_mode_warned_once(&self) {
        for var in [CONFIG_DIR_VAR, REQUESTS_DIR_VAR] {
            let warning = format!("{var}: {UNVERIFIABLE_MOUNT_MODE_WARNING}");
            assert_eq!(
                self.log.count(&warning),
                1,
                "the watcher should have logged '{warning}' exactly once.\n{}",
                self.log.render()
            );
        }
    }

    /// Stops the watcher and prints its transcript, which `--nocapture`
    /// shows.
    fn finish(self) {
        let Self { child, log, .. } = self;
        drop(child);
        println!("{}", log.render());
        log.join();
    }
}

/// Canonicalizes the temp root, stripping the verbatim `\\?\` prefix that
/// `std::fs::canonicalize` adds on Windows.
///
/// The watcher's directory check canonicalizes through `dunce`, which yields
/// the non-verbatim form for an ordinary local-drive path, and the reload
/// command's character class forbids the `?`.
fn canonical_root(path: &Path) -> PathBuf {
    let canonical = std::fs::canonicalize(path).expect("the temp root should canonicalize");
    let stripped = canonical
        .to_str()
        .and_then(|s| s.strip_prefix(r"\\?\"))
        .map(PathBuf::from);
    stripped.unwrap_or(canonical)
}

/// `%SystemRoot%\System32\cmd.exe`; element 0 of a reload command must be
/// absolute.
fn cmd_exe() -> PathBuf {
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    Path::new(&system_root).join("System32").join("cmd.exe")
}

fn path_arg(path: &Path) -> String {
    path.to_str().expect("a UTF-8 test path").to_string()
}

/// Fails early if `element` could not survive the watcher's command
/// validation, which would otherwise surface as the child exiting at startup.
fn assert_command_element(element: &str) {
    for c in element.chars() {
        assert!(
            c.is_ascii_alphanumeric() || SAFE_COMMAND_CHARS.contains(c),
            "'{element}' contains '{c}', which a reload command element may not contain \
             (or which this test's hand-built TOML would not quote correctly). \
             Likely cause: TEMP."
        );
    }
}
