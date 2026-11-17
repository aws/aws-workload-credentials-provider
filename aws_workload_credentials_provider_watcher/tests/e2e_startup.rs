//! End-to-end startup tests for the `wcp-watcher` binary.
//!
//! Pins that the shipped binary (`CARGO_BIN_EXE_wcp-watcher`) cannot bypass the
//! mount-mode check, which runs before any configuration is read. On Unix it
//! refuses a writable config mount; on Linux it also refuses a read-only
//! requests mount, using real tmpfs mounts in a private namespace
//! (`support::namespace`). Windows cannot read the mount mode, so there it
//! stops at the missing configuration file instead. The accepting path is
//! `tests/e2e_reload.rs`. Needs no credentials, network or privilege.

mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use aws_workload_credentials_provider_common::config::error_messages::WATCHER_DIRECTORY_WRONG_MOUNT_MODE_ERR_MSG;
use tempfile::TempDir;

#[cfg(target_os = "linux")]
use support::namespace::{skip_without_namespaces, MountMode, NamespaceSetup};
#[cfg(target_os = "linux")]
use support::Layout;
use support::{CONFIG_DIR_VAR, REQUESTS_DIR_VAR, TEST_WATCHER_ID, WATCHER_ID_VAR};

/// The start of the error the binary reports when the configuration file
/// cannot be read. Its absence shows the binary stopped before the read.
const CONFIG_READ_ERR_PREFIX: &str = "Failed to read the watcher configuration file";

/// The stable part of the warning logged, to stdout, for a root whose mount
/// mode Windows cannot read. Each line starts `<variable>: ` and then this.
#[cfg(windows)]
const UNVERIFIABLE_MOUNT_MODE_WARNING: &str = "could not verify the mount access mode";

/// What the binary printed when run against the temp-directory layout.
struct Run {
    status: std::process::ExitStatus,
    /// The log: log4rs's console appender writes to stdout.
    #[cfg_attr(not(windows), allow(dead_code))]
    stdout: String,
    stderr: String,
    transcript: String,
}

/// Runs the binary against distinct `<tmp>/config` and `<tmp>/requests`
/// roots, both on the temp directory's read-write mount.
///
/// No configuration file is written. If the directory check passes, the
/// binary stops at the configuration read instead of running, so `output()`
/// cannot hang.
fn run_against_one_writable_temp_dir() -> Run {
    let tmp = TempDir::new().expect("a temp directory");
    // The directory check refuses a root that does not canonicalize to
    // itself; canonicalizing here makes the result the mount mode, not a
    // symlinked `TMPDIR`.
    let root = canonicalize_root(tmp.path());

    let config_dir = root.join("config");
    let requests_dir = root.join("requests");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::create_dir_all(requests_dir.join(TEST_WATCHER_ID).join("inbox")).unwrap();
    std::fs::create_dir_all(requests_dir.join(TEST_WATCHER_ID).join("outbox")).unwrap();

    // Set by Cargo for integration tests; see tests/support/mod.rs.
    let output = Command::new(env!("CARGO_BIN_EXE_wcp-watcher"))
        .env(WATCHER_ID_VAR, TEST_WATCHER_ID)
        .env(CONFIG_DIR_VAR, &config_dir)
        .env(REQUESTS_DIR_VAR, &requests_dir)
        .output()
        .expect("the wcp-watcher binary should run");

    Run::from(output)
}

impl From<Output> for Run {
    fn from(output: Output) -> Self {
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let transcript = format!("--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}\n---");
        Run {
            status: output.status,
            stdout,
            stderr,
            transcript,
        }
    }
}

#[cfg(unix)]
#[test]
fn the_watcher_binary_refuses_a_writable_config_mount() {
    let Run {
        status,
        stderr,
        transcript,
        ..
    } = run_against_one_writable_temp_dir();

    assert!(
        !status.success(),
        "the binary must refuse a writable config mount, but exited {status:?}.\n{transcript}"
    );
    assert!(
        stderr.contains(WATCHER_DIRECTORY_WRONG_MOUNT_MODE_ERR_MSG),
        "stderr should report the wrong-mount-mode refusal.\n{transcript}"
    );
    assert!(
        stderr.contains(CONFIG_DIR_VAR),
        "stderr should name {CONFIG_DIR_VAR}.\n{transcript}"
    );
    assert!(
        !stderr.contains(REQUESTS_DIR_VAR),
        "the requests root is read-write, as required, and must not be named.\n{transcript}"
    );
    assert!(
        !stderr.contains(CONFIG_READ_ERR_PREFIX),
        "the binary should stop at the directory check, before reading configuration.\n\
         {transcript}"
    );
}

/// The requests root must be read-write. Both roots are tmpfs mounts in the
/// child's namespace, and both are remounted read-only after the
/// `<id>/{inbox,outbox}` layout is created, so the config root passes and the
/// only refusal is the requests root's mount mode. No configuration file is
/// written: a binary that skipped the check would stop at the configuration
/// read.
#[cfg(target_os = "linux")]
#[test]
fn the_watcher_binary_refuses_a_read_only_requests_mount() {
    let tmp = TempDir::new().expect("a temp directory");
    let layout = Layout::under(canonicalize_root(tmp.path()));
    // The mountpoints exist on the host and stay empty there.
    std::fs::create_dir(&layout.config_dir).unwrap();
    std::fs::create_dir(&layout.requests_dir).unwrap();

    // Set by Cargo for integration tests; see tests/support/mod.rs.
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_wcp-watcher"));
    cmd.env(WATCHER_ID_VAR, TEST_WATCHER_ID)
        .env(CONFIG_DIR_VAR, &layout.config_dir)
        .env(REQUESTS_DIR_VAR, &layout.requests_dir);
    NamespaceSetup::for_current_user(
        &[
            (&layout.config_dir, MountMode::ReadOnly),
            (&layout.requests_dir, MountMode::ReadOnly),
        ],
        // Parents before children: `mkdir` is not recursive.
        &[&layout.watcher_requests_dir, &layout.inbox, &layout.outbox],
        &[],
    )
    .install(&mut cmd);

    let output = match cmd.output() {
        Ok(output) => output,
        Err(error) if skip_without_namespaces(&error) => return,
        Err(error) => panic!("the wcp-watcher binary should run: {error}"),
    };
    let Run {
        status,
        stderr,
        transcript,
        ..
    } = Run::from(output);

    assert!(
        !status.success(),
        "the binary must refuse a read-only requests mount, but exited {status:?}.\n{transcript}"
    );
    assert!(
        stderr.contains(WATCHER_DIRECTORY_WRONG_MOUNT_MODE_ERR_MSG),
        "stderr should report the wrong-mount-mode refusal.\n{transcript}"
    );
    assert!(
        stderr.contains(REQUESTS_DIR_VAR),
        "stderr should name {REQUESTS_DIR_VAR}.\n{transcript}"
    );
    assert!(
        !stderr.contains(CONFIG_DIR_VAR),
        "the config root is read-only, as required, and must not be named.\n{transcript}"
    );
    assert!(
        !stderr.contains(CONFIG_READ_ERR_PREFIX),
        "the binary should stop at the directory check, before reading configuration.\n\
         {transcript}"
    );
}

/// The Windows gap, pinned: the mount mode cannot be read there, so the
/// directory check accepts both roots with one logged warning each, and the
/// binary goes on to the configuration read, which fails because no file was
/// written.
#[cfg(windows)]
#[test]
fn the_watcher_binary_accepts_an_unverifiable_mount_mode_on_windows() {
    let Run {
        status,
        stdout,
        stderr,
        transcript,
    } = run_against_one_writable_temp_dir();

    assert!(
        !status.success(),
        "the binary must fail at the missing configuration, but exited {status:?}.\n{transcript}"
    );
    assert!(
        !stderr.contains(WATCHER_DIRECTORY_WRONG_MOUNT_MODE_ERR_MSG),
        "an unverifiable mount mode must not be refused on Windows.\n{transcript}"
    );
    assert!(
        stderr.contains(CONFIG_READ_ERR_PREFIX),
        "the binary should pass the directory check and stop at the configuration read.\n\
         {transcript}"
    );
    for var in [CONFIG_DIR_VAR, REQUESTS_DIR_VAR] {
        let warning = format!("{var}: {UNVERIFIABLE_MOUNT_MODE_WARNING}");
        let count = stdout
            .lines()
            .filter(|line| line.contains(&warning))
            .count();
        assert_eq!(
            count, 1,
            "the log should warn '{warning}' exactly once.\n{transcript}"
        );
    }
}

/// Canonicalizes the temp root the test derives every other path from.
#[cfg(unix)]
fn canonicalize_root(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).expect("the temp root should canonicalize")
}

/// Canonicalizes the temp root, stripping the Windows verbatim prefix.
///
/// `std::fs::canonicalize` returns an extended-length `\\?\` path on Windows.
/// The watcher's validator canonicalizes through `dunce`, which yields
/// non-verbatim paths for ordinary local-drive paths like the CI temp
/// directory, so the roots this test hands the watcher must be stripped to
/// match — otherwise `canonical == dir` fails and the watcher refuses the root
/// for the wrong reason.
#[cfg(windows)]
fn canonicalize_root(path: &Path) -> PathBuf {
    let canonical = std::fs::canonicalize(path).expect("the temp root should canonicalize");
    let stripped = canonical
        .to_str()
        .and_then(|s| s.strip_prefix(r"\\?\"))
        .map(PathBuf::from);
    stripped.unwrap_or(canonical)
}
