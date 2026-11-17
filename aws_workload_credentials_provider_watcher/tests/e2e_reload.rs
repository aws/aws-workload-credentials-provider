//! End-to-end reload test for the `wcp-watcher` binary, on a read-only config
//! mount and a read-write requests mount.
//!
//! The binary refuses a writable config root (`tests/e2e_startup.rs`), so this
//! test runs it unmodified, with no mock and no test knob, on real tmpfs
//! mounts made without privilege.
//!
//! # Mounts
//!
//! [`NamespaceSetup`] mounts a tmpfs on each root in the child's own mount
//! namespace, writes the configuration, the `<id>/{inbox,outbox}` layout and
//! a `pending/` request for the recovery test, then remounts the config tmpfs
//! read-only and execs the watcher. Where the host blocks unprivileged user
//! namespaces the test prints `SKIPPED: <reason>` and passes, unless
//! `WCP_WATCHER_E2E_REQUIRE_MOUNTS=1` makes it fail.
//!
//! The test reaches the child's mounts through `/proc/<pid>/root/...`, writing
//! the inbox request only after the watcher is ready so that the watch, not
//! the startup scan, reports it. The reload marker lives outside both mounts.
//!
//! The configuration and requests are test-local constants, not the ACM
//! provider's generator or writer; the ACM provider/watcher format contract is
//! pinned by unit tests.
#![cfg(target_os = "linux")]

mod support;

use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use tempfile::TempDir;

use support::namespace::{skip_without_namespaces, MountMode, NamespaceSetup};
use support::{
    request_body, request_name, wait_for_empty_pending, wait_for_marker, watcher_config,
    write_request, ChildGuard, Layout, Transcript, CONFIG_DIR_VAR, READY_TIMEOUT,
    RECOVERED_ONE_LINE, REQUESTS_DIR_VAR, STARTUP_HOLD_MS, STARTUP_HOLD_MS_VAR, TEST_WATCHER_ID,
    WATCHER_ID_VAR,
};

/// How long the watcher sits idle, with no request, before one is written.
/// Long enough that the inbox busy-loop this guards against (the watcher
/// re-admitting its own inbox directory on every `Access(Open)` event, about
/// 17k log lines a second) would show up thousands of times.
const IDLE_WINDOW: Duration = Duration::from_millis(500);

/// The busy-loop's log line, and how many of them the whole run may contain.
/// A correct watcher logs none
const UNPARSEABLE_LINE: &str = "isn't a usable request";
const MAX_UNPARSEABLE_LINES: usize = 1;

/// Characters a reload command element may contain for this test.
///
/// A subset of `common::config::watcher_config`'s Unix `COMMAND_ELEMENT_RE`
/// (`^[a-zA-Z0-9/_\-\. =+@]+$`) without the space, since the command is
/// written into a hand-built TOML array.
const SAFE_COMMAND_CHARS: &str = "/_-.=+@";

#[test]
fn a_request_in_the_inbox_makes_the_watcher_binary_run_the_reload_command(
) -> Result<(), Box<dyn Error>> {
    let Some(watcher) = Watcher::start(false)? else {
        return Ok(());
    };

    // Idle first, so a watcher that spins on its own inbox directory has time
    // to show it. Counted after the reload, below.
    std::thread::sleep(IDLE_WINDOW);

    let request = write_request(&watcher.in_child(&watcher.layout.inbox))?;

    // A request inside the startup hold window is released when it closes;
    // one after it runs immediately. Either way the command runs once.
    watcher.wait_for_marker();

    // Claimed on pickup: the file leaves the inbox before the reload starts.
    assert!(
        !request.exists(),
        "a picked-up request should have left the inbox: {}",
        request.display()
    );
    // Deleted on complete: gone from `pending/` once the reload has finished.
    watcher.wait_for_empty_pending();

    // Covers the idle window and the request's own events.
    let unparseable = watcher.log.count(UNPARSEABLE_LINE);
    assert!(
        unparseable <= MAX_UNPARSEABLE_LINES,
        "the watcher logged '{UNPARSEABLE_LINE}' {unparseable} times (at most \
         {MAX_UNPARSEABLE_LINES} allowed); it is probably spinning on its inbox directory.\n{}",
        watcher.log.render()
    );

    watcher.finish();
    Ok(())
}

/// Startup recovery: a request a previous run claimed and never completed is
/// left in `pending/`. The watcher reloads it once its hold window closes and
/// then deletes it.
#[test]
fn a_request_left_in_pending_is_reloaded_and_deleted_at_startup() -> Result<(), Box<dyn Error>> {
    let Some(watcher) = Watcher::start(true)? else {
        return Ok(());
    };

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

/// A running `wcp-watcher` in its own namespace, past its readiness line.
///
/// Fields drop in declaration order: the child is killed and reaped first, on
/// every path out of a test including an unwinding assertion, so its
/// namespace and mounts go with it before the temp root is removed.
struct Watcher {
    child: ChildGuard,
    log: Transcript,
    layout: Layout,
    config: String,
    _tmp: TempDir,
}

impl Watcher {
    /// Starts the watcher, with one request already in `pending/` when
    /// `with_pending_request` is set. `None` when the host cannot create the
    /// namespace and the test should skip.
    fn start(with_pending_request: bool) -> Result<Option<Self>, Box<dyn Error>> {
        let tmp = TempDir::new()?;
        // The watcher refuses a root that does not canonicalize to itself, so
        // every path is derived from the canonical temp root.
        let layout = Layout::under(std::fs::canonicalize(tmp.path())?);

        let command = vec![
            touch_path().to_string_lossy().into_owned(),
            layout.marker.to_string_lossy().into_owned(),
        ];
        for element in &command {
            assert_command_element(element);
        }

        // The two mountpoints exist on the host and stay empty there.
        // Everything under them is created inside the child's mounts by
        // `pre_exec`.
        std::fs::create_dir(&layout.config_dir)?;
        std::fs::create_dir(&layout.requests_dir)?;

        let config = watcher_config(&command);

        // Parents before children: `mkdir` is not recursive.
        let mut dirs = vec![
            &layout.watcher_config_dir,
            &layout.watcher_requests_dir,
            &layout.inbox,
            &layout.outbox,
        ];
        let mut files = vec![(layout.config_file.clone(), config.as_bytes().to_vec())];
        if with_pending_request {
            dirs.push(&layout.pending);
            files.push((
                layout.pending.join(request_name()),
                request_body().into_bytes(),
            ));
        }

        // Set by Cargo for integration tests; see tests/support/mod.rs.
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_wcp-watcher"));
        cmd.env(WATCHER_ID_VAR, TEST_WATCHER_ID)
            .env(CONFIG_DIR_VAR, &layout.config_dir)
            .env(REQUESTS_DIR_VAR, &layout.requests_dir)
            .env(STARTUP_HOLD_MS_VAR, STARTUP_HOLD_MS.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        NamespaceSetup::for_current_user(
            &[
                (&layout.config_dir, MountMode::ReadOnly),
                (&layout.requests_dir, MountMode::ReadWrite),
            ],
            &dirs,
            &files,
        )
        .install(&mut cmd);

        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(error) if skip_without_namespaces(&error) => return Ok(None),
            Err(error) => {
                return Err(format!("the wcp-watcher binary should spawn: {error}").into())
            }
        };

        let log = Transcript::capture(
            &mut child,
            &format!("Watching '{}'", layout.inbox.display()),
        );
        let mut child = ChildGuard(child);

        // `Watching '<inbox>'` is logged after the mount-mode check, the
        // pending directory's recovery and the watch start, so an inbox
        // request written after it is reported by the watch.
        log.wait_for_ready(READY_TIMEOUT, &mut child);

        let watcher = Self {
            child,
            log,
            layout,
            config,
            _tmp: tmp,
        };
        watcher.assert_mount_modes()?;
        Ok(Some(watcher))
    }

    /// `path`, a host-side path, as seen in the child's mount namespace.
    fn in_child(&self, path: &Path) -> PathBuf {
        PathBuf::from(format!("/proc/{}/root", self.child.0.id()))
            .join(path.strip_prefix("/").unwrap())
    }

    /// The watcher just passed its real mount-mode check. Pins that, in its
    /// namespace, the config root really is read-only and the requests root
    /// read-write, and that both are mounts the host cannot see.
    fn assert_mount_modes(&self) -> io::Result<()> {
        let layout = &self.layout;

        let config_probe = self.in_child(&layout.config_dir).join(".probe");
        match std::fs::File::create(&config_probe) {
            Ok(_) => panic!(
                "the config root must be read-only in the child's namespace, but '{}' was created",
                config_probe.display()
            ),
            Err(error) => assert_eq!(
                error.raw_os_error(),
                Some(libc::EROFS),
                "writing into the config root should fail as a read-only mount: {error}"
            ),
        }

        let requests_probe = self.in_child(&layout.requests_dir).join(".probe");
        std::fs::File::create(&requests_probe)?;
        std::fs::remove_file(&requests_probe)?;

        assert!(
            self.in_child(&layout.config_file).is_file() && !layout.config_file.exists(),
            "the configuration must exist only inside the child's config mount"
        );
        assert!(
            self.in_child(&layout.inbox).is_dir() && !layout.inbox.exists(),
            "the inbox must exist only inside the child's requests mount"
        );
        Ok(())
    }

    /// Blocks until the reload command's marker exists, or fails the test.
    /// The marker lives outside both mounts, so its host path is used.
    fn wait_for_marker(&self) {
        wait_for_marker(&self.layout.marker, &self.config, &self.log);
    }

    /// Blocks until `pending/`, inside the child's requests mount, exists and
    /// is empty, or fails the test.
    fn wait_for_empty_pending(&self) {
        wait_for_empty_pending(&self.in_child(&self.layout.pending), &self.log);
    }

    /// Stops the watcher and prints its transcript, which `--nocapture`
    /// shows: the config load, the recovery, the accepted request and the
    /// reload.
    fn finish(self) {
        let Self { child, log, .. } = self;
        drop(child);
        println!("{}", log.render());
        log.join();
    }
}

/// Absolute path to `touch`; element 0 of a reload command must be absolute.
fn touch_path() -> PathBuf {
    ["/usr/bin/touch", "/bin/touch"]
        .into_iter()
        .map(PathBuf::from)
        .find(|candidate| candidate.is_file())
        .expect("this test needs `touch` at /usr/bin/touch or /bin/touch as its reload command")
}

/// Fails early if `element` could not survive the watcher's command
/// validation, which would otherwise surface as the child exiting at startup.
fn assert_command_element(element: &str) {
    for c in element.chars() {
        assert!(
            c.is_ascii_alphanumeric() || SAFE_COMMAND_CHARS.contains(c),
            "'{element}' contains '{c}', which a reload command element may not contain \
             (or which this test's hand-built TOML would not quote correctly). \
             Likely cause: TMPDIR."
        );
    }
}
