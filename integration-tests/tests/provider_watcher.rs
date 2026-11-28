//! End-to-end test of the provider and the real `wcp-watcher` together: the provider
//! writes the watcher's config, the watcher loads it, the provider queues a
//! refresh request, and the watcher runs the reload command.
//!
//! The watcher refuses a writable config root on Linux, while the provider has to
//! write it. As in a container, the watcher gets the same directory read-only:
//! it runs in a private user and mount namespace with the config directory
//! bind-mounted read-only onto itself. Where the host blocks unprivileged user
//! namespaces (including Ubuntu 23.10+'s AppArmor restriction, under which
//! `unshare` succeeds and the namespace's uid/gid maps are denied) the test
//! prints `SKIPPED: <reason>` and passes, unless
//! `WCP_WATCHER_E2E_REQUIRE_MOUNTS=1` makes it fail. Windows has no read-only
//! check yet, so the watcher runs as is there.
//!
//! The watcher starts before the provider queues its request, as the deployment
//! guidance says: a request queued before the watcher creates its inbox is
//! lost, and the provider's own tests (`watcher.rs`) cover that path.
//!
//! Exports a real certificate, so it needs:
//!
//!   ACM_TEST_CERTIFICATE_ARN — Certificate the provider exports
//!   ACM_TEST_ROLE_ARN        — IAM role the provider assumes when exporting
#![cfg(any(target_os = "linux", windows))]

mod common;

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::{
    ffi::CString,
    io,
    os::unix::{ffi::OsStrExt, fs::PermissionsExt, process::CommandExt},
};

use common::{locate_watcher_binary, AcmProviderProcess, TestCertificate};

const WATCHER_ID: &str = "e2e";

/// Time for the first refresh cycle: startup jitter (up to 5s), the ACM
/// export and the file writes.
const FIRST_CYCLE_TIMEOUT: Duration = Duration::from_secs(45);

/// Time for the watcher to create its inbox after it starts.
const WATCHER_READY_TIMEOUT: Duration = Duration::from_secs(15);

/// The watcher's startup hold, shortened from its 30s default.
const STARTUP_HOLD_MS: &str = "1000";

/// Time from the provider's restart to the watcher's reload: startup jitter, the
/// export, and the watcher's startup hold.
const RELOAD_TIMEOUT: Duration = Duration::from_secs(45);

/// Set to `1` to turn a missing-user-namespace skip into a failure.
#[cfg(target_os = "linux")]
const REQUIRE_MOUNTS_VAR: &str = "WCP_WATCHER_E2E_REQUIRE_MOUNTS";

const ACM_LOG_FILE: &str = "logs/acm_provider.log";

/// A test directory with the provider's config, the two watcher roots, the
/// certificate directory and the watcher's log.
struct TestDirs {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    config: PathBuf,
    requests: PathBuf,
}

impl TestDirs {
    fn new() -> Self {
        let tmp = tempfile::TempDir::new().expect("could not create test dir");
        // The validator requires canonical watcher directories.
        // Using dunce for windows compatibility
        let root = dunce::canonicalize(tmp.path()).expect("could not canonicalize test dir");
        let config = root.join("watcher-config");
        let requests = root.join("watcher-requests");
        for dir in [&config, &requests, &root.join("cert")] {
            std::fs::create_dir(dir).unwrap();
        }
        Self {
            _tmp: tmp,
            root,
            config,
            requests,
        }
    }

    fn watcher_dir(&self, sub: &str) -> PathBuf {
        self.requests.join(WATCHER_ID).join(sub)
    }

    fn marker(&self) -> PathBuf {
        self.root.join("reload-started")
    }

    #[cfg(target_os = "linux")]
    fn reload_release(&self) -> PathBuf {
        self.root.join("reload-release")
    }

    #[cfg(target_os = "linux")]
    fn reload_failure_mode(&self) -> PathBuf {
        self.root.join("reload-failure")
    }

    fn provider_log(&self) -> PathBuf {
        self.root.join(ACM_LOG_FILE)
    }

    fn watcher_log(&self) -> PathBuf {
        self.root.join("watcher.log")
    }

    /// The watcher's reload command. On Linux the fixture marks that it started,
    /// waits for the test to release it, and can then return a fixed failure.
    fn reload_command(&self) -> String {
        #[cfg(target_os = "linux")]
        {
            let program = self.root.join("reload-fixture");
            let script = format!(
                "#!/bin/sh\nset -eu\n: > '{}'\nwhile [ ! -e '{}' ]; do sleep 0.1; done\nif [ -e '{}' ]; then exit 42; fi\n",
                self.marker().display(),
                self.reload_release().display(),
                self.reload_failure_mode().display(),
            );
            std::fs::write(&program, script).unwrap();
            std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
            return program.display().to_string();
        }
        #[cfg(windows)]
        {
            let program = format!(
                r"{}\System32\cmd.exe /c mkdir",
                std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into())
            );
            format!("{program} {}", self.marker().display())
        }
    }

    /// Writes the provider's config for `cert`, routed to the watcher, whose
    /// reload command creates the marker.
    fn write_config(&self, cert: &TestCertificate) -> PathBuf {
        let cert_dir = self.root.join("cert");
        let toml = format!(
            "[capabilities.acm]\nenabled = true\nwatcher_config_dir = '{}'\nwatcher_requests_dir = '{}'\n\n\
             [[capabilities.acm.certificates]]\ncertificate_arn = '{}'\nrole_arn = '{}'\n\
             certificate_path = '{}'\nprivate_key_path = '{}'\nchain_path = '{}'\n\
             watcher_id = '{WATCHER_ID}'\nrefresh_command = '{}'\n",
            self.config.display(),
            self.requests.display(),
            cert.arn(),
            cert.role_arn(),
            cert_dir.join("cert.pem").display(),
            cert_dir.join("key.pem").display(),
            cert_dir.join("chain.pem").display(),
            self.reload_command(),
        );
        let path = self.root.join("config.toml");
        std::fs::write(&path, toml).unwrap();
        path
    }
}

/// Kills and reaps the watcher when the test ends, pass or fail.
struct WatcherProcess(Child);

impl Drop for WatcherProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Starts the watcher with the config root read-only in its own namespace, or
/// returns `None` when the host can't create the namespace.
fn start_watcher(dirs: &TestDirs) -> Option<WatcherProcess> {
    let log = File::create(dirs.watcher_log()).unwrap();
    let mut cmd = Command::new(locate_watcher_binary().canonicalize().unwrap());
    cmd.env("WCP_WATCHER_ID", WATCHER_ID)
        .env("WCP_WATCHER_CONFIG_DIR", &dirs.config)
        .env("WCP_WATCHER_REQUESTS_DIR", &dirs.requests)
        .env("WCP_WATCHER_STARTUP_HOLD_MS", STARTUP_HOLD_MS)
        .stdout(log.try_clone().unwrap())
        .stderr(log);
    #[cfg(target_os = "linux")]
    ReadOnlyBind::of(&dirs.config).install(&mut cmd);
    match cmd.spawn() {
        Ok(child) => Some(WatcherProcess(child)),
        #[cfg(target_os = "linux")]
        Err(e) if skip_without_namespaces(&e) => None,
        #[cfg(target_os = "linux")]
        Err(e) if setup_failure(&e).is_some() => {
            panic!(
                "could not start the watcher: {}",
                setup_failure(&e).unwrap()
            )
        }
        Err(e) => panic!("could not start the watcher: {e}"),
    }
}

#[cfg(target_os = "linux")]
/// A read-only bind mount of a directory onto itself, made in the child
/// before it execs.
struct ReadOnlyBind {
    path: CString,
    uid_map: CString,
    gid_map: CString,
    /// Flags the remount must keep: a mount namespace owned by a new user
    /// namespace can't clear the source mount's locked flags (mount(2)).
    kept_flags: libc::c_ulong,
}

#[cfg(target_os = "linux")]
impl ReadOnlyBind {
    fn of(path: &Path) -> Self {
        // SAFETY: `getuid`/`getgid` always succeed and touch no memory.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: `path` is a NUL-terminated string and `stat` is a valid,
        // zeroed `statvfs` buffer.
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::statvfs(path.as_ptr(), &mut stat) }, 0);
        let kept_flags = [
            (libc::ST_NOSUID, libc::MS_NOSUID),
            (libc::ST_NODEV, libc::MS_NODEV),
            (libc::ST_NOEXEC, libc::MS_NOEXEC),
            (libc::ST_NOATIME, libc::MS_NOATIME),
            (libc::ST_NODIRATIME, libc::MS_NODIRATIME),
            (libc::ST_RELATIME, libc::MS_RELATIME),
        ]
        .into_iter()
        .filter(|(st, _)| stat.f_flag & st != 0)
        .fold(0, |flags, (_, ms)| flags | ms);
        Self {
            path,
            uid_map: CString::new(format!("{uid} {uid} 1\n")).unwrap(),
            gid_map: CString::new(format!("{gid} {gid} 1\n")).unwrap(),
            kept_flags,
        }
    }

    fn install(self, cmd: &mut Command) {
        // SAFETY: the closure runs in the forked child, so it makes only raw
        // syscalls (`unshare`, `mount`, `open`, `write`, `close`) on buffers
        // allocated before `fork`, and reports errors through `errno`.
        unsafe {
            cmd.pre_exec(move || {
                // Later steps' errors are offset so the parent can tell them
                // apart: a host limit skips (`host_limit`), anything else
                // fails the test (`setup_failure`).
                if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) != 0 {
                    return Err(io::Error::last_os_error());
                }
                // `setgroups` must be denied before writing the gid map
                // (user_namespaces(7)).
                write_proc(c"/proc/self/setgroups", b"deny").map_err(|e| after(MAPS_FAILED, e))?;
                write_proc(c"/proc/self/uid_map", self.uid_map.as_bytes())
                    .map_err(|e| after(MAPS_FAILED, e))?;
                write_proc(c"/proc/self/gid_map", self.gid_map.as_bytes())
                    .map_err(|e| after(MAPS_FAILED, e))?;
                // The namespace is owned by the new user namespace, so these
                // mounts can't propagate to the host (mount_namespaces(7)).
                let p = self.path.as_ptr();
                let none = std::ptr::null();
                if libc::mount(p, p, none, libc::MS_BIND, none.cast()) != 0
                    || libc::mount(
                        none,
                        p,
                        none,
                        libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY | self.kept_flags,
                        none.cast(),
                    ) != 0
                {
                    return Err(after(BIND_FAILED, io::Error::last_os_error()));
                }
                Ok(())
            });
        }
    }
}

/// Offsets added to `errno` for setup steps after `unshare`, so the parent can
/// tell them from a host without namespaces.
#[cfg(target_os = "linux")]
const MAPS_FAILED: i32 = 1000;
#[cfg(target_os = "linux")]
const BIND_FAILED: i32 = 2000;

/// `error`'s errno offset by `step`. Doesn't allocate, so it's safe before `exec`.
#[cfg(target_os = "linux")]
fn after(step: i32, error: io::Error) -> io::Error {
    io::Error::from_raw_os_error(step + error.raw_os_error().unwrap_or(0))
}

/// What failed, if `error` came from a setup step after `unshare`.
#[cfg(target_os = "linux")]
fn setup_failure(error: &io::Error) -> Option<String> {
    let code = error.raw_os_error()?;
    let (step, errno) = match code {
        c if c >= BIND_FAILED => (
            "bind-mounting the config directory read-only",
            c - BIND_FAILED,
        ),
        c if c >= MAPS_FAILED => ("writing the namespace's uid/gid maps", c - MAPS_FAILED),
        _ => return None,
    };
    Some(format!(
        "{step} failed: {}",
        io::Error::from_raw_os_error(errno)
    ))
}

#[cfg(target_os = "linux")]
/// Writes all of `bytes` to an existing `/proc` file with raw syscalls.
///
/// # Safety
///
/// Safe to call in a forked child before `exec`: it makes no allocation.
unsafe fn write_proc(path: &std::ffi::CStr, bytes: &[u8]) -> io::Result<()> {
    let fd = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let written = libc::write(fd, bytes.as_ptr().cast(), bytes.len());
    libc::close(fd);
    if written != bytes.len() as isize {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Why the host, not the test, kept the namespace from being set up, if it did:
///
/// - `unshare` failed with `EPERM`/`EACCES` (blocked by policy), `ENOSPC`
///   (`user.max_user_namespaces=0`) or `EINVAL` (unsupported).
/// - `unshare` succeeded but writing the uid/gid maps got `EPERM`/`EACCES`.
///   Ubuntu 23.10 and later do this to an unprivileged, unconfined process
///   when `kernel.apparmor_restrict_unprivileged_userns=1`: AppArmor moves the
///   new namespace into its `unprivileged_userns` profile, which denies
///   `CAP_SYS_ADMIN` (seen on Ubuntu 24.04, where `setgroups` gets `EACCES`).
///
/// A failure of the bind mount itself is never a host limit: it is how a
/// wrong remount shows up, so it fails the test.
#[cfg(target_os = "linux")]
fn host_limit(error: &io::Error) -> Option<String> {
    let code = error.raw_os_error()?;
    match code {
        libc::EPERM | libc::EACCES | libc::ENOSPC | libc::EINVAL => Some(format!(
            "could not create a private user+mount namespace ({error}); unprivileged user \
             namespaces are probably disabled on this host"
        )),
        c if (MAPS_FAILED..BIND_FAILED).contains(&c)
            && matches!(c - MAPS_FAILED, libc::EPERM | libc::EACCES) =>
        {
            Some(format!(
                "the user namespace was created but its uid/gid maps were denied ({}); on \
                 Ubuntu 23.10+ set kernel.apparmor_restrict_unprivileged_userns=0 or run as root",
                io::Error::from_raw_os_error(c - MAPS_FAILED)
            ))
        }
        _ => None,
    }
}

/// Whether `error`, from spawning the watcher, is a [`host_limit`]. Prints
/// `SKIPPED: <reason>` when it is, or panics when [`REQUIRE_MOUNTS_VAR`] is
/// `1`.
#[cfg(target_os = "linux")]
fn skip_without_namespaces(error: &io::Error) -> bool {
    let Some(reason) = host_limit(error) else {
        return false;
    };
    if std::env::var(REQUIRE_MOUNTS_VAR).as_deref() == Ok("1") {
        panic!("{reason}, and {REQUIRE_MOUNTS_VAR}=1 requires a working namespace");
    }
    println!("SKIPPED: {reason}");
    true
}

/// Polls `done` until it returns true, or panics after `timeout` naming
/// `what` and showing both logs.
async fn wait_until(
    what: &str,
    timeout: Duration,
    dirs: &TestDirs,
    mut done: impl FnMut() -> bool,
) {
    let result = tokio::time::timeout(timeout, async {
        while !done() {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await;
    if result.is_err() {
        panic!(
            "timed out after {timeout:?} waiting for {what}.\nProvider log:\n{}\nWatcher log:\n{}",
            read(&dirs.provider_log()),
            read(&dirs.watcher_log()),
        );
    }
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// The entries in `dir`, or none if it doesn't exist.
fn entries(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .map(|e| e.filter_map(|e| e.ok().map(|e| e.path())).collect())
        .unwrap_or_default()
}

fn watcher_directories_are_empty(dirs: &TestDirs) -> bool {
    ["inbox", "pending", "outbox"]
        .into_iter()
        .all(|name| entries(&dirs.watcher_dir(name)).is_empty())
}

mod requests {
    use super::*;

    #[tokio::test]
    async fn the_watcher_runs_the_reload_for_the_providers_request() {
        let cert = TestCertificate::from_env();
        let dirs = TestDirs::new();
        let config = dirs.write_config(&cert);
        let watcher_config = dirs.config.join(WATCHER_ID).join("watcher.config.toml");

        // First run: the provider writes the watcher's config and the
        // certificate. With no watcher yet, its request can't be queued.
        {
            let mut provider = AcmProviderProcess::start(&config, &dirs.root).await;
            wait_until(
                "the first refresh to finish",
                FIRST_CYCLE_TIMEOUT,
                &dirs,
                || {
                    assert!(
                        provider.is_running(),
                        "the provider exited; see its output above"
                    );
                    watcher_config.exists()
                        && read(&dirs.provider_log())
                            .contains("Could not queue the refresh request")
                },
            )
            .await;
        }
        assert!(
            !dirs.marker().exists(),
            "the provider ran the watcher's command"
        );

        let Some(_watcher) = start_watcher(&dirs) else {
            return;
        };
        wait_until("the watcher's inbox", WATCHER_READY_TIMEOUT, &dirs, || {
            dirs.watcher_dir("inbox").is_dir() && dirs.watcher_dir("outbox").is_dir()
        })
        .await;

        // Second run: a restart queues a request even though the files are
        // unchanged. On Linux the reload fixture pauses before returning so
        // the provider's completion can be proven to wait for watcher status.
        let mut provider = AcmProviderProcess::start(&config, &dirs.root).await;
        wait_until("the watcher's reload", RELOAD_TIMEOUT, &dirs, || {
            assert!(
                provider.is_running(),
                "the provider exited; see its output above"
            );
            dirs.marker().exists()
        })
        .await;
        #[cfg(target_os = "linux")]
        {
            let provider_log = read(&dirs.provider_log());
            assert!(
                !provider_log.contains("Watcher refresh command completed")
                    && !provider_log.contains("Certificate refresh successful"),
                "the provider completed before the watcher returned status:\n{provider_log}"
            );
            std::fs::write(dirs.reload_release(), b"").unwrap();
        }
        wait_until(
            "the provider to consume the successful watcher outcome",
            RELOAD_TIMEOUT,
            &dirs,
            || {
                assert!(
                    provider.is_running(),
                    "the provider exited; see its output above"
                );
                let log = read(&dirs.provider_log());
                log.lines().any(|line| {
                    line.contains("Watcher refresh command completed:")
                        && line.contains(&format!("watcher={WATCHER_ID}"))
                        && line.contains(cert.arn())
                        && line.contains("outcome=success")
                }) && log.contains("Certificate refresh successful")
            },
        )
        .await;
        wait_until(
            "the successful request and status to be deleted",
            WATCHER_READY_TIMEOUT,
            &dirs,
            || watcher_directories_are_empty(&dirs),
        )
        .await;

        let provider_log = read(&dirs.provider_log());
        // The first run's failure also names the watcher, so match the success line.
        assert!(
            provider_log.contains("Queued refresh request")
                && provider_log.contains(&format!("to watcher {WATCHER_ID}:")),
            "the provider didn't queue the request:\n{provider_log}"
        );

        #[cfg(target_os = "linux")]
        {
            drop(provider);
            std::fs::remove_file(dirs.marker()).unwrap();
            std::fs::remove_file(dirs.reload_release()).unwrap();
            std::fs::write(dirs.reload_failure_mode(), b"").unwrap();
            let prior_failures = provider_log.matches("outcome=failure").count();

            let mut failing_provider = AcmProviderProcess::start(&config, &dirs.root).await;
            wait_until("the failing reload to start", RELOAD_TIMEOUT, &dirs, || {
                assert!(
                    failing_provider.is_running(),
                    "the provider exited; see its output above"
                );
                dirs.marker().exists()
            })
            .await;
            std::fs::write(dirs.reload_release(), b"").unwrap();
            wait_until(
                "the provider to consume the failed watcher outcome",
                RELOAD_TIMEOUT,
                &dirs,
                || {
                    assert!(
                        failing_provider.is_running(),
                        "the provider exited; see its output above"
                    );
                    let log = read(&dirs.provider_log());
                    let correlated_failure = log.lines().any(|line| {
                        line.contains("Watcher refresh command completed:")
                            && line.contains(&format!("watcher={WATCHER_ID}"))
                            && line.contains(cert.arn())
                            && line.contains("outcome=failure")
                            && line.contains("exit_code=Some(42)")
                    });
                    log.matches("outcome=failure").count() == prior_failures + 1
                        && correlated_failure
                        && log.contains("Error refreshing certificate")
                        && log.contains("Watcher refresh command failed")
                },
            )
            .await;
            wait_until(
                "the failed request and status to be deleted",
                WATCHER_READY_TIMEOUT,
                &dirs,
                || watcher_directories_are_empty(&dirs),
            )
            .await;
        }

        let watcher_log = read(&dirs.watcher_log());
        for line in [
            "1 certificate(s), 1 distinct reload command(s)",
            "Accepted request",
            "Running reload",
        ] {
            assert!(
                watcher_log.contains(line),
                "watcher log lacks {line:?}:\n{watcher_log}"
            );
        }
        assert!(
            watcher_log.contains(cert.arn()),
            "the reload isn't for the test certificate:\n{watcher_log}"
        );
    }
}
