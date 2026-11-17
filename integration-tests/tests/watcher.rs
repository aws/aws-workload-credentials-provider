//! Integration tests for the provider's side of the watcher protocol: at startup
//! the provider writes each watcher's `watcher.config.toml`, and for a
//! certificate with a `watcher_id` it queues a refresh request in that
//! watcher's inbox instead of running the refresh command itself.
//!
//! The config tests use placeholder ARNs, since the configs are written before
//! any AWS call. The request tests export a real certificate and need:
//!
//!   ACM_TEST_CERTIFICATE_ARN — Certificate the provider exports
//!   ACM_TEST_ROLE_ARN        — IAM role the provider assumes when exporting

mod common;

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use common::{run_provider_until_exit, AcmProviderProcess, TestCertificate};

/// Time for the provider to start and write the watcher configs.
const CONFIG_WRITE_TIMEOUT: Duration = Duration::from_secs(15);

/// Time for the first refresh cycle: startup jitter (up to 5s), the ACM
/// export and the file writes.
const FIRST_CYCLE_TIMEOUT: Duration = Duration::from_secs(45);

const ACM_LOG_FILE: &str = "logs/acm_provider.log";

const CONFIG_FILE: &str = "watcher.config.toml";

/// A test directory with the two watcher roots the validator requires.
struct TestDirs {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    config: PathBuf,
    requests: PathBuf,
}

impl TestDirs {
    fn new() -> Self {
        let tmp = tempfile::TempDir::new().expect("could not create test dir");
        // The validator requires canonical paths and canonicalizes with
        // `dunce`: on Windows that expands 8.3 short names in `%TEMP%` (e.g.
        // `ADMINI~1`) without adding the `\\?\` prefix the validator rejects.
        let root = dunce::canonicalize(tmp.path()).expect("could not canonicalize test dir");
        let config = root.join("watcher-config");
        let requests = root.join("watcher-requests");
        std::fs::create_dir(&config).unwrap();
        std::fs::create_dir(&requests).unwrap();
        Self {
            _tmp: tmp,
            root,
            config,
            requests,
        }
    }

    fn inbox(&self, watcher_id: &str) -> PathBuf {
        self.requests.join(watcher_id).join("inbox")
    }

    fn log(&self) -> PathBuf {
        self.root.join(ACM_LOG_FILE)
    }

    /// A refresh command for a watcher certificate. The provider must never
    /// run it, so the tests check that its marker doesn't appear.
    fn command(&self, marker: &str) -> String {
        format!("{} {}", program(), self.root.join(marker).display())
    }
}

struct Cert {
    arn: String,
    role_arn: String,
    watcher_id: Option<&'static str>,
    refresh_command: Option<String>,
}

impl Cert {
    fn placeholder(n: u32, watcher_id: Option<&'static str>, refresh_command: &str) -> Self {
        Self {
            arn: format!(
                "arn:aws:acm:us-east-1:123456789012:certificate/0000000{n}-1234-1234-1234-123456789012"
            ),
            role_arn: "arn:aws:iam::123456789012:role/PlaceholderRole".into(),
            watcher_id,
            refresh_command: Some(refresh_command.into()),
        }
    }

    fn real(cert: &TestCertificate, watcher_id: &'static str, refresh_command: &str) -> Self {
        Self {
            arn: cert.arn().into(),
            role_arn: cert.role_arn().into(),
            watcher_id: Some(watcher_id),
            refresh_command: Some(refresh_command.into()),
        }
    }
}

/// An absolute program the validator accepts in a watcher's command.
fn program() -> &'static str {
    #[cfg(unix)]
    {
        if Path::new("/usr/bin/touch").exists() {
            "/usr/bin/touch"
        } else {
            "/bin/touch"
        }
    }
    #[cfg(windows)]
    {
        r"C:\Windows\System32\whoami.exe"
    }
}

/// Writes the config and each certificate's directory, and returns the
/// config path. Certificate `i` writes its files under `cert-<i>/`.
fn write_config(dirs: &TestDirs, certs: &[Cert]) -> PathBuf {
    let mut toml = format!(
        "[capabilities.acm]\nenabled = true\nwatcher_config_dir = '{}'\nwatcher_requests_dir = '{}'\n",
        dirs.config.display(),
        dirs.requests.display()
    );
    for (i, cert) in certs.iter().enumerate() {
        let cert_dir = dirs.root.join(format!("cert-{i}"));
        std::fs::create_dir_all(&cert_dir).unwrap();
        toml.push_str(&format!(
            "\n[[capabilities.acm.certificates]]\ncertificate_arn = '{}'\nrole_arn = '{}'\ncertificate_path = '{}'\nprivate_key_path = '{}'\nchain_path = '{}'\n",
            cert.arn,
            cert.role_arn,
            cert_dir.join("cert.pem").display(),
            cert_dir.join("key.pem").display(),
            cert_dir.join("chain.pem").display(),
        ));
        if let Some(id) = cert.watcher_id {
            toml.push_str(&format!("watcher_id = '{id}'\n"));
        }
        if let Some(command) = &cert.refresh_command {
            toml.push_str(&format!("refresh_command = '{command}'\n"));
        }
    }
    let path = dirs.root.join("config.toml");
    std::fs::write(&path, toml).unwrap();
    path
}

/// Polls `done` until it returns true, or panics after `timeout` naming
/// `what` and showing the provider log.
async fn wait_until(what: &str, timeout: Duration, log: &Path, mut done: impl FnMut() -> bool) {
    let result = tokio::time::timeout(timeout, async {
        while !done() {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await;
    if result.is_err() {
        let content = std::fs::read_to_string(log).unwrap_or_default();
        panic!("timed out after {timeout:?} waiting for {what}.\nProvider log:\n{content}");
    }
}

fn log_contains(log: &Path, text: &str) -> bool {
    std::fs::read_to_string(log).is_ok_and(|l| l.contains(text))
}

/// The `.cmd` requests in `inbox`, sorted by name (oldest first).
fn requests(inbox: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(inbox)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|x| x == "cmd"))
                .collect()
        })
        .unwrap_or_default();
    found.sort();
    found
}

fn read_toml(path: &Path) -> toml::Value {
    toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn strings(value: &toml::Value) -> Vec<&str> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect()
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

// -- watcher configs --

#[tokio::test]
async fn startup_writes_one_config_per_watcher_grouped_by_command() {
    let dirs = TestDirs::new();
    let command = dirs.command("marker");
    // The same command with extra spaces.
    let spaced = command.replacen(' ', "   ", 1);
    let certs = [
        Cert::placeholder(1, Some("nginx"), &command),
        Cert::placeholder(2, Some("nginx"), &spaced),
        Cert::placeholder(3, Some("haproxy"), &dirs.command("other")),
        Cert::placeholder(4, None, &command),
    ];
    let config = write_config(&dirs, &certs);

    let _provider = AcmProviderProcess::start(&config, &dirs.root).await;
    let nginx = dirs.config.join("nginx").join(CONFIG_FILE);
    let haproxy = dirs.config.join("haproxy").join(CONFIG_FILE);
    wait_until(
        "both watcher configs",
        CONFIG_WRITE_TIMEOUT,
        &dirs.log(),
        || nginx.exists() && haproxy.exists(),
    )
    .await;

    let nginx = read_toml(&nginx);
    assert_eq!(nginx["schema_version"].as_integer(), Some(1));
    assert_eq!(nginx["watcher_id"].as_str(), Some("nginx"));
    let reloads = nginx["reload"].as_array().unwrap();
    assert_eq!(reloads.len(), 1, "{nginx}");
    let marker = dirs.root.join("marker").display().to_string();
    assert_eq!(strings(&reloads[0]["command"]), [program(), &marker]);
    assert_eq!(
        strings(&reloads[0]["certificate_arns"]),
        [certs[0].arn.as_str(), certs[1].arn.as_str()]
    );
    let haproxy = read_toml(&haproxy);
    assert_eq!(
        strings(&haproxy["reload"][0]["certificate_arns"]),
        [certs[2].arn.as_str()]
    );

    // Nothing for the certificate without a watcher, and no temp files.
    assert_eq!(names(&dirs.config), ["haproxy", "nginx"]);
    for id in ["haproxy", "nginx"] {
        assert_eq!(names(&dirs.config.join(id)), [CONFIG_FILE], "{id}");
    }
}

#[cfg(unix)]
#[tokio::test]
async fn watcher_configs_are_readable_by_other_users() {
    use std::os::unix::fs::PermissionsExt;
    let dirs = TestDirs::new();
    let config = write_config(
        &dirs,
        &[Cert::placeholder(1, Some("nginx"), &dirs.command("marker"))],
    );

    // The watcher may run as another user, so the provider's umask mustn't matter.
    let provider = common::locate_provider_binary().canonicalize().unwrap();
    let _child = tokio::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(r#"umask 077 && exec "$0" acm start --config "$1""#)
        .arg(&provider)
        .arg(&config)
        .current_dir(&dirs.root)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let file = dirs.config.join("nginx").join(CONFIG_FILE);
    wait_until(
        "the nginx config",
        CONFIG_WRITE_TIMEOUT,
        &dirs.log(),
        || file.exists(),
    )
    .await;

    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&dirs.config.join("nginx")), 0o755);
    assert_eq!(mode(&file), 0o644);
}

#[tokio::test]
async fn a_watcher_config_that_cannot_be_written_stops_startup() {
    let dirs = TestDirs::new();
    // A file where the watcher's directory should be.
    std::fs::write(dirs.config.join("nginx"), b"").unwrap();
    let config = write_config(
        &dirs,
        &[Cert::placeholder(1, Some("nginx"), &dirs.command("marker"))],
    );

    let (status, stdout, stderr) = run_provider_until_exit(&config, &dirs.root).await;

    assert!(!status.success(), "stdout: {stdout}\nstderr: {stderr}");
    assert!(
        stderr.contains("writing the config for watcher nginx"),
        "stderr: {stderr}"
    );
}

#[tokio::test]
async fn a_watcher_certificate_needs_a_refresh_command() {
    let dirs = TestDirs::new();
    let mut cert = Cert::placeholder(1, Some("nginx"), "unused");
    cert.refresh_command = None;
    let config = write_config(&dirs, &[cert]);

    let (status, stdout, stderr) = run_provider_until_exit(&config, &dirs.root).await;

    assert!(!status.success(), "stdout: {stdout}\nstderr: {stderr}");
    assert!(
        stderr.contains("certificates[0].refresh_command"),
        "stderr: {stderr}"
    );
    assert!(names(&dirs.config).is_empty(), "a config was written");
}

#[tokio::test]
async fn a_missing_watcher_directory_fails_validation() {
    let dirs = TestDirs::new();
    std::fs::remove_dir(&dirs.requests).unwrap();
    let config = write_config(
        &dirs,
        &[Cert::placeholder(1, Some("nginx"), &dirs.command("marker"))],
    );

    let (status, stdout, stderr) = run_provider_until_exit(&config, &dirs.root).await;

    assert!(!status.success(), "stdout: {stdout}\nstderr: {stderr}");
    assert!(stderr.contains("watcher_requests_dir"), "stderr: {stderr}");
}

#[tokio::test]
async fn a_config_too_large_for_the_watcher_stops_startup() {
    let dirs = TestDirs::new();
    // Validation limits the characters in a command, not its length.
    let long = format!("{} {}", program(), "a".repeat(300 * 1024));
    let config = write_config(&dirs, &[Cert::placeholder(1, Some("nginx"), &long)]);

    let (status, stdout, stderr) = run_provider_until_exit(&config, &dirs.root).await;

    assert!(!status.success(), "stdout: {stdout}\nstderr: {stderr}");
    assert!(stderr.contains("a watcher reads"), "stderr: {stderr}");
    assert!(std::fs::read_dir(&dirs.config).unwrap().next().is_none());
}

#[tokio::test]
async fn a_config_left_by_a_removed_watcher_is_reported_and_kept() {
    let dirs = TestDirs::new();
    // Written by an earlier start, when `old` was still configured.
    let old = dirs.config.join("old").join(CONFIG_FILE);
    std::fs::create_dir(dirs.config.join("old")).unwrap();
    std::fs::write(&old, b"schema_version = 1\n").unwrap();
    let config = write_config(
        &dirs,
        &[Cert::placeholder(1, Some("nginx"), &dirs.command("marker"))],
    );

    let _provider = AcmProviderProcess::start(&config, &dirs.root).await;
    wait_until(
        "the stale config warning",
        CONFIG_WRITE_TIMEOUT,
        &dirs.log(),
        || log_contains(&dirs.log(), "no longer in the provider's config"),
    )
    .await;

    assert!(log_contains(&dirs.log(), " for old are no longer"));
    assert!(old.exists(), "the stale config was deleted");
    assert!(dirs.config.join("nginx").join(CONFIG_FILE).exists());
}

/// The OS error in the provider's log line `line`, rebuilt from its code.
/// `io::Error` shows an OS error as "<description> (os error <code>)", and
/// an error the writer builds itself as its message alone.
fn logged_os_error(line: &str) -> Option<io::Error> {
    let (_, rest) = line.rsplit_once("(os error ")?;
    let (code, _) = rest.split_once(')')?;
    Some(io::Error::from_raw_os_error(code.parse().ok()?))
}

/// Errnos besides `ENOTDIR` that macOS and FreeBSD may give for a symlink
/// opened with `O_NOFOLLOW` (unverified): `ELOOP` (62), and on FreeBSD
/// `EMLINK` (31). `std` has no stable `ErrorKind` for `ELOOP`.
#[cfg(unix)]
const BSD_LINK_ERRNOS: &[i32] = &[
    #[cfg(any(target_vendor = "apple", target_os = "freebsd"))]
    62,
    #[cfg(target_os = "freebsd")]
    31,
];

/// True when the queue failure in `line` is the writer refusing the symlink
/// the swap test puts at `<watcher_id>`. The walk opens it with
/// `O_DIRECTORY | O_NOFOLLOW`; Linux checks `O_DIRECTORY` first, so the open
/// fails with `ENOTDIR` whatever the link points to, never `ELOOP`.
#[cfg(unix)]
fn is_link_refusal(line: &str) -> bool {
    logged_os_error(line).is_some_and(|e| {
        e.kind() == io::ErrorKind::NotADirectory
            || e.raw_os_error()
                .is_some_and(|code| BSD_LINK_ERRNOS.contains(&code))
    })
}

/// True when the queue failure in `line` is the writer refusing the junction
/// the swap test puts at `<watcher_id>`. The open follows a junction, so the
/// writer refuses it with an error of its own, logged as its message alone.
/// The messages are copied from `watcher_request.rs`, which has no constant.
#[cfg(windows)]
fn is_link_refusal(line: &str) -> bool {
    const REFUSALS: [&str; 2] = [
        // The inbox handle's final path is not `<root>\<watcher_id>\inbox`.
        "watcher inbox is reached through a link",
        // `<watcher_id>` was swapped between the inbox and temp-file opens.
        "watcher inbox changed while writing",
    ];
    logged_os_error(line).is_none() && REFUSALS.iter().any(|m| line.contains(m))
}

/// True when the queue failure in `line` is `ENOENT`: the walk opened
/// `<watcher_id>` between the swap's two renames, when nothing is there.
#[cfg(unix)]
fn is_race_gap(line: &str) -> bool {
    logged_os_error(line).is_some_and(|e| e.kind() == io::ErrorKind::NotFound)
}

/// True when the queue failure in `line` is `ERROR_FILE_NOT_FOUND` (2) or
/// `ERROR_PATH_NOT_FOUND` (3): the writer opened a path under `<watcher_id>`
/// between the swap's two renames, when nothing is there.
#[cfg(windows)]
fn is_race_gap(line: &str) -> bool {
    logged_os_error(line).is_some_and(|e| matches!(e.raw_os_error(), Some(2 | 3)))
}

/// The swap test accepts only a link refusal or the gap between its renames,
/// so an unrelated failure, such as a permission or I/O error, fails it.
#[test]
fn the_swap_test_accepts_only_a_link_refusal_or_the_swap_gap() {
    // As the provider logs a failed request.
    let logged = |e: io::Error| {
        format!("Could not queue the refresh request for arn (failure #1): Refresh request to watcher nginx failed for arn: {e}. Will retry next cycle.")
    };
    #[cfg(unix)]
    let (refusals, gaps, others) = {
        const ENOENT: i32 = 2;
        const EIO: i32 = 5;
        const EACCES: i32 = 13;
        const ENOTDIR: i32 = 20;
        (
            vec![io::Error::from_raw_os_error(ENOTDIR)],
            vec![io::Error::from_raw_os_error(ENOENT)],
            vec![
                io::Error::from_raw_os_error(EACCES),
                io::Error::from_raw_os_error(EIO),
            ],
        )
    };
    #[cfg(windows)]
    let (refusals, gaps, others) = (
        vec![
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "watcher inbox is reached through a link",
            ),
            io::Error::other("watcher inbox changed while writing"),
        ],
        vec![
            io::Error::from_raw_os_error(2),
            io::Error::from_raw_os_error(3),
        ],
        // ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION.
        vec![
            io::Error::from_raw_os_error(5),
            io::Error::from_raw_os_error(32),
        ],
    );
    for e in refusals {
        let line = logged(e);
        assert!(is_link_refusal(&line) && !is_race_gap(&line), "{line}");
    }
    for e in gaps {
        let line = logged(e);
        assert!(is_race_gap(&line) && !is_link_refusal(&line), "{line}");
    }
    for e in others {
        let line = logged(e);
        assert!(!is_link_refusal(&line) && !is_race_gap(&line), "{line}");
    }
}

/// Tests that export a real certificate. `test-local` skips them without
/// `ACM_TEST_CERTIFICATE_ARN` and `ACM_TEST_ROLE_ARN`.
mod requests {
    use super::*;

    #[tokio::test]
    async fn a_watcher_certificate_queues_a_request_instead_of_running_its_command() {
        let cert = TestCertificate::from_env();
        let dirs = TestDirs::new();
        let inbox = dirs.inbox("nginx");
        std::fs::create_dir_all(&inbox).unwrap();
        let config = write_config(
            &dirs,
            &[Cert::real(&cert, "nginx", &dirs.command("marker"))],
        );

        let _provider = AcmProviderProcess::start(&config, &dirs.root).await;
        wait_until(
            "a request in the inbox",
            FIRST_CYCLE_TIMEOUT,
            &dirs.log(),
            || !requests(&inbox).is_empty(),
        )
        .await;

        assert_eq!(
            names(&dirs.root.join("cert-0")),
            ["cert.pem", "chain.pem", "key.pem"]
        );
        let queued = requests(&inbox);
        assert_eq!(queued.len(), 1, "{queued:?}");
        let body: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&queued[0]).unwrap()).unwrap();
        assert_eq!(body["certificate_arn"].as_str(), Some(cert.arn()));
        let command_id = body["command_id"].as_str().unwrap();
        assert_eq!(command_id.len(), 36, "{body}");
        assert!(body["created_at"].as_str().is_some_and(|t| !t.is_empty()));
        let name = queued[0].file_name().unwrap().to_str().unwrap();
        assert!(name.ends_with(&format!("-{command_id}.cmd")), "{name}");
        // No temp file is left next to the request.
        assert_eq!(names(&inbox).len(), 1);
        assert!(
            !dirs.root.join("marker").exists(),
            "the provider ran the watcher's command"
        );
        // Windows reloads through a scheduled task, so check the log as well.
        assert!(
            !log_contains(&dirs.log(), "Running refresh command"),
            "the provider ran the watcher's command"
        );
    }

    #[tokio::test]
    async fn a_restart_queues_another_request() {
        let cert = TestCertificate::from_env();
        let dirs = TestDirs::new();
        let inbox = dirs.inbox("nginx");
        std::fs::create_dir_all(&inbox).unwrap();
        let config = write_config(
            &dirs,
            &[Cert::real(&cert, "nginx", &dirs.command("marker"))],
        );

        let provider = AcmProviderProcess::start(&config, &dirs.root).await;
        wait_until(
            "the first request",
            FIRST_CYCLE_TIMEOUT,
            &dirs.log(),
            || requests(&inbox).len() == 1,
        )
        .await;
        drop(provider);

        // The files are unchanged now, but the first cycle after a start reloads.
        let _provider = AcmProviderProcess::start(&config, &dirs.root).await;
        wait_until("a second request", FIRST_CYCLE_TIMEOUT, &dirs.log(), || {
            requests(&inbox).len() == 2
        })
        .await;
        // Logged after the request is in place, so wait for it too.
        wait_until(
            "the first-cycle log line",
            CONFIG_WRITE_TIMEOUT,
            &dirs.log(),
            || log_contains(&dirs.log(), "first cycle after provider startup"),
        )
        .await;
    }

    #[tokio::test]
    async fn a_missing_inbox_is_reported_and_not_created() {
        let cert = TestCertificate::from_env();
        let dirs = TestDirs::new();
        // The watcher creates its inbox; this one hasn't yet.
        std::fs::create_dir(dirs.requests.join("nginx")).unwrap();
        let config = write_config(
            &dirs,
            &[Cert::real(&cert, "nginx", &dirs.command("marker"))],
        );

        let _provider = AcmProviderProcess::start(&config, &dirs.root).await;
        wait_until(
            "the request failure",
            FIRST_CYCLE_TIMEOUT,
            &dirs.log(),
            || log_contains(&dirs.log(), "Could not queue the refresh request"),
        )
        .await;

        assert!(
            !dirs.inbox("nginx").exists(),
            "the provider created the inbox"
        );
        assert!(dirs.root.join("cert-0").join("cert.pem").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_symlinked_inbox_is_refused() {
        let cert = TestCertificate::from_env();
        let dirs = TestDirs::new();
        let elsewhere = dirs.root.join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::create_dir(dirs.requests.join("nginx")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, dirs.inbox("nginx")).unwrap();
        let config = write_config(
            &dirs,
            &[Cert::real(&cert, "nginx", &dirs.command("marker"))],
        );

        let _provider = AcmProviderProcess::start(&config, &dirs.root).await;
        wait_until(
            "the request failure",
            FIRST_CYCLE_TIMEOUT,
            &dirs.log(),
            || log_contains(&dirs.log(), "Could not queue the refresh request"),
        )
        .await;

        assert!(
            names(&elsewhere).is_empty(),
            "a request was written where the symlink points"
        );
    }

    /// How many times [`a_watcher_directory_swapped_for_a_link_after_startup_is_refused`]
    /// runs its swap before a lost race fails the test.
    const SWAP_ATTEMPTS: usize = 6;

    /// The provider's log line for a request it could not write.
    const QUEUE_FAILED_LINE: &str = "Could not queue the refresh request";

    /// What one swap attempt showed.
    enum SwapOutcome {
        /// The provider refused to write through the link.
        Refused,
        /// The provider wrote the request, or failed to, before the link was in
        /// place, so the attempt says nothing about the link.
        LostRace(&'static str),
    }

    /// A watcher directory that is real when the provider starts, and is replaced
    /// by a link to another directory with an `inbox` before the first
    /// refresh, must not redirect the request there.
    ///
    /// Any container that shares the requests volume can make this swap at any
    /// time, so a check at startup cannot stop it: the writer has to refuse
    /// the link on every write.
    ///
    /// The swap can lose a race with the provider's first refresh, which each
    /// attempt detects (see [`swap_attempt`]). A lost race restarts the provider
    /// on fresh directories, up to [`SWAP_ATTEMPTS`] times.
    #[tokio::test]
    async fn a_watcher_directory_swapped_for_a_link_after_startup_is_refused() {
        let cert = TestCertificate::from_env();
        let mut lost = Vec::new();
        for attempt in 1..=SWAP_ATTEMPTS {
            match swap_attempt(&cert).await {
                SwapOutcome::Refused => return,
                SwapOutcome::LostRace(reason) => {
                    eprintln!("swap attempt {attempt} lost the race: {reason}; retrying");
                    lost.push(reason);
                }
            }
        }
        panic!("every swap attempt lost the race with the provider's first refresh: {lost:?}");
    }

    /// Starts the provider with a real `<requests>/nginx/inbox`, and
    /// as soon as the provider has written the watcher config, swaps that
    /// directory for a link to `elsewhere`, which has an `inbox` of its own.
    ///
    /// The provider writes the watcher config after validating its directories
    /// and before it loads AWS credentials or starts a refresh, so the first
    /// request is normally at least one ACM export away. The link is created
    /// before the provider starts, so the swap is two renames: the real
    /// directory out to `nginx-original`, and the link in.
    ///
    /// Two races can make an attempt say nothing about the link:
    ///
    /// - the provider writes the request before the first rename: it is in the
    ///   original inbox;
    /// - the provider writes it between the two renames: nothing is at the path,
    ///   and the failure the provider logs is "not found" ([`is_race_gap`]).
    ///
    /// Either is a [`SwapOutcome::LostRace`]. A refusal that the writer
    /// reported as "not found" would be counted as one too, and fail the test
    /// after the last attempt rather than pass it.
    ///
    /// Panics with the provider log if the request was redirected, or if it
    /// failed with anything but the platform's link refusal
    /// ([`is_link_refusal`]) or "not found".
    async fn swap_attempt(cert: &TestCertificate) -> SwapOutcome {
        let dirs = TestDirs::new();
        let watcher_dir = dirs.requests.join("nginx");
        std::fs::create_dir_all(dirs.inbox("nginx")).unwrap();
        let elsewhere = dirs.root.join("elsewhere");
        let elsewhere_inbox = elsewhere.join("inbox");
        std::fs::create_dir_all(&elsewhere_inbox).unwrap();
        // Outside the requests root, which the provider never lists.
        let staged_link = dirs.root.join("staged-link");
        link_dir(&elsewhere, &staged_link);
        let config = write_config(&dirs, &[Cert::real(cert, "nginx", &dirs.command("marker"))]);

        let _provider = AcmProviderProcess::start(&config, &dirs.root).await;
        // Polled faster than `wait_until`, to swap as early as possible.
        let watcher_config = dirs.config.join("nginx").join(CONFIG_FILE);
        let written = tokio::time::timeout(CONFIG_WRITE_TIMEOUT, async {
            while !watcher_config.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        if written.is_err() {
            panic!(
                "timed out waiting for the nginx config.\nProvider log:\n{}",
                provider_log(&dirs)
            );
        }

        let original = dirs.root.join("nginx-original");
        std::fs::rename(&watcher_dir, &original).unwrap();
        // Moves the link itself, not what it points to.
        std::fs::rename(&staged_link, &watcher_dir).unwrap();

        let original_inbox = original.join("inbox");
        wait_until(
            "the request to be queued or refused",
            FIRST_CYCLE_TIMEOUT,
            &dirs.log(),
            || {
                !requests(&elsewhere_inbox).is_empty()
                    || !requests(&original_inbox).is_empty()
                    || log_contains(&dirs.log(), QUEUE_FAILED_LINE)
            },
        )
        .await;

        if !requests(&elsewhere_inbox).is_empty() {
            panic!(
                "a request was written where the link points: {:?}\nProvider log:\n{}",
                requests(&elsewhere_inbox),
                provider_log(&dirs)
            );
        }
        if !requests(&original_inbox).is_empty() {
            return SwapOutcome::LostRace("the request was queued before the swap");
        }
        let log = provider_log(&dirs);
        let failure = log
            .lines()
            .find(|line| line.contains(QUEUE_FAILED_LINE))
            .expect("waited for a request or this line");
        if is_race_gap(failure) {
            return SwapOutcome::LostRace("the request failed mid-swap with \"not found\"");
        }
        let os = logged_os_error(failure);
        assert!(
            is_link_refusal(failure),
            "the request failed, but not because of the link: kind {:?}, os error {:?}: {failure}\nProvider log:\n{log}",
            os.as_ref().map(io::Error::kind),
            os.as_ref().and_then(io::Error::raw_os_error),
        );
        SwapOutcome::Refused
    }

    fn provider_log(dirs: &TestDirs) -> String {
        std::fs::read_to_string(dirs.log()).unwrap_or_default()
    }

    /// Makes `link` a directory link to `target`: a symlink on Unix, and a
    /// junction on Windows, which needs no privilege, unlike a directory
    /// symlink. `std` has no junction API, so it goes through `mklink /J`.
    /// Slow on Windows (a process start), so callers create it ahead of time.
    fn link_dir(target: &Path, link: &Path) {
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, link).unwrap();
        #[cfg(windows)]
        {
            let status = std::process::Command::new("cmd")
                .arg("/C")
                .arg("mklink")
                .arg("/J")
                .arg(link)
                .arg(target)
                .stdout(std::process::Stdio::null())
                .status()
                .unwrap();
            assert!(status.success(), "mklink /J failed: {status}");
        }
    }
}
