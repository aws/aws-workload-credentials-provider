//! Integration tests for the ACM certificate provider.
//!
//! These tests run the provider end-to-end against a pre-existing ACM
//! certificate owned by the test operator. They require:
//!
//!   ACM_TEST_CERTIFICATE_ARN — Certificate the provider exports
//!   ACM_TEST_ROLE_ARN        — IAM role the provider assumes when exporting
//!
//! The certificate's lifecycle (creation, renewal, deletion) is the
//! operator's responsibility; these tests neither create nor delete it.
//!
//! Platform notes:
//! - Unix: `DefaultRefreshExecutor` invokes `sudo -n` for refresh commands,
//!   so the tests must run as root (or via sudo). `test-local.sh` handles
//!   the re-exec automatically.
//! - Windows: the refresh executor triggers a pre-registered scheduled task
//!   via `schtasks /Run`. Each test registers a per-cert scheduled task
//!   (current user, Interactive logon — no admin needed) that creates the
//!   marker file when triggered.

mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(unix)]
use common::assert_mode;
#[cfg(windows)]
use common::AcmTestScheduledTask;
use common::{
    create_test_config, is_pem_certificate, is_pem_private_key, run_provider_until_exit,
    AcmProviderProcess, AcmTestConfigOptions, AcmTestPaths, RoleChainingHelper, TestCertificate,
    NO_ACCESS_ROLE_NAME,
};

/// Maximum time to wait for the provider to complete its initial startup and
/// first certificate refresh cycle (startup jitter + ACM API call + file writes + command).
const PROVIDER_STARTUP_TIMEOUT: Duration = Duration::from_secs(45);

/// Maximum time to wait for the provider to complete a subsequent refresh cycle
/// where no file changes are expected (startup jitter + ACM API call + compare).
const PROVIDER_REFRESH_CYCLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Log file name the ACM provider writes to (relative to its working directory).
const ACM_LOG_FILE: &str = "logs/acm_provider.log";

/// Polls the given paths until each one exists or the timeout elapses.
/// Panics with a descriptive message if any path is still missing at timeout.
async fn wait_for_files(paths: &[&Path], timeout: Duration) {
    let poll_interval = Duration::from_millis(200);
    tokio::time::timeout(timeout, async {
        loop {
            if paths.iter().all(|p| p.exists()) {
                return;
            }
            tokio::time::sleep(poll_interval).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        let missing: Vec<_> = paths.iter().filter(|p| !p.exists()).collect();
        panic!("timed out after {timeout:?} waiting for files; missing: {missing:?}");
    });
}

/// Polls a log file until a line containing `target_string` appears or the timeout elapses.
/// Panics if the target string is not found within the timeout.
async fn wait_for_log_line(log_path: &Path, target_string: &str, timeout: Duration) {
    let poll_interval = Duration::from_millis(200);
    tokio::time::timeout(timeout, async {
        loop {
            if let Ok(content) = std::fs::read_to_string(log_path) {
                if content.contains(target_string) {
                    return;
                }
            }
            tokio::time::sleep(poll_interval).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        let content = std::fs::read_to_string(log_path).unwrap_or_default();
        panic!(
            "timed out after {timeout:?} waiting for \"{target_string}\" in {}.\nLog contents:\n{content}",
            log_path.display()
        );
    });
}

pub fn create_canon_tempdir() -> (tempfile::TempDir, PathBuf) {
    let tmp_dir = tempfile::TempDir::new().expect("could not create test dir");
    #[cfg(unix)]
    let canon_dir = tmp_dir
        .path()
        .canonicalize()
        .expect("unable to canonicalize temp test dir");

    // Using dunce canonicalize as this is used to validate paths in field_validators
    #[cfg(windows)]
    let canon_dir =
        dunce::canonicalize(tmp_dir.path()).expect("unable to canonicalize temp test dir");

    return (tmp_dir, canon_dir);
}

#[tokio::test]
async fn certificate_provider_writes_cert_and_runs_refresh_command() {
    let cert = TestCertificate::from_env();

    // Holding _tmp_dir keeps the directory from being cleaned up, deleted on return by default
    let (_tmp_dir, test_dir) = create_canon_tempdir();
    let paths = AcmTestPaths::under(&test_dir);

    // On Windows, register a scheduled task whose name matches what the
    // provider will trigger. Drop on test exit unregisters it.
    #[cfg(windows)]
    let _scheduled_task = AcmTestScheduledTask::register(cert.arn(), &paths.refresh_marker);

    let config_toml = create_test_config(&test_dir, AcmTestConfigOptions::for_cert(&cert));
    let config_path = test_dir.join("config.toml");
    std::fs::write(&config_path, config_toml).expect("could not write config");

    // Holding `_provider` keeps the child alive; `kill_on_drop` stops it on return.
    let _provider = AcmProviderProcess::start(&config_path, &test_dir).await;

    // The provider boots, exports the cert, writes the files, then runs the
    // refresh command. Initial-delay jitter is up to 5s; allow headroom
    // for the provider's startup + ACM API call + file writes.
    wait_for_files(
        &[
            &paths.certificate,
            &paths.private_key,
            &paths.chain,
            &paths.refresh_marker,
        ],
        PROVIDER_STARTUP_TIMEOUT,
    )
    .await;

    let cert_pem = std::fs::read_to_string(&paths.certificate).expect("could not read cert");
    assert!(
        is_pem_certificate(&cert_pem),
        "certificate file is not PEM-encoded"
    );

    let key_pem = std::fs::read_to_string(&paths.private_key).expect("could not read key");
    assert!(
        is_pem_private_key(&key_pem),
        "private key file is not PEM-encoded"
    );

    let chain_pem = std::fs::read_to_string(&paths.chain).expect("could not read chain");
    assert!(
        is_pem_certificate(&chain_pem),
        "chain file is not PEM-encoded"
    );

    #[cfg(unix)]
    {
        assert_mode(&paths.certificate, 0o600);
        assert_mode(&paths.private_key, 0o600);
        assert_mode(&paths.chain, 0o600);
    }

    // Refresh command must run AFTER the cert is written, otherwise the
    // provider is firing the command before the cert lands on disk.
    let cert_mtime = std::fs::metadata(&paths.certificate)
        .expect("could not stat cert")
        .modified()
        .expect("modified() unsupported");
    let marker_mtime = std::fs::metadata(&paths.refresh_marker)
        .expect("could not stat refresh marker")
        .modified()
        .expect("modified() unsupported");
    assert!(
        marker_mtime >= cert_mtime,
        "refresh command ran before certificate was written"
    );
}

#[tokio::test]
async fn certificate_provider_bundles_chain_when_chain_path_omitted() {
    let cert = TestCertificate::from_env();

    let (_tmp_dir, test_dir) = create_canon_tempdir();
    let paths = AcmTestPaths::under(&test_dir);

    #[cfg(windows)]
    let _scheduled_task = AcmTestScheduledTask::register(cert.arn(), &paths.refresh_marker);

    let config_toml = create_test_config(
        &test_dir,
        AcmTestConfigOptions {
            bundled: true,
            ..AcmTestConfigOptions::for_cert(&cert)
        },
    );
    let config_path = test_dir.join("config.toml");
    std::fs::write(&config_path, config_toml).expect("could not write config");

    let _provider = AcmProviderProcess::start(&config_path, &test_dir).await;

    // Bundled mode writes only the cert (now a fullchain) and key.
    wait_for_files(
        &[
            &paths.certificate,
            &paths.private_key,
            &paths.refresh_marker,
        ],
        PROVIDER_STARTUP_TIMEOUT,
    )
    .await;

    assert!(
        !paths.chain.exists(),
        "standalone chain file should not exist in bundled mode"
    );

    let key_pem = std::fs::read_to_string(&paths.private_key).expect("could not read key");
    assert!(
        is_pem_private_key(&key_pem),
        "private key file is not PEM-encoded"
    );

    // Fullchain is the leaf cert concatenated with the chain — at least
    // two BEGIN/END CERTIFICATE blocks should be present.
    let fullchain = std::fs::read_to_string(&paths.certificate).expect("could not read fullchain");
    let begin_count = fullchain.matches("-----BEGIN CERTIFICATE-----").count();
    let end_count = fullchain.matches("-----END CERTIFICATE-----").count();
    assert_eq!(
        begin_count, end_count,
        "mismatched BEGIN/END markers in fullchain"
    );
    assert!(
        begin_count >= 2,
        "fullchain should contain leaf + chain cert(s), got {} BEGIN markers",
        begin_count
    );

    #[cfg(unix)]
    {
        assert_mode(&paths.certificate, 0o600);
        assert_mode(&paths.private_key, 0o600);
    }

    let cert_mtime = std::fs::metadata(&paths.certificate)
        .expect("could not stat cert")
        .modified()
        .expect("modified() unsupported");
    let marker_mtime = std::fs::metadata(&paths.refresh_marker)
        .expect("could not stat refresh marker")
        .modified()
        .expect("modified() unsupported");
    assert!(
        marker_mtime >= cert_mtime,
        "refresh command ran before certificate was written"
    );
}

#[tokio::test]
async fn certificate_provider_runs_refresh_on_restart_even_when_cert_unchanged() {
    let cert = TestCertificate::from_env();

    let (_tmp_dir, test_dir) = create_canon_tempdir();
    let paths = AcmTestPaths::under(&test_dir);

    #[cfg(windows)]
    let _scheduled_task = AcmTestScheduledTask::register(cert.arn(), &paths.refresh_marker);

    let config_toml = create_test_config(&test_dir, AcmTestConfigOptions::for_cert(&cert));
    let config_path = test_dir.join("config.toml");
    std::fs::write(&config_path, config_toml).expect("could not write config");

    // First run: provider exports, writes files, runs refresh command.
    // Wait for the log confirmation before dropping to avoid kill racing I/O.
    {
        let _provider = AcmProviderProcess::start(&config_path, &test_dir).await;
        wait_for_files(
            &[
                &paths.certificate,
                &paths.private_key,
                &paths.chain,
                &paths.refresh_marker,
            ],
            PROVIDER_STARTUP_TIMEOUT,
        )
        .await;

        let log_path = &test_dir.join(ACM_LOG_FILE);
        wait_for_log_line(
            &log_path,
            "Certificate refresh successful for",
            PROVIDER_STARTUP_TIMEOUT,
        )
        .await;
    }

    let first_cert_mtime = std::fs::metadata(&paths.certificate)
        .expect("could not stat cert")
        .modified()
        .expect("modified() unsupported");

    std::fs::remove_file(&paths.refresh_marker).expect("could not remove marker");

    // Clear the log from the first run so we only match second-run output.
    let log_path = &test_dir.join(ACM_LOG_FILE);
    let _ = std::fs::remove_file(&log_path);

    // Restart the provider. The first cycle always runs the refresh command
    // (even when cert files are unchanged) to ensure the application picks
    // up certs after an provider restart.
    // Wait for the log confirmation before dropping to avoid kill racing I/O.
    {
        let _provider = AcmProviderProcess::start(&config_path, &test_dir).await;
        wait_for_log_line(
            &log_path,
            "Certificate refresh successful for",
            PROVIDER_STARTUP_TIMEOUT,
        )
        .await;
    }

    // The marker must exist — the refresh command ran on restart despite
    // unchanged certificate files.
    assert!(
        paths.refresh_marker.exists(),
        "refresh marker was not recreated; provider must always run refresh command on first cycle after restart"
    );

    let second_cert_mtime = std::fs::metadata(&paths.certificate)
        .expect("could not stat cert")
        .modified()
        .expect("modified() unsupported");
    assert_eq!(
        second_cert_mtime, first_cert_mtime,
        "certificate file was rewritten on the second run; provider did not skip the write"
    );
}

/// Returns true if `dir` contains any leftover `.tmp*` file. The
/// `tempfile` crate's default prefix is `.tmp`, so any abandoned temp
/// would surface as `<dir>/.tmpXXXXXX`. Non-recursive — the provider only
/// writes temp files in the cert's parent directory.
fn has_leftover_temp_files(dir: &Path) -> bool {
    std::fs::read_dir(dir)
        .expect("could not read test dir")
        .filter_map(Result::ok)
        .any(|entry| {
            entry
                .file_name()
                .to_str()
                .map(|name| name.starts_with(".tmp"))
                .unwrap_or(false)
        })
}

#[tokio::test]
async fn certificate_provider_cleans_up_temp_files_after_refresh() {
    // Each refresh writes via NamedTempFile + atomic rename: the temp
    // file is consumed by the rename on success, or wiped by
    // `TempFileWithDropCleanup` on failure. Either way, the cert
    // directory must not contain stragglers once the cycle is done.
    let cert = TestCertificate::from_env();

    let (_tmp_dir, test_dir) = create_canon_tempdir();
    let paths = AcmTestPaths::under(&test_dir);

    #[cfg(windows)]
    let _scheduled_task = AcmTestScheduledTask::register(cert.arn(), &paths.refresh_marker);

    let config_toml = create_test_config(&test_dir, AcmTestConfigOptions::for_cert(&cert));
    let config_path = &test_dir.join("config.toml");
    std::fs::write(&config_path, config_toml).expect("could not write config");

    let _provider = AcmProviderProcess::start(&config_path, &test_dir).await;

    wait_for_files(
        &[
            &paths.certificate,
            &paths.private_key,
            &paths.chain,
            &paths.refresh_marker,
        ],
        PROVIDER_STARTUP_TIMEOUT,
    )
    .await;

    // Wait for the success log line to confirm the cycle finished — temp
    // file cleanup happens at the very end, when the temp guards drop.
    let log_path = &test_dir.join(ACM_LOG_FILE);
    wait_for_log_line(
        &log_path,
        "Certificate refresh successful for",
        PROVIDER_STARTUP_TIMEOUT,
    )
    .await;

    assert!(
        !has_leftover_temp_files(&test_dir),
        "leftover .tmp* files found in {} after refresh; atomic_rename or drop cleanup did not run",
        &test_dir.display()
    );
}

#[tokio::test]
async fn certificate_provider_detects_byte_level_drift() {
    // The store does an exact string comparison, not a semantic PEM
    // diff. Appending a single trailing newline to the cert on disk
    // must trigger a rewrite on the next cycle even though the PEM is
    // semantically equivalent.
    let cert = TestCertificate::from_env();

    let (_tmp_dir, test_dir) = create_canon_tempdir();
    let paths = AcmTestPaths::under(&test_dir);

    #[cfg(windows)]
    let _scheduled_task = AcmTestScheduledTask::register(cert.arn(), &paths.refresh_marker);

    let config_toml = create_test_config(&test_dir, AcmTestConfigOptions::for_cert(&cert));
    let config_path = &test_dir.join("config.toml");
    std::fs::write(&config_path, config_toml).expect("could not write config");

    // First run: provider exports and writes the cert.
    {
        let _provider = AcmProviderProcess::start(&config_path, &test_dir).await;
        wait_for_files(
            &[
                &paths.certificate,
                &paths.private_key,
                &paths.chain,
                &paths.refresh_marker,
            ],
            PROVIDER_STARTUP_TIMEOUT,
        )
        .await;

        let log_path = &test_dir.join(ACM_LOG_FILE);
        wait_for_log_line(
            &log_path,
            "Certificate refresh successful for",
            PROVIDER_STARTUP_TIMEOUT,
        )
        .await;
    }

    let original_cert = std::fs::read_to_string(&paths.certificate).expect("could not read cert");
    let drifted = format!("{original_cert}\n");
    std::fs::write(&paths.certificate, &drifted).expect("could not append newline to cert");

    // Unix-only. On Windows, NTFS "file system tunneling" copies the old
    // file's creation time onto a file that takes its name within ~15s of
    // the old one being removed or replaced. The provider's atomic rename
    // therefore leaves `created()` unchanged to the 100ns tick, so this
    // check can never pass there. The content assertions below still prove
    // the rewrite on Windows.
    #[cfg(unix)]
    let pre_ctime = std::fs::metadata(&paths.certificate)
        .expect("unable to get cert file metadata")
        .created()
        .expect("unable to get cert file created time");

    // Reset observable side-effects so the second cycle is unambiguous.
    std::fs::remove_file(&paths.refresh_marker).expect("could not remove marker");
    let log_path = test_dir.join(ACM_LOG_FILE);
    let _ = std::fs::remove_file(&log_path);

    // Second run: cycle hits the byte-by-byte comparison, sees the
    // trailing newline as drift, and rewrites the cert.
    {
        let _provider = AcmProviderProcess::start(&config_path, &test_dir).await;
        wait_for_log_line(
            &log_path,
            "Certificate refresh successful for",
            PROVIDER_REFRESH_CYCLE_TIMEOUT,
        )
        .await;
        // The rewrite path also fires the refresh command, so wait for
        // the marker as a second confirmation.
        wait_for_files(&[&paths.refresh_marker], PROVIDER_REFRESH_CYCLE_TIMEOUT).await;
    }

    let rewritten = std::fs::read_to_string(&paths.certificate).expect("could not read cert");
    assert_eq!(
        rewritten, original_cert,
        "provider did not detect the trailing-newline drift; cert on disk still has the appended byte"
    );
    assert_ne!(
        rewritten, drifted,
        "cert content unchanged; rewrite did not happen"
    );

    // Unix-only; see the tunneling note at `pre_ctime`.
    #[cfg(unix)]
    {
        let post_ctime = std::fs::metadata(&paths.certificate)
            .expect("unable to get cert file metadata")
            .created()
            .expect("unable to get cert file created time");

        assert!(
            post_ctime > pre_ctime,
            "certificate file was not recreated on reload"
        );
    }
}

/// `refresh_command` is optional. When omitted, the provider must still
/// export and write the certificate files cleanly, and must NOT log
/// anything about running, skipping, or failing a refresh command —
/// the entire command-execution branch should be a no-op.
#[tokio::test]
async fn certificate_provider_skips_command_when_refresh_command_omitted() {
    let cert = TestCertificate::from_env();

    let (_tmp_dir, test_dir) = create_canon_tempdir();
    let paths = AcmTestPaths::under(&test_dir);

    let config_toml = create_test_config(
        &test_dir,
        AcmTestConfigOptions {
            include_refresh_command: false,
            ..AcmTestConfigOptions::for_cert(&cert)
        },
    );
    let config_path = &test_dir.join("config.toml");
    std::fs::write(&config_path, config_toml).expect("could not write config");

    let log_path = &test_dir.join(ACM_LOG_FILE);

    {
        let _provider = AcmProviderProcess::start(&config_path, &test_dir).await;

        // Cert files land on disk just like in the happy path.
        wait_for_files(
            &[&paths.certificate, &paths.private_key, &paths.chain],
            PROVIDER_STARTUP_TIMEOUT,
        )
        .await;

        // The cycle must complete cleanly. Waiting for this line confirms
        // the provider didn't error out on the missing field.
        wait_for_log_line(
            &log_path,
            "Certificate refresh successful for",
            PROVIDER_STARTUP_TIMEOUT,
        )
        .await;
    }

    let cert_pem = std::fs::read_to_string(&paths.certificate).expect("could not read cert");
    assert!(
        is_pem_certificate(&cert_pem),
        "certificate file is not PEM-encoded"
    );

    // No log line should mention the refresh command in any form. The
    // entire `if let Some(ref command)` branch in certificate_task.rs is
    // expected to be skipped, so none of these phrases should appear.
    let log_contents = std::fs::read_to_string(&log_path).unwrap_or_default();
    for forbidden in [
        "Running refresh command",
        "Skipping refresh command",
        "Refresh command failed",
        "refresh command timed out",
        "Refresh command succeeded",
    ] {
        assert!(
            !log_contents.contains(forbidden),
            "log unexpectedly mentions \"{forbidden}\" when no refresh_command was configured.\nLog:\n{log_contents}"
        );
    }
}

/// `certificate_and_chain_permission` and `key_permission` in the config
/// must flow through to the actual file modes on disk. Proves the seam
/// between config parsing, validation, the file store, and the OS.
///
/// Unix-only: on Windows, per-file ACLs are applied by the install script,
/// not by the provider at refresh time, so this seam doesn't exist.
#[cfg(unix)]
#[tokio::test]
async fn certificate_provider_applies_configured_permissions() {
    let cert = TestCertificate::from_env();

    let (_tmp_dir, test_dir) = create_canon_tempdir();
    let paths = AcmTestPaths::under(&test_dir);

    let config_toml = create_test_config(
        &test_dir,
        AcmTestConfigOptions {
            cert_and_chain_mode: Some("644".to_string()),
            key_mode: Some("400".to_string()),
            ..AcmTestConfigOptions::for_cert(&cert)
        },
    );
    let config_path = &test_dir.join("config.toml");
    std::fs::write(&config_path, config_toml).expect("could not write config");

    let _provider = AcmProviderProcess::start(&config_path, &test_dir).await;

    wait_for_files(
        &[
            &paths.certificate,
            &paths.private_key,
            &paths.chain,
            &paths.refresh_marker,
        ],
        PROVIDER_STARTUP_TIMEOUT,
    )
    .await;

    assert_mode(&paths.certificate, 0o644);
    assert_mode(&paths.chain, 0o644);
    assert_mode(&paths.private_key, 0o400);
}

// ============================================================================
// Startup validation tests
//
// These tests don't depend on a real ACM certificate — they verify that the
// provider rejects malformed config and exits with a useful error message before
// it ever reaches the AWS API. We write a config with one invalid field at a
// time and assert the validator's complaint surfaces in stderr.
//
// Unlike the happy-path tests above, these don't need root or
// ACM_TEST_CERTIFICATE_ARN/ACM_TEST_ROLE_ARN: the provider fails before calling
// any sudo or AWS-side machinery.
// ============================================================================

#[tokio::test]
async fn certificate_provider_rejects_invalid_certificate_arn() {
    let (_tmp_dir, test_dir) = create_canon_tempdir();
    let config_path = &test_dir.join("config.toml");

    let config_toml = create_test_config(
        &test_dir,
        AcmTestConfigOptions {
            certificate_arn: "not-a-valid-arn".to_string(),
            ..AcmTestConfigOptions::placeholder()
        },
    );
    std::fs::write(&config_path, config_toml).expect("could not write config");

    let (status, stdout, stderr) = run_provider_until_exit(&config_path, &test_dir).await;

    assert!(
        !status.success(),
        "provider exited successfully with invalid certificate ARN; stdout: {stdout}, stderr: {stderr}"
    );

    // Validator emits the field path + the expected ARN format as guidance.
    // Both pieces should appear so operators can fix the config without
    // hunting through docs.
    assert!(
        stderr.contains("certificate_arn"),
        "stderr did not mention the offending field. stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("arn:{partition}:acm:{region}:{account-id}:certificate/{certificate-id}"),
        "stderr did not mention the expected certificate ARN format. stderr:\n{stderr}"
    );
}

#[tokio::test]
async fn certificate_provider_rejects_invalid_role_arn() {
    let (_tmp_dir, test_dir) = create_canon_tempdir();
    let config_path = test_dir.join("config.toml");

    let config_toml = create_test_config(
        &test_dir,
        AcmTestConfigOptions {
            role_arn: "not-a-valid-arn".to_string(),
            ..AcmTestConfigOptions::placeholder()
        },
    );
    std::fs::write(&config_path, config_toml).expect("could not write config");

    let (status, stdout, stderr) = run_provider_until_exit(&config_path, &test_dir).await;

    assert!(
        !status.success(),
        "provider exited successfully with invalid role ARN; stdout: {stdout}, stderr: {stderr}"
    );

    assert!(
        stderr.contains("role_arn"),
        "stderr did not mention the offending field. stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("arn:{partition}:iam::{account-id}:role/{role-name}"),
        "stderr did not mention the expected role ARN format. stderr:\n{stderr}"
    );
}

#[tokio::test]
async fn certificate_provider_rejects_relative_certificate_path() {
    let (_tmp_dir, test_dir) = create_canon_tempdir();
    let config_path = test_dir.join("config.toml");

    let config_toml = create_test_config(
        &test_dir,
        AcmTestConfigOptions {
            certificate_path: Some("certs/server.crt".to_string()),
            ..AcmTestConfigOptions::placeholder()
        },
    );
    std::fs::write(&config_path, config_toml).expect("could not write config");

    let (status, stdout, stderr) = run_provider_until_exit(&config_path, &test_dir).await;

    assert!(
        !status.success(),
        "provider exited successfully with relative certificate path; stdout: {stdout}, stderr: {stderr}"
    );

    assert!(
        stderr.contains("certificate_path"),
        "stderr did not mention the offending field. stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("Path must be absolute"),
        "stderr did not state the path must be absolute. stderr:\n{stderr}"
    );
}

#[tokio::test]
async fn certificate_provider_exits_cleanly_when_acm_disabled() {
    // Config has [capabilities.acm] but enabled = false. The provider should
    // log "ACM is explicitly disabled" and exit 0 without contacting AWS or
    // writing any cert files.
    let (_tmp_dir, test_dir) = create_canon_tempdir();
    let config_path = test_dir.join("config.toml");

    std::fs::write(
        &config_path,
        r#"
[logging]
log_to_file = false

[capabilities.acm]
enabled = false
"#,
    )
    .expect("could not write config");

    let (status, stdout, stderr) = run_provider_until_exit(&config_path, &test_dir).await;

    assert!(
        status.success(),
        "provider should exit 0 when ACM is disabled, got {status}; stdout: {stdout}, stderr: {stderr}"
    );

    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("ACM is explicitly disabled"),
        "provider did not log the expected disabled message. stdout: {stdout}, stderr: {stderr}"
    );
}

#[tokio::test]
async fn certificate_provider_exits_cleanly_when_acm_section_missing() {
    // Config has no [capabilities.acm] section. The provider should log
    // "ACM is not configured" and exit 0.
    let (_tmp_dir, test_dir) = create_canon_tempdir();
    let config_path = test_dir.join("config.toml");

    std::fs::write(
        &config_path,
        r#"
[logging]
log_to_file = false
"#,
    )
    .expect("could not write config");

    let (status, stdout, stderr) = run_provider_until_exit(&config_path, &test_dir).await;

    assert!(
        status.success(),
        "provider should exit 0 when ACM section is missing, got {status}; stdout: {stdout}, stderr: {stderr}"
    );

    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("ACM is not configured"),
        "provider did not log the expected missing-section message. stdout: {stdout}, stderr: {stderr}"
    );
}

// ============================================================================
// Automation gap tests
//
// These tests verify fault isolation, error handling, and resilience
// behaviors that matter in multi-certificate production deployments but
// are not covered by the single-certificate happy-path tests above.
//
// Like the happy-path ACM tests, these require ACM_TEST_CERTIFICATE_ARN
// and ACM_TEST_ROLE_ARN (except where noted).
// ============================================================================

/// Proves that one certificate's export failure does not block or crash the
/// provider — the healthy certificate still lands on disk.
///
/// Configures two certificates: one real (from the environment), one with a
/// nonexistent ARN. The provider must export and write the real cert while
/// logging an error for the bad one, without exiting.
#[tokio::test]
async fn test_multi_cert_fault_isolation() {
    let cert = TestCertificate::from_env();

    let (_tmp_dir, test_dir) = create_canon_tempdir();

    // Paths for the real certificate
    let real_cert_path = test_dir.join("real_server.pem");
    let real_key_path = test_dir.join("real_server.key");
    let real_chain_path = test_dir.join("real_chain.pem");
    let real_marker_path = test_dir.join("real_refresh_marker");

    // Paths for the bad certificate
    let bad_cert_path = test_dir.join("bad_server.pem");
    let bad_key_path = test_dir.join("bad_server.key");
    let bad_chain_path = test_dir.join("bad_chain.pem");

    let real_arn =
        std::env::var("ACM_TEST_CERTIFICATE_ARN").expect("ACM_TEST_CERTIFICATE_ARN must be set");
    let parts: Vec<&str> = real_arn.split(':').collect();
    let region = parts[3];
    let account = parts[4];
    let bad_arn = format!(
        "arn:aws:acm:{}:{}:certificate/00000000-0000-0000-0000-000000000000",
        region, account
    );

    // Build a multi-cert TOML config manually since create_test_config()
    // only supports a single certificate entry.
    #[cfg(unix)]
    let touch = ["/usr/bin/touch", "/bin/touch"]
        .iter()
        .find(|p| Path::new(p).exists())
        .expect("could not locate touch");
    #[cfg(unix)]
    let real_refresh_cmd = format!("{touch} {}", real_marker_path.display());
    #[cfg(windows)]
    let real_refresh_cmd = format!("scheduled-task:{}", cert.arn());

    let config_toml = format!(
        r#"
[capabilities.acm]
enabled = true

[[capabilities.acm.certificates]]
certificate_arn = "{real_arn}"
role_arn = "{role_arn}"
certificate_path = '{real_cert}'
private_key_path = '{real_key}'
chain_path = '{real_chain}'
refresh_command = "{refresh_cmd}"

[[capabilities.acm.certificates]]
certificate_arn = "{bad_arn}"
role_arn = "{role_arn}"
certificate_path = '{bad_cert}'
private_key_path = '{bad_key}'
chain_path = '{bad_chain}'
"#,
        real_arn = cert.arn(),
        role_arn = cert.role_arn(),
        real_cert = real_cert_path.display(),
        real_key = real_key_path.display(),
        real_chain = real_chain_path.display(),
        refresh_cmd = real_refresh_cmd,
        bad_arn = bad_arn,
        bad_cert = bad_cert_path.display(),
        bad_key = bad_key_path.display(),
        bad_chain = bad_chain_path.display(),
    );

    let config_path = test_dir.join("config.toml");
    std::fs::write(&config_path, config_toml).expect("could not write config");

    #[cfg(windows)]
    let _scheduled_task = AcmTestScheduledTask::register(cert.arn(), &real_marker_path);

    let mut provider = AcmProviderProcess::start(&config_path, &test_dir).await;

    // The real certificate should be exported and written successfully.
    wait_for_files(
        &[
            &real_cert_path,
            &real_key_path,
            &real_chain_path,
            &real_marker_path,
        ],
        PROVIDER_STARTUP_TIMEOUT,
    )
    .await;

    let cert_pem = std::fs::read_to_string(&real_cert_path).expect("could not read real cert");
    assert!(
        is_pem_certificate(&cert_pem),
        "real certificate file is not PEM-encoded"
    );

    let key_pem = std::fs::read_to_string(&real_key_path).expect("could not read real key");
    assert!(
        is_pem_private_key(&key_pem),
        "real private key file is not PEM-encoded"
    );

    // Wait for the bad cert to be attempted and fail before asserting.
    // Each cert gets its own random 0–5s startup jitter, so the bad cert
    // may not have been attempted yet when the good cert finishes. Wait for
    // the error line itself: the bad ARN alone already appears in the
    // "Certificate task started" line logged at startup, before the attempt.
    let log_path = test_dir.join(ACM_LOG_FILE);
    wait_for_log_line(
        &log_path,
        &format!("Error refreshing certificate {bad_arn}"),
        PROVIDER_STARTUP_TIMEOUT,
    )
    .await;

    // The bad certificate's files should NOT have been written.
    assert!(
        !bad_cert_path.exists(),
        "bad certificate file should not exist — export should have failed"
    );

    // Verify the log contains an error for the nonexistent cert ARN,
    // confirming the failure was reported rather than silently swallowed.
    let log_contents = std::fs::read_to_string(&log_path).unwrap_or_default();
    assert!(
        log_contents.lines().any(|line| {
            line.contains("Error refreshing certificate")
                && line.contains("00000000-0000-0000-0000-000000000000")
        }),
        "log should contain an error for the nonexistent certificate ARN.\nLog:\n{log_contents}"
    );

    assert!(
        provider.is_running(),
        "Provider should still be running after one cert fails"
    );
}

/// Verifies that the provider handles an access-denied error on
/// `ExportCertificate` gracefully — logs the error and keeps running.
///
/// Uses `provider-no-access-role`, which exists for SM role-chaining tests
/// and lacks `acm:ExportCertificate` permissions.
#[tokio::test]
async fn test_export_insufficient_permissions() {
    let cert = TestCertificate::from_env();
    let role_helper = RoleChainingHelper::new().await;
    let no_access_role_arn = role_helper.get_role_arn(NO_ACCESS_ROLE_NAME).await;

    let (_tmp_dir, test_dir) = create_canon_tempdir();
    let paths = AcmTestPaths::under(&test_dir);

    let config_toml = create_test_config(
        &test_dir,
        AcmTestConfigOptions {
            role_arn: no_access_role_arn,
            ..AcmTestConfigOptions::for_cert(&cert)
        },
    );
    let config_path = test_dir.join("config.toml");
    std::fs::write(&config_path, config_toml).expect("could not write config");

    let mut provider = AcmProviderProcess::start(&config_path, &test_dir).await;

    // Wait for the provider to attempt the export and log the failure.
    let log_path = test_dir.join(ACM_LOG_FILE);
    wait_for_log_line(
        &log_path,
        "Error refreshing certificate",
        PROVIDER_STARTUP_TIMEOUT,
    )
    .await;

    let log_contents = std::fs::read_to_string(&log_path).unwrap_or_default();
    let error_line = log_contents
        .lines()
        .find(|line| line.contains("Error refreshing certificate"))
        .expect("log should contain an error line for the access-denied export failure");
    assert!(
        error_line.contains("AccessDeniedException"),
        "expected AccessDeniedException from ExportCertificate, got: {}",
        error_line
    );

    // Provider must still be running (not crashed). Certificate files
    // should not have been written since the export failed.
    assert!(
        !paths.certificate.exists(),
        "certificate file should not exist after access-denied export failure"
    );
    assert!(
        provider.is_running(),
        "provider should still be running after access-denied export failure"
    );
}

/// Verifies that the provider handles a nonexistent certificate ARN
/// gracefully — logs a ResourceNotFoundException-style error and keeps
/// running without crashing.
#[tokio::test]
async fn test_export_nonexistent_cert() {
    let cert = TestCertificate::from_env();

    let (_tmp_dir, test_dir) = create_canon_tempdir();
    let paths = AcmTestPaths::under(&test_dir);

    // Derive region and account from the real test cert ARN so the
    // nonexistent ARN targets the correct account (avoids AccessDeniedException)
    // and region (CI uses us-west-2, not us-east-1).
    let real_arn =
        std::env::var("ACM_TEST_CERTIFICATE_ARN").expect("ACM_TEST_CERTIFICATE_ARN must be set");
    let parts: Vec<&str> = real_arn.split(':').collect();
    let region = parts[3];
    let account = parts[4];
    let nonexistent_arn =
        format!("arn:aws:acm:{region}:{account}:certificate/00000000-0000-0000-0000-000000000000");

    let config_toml = create_test_config(
        &test_dir,
        AcmTestConfigOptions {
            certificate_arn: nonexistent_arn,
            ..AcmTestConfigOptions::for_cert(&cert)
        },
    );
    let config_path = test_dir.join("config.toml");
    std::fs::write(&config_path, config_toml).expect("could not write config");

    let mut provider = AcmProviderProcess::start(&config_path, &test_dir).await;

    // Wait for the provider to attempt the export and log the failure.
    let log_path = test_dir.join(ACM_LOG_FILE);
    wait_for_log_line(
        &log_path,
        "Error refreshing certificate",
        PROVIDER_STARTUP_TIMEOUT,
    )
    .await;

    let log_contents = std::fs::read_to_string(&log_path).unwrap_or_default();
    let error_line = log_contents
        .lines()
        .find(|line| line.contains("Error refreshing certificate"))
        .expect("log should contain an error line for the nonexistent certificate");
    assert!(
        error_line.contains("ResourceNotFoundException"),
        "expected ResourceNotFoundException, got: {}",
        error_line
    );

    // Provider must still be running. No cert files should exist.
    assert!(
        !paths.certificate.exists(),
        "certificate file should not exist after export of nonexistent ARN"
    );
    assert!(
        provider.is_running(),
        "provider should still be running after nonexistent certificate export failure"
    );
}

/// Placeholder: config reload is not yet implemented in the ACM provider.
///
/// The provider reads its configuration once at startup and does not watch
/// the config file for changes or respond to SIGHUP. This test should be
/// unignored once a config-reload mechanism (file watcher, signal handler,
/// or similar) is added.
///
/// Expected behavior when implemented:
/// 1. Start provider with cert A
/// 2. Rewrite config to include cert A + cert B
/// 3. Trigger reload (SIGHUP / file change)
/// 4. Assert cert B files appear on disk
#[ignore = "blocked on config-reload feature: the ACM provider does not yet support runtime config changes (no SIGHUP, no file watcher)"]
#[tokio::test]
async fn test_config_reload_updates_certificates() {
    // Intentionally empty — see ignore reason above.
}

/// Placeholder: crash recovery during atomic writes.
///
/// The provider uses atomic writes (temp file → rename) via
/// `TempFileWithDropCleanup`, which makes partial-write corruption
/// unlikely. A true crash-recovery test would need to kill the provider
/// mid-rename (a narrow window) and verify the cert files are intact on
/// restart. This is difficult to implement reliably in a deterministic
/// test.
///
/// Expected behavior:
/// 1. Start provider, let it write cert files
/// 2. Kill during a subsequent refresh (between temp-write and rename)
/// 3. Restart and verify existing cert files are still valid PEM
#[ignore = "blocked on deterministic crash injection: atomic writes via TempFileWithDropCleanup make the corruption window too narrow to hit reliably"]
#[tokio::test]
async fn test_crash_recovery_during_write() {
    // Intentionally empty — see ignore reason above.
}

/// Validates that the provider refreshes certificate files on a periodic interval.
/// Start the provider, wait for the refresh interval, confirm changed cert replaces files.
/// Currently blocked: requires a long-running test with configurable refresh interval.
#[tokio::test]
#[ignore = "requires long-running wait for periodic refresh interval"]
async fn test_periodic_refresh_updates() {}
