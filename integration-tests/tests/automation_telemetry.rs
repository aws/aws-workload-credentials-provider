//! Integration tests for automation telemetry: the `cert_automation` record
//! the provider queues for each refresh flow and sends when the drain flushes.
//!
//! The provider runs with `[telemetry] dry_run = true`, which writes each
//! request it would send to `logs/acm_provider_telemetry_dryrun.log`, one JSON
//! request per line, instead of sending it. The drain flushes about hourly and
//! at shutdown, so each test stops the provider with SIGTERM and then reads
//! the file.
//!
//! The provider identifies itself from a mock IMDS the test serves on
//! loopback, through `AWS_EC2_METADATA_SERVICE_ENDPOINT`, so the record carries
//! the same identity on any host. The container identities (ECS, EKS) are in
//! `container.rs`.
//!
//! The tests in `mod requests` export a real certificate and need:
//!
//!   ACM_TEST_CERTIFICATE_ARN — Certificate the provider exports
//!   ACM_TEST_ROLE_ARN        — IAM role the provider assumes when exporting
//!
//! and credentials in the `AWS_*` variables: the mock IMDS serves no instance
//! profile.
#![cfg(target_os = "linux")]

mod common;
mod mock_imds;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::{
    dry_run_automation_records, first_certificate_der_base64, locate_provider_binary,
    TelemetryTestCertificate, TelemetryTestConfig, TestCertificate,
};
use mock_imds::{start_mock_imds, MockImds, MockImdsConfig};
use serde_json::Value;

const ACM_LOG_FILE: &str = "logs/acm_provider.log";
const DRY_RUN_LOG_FILE: &str = "logs/acm_provider_telemetry_dryrun.log";

/// Time for the first refresh cycle: startup jitter (up to 5s), the ACM
/// export and the file writes.
const FIRST_CYCLE_TIMEOUT: Duration = Duration::from_secs(45);

/// Time for the provider to stop after SIGTERM, including the drain's flush.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(15);

/// The instance the mock IMDS reports.
const INSTANCE_ID: &str = "i-0123456789abcdef0";

/// Well-formed ARNs no account holds: the export fails, and the provider
/// still reports the flow.
const PLACEHOLDER_CERT_ARN: &str =
    "arn:aws:acm:us-west-2:123456789012:certificate/12345678-1234-1234-1234-123456789012";
const PLACEHOLDER_ROLE_ARN: &str = "arn:aws:iam::123456789012:role/PlaceholderRole";

/// Variables that would make the provider identify as Lambda, ECS or EKS
/// instead of asking IMDS.
const CONTAINER_VARS: &[&str] = &[
    "AWS_LAMBDA_FUNCTION_NAME",
    "ECS_CONTAINER_METADATA_URI_V4",
    "ECS_CONTAINER_METADATA_URI",
    "KUBERNETES_SERVICE_HOST",
];

/// Serves IMDSv2 on loopback with [`INSTANCE_ID`]'s identity document. The
/// server stops when the returned value is dropped.
async fn start_imds() -> MockImds {
    start_mock_imds(MockImdsConfig {
        instance_id: INSTANCE_ID.to_string(),
        ..MockImdsConfig::default()
    })
    .await
}

/// A test directory with the provider's config and its logs.
struct TestDirs {
    _tmp: tempfile::TempDir,
    root: PathBuf,
}

impl TestDirs {
    fn new() -> Self {
        let tmp = tempfile::TempDir::new().expect("could not create test dir");
        let root = dunce::canonicalize(tmp.path()).unwrap();
        std::fs::create_dir(root.join("cert")).unwrap();
        Self { _tmp: tmp, root }
    }

    fn log(&self) -> PathBuf {
        self.root.join(ACM_LOG_FILE)
    }

    fn cert_dir(&self) -> PathBuf {
        self.root.join("cert")
    }

    /// Writes a config with dry-run telemetry for one certificate, with the
    /// automation telemetry opt-in when `opted_in`. `watcher` routes the
    /// certificate to a watcher whose inbox exists.
    fn write_config(
        &self,
        cert_arn: &str,
        role_arn: &str,
        opted_in: bool,
        watcher: bool,
    ) -> PathBuf {
        let mut certificate = TelemetryTestCertificate::in_dir(
            cert_arn,
            role_arn,
            &self.cert_dir().display().to_string(),
        );
        let mut config = TelemetryTestConfig {
            dry_run: true,
            automation_telemetry: opted_in,
            ..TelemetryTestConfig::default()
        };
        if watcher {
            for sub in ["watcher-config", "watcher-requests/integ/inbox"] {
                std::fs::create_dir_all(self.root.join(sub)).unwrap();
            }
            config.watcher_config_dir =
                Some(self.root.join("watcher-config").display().to_string());
            config.watcher_requests_dir =
                Some(self.root.join("watcher-requests").display().to_string());
            certificate = certificate.for_watcher("integ", "/usr/bin/true");
        }
        config.certificates.push(certificate);
        let path = self.root.join("config.toml");
        std::fs::write(&path, config.to_toml()).unwrap();
        path
    }

    /// Writes a config with dry-run, opted-in telemetry for `certs`, each
    /// `(certificate ARN, role ARN, refresh command)`. Certificate `i` writes
    /// its files under `cert-<i>/`.
    fn write_certs_config(&self, certs: &[(&str, &str, Option<&str>)]) -> PathBuf {
        let mut config = TelemetryTestConfig {
            dry_run: true,
            automation_telemetry: true,
            ..TelemetryTestConfig::default()
        };
        for (i, (cert_arn, role_arn, command)) in certs.iter().enumerate() {
            let dir = self.root.join(format!("cert-{i}"));
            std::fs::create_dir_all(&dir).unwrap();
            let mut certificate =
                TelemetryTestCertificate::in_dir(cert_arn, role_arn, &dir.display().to_string());
            certificate.refresh_command = command.map(str::to_string);
            config.certificates.push(certificate);
        }
        let path = self.root.join("config.toml");
        std::fs::write(&path, config.to_toml()).unwrap();
        path
    }
}

/// The provider, killed when the test ends if it hasn't been stopped.
struct Provider(Child);

impl Provider {
    fn start(config: &Path, dirs: &TestDirs, imds: &str) -> Self {
        let mut cmd = Command::new(locate_provider_binary().canonicalize().unwrap());
        cmd.args(["acm", "start", "--config"])
            .arg(config)
            .current_dir(&dirs.root)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .env("AWS_EC2_METADATA_SERVICE_ENDPOINT", imds)
            .env("AWS_EC2_METADATA_DISABLED", "false")
            .env(
                "AWS_REGION",
                std::env::var("AWS_REGION").unwrap_or("us-west-2".into()),
            );
        for var in CONTAINER_VARS {
            cmd.env_remove(var);
        }
        Self(cmd.spawn().expect("could not start the provider"))
    }

    /// Sends SIGTERM and waits for the provider to exit.
    async fn stop(&mut self) -> ExitStatus {
        let pid = libc::pid_t::try_from(self.0.id()).unwrap();
        // SAFETY: kill(2) on a child process this test spawned and hasn't reaped.
        assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
        let result = tokio::time::timeout(SHUTDOWN_TIMEOUT, async {
            loop {
                if let Some(status) = self.0.try_wait().unwrap() {
                    return status;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await;
        result.expect("the provider didn't stop after SIGTERM")
    }
}

impl Drop for Provider {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// Polls the provider log until it has `text`, or panics after `timeout`.
async fn wait_for_log(dirs: &TestDirs, text: &str, timeout: Duration) {
    let found = tokio::time::timeout(timeout, async {
        while !read(&dirs.log()).contains(text) {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await;
    assert!(
        found.is_ok(),
        "timed out after {timeout:?} waiting for {text:?}:\n{}",
        read(&dirs.log())
    );
}

/// The automation records in the dry-run log, each with the request that
/// carries it.
fn automation_records(dirs: &TestDirs) -> Vec<(Value, Value)> {
    dry_run_automation_records(&dirs.root.join(DRY_RUN_LOG_FILE))
}

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

/// Runs the provider until each of `arns` has finished its first refresh,
/// stops it, and returns the automation records this run added. Each run in
/// the same directory appends to the same logs, so only new lines count.
async fn run_until_refreshed(
    dirs: &TestDirs,
    config: &Path,
    imds: &str,
    arns: &[&str],
) -> Vec<(Value, Value)> {
    let log_start = read(&dirs.log()).len();
    // Empty rather than a panic if the log shrank or couldn't be read.
    let new_log = || read(&dirs.log()).get(log_start..).unwrap_or("").to_string();
    let records_before = automation_records(dirs).len();
    let mut provider = Provider::start(config, dirs, imds);
    let finished = |log: &str| {
        arns.iter().all(|arn| {
            log.contains(&format!("Certificate refresh successful for {arn}"))
                || log.contains(&format!("Error refreshing certificate {arn}"))
        })
    };
    let waited = tokio::time::timeout(FIRST_CYCLE_TIMEOUT, async {
        while !finished(&new_log()) {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await;
    assert!(
        waited.is_ok(),
        "timed out after {FIRST_CYCLE_TIMEOUT:?} waiting for every refresh:\n{}",
        new_log()
    );
    assert!(provider.stop().await.success());
    automation_records(dirs).split_off(records_before)
}

/// The one record for `arn`.
fn record_for<'a>(records: &'a [(Value, Value)], arn: &str) -> &'a (Value, Value) {
    let found: Vec<_> = records
        .iter()
        .filter(|(_, record)| record["certificateArn"] == arn)
        .collect();
    assert_eq!(found.len(), 1, "want one record for {arn}: {records:?}");
    found[0]
}

/// The base64 DER of every certificate in `pem`, in order, as `chainDer` carries them.
fn certificate_ders_base64(pem: &str) -> Vec<String> {
    pem.split("-----BEGIN CERTIFICATE-----")
        .skip(1)
        .filter_map(|block| block.split_once("-----END CERTIFICATE-----"))
        .map(|(body, _)| body.split_whitespace().collect())
        .collect()
}

/// Asserts no private key reached the telemetry request.
fn assert_no_private_key(request: &Value) {
    assert!(
        !request.to_string().contains("PRIVATE KEY"),
        "a private key is in the telemetry request: {request}"
    );
}

/// The boot nonce in a `{instance}:{nonce}:acm:cert_automation:{seq}:0` key.
fn boot_nonce(request: &Value) -> String {
    let key = request["idempotencyKey"].as_str().expect("idempotencyKey");
    let rest = key
        .strip_prefix(&format!("{INSTANCE_ID}:"))
        .unwrap_or_else(|| panic!("{key} doesn't start with the instance ID"));
    let parts: Vec<&str> = rest.split(':').collect();
    assert!(
        matches!(parts[..], [nonce, "acm", "cert_automation", seq, "0"]
            if !nonce.is_empty() && seq.parse::<u64>().is_ok()),
        "malformed idempotency key: {key}"
    );
    parts[0].to_string()
}

/// Asserts the cycle fields of the first refresh of a run: `eventTime` within
/// the test's run, and a `refreshCycleId` of the run ID (32 hex digits) and
/// cycle 0.
fn assert_first_cycle_fields(record: &Value, started_ms: u64) {
    let event_time = record["eventTime"].as_u64().expect("eventTime");
    assert!(
        (started_ms..=now_ms()).contains(&event_time),
        "eventTime {event_time} is outside the test's run: {record}"
    );
    let cycle = record["refreshCycleId"].as_str().expect("refreshCycleId");
    let (run_id, number) = cycle.rsplit_once('-').expect("{run ID}-{cycle}");
    assert!(
        run_id.len() == 32 && run_id.bytes().all(|b| b.is_ascii_hexdigit()),
        "{cycle}"
    );
    assert_eq!(number, "0", "{cycle}");
}

/// A failed export is reported: one `cert_automation` record for the
/// certificate, with the failing stage and the EC2 identity, sent at shutdown.
#[tokio::test]
async fn test_automation_record_emitted() {
    let imds = start_imds().await;
    let dirs = TestDirs::new();
    let config = dirs.write_config(PLACEHOLDER_CERT_ARN, PLACEHOLDER_ROLE_ARN, true, false);

    let started_ms = now_ms();
    let mut provider = Provider::start(&config, &dirs, &imds.endpoint);
    wait_for_log(
        &dirs,
        &format!("Error refreshing certificate {PLACEHOLDER_CERT_ARN}"),
        FIRST_CYCLE_TIMEOUT,
    )
    .await;
    assert!(provider.stop().await.success());

    let records = automation_records(&dirs);
    assert_eq!(records.len(), 1, "{records:?}\n{}", read(&dirs.log()));
    let (request, record) = &records[0];
    assert_eq!(request["computeType"], "EC2", "{request}");
    assert_eq!(request["computeId"], INSTANCE_ID, "{request}");
    // `{instance}:{boot nonce}:acm:cert_automation:{batch sequence}:{batch
    // index}`, the first batch of the run.
    let key = request["idempotencyKey"].as_str().unwrap();
    let nonce = key
        .strip_prefix(&format!("{INSTANCE_ID}:"))
        .and_then(|rest| rest.strip_suffix(":acm:cert_automation:0:0"))
        .unwrap_or_else(|| panic!("malformed idempotency key: {key}"));
    assert!(
        !nonce.is_empty() && !nonce.contains(':'),
        "malformed boot nonce in {key}"
    );
    assert_eq!(record["certificateArn"], PLACEHOLDER_CERT_ARN);
    assert_eq!(record["result"]["failure"]["stage"], "EXPORT", "{record}");
    assert_eq!(record["result"]["failure"]["filesOnDisk"], "NOT_REPLACED");
    // Nothing was ever written, so the record reports no certificate.
    assert!(record.get("certificateDer").is_none(), "{record}");
    assert!(record.get("chainDer").is_none(), "{record}");
    assert_eq!(record["consecutiveFailures"], 0);
    assert_eq!(record["configuredCertificateCount"], 1);
    assert_eq!(record["certIndex"], 0);
    assert!(record["refreshDurationMilliseconds"].is_u64(), "{record}");
    assert_first_cycle_fields(record, started_ms);
}

/// Without `[telemetry.acm]`, no automation record is written.
#[tokio::test]
async fn automation_telemetry_needs_the_opt_in() {
    let imds = start_imds().await;
    let dirs = TestDirs::new();
    let config = dirs.write_config(PLACEHOLDER_CERT_ARN, PLACEHOLDER_ROLE_ARN, false, false);

    let mut provider = Provider::start(&config, &dirs, &imds.endpoint);
    wait_for_log(
        &dirs,
        &format!("Error refreshing certificate {PLACEHOLDER_CERT_ARN}"),
        FIRST_CYCLE_TIMEOUT,
    )
    .await;
    assert!(provider.stop().await.success());

    assert!(
        automation_records(&dirs).is_empty(),
        "{:?}",
        automation_records(&dirs)
    );
}

/// The tests that export the real `ACM_TEST_CERTIFICATE_ARN` certificate.
mod requests {
    use super::*;

    /// A certificate routed to a watcher that predates status reports (an
    /// `inbox/` but no `outbox/`): the provider queues the reload instead of
    /// running it and, with no status to wait for, reports the new files as
    /// written but not reloaded, with the certificate it wrote. No watcher
    /// runs here, so an `outbox/` would only make the provider wait out its
    /// response timeout.
    #[tokio::test]
    async fn test_automation_telemetry_for_a_watcher_certificate() {
        let cert = TestCertificate::from_env();
        let imds = start_imds().await;
        let dirs = TestDirs::new();
        let config = dirs.write_config(cert.arn(), cert.role_arn(), true, true);

        let mut provider = Provider::start(&config, &dirs, &imds.endpoint);
        wait_for_log(&dirs, "Queued refresh request", FIRST_CYCLE_TIMEOUT).await;
        assert!(provider.stop().await.success());

        let records = automation_records(&dirs);
        assert_eq!(records.len(), 1, "{records:?}");
        let (request, record) = &records[0];
        assert_eq!(request["computeType"], "EC2", "{request}");
        assert_eq!(record["certificateArn"], cert.arn());
        assert_eq!(
            record["result"]["success"], "WRITTEN_NOT_RELOADED",
            "{record}"
        );
        assert!(
            read(&dirs.log()).contains("predates status reports"),
            "the provider didn't treat the watcher as predating status reports"
        );
        // The record describes the leaf this refresh wrote.
        let written = read(&dirs.cert_dir().join("cert.pem"));
        assert_eq!(
            record["certificateDer"].as_str(),
            Some(first_certificate_der_base64(&written).as_str()),
            "{record}"
        );
        assert!(
            !read(&dirs.log()).contains("Running refresh command"),
            "the provider ran the watcher's command"
        );
    }

    /// A new certificate is deployed (files written, command run), and a
    /// restart with the same files reloads it, in a new refresh cycle and
    /// with a new boot nonce.
    #[tokio::test]
    async fn a_new_certificate_is_deployed_then_reloaded_after_a_restart() {
        let cert = TestCertificate::from_env();
        let imds = start_imds().await;
        let dirs = TestDirs::new();
        let config =
            dirs.write_certs_config(&[(cert.arn(), cert.role_arn(), Some("/usr/bin/true"))]);

        let started_ms = now_ms();
        let first = run_until_refreshed(&dirs, &config, &imds.endpoint, &[cert.arn()]).await;
        let (first_request, deployed) = record_for(&first, cert.arn());
        assert_eq!(deployed["result"]["success"], "DEPLOYED", "{deployed}");
        assert_eq!(first_request["computeType"], "EC2", "{first_request}");
        assert_eq!(first_request["computeId"], INSTANCE_ID, "{first_request}");
        assert_first_cycle_fields(deployed, started_ms);
        let written = read(&dirs.root.join("cert-0/cert.pem"));
        assert_eq!(
            deployed["certificateDer"].as_str(),
            Some(first_certificate_der_base64(&written).as_str()),
            "{deployed}"
        );
        let chain = certificate_ders_base64(&read(&dirs.root.join("cert-0/chain.pem")));
        assert!(!chain.is_empty(), "the test certificate has no chain");
        assert_eq!(deployed["chainDer"], serde_json::json!(chain), "{deployed}");
        assert_no_private_key(first_request);
        assert_eq!(deployed["configuredCertificateCount"], 1);
        assert_eq!(deployed["certIndex"], 0);
        assert_eq!(deployed["consecutiveFailures"], 0);

        let second = run_until_refreshed(&dirs, &config, &imds.endpoint, &[cert.arn()]).await;
        let (second_request, reloaded) = record_for(&second, cert.arn());
        assert_eq!(reloaded["result"]["success"], "RELOADED", "{reloaded}");
        assert_eq!(reloaded["certificateDer"], deployed["certificateDer"]);
        assert_ne!(
            reloaded["refreshCycleId"], deployed["refreshCycleId"],
            "a restart starts a new refresh cycle"
        );
        assert_ne!(
            boot_nonce(first_request),
            boot_nonce(second_request),
            "a restart keeps the boot nonce, so its keys could repeat"
        );
    }

    /// Without a refresh command, new files are written but not reloaded,
    /// and a restart with the same files changes nothing.
    #[tokio::test]
    async fn without_a_command_new_files_are_written_not_reloaded_then_unchanged() {
        let cert = TestCertificate::from_env();
        let imds = start_imds().await;
        let dirs = TestDirs::new();
        let config = dirs.write_certs_config(&[(cert.arn(), cert.role_arn(), None)]);

        let first = run_until_refreshed(&dirs, &config, &imds.endpoint, &[cert.arn()]).await;
        let (first_request, written) = record_for(&first, cert.arn());
        assert_eq!(
            written["result"]["success"], "WRITTEN_NOT_RELOADED",
            "{written}"
        );
        assert!(written["certificateDer"].is_string(), "{written}");
        assert_no_private_key(first_request);

        let second = run_until_refreshed(&dirs, &config, &imds.endpoint, &[cert.arn()]).await;
        let (_, unchanged) = record_for(&second, cert.arn());
        assert_eq!(unchanged["result"]["success"], "UNCHANGED", "{unchanged}");
        assert_eq!(
            unchanged["certificateDer"], written["certificateDer"],
            "the files on disk didn't change, so neither does the certificate"
        );
    }

    /// A failed refresh command and a failed export each report their stage,
    /// code and files on disk, and both records share the run's refresh
    /// cycle. Indexes follow the configured ARNs sorted, not config order.
    #[tokio::test]
    async fn failures_report_their_stage_and_share_the_refresh_cycle() {
        let cert = TestCertificate::from_env();
        // In the test certificate's account and Region, but not issued.
        let (prefix, _) = cert.arn().rsplit_once('/').expect("certificate ARN");
        let missing = format!("{prefix}/00000000-0000-0000-0000-000000000000");
        let imds = start_imds().await;
        let dirs = TestDirs::new();
        let config = dirs.write_certs_config(&[
            (cert.arn(), cert.role_arn(), Some("/usr/bin/false")),
            (&missing, cert.role_arn(), Some("/usr/bin/true")),
        ]);

        let records =
            run_until_refreshed(&dirs, &config, &imds.endpoint, &[cert.arn(), &missing]).await;

        let (_, reload) = record_for(&records, cert.arn());
        let failure = &reload["result"]["failure"];
        assert_eq!(failure["stage"], "RELOAD", "{reload}");
        assert_eq!(failure["code"], "CommandFailed", "{reload}");
        assert_eq!(failure["filesOnDisk"], "REPLACED", "{reload}");
        assert!(
            reload["certificateDer"].is_string(),
            "the files were written: {reload}"
        );

        let (_, export) = record_for(&records, &missing);
        let failure = &export["result"]["failure"];
        assert_eq!(failure["stage"], "EXPORT", "{export}");
        assert_eq!(failure["code"], "ResourceNotFoundException", "{export}");
        assert_eq!(failure["filesOnDisk"], "NOT_REPLACED", "{export}");
        assert!(
            export.get("certificateDer").is_none(),
            "nothing was written: {export}"
        );
        assert!(
            export.get("chainDer").is_none(),
            "nothing was written: {export}"
        );

        for record in [reload, export] {
            assert_eq!(record["configuredCertificateCount"], 2, "{record}");
            assert_eq!(record["consecutiveFailures"], 0, "{record}");
            assert_eq!(
                record["refreshCycleId"], reload["refreshCycleId"],
                "{record}"
            );
        }
        let sorted: BTreeSet<&str> = [cert.arn(), missing.as_str()].into_iter().collect();
        for (index, arn) in sorted.iter().enumerate() {
            assert_eq!(record_for(&records, arn).1["certIndex"], index, "{arn}");
        }
    }
}
