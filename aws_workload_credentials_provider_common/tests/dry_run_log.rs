//! Checks what telemetry logs. A dry-run sender logs each request's JSON at
//! INFO under `telemetry_dryrun` instead of sending it. The drain logs
//! evictions once per flush, logs a dry run's queued requests at the flush,
//! and names a record pushed after shutdown by its key. A Secrets Manager
//! sender that isn't a dry run warns at construction that it is held back,
//! since its records aren't in the request's shape. A Secrets Manager record
//! has no request part, so the sender rejects it before its one-line
//! `Telemetry (not sent)` summary, and that summary isn't checked.
//!
//! This binary installs its own logger. The library's unit tests can't, since
//! they run log4rs and a process gets only one global logger.

use std::sync::Mutex;

use aws_config::{Region, SdkConfig};
use aws_credential_types::provider::SharedCredentialsProvider;
use aws_credential_types::Credentials;
use aws_workload_credentials_provider_common::telemetry::{
    drain, Blob, Capability, DeploymentType, Discovery, Entry, Observation, PayloadEnvelope,
    PayloadType, ProbeOutcome, RequestPart, TelemetryConfig, TelemetryRecord, TelemetrySender,
};

/// Every line logged in this test binary.
static LOGGED: Mutex<Vec<(log::Level, String, String)>> = Mutex::new(Vec::new());

struct CapturingLogger;

impl log::Log for CapturingLogger {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        LOGGED.lock().unwrap().push((
            record.level(),
            record.target().to_string(),
            record.args().to_string(),
        ));
    }

    fn flush(&self) {}
}

/// The tests run in one process, so only the first one installs the logger.
fn capture_logs() {
    let _ = log::set_logger(&CapturingLogger);
    log::set_max_level(log::LevelFilter::Info);
}

/// An ACM envelope for a `payload_type` record whose boot nonce is `name`, so
/// its key carries the test's name.
fn envelope(payload_type: PayloadType, name: &str) -> PayloadEnvelope {
    PayloadEnvelope::new(
        Capability::Acm,
        payload_type,
        0,
        0,
        "i-1",
        name,
        "4.0.0",
        "us-west-2",
        DeploymentType::Ec2,
    )
    .unwrap()
}

/// A discovery record whose request carries its name as the SNI, so each test
/// finds its own lines.
struct Record(&'static str, PayloadEnvelope);

impl Record {
    fn new(name: &'static str) -> Self {
        Self(name, envelope(PayloadType::CertDiscovery, name))
    }
}

impl TelemetryRecord for Record {
    fn payload_type(&self) -> PayloadType {
        PayloadType::CertDiscovery
    }

    fn capability(&self) -> Capability {
        Capability::Acm
    }

    fn serialize(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&serde_json::json!({ "name": self.0 }))
    }

    fn request_part(&self) -> Option<RequestPart> {
        let discovery = Discovery {
            scan_time: 1_793_315_962_000,
            scan_id: "i-1:1793315962".to_string(),
            observations: vec![Observation {
                port: 443,
                sni: Some(self.0.to_string()),
                outcome: ProbeOutcome::Success,
                certificate_der: Some(Blob(vec![0x30])),
                chain_der: None,
                mtls_detected: None,
                tls_version: None,
                cipher_suite: None,
                handshake_signature_scheme: None,
                key_algorithm: None,
            }],
            batch_index: 1,
            total_batches: 1,
            scan_complete: None,
            total_targets_probed: None,
            successful_probes: None,
            failed_probes: None,
            dropped_observations: None,
            configured_certificate_count: None,
        };
        Some(RequestPart::new(&self.1, Entry::Discovery(discovery)))
    }

    fn idempotency_key(&self) -> &str {
        &self.1.idempotency_key
    }
}

/// A discovery record with JSON but no request part.
struct JsonOnlyRecord(&'static str);

impl TelemetryRecord for JsonOnlyRecord {
    fn payload_type(&self) -> PayloadType {
        PayloadType::CertDiscovery
    }

    fn capability(&self) -> Capability {
        Capability::Acm
    }

    fn serialize(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&serde_json::json!({ "name": self.0 }))
    }

    fn idempotency_key(&self) -> &str {
        self.0
    }
}

/// An SDK config with test credentials in us-west-2.
fn sdk_config() -> SdkConfig {
    SdkConfig::builder()
        .credentials_provider(SharedCredentialsProvider::new(Credentials::new(
            "AKIDEXAMPLE",
            "secret",
            None,
            None,
            "test",
        )))
        .region(Region::new("us-west-2"))
        .build()
}

/// A sender for ACM discovery records, the type `Record` is.
fn acm_sender(dry_run: bool) -> TelemetrySender {
    let mut settings = TelemetryConfig::default();
    settings.acm_discovery_enabled = true;
    settings.dry_run = dry_run;
    TelemetrySender::for_capability(&settings, Capability::Acm, &sdk_config()).unwrap()
}

/// The lines logged so far that mention `name`.
fn logged_about(name: &str) -> Vec<(log::Level, String, String)> {
    LOGGED
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, _, message)| message.contains(name))
        .cloned()
        .collect()
}

/// Whether a WARN containing `text` has been logged.
fn warned(text: &str) -> bool {
    LOGGED
        .lock()
        .unwrap()
        .iter()
        .any(|(level, _, message)| *level == log::Level::Warn && message.contains(text))
}

#[tokio::test]
async fn a_dry_run_logs_the_request_at_info_under_its_target() {
    capture_logs();
    let sender = acm_sender(true);
    assert!(warned(
        "each request is written to the *_telemetry_dryrun.log file"
    ));
    assert!(sender.send(&Record::new("dry-run")).await.is_ok());
    let logged = logged_about("dry-run");
    assert_eq!(logged.len(), 1, "{logged:?}");
    let (level, target, message) = &logged[0];
    assert_eq!(*level, log::Level::Info);
    assert_eq!(target, "telemetry_dryrun");
    let request: serde_json::Value = serde_json::from_str(message).unwrap();
    assert_eq!(request["computeId"], "i-1");
    assert_eq!(
        request["telemetry"]["discovery"]["observations"][0]["sni"],
        "dry-run"
    );
}

#[tokio::test]
async fn a_dry_run_logs_the_json_of_a_record_without_a_request_part() {
    capture_logs();
    let sender = acm_sender(true);
    assert!(sender.send(&JsonOnlyRecord("json-only")).await.is_ok());
    assert_eq!(
        logged_about("json-only"),
        [(
            log::Level::Info,
            "telemetry_dryrun".to_string(),
            r#"{"name":"json-only"}"#.to_string(),
        )]
    );
}

/// Evictions are logged once per flush and after the final flush, not per
/// push, and a dry run logs queued requests at those flushes, not at push.
#[tokio::test(start_paused = true)]
async fn evictions_are_logged_once_when_the_drain_flushes() {
    capture_logs();
    let token = tokio_util::sync::CancellationToken::new();
    let (queue, task) = drain::spawn(acm_sender(true), token.clone());
    let evictions = || {
        LOGGED
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, _, message)| message.contains("because the queue was full"))
            .map(|(_, _, message)| message.clone())
            .collect::<Vec<_>>()
    };
    let requests = || {
        LOGGED
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, target, message)| {
                target == "telemetry_dryrun" && message.contains("evicting")
            })
            .count()
    };
    let three = "Telemetry: dropped 3 record(s) because the queue was full";
    // The queue holds 1,000 records, so the last 3 evict the oldest.
    let fill = || {
        for _ in 0..1_003 {
            queue.push(&Record::new("evicting"));
        }
    };

    fill();
    assert!(evictions().is_empty());
    assert_eq!(requests(), 0);
    // Past the longest flush interval, 1.2 hours: that flush logs them.
    tokio::time::sleep(std::time::Duration::from_secs(4_400)).await;
    assert_eq!(evictions(), [three]);
    assert_eq!(requests(), 1_000);

    fill();
    assert_eq!(evictions(), [three]);
    token.cancel();
    task.await.unwrap();
    assert_eq!(evictions(), [three, three]);
    assert_eq!(requests(), 2_000);
}

/// An ACM sender that isn't a dry run doesn't warn that it is held back; a
/// Secrets Manager sender does. The ACM dry-run warning isn't checked, since other tests in
/// this binary make dry-run ACM senders and share the log.
#[tokio::test]
async fn only_a_secrets_manager_sender_is_held_back() {
    capture_logs();
    let _acm = acm_sender(false);
    assert!(!warned("Telemetry for acm: this release doesn't send"));

    let mut settings = TelemetryConfig::default();
    settings.secrets_manager_enabled = true;
    let _secrets_manager =
        TelemetrySender::for_capability(&settings, Capability::SecretsManager, &sdk_config())
            .unwrap();
    assert!(warned(
        "Telemetry for secrets_manager: this release doesn't send its telemetry yet"
    ));
}

/// A record pushed after the final flush is named by its part's key.
#[tokio::test]
async fn a_record_pushed_after_shutdown_is_named_by_its_parts_key() {
    capture_logs();
    let token = tokio_util::sync::CancellationToken::new();
    let (queue, task) = drain::spawn(acm_sender(true), token.clone());
    token.cancel();
    task.await.unwrap();
    queue.push(&Record::new("late"));
    assert!(warned(
        "Telemetry: record i-1:late:acm:cert_discovery:0:0 pushed after shutdown and dropped"
    ));
}
