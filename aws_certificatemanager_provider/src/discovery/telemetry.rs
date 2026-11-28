//! Telemetry submission interface.

use aws_workload_credentials_provider_common::telemetry::{
    SendError, TelemetryRecord, TelemetrySender,
};
use log::info;

/// Submission errors. Transient means the sender has already exhausted its
/// retries; rejected payloads would fail the same way on retry.
#[derive(Debug)]
pub enum SubmitError {
    Transient(String),
    Rejected(String),
}

impl std::fmt::Display for SubmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubmitError::Transient(msg) => write!(f, "transient: {}", msg),
            SubmitError::Rejected(msg) => write!(f, "rejected: {}", msg),
        }
    }
}

impl From<SendError> for SubmitError {
    fn from(error: SendError) -> Self {
        match error {
            SendError::Transient(message) => SubmitError::Transient(message),
            SendError::Rejected(message) => SubmitError::Rejected(message),
        }
    }
}

/// Stub submitter that logs records when the shared telemetry sender is unavailable.
#[derive(Debug, Default)]
pub struct LogOnlySubmitter;

impl LogOnlySubmitter {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl TelemetrySubmitter for LogOnlySubmitter {
    async fn submit(&self, record: &dyn TelemetryRecord) -> Result<(), SubmitError> {
        let size = record.serialize().map(|b| b.len()).unwrap_or(0);
        info!(
            "Telemetry (stub): {} record {} ({} bytes)",
            record.payload_type().as_str(),
            record.idempotency_key(),
            size
        );
        Ok(())
    }
}

/// Adapter that bridges the shared `TelemetrySender` to ACM's
/// `TelemetrySubmitter` trait. Maps `SendError` variants to `SubmitError`.
pub struct SenderSubmitter(pub TelemetrySender);

#[async_trait::async_trait]
impl TelemetrySubmitter for SenderSubmitter {
    async fn submit(&self, record: &dyn TelemetryRecord) -> Result<(), SubmitError> {
        self.0.send(record).await.map_err(SubmitError::from)
    }
}

/// Async interface for submitting telemetry records.
///
/// Implementations own retry behavior and must complete within bounded
/// time. The scheduler calls submit() once per record and treats any
/// error as a final failure for that batch.
#[async_trait::async_trait]
pub trait TelemetrySubmitter: Send + Sync {
    async fn submit(&self, record: &dyn TelemetryRecord) -> Result<(), SubmitError>;
}

#[cfg(test)]
mod adapter_tests {
    use super::*;
    use aws_credential_types::{provider::SharedCredentialsProvider, Credentials};
    use aws_workload_credentials_provider_common::telemetry::{
        Blob, Capability, PayloadType, TelemetryConfig,
    };

    struct DiscoveryRecord;

    impl TelemetryRecord for DiscoveryRecord {
        fn payload_type(&self) -> PayloadType {
            PayloadType::CertDiscovery
        }

        fn capability(&self) -> Capability {
            Capability::Acm
        }

        fn serialize(&self) -> Result<Vec<u8>, serde_json::Error> {
            Ok(Vec::new())
        }

        fn idempotency_key(&self) -> &str {
            "test-key"
        }
    }

    #[tokio::test]
    async fn sender_submitter_maps_rejected_errors() {
        let mut settings = TelemetryConfig::default();
        settings.acm_enabled = true;
        let sdk_config = aws_config::SdkConfig::builder()
            .region(aws_config::Region::new("us-west-2"))
            .credentials_provider(SharedCredentialsProvider::new(Credentials::new(
                "access-key",
                "secret-key",
                None,
                None,
                "test",
            )))
            .build();
        let sender = TelemetrySender::for_capability(&settings, Capability::Acm, &sdk_config)
            .expect("sender should be available with region and credentials");

        let error = SenderSubmitter(sender)
            .submit(&DiscoveryRecord)
            .await
            .expect_err("discovery consent is disabled");

        assert!(
            matches!(error, SubmitError::Rejected(message) if message.contains("hasn't consented"))
        );
    }

    /// Validates that the sender, which checks every request against the
    /// service model's limits before sending, accepts ACM's discovery and
    /// automation records, and pins the request each gives on the wire: a dry
    /// run reaches the check and logs the request's JSON instead of sending.
    #[tokio::test]
    async fn a_dry_run_sender_accepts_acm_discovery_and_automation_records() {
        use crate::discovery::payload::{
            BatchInfo, CertDiscoveryRecord, Observation, ProbeOutcome,
        };
        use crate::discovery::test_support::capture_logs;
        use crate::telemetry::{
            AutomationSequence, CertAutomationRecord, RefreshOutcome, SuccessStatus,
        };
        use aws_workload_credentials_provider_common::telemetry::{
            AgentIdentity, DeploymentType, PayloadEnvelope,
        };
        use testing::{dry_run_acm_sender, logged_requests};

        capture_logs();
        let sender = dry_run_acm_sender();

        let discovery = CertDiscoveryRecord {
            envelope: PayloadEnvelope::new(
                Capability::Acm,
                PayloadType::CertDiscovery,
                0,
                0,
                "i-test",
                "boot-test",
                env!("CARGO_PKG_VERSION"),
                "us-west-2",
                DeploymentType::Ec2,
            )
            .expect("valid telemetry envelope"),
            cycle_id: "i-test:1722297600".to_string(),
            cycle_start_ms: 1_722_297_600_000,
            cycle_timestamp: "2024-07-30T00:00:00Z".to_string(),
            cycle_duration_ms: 1500,
            batch_info: BatchInfo { total_batches: 1 },
            scan_complete: Some(true),
            total_targets_probed: Some(1),
            successful_probes: Some(1),
            failed_probes: Some(0),
            dropped_observations: None,
            configured_cert_count: Some(1),
            observations: vec![Observation {
                port: 443,
                sni: Some("api.example.com".to_string()),
                outcome: ProbeOutcome::Success,
                certificate_der: Some("MIIB".to_string()),
                chain_der: Some(vec!["MIIC".to_string()]),
                mtls_detected: Some(false),
                tls_version: Some("TLSv1.3".to_string()),
                cipher_suite: None,
                handshake_signature_scheme: None,
                key_algorithm: None,
            }],
        };
        SenderSubmitter(sender.clone())
            .submit(&discovery)
            .await
            .expect("a discovery record within the model's limits is accepted");

        let identity = AgentIdentity {
            host_id: "i-test".to_string(),
            deployment_type: DeploymentType::Ec2,
            region: "us-west-2".to_string(),
            boot_nonce: "boot-test".to_string(),
            ecs_network_mode: None,
        };
        let automation = CertAutomationRecord::new(
            &AutomationSequence::default(),
            &identity,
            "arn:aws:acm:us-west-2:111122223333:certificate/abc",
            Some(Blob(vec![0x30, 0x82, 0x01])),
            None,
            RefreshOutcome::Succeeded {
                status: SuccessStatus::Deployed,
            },
            1_722_297_600_000,
        )
        .expect("valid telemetry envelope");
        sender
            .send(&automation)
            .await
            .expect("an automation record within the model's limits is accepted");

        let sent = logged_requests();
        // The request reports the OS and architecture the agent was built
        // for, so the expected values follow the build target.
        let os = if cfg!(target_os = "macos") {
            "MACOS"
        } else if cfg!(windows) {
            "WINDOWS"
        } else {
            "LINUX"
        };
        let arch = if cfg!(target_arch = "aarch64") {
            "ARM64"
        } else {
            "X86_64"
        };
        // Each request as the dry run logs it, the field names and values the
        // service model expects; a sending sender encodes the same request
        // as CBOR. Certificates are base64 in JSON.
        assert_eq!(
            sent,
            vec![
                serde_json::json!({
                    "telemetry": {"discovery": {
                        "scanTime": 1_722_297_600_000_u64,
                        "scanId": "i-test:1722297600",
                        "observations": [{
                            "port": 443,
                            "sni": "api.example.com",
                            "outcome": "SUCCESS",
                            "certificateDer": "MIIB",
                            "chainDer": ["MIIC"],
                            "mtlsDetected": false,
                            "tlsVersion": "TLSv1.3",
                        }],
                        "batchIndex": 1,
                        "totalBatches": 1,
                        "scanComplete": true,
                        "totalTargetsProbed": 1,
                        "successfulProbes": 1,
                        "failedProbes": 0,
                        "configuredCertificateCount": 1,
                    }},
                    "computeId": "i-test",
                    "idempotencyKey": "i-test:boot-test:acm:cert_discovery:0:0",
                    "computeType": "EC2",
                    "os": os,
                    "arch": arch,
                    "schemaVersion": 1,
                }),
                serde_json::json!({
                    "telemetry": {"automation": {"records": [{
                        "certificateArn": "arn:aws:acm:us-west-2:111122223333:certificate/abc",
                        "eventTime": 1_722_297_600_000_u64,
                        "result": {"success": "DEPLOYED"},
                        "certificateDer": "MIIB",
                    }]}},
                    "computeId": "i-test",
                    "idempotencyKey": "i-test:boot-test:acm:cert_automation:0:0",
                    "computeType": "EC2",
                    "os": os,
                    "arch": arch,
                    "schemaVersion": 1,
                }),
            ]
        );
    }

    #[test]
    fn sender_submitter_maps_transient_errors() {
        let send_error = SendError::Transient("timeout".to_string());
        let submit_error = SubmitError::from(send_error);

        assert!(matches!(
            submit_error,
            SubmitError::Transient(message) if message == "timeout"
        ));
    }

    #[tokio::test]
    async fn sender_submitter_forwards_success() {
        let mut settings = TelemetryConfig::default();
        settings.acm_discovery_enabled = true;
        settings.dry_run = true;
        let sdk_config = aws_config::SdkConfig::builder()
            .region(aws_config::Region::new("us-west-2"))
            .credentials_provider(SharedCredentialsProvider::new(Credentials::new(
                "access-key",
                "secret-key",
                None,
                None,
                "test",
            )))
            .build();
        let sender = TelemetrySender::for_capability(&settings, Capability::Acm, &sdk_config)
            .expect("sender should be available with region and credentials");

        SenderSubmitter(sender)
            .submit(&DiscoveryRecord)
            .await
            .expect("consented dry-run records succeed");
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use aws_workload_credentials_provider_common::telemetry::{
        Capability, DeploymentType, PayloadEnvelope, PayloadType,
    };
    use log::{debug, info, warn};
    use std::collections::VecDeque;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// A dry-run ACM sender in us-west-2 with test credentials, consenting
    /// to discovery and automation records: it checks each request against
    /// the service model's limits, then logs its JSON instead of sending it.
    pub(crate) fn dry_run_acm_sender() -> TelemetrySender {
        use aws_credential_types::{provider::SharedCredentialsProvider, Credentials};
        use aws_workload_credentials_provider_common::telemetry::TelemetryConfig;

        let mut settings = TelemetryConfig::default();
        settings.acm_enabled = true;
        settings.acm_discovery_enabled = true;
        settings.dry_run = true;
        let sdk_config = aws_config::SdkConfig::builder()
            .region(aws_config::Region::new("us-west-2"))
            .credentials_provider(SharedCredentialsProvider::new(Credentials::new(
                "access-key",
                "secret-key",
                None,
                None,
                "test",
            )))
            .build();
        TelemetrySender::for_capability(&settings, Capability::Acm, &sdk_config)
            .expect("sender should be available with region and credentials")
    }

    /// The requests a dry-run sender logged on the calling thread, in order,
    /// as JSON. Needs `test_support::capture_logs()` first.
    pub(crate) fn logged_requests() -> Vec<serde_json::Value> {
        crate::discovery::test_support::logged_on_this_thread()
            .iter()
            .filter(|message| message.starts_with('{'))
            .map(|json| serde_json::from_str(json).expect("a dry run logs the request's JSON"))
            .collect()
    }

    pub struct MockSubmitter {
        output_dir: Option<PathBuf>,
        submit_count: Arc<AtomicUsize>,
    }

    impl MockSubmitter {
        pub fn with_directory(dir: PathBuf) -> Self {
            Self {
                output_dir: Some(dir),
                submit_count: Arc::new(AtomicUsize::new(0)),
            }
        }

        pub fn log_only() -> Self {
            Self {
                output_dir: None,
                submit_count: Arc::new(AtomicUsize::new(0)),
            }
        }

        pub fn submit_count(&self) -> usize {
            self.submit_count.load(Ordering::Relaxed)
        }
    }

    pub struct ScriptedSubmitter {
        responses: Mutex<VecDeque<Result<(), SubmitError>>>,
        submit_count: AtomicUsize,
    }

    impl ScriptedSubmitter {
        pub fn new(responses: Vec<Result<(), SubmitError>>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                submit_count: AtomicUsize::new(0),
            }
        }

        pub fn submit_count(&self) -> usize {
            self.submit_count.load(Ordering::Relaxed)
        }
    }

    #[async_trait::async_trait]
    impl TelemetrySubmitter for ScriptedSubmitter {
        async fn submit(&self, _record: &dyn TelemetryRecord) -> Result<(), SubmitError> {
            self.submit_count.fetch_add(1, Ordering::Relaxed);
            self.responses
                .lock()
                .expect("scripted responses lock poisoned")
                .pop_front()
                .unwrap_or_else(|| Err(SubmitError::Rejected("script exhausted".to_string())))
        }
    }

    pub struct PendingSubmitter {
        submit_count: AtomicUsize,
    }

    impl PendingSubmitter {
        pub fn new() -> Self {
            Self {
                submit_count: AtomicUsize::new(0),
            }
        }

        pub fn submit_count(&self) -> usize {
            self.submit_count.load(Ordering::Relaxed)
        }
    }

    #[async_trait::async_trait]
    impl TelemetrySubmitter for PendingSubmitter {
        async fn submit(&self, _record: &dyn TelemetryRecord) -> Result<(), SubmitError> {
            self.submit_count.fetch_add(1, Ordering::Relaxed);
            std::future::pending().await
        }
    }

    #[async_trait::async_trait]
    impl TelemetrySubmitter for MockSubmitter {
        async fn submit(&self, record: &dyn TelemetryRecord) -> Result<(), SubmitError> {
            self.submit_count.fetch_add(1, Ordering::Relaxed);
            let payload_type = record.payload_type();
            let idempotency_key = record.idempotency_key();

            match &self.output_dir {
                Some(dir) => {
                    let filename = format!(
                        "telemetry_{:?}_{}.json",
                        payload_type,
                        idempotency_key.replace([':', '/'], "_")
                    );
                    let path = dir.join(&filename);
                    let bytes = record
                        .serialize()
                        .map_err(|e| SubmitError::Rejected(e.to_string()))?;

                    match std::fs::write(&path, &bytes) {
                        Ok(()) => {
                            info!(
                                "MockSubmitter: wrote {:?} record ({} bytes) to {}",
                                payload_type,
                                bytes.len(),
                                path.display()
                            );
                            Ok(())
                        }
                        Err(e) => {
                            warn!("MockSubmitter: write failed {}: {}", path.display(), e);
                            Err(SubmitError::Transient(e.to_string()))
                        }
                    }
                }
                None => {
                    debug!(
                        "MockSubmitter: discarding {:?} record {}",
                        payload_type, idempotency_key
                    );
                    Ok(())
                }
            }
        }
    }

    #[tokio::test]
    async fn log_only_submitter_accepts_record() {
        let submitter = LogOnlySubmitter::new();

        assert!(submitter.submit(&sample_record()).await.is_ok());
    }

    #[tokio::test]
    async fn mock_log_only() {
        let submitter = MockSubmitter::log_only();
        assert!(submitter.submit(&sample_record()).await.is_ok());
    }

    #[tokio::test]
    async fn mock_writes_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let submitter = MockSubmitter::with_directory(tmp.path().to_path_buf());
        // An EKS host_id contains '/', which must not turn into a subdirectory.
        let record = sample_record_for(
            "default/my-pod/123e4567-e89b-12d3-a456-426614174000",
            DeploymentType::Eks,
        );
        assert!(submitter.submit(&record).await.is_ok());

        let entries: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].file_name(),
            "telemetry_CertDiscovery_default_my-pod_123e4567-e89b-12d3-a456-426614174000_boot-test_acm_cert_discovery_7_0.json"
        );

        let content = std::fs::read_to_string(entries[0].path()).unwrap();
        let parsed: CertDiscoveryRecord = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed.envelope.payload_type, PayloadType::CertDiscovery);
    }

    /// Validates that submitting to a nonexistent directory returns an error.
    #[tokio::test]
    async fn mock_bad_directory() {
        let submitter = MockSubmitter::with_directory(PathBuf::from("/nonexistent/path"));
        assert!(submitter.submit(&sample_record()).await.is_err());
    }

    use crate::discovery::payload::*;

    fn sample_record() -> CertDiscoveryRecord {
        sample_record_for("i-test", DeploymentType::Ec2)
    }

    fn sample_record_for(host_id: &str, deployment_type: DeploymentType) -> CertDiscoveryRecord {
        let envelope = PayloadEnvelope::new(
            Capability::Acm,
            PayloadType::CertDiscovery,
            7,
            0,
            host_id,
            "boot-test",
            env!("CARGO_PKG_VERSION"),
            "us-west-2",
            deployment_type,
        )
        .expect("valid telemetry envelope");
        CertDiscoveryRecord {
            envelope,
            cycle_id: "i-test:1722297600".to_string(),
            cycle_start_ms: 1_722_297_600_000,
            cycle_timestamp: "2026-08-31T00:00:00Z".to_string(),
            cycle_duration_ms: 1500,
            batch_info: BatchInfo { total_batches: 1 },
            scan_complete: None,
            total_targets_probed: None,
            successful_probes: None,
            failed_probes: None,
            dropped_observations: None,
            configured_cert_count: None,
            observations: vec![Observation {
                port: 443,
                sni: None,
                outcome: ProbeOutcome::Success,
                certificate_der: Some("MIID...==".to_string()),
                chain_der: None,
                mtls_detected: None,
                tls_version: None,
                cipher_suite: None,
                handshake_signature_scheme: None,
                key_algorithm: None,
            }],
        }
    }
}
