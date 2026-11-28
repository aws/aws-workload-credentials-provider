//! Builds automation telemetry records from refresh results.

use std::future::Future;
use std::io::ErrorKind;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_workload_credentials_provider_common::config::types::CertificateConfig;
use aws_workload_credentials_provider_common::telemetry::request::MAX_CERTIFICATE_BYTES;
use aws_workload_credentials_provider_common::telemetry::{
    AgentIdentity, Blob, EnvelopeError, IdentityError, TelemetryQueue, TelemetryRecord,
};
use base64ct::{Base64, Encoding};
use log::{info, warn};
use tokio::sync::OnceCell;
use tokio::time::Instant;

use super::payload::{
    AutomationSequence, CertAutomationRecord, FailureCode, FilesOnDisk, RefreshOutcome,
    RenewalFailure, RenewalStage, SuccessStatus,
};
use crate::certificate_file_store::error::StoreError;
use crate::error::RefreshError;

/// Where automation records go: the drain's queue, which sends them later.
pub(crate) trait RecordSink: Send + Sync {
    fn push(&self, record: &dyn TelemetryRecord);
}

impl RecordSink for TelemetryQueue {
    fn push(&self, record: &dyn TelemetryRecord) {
        TelemetryQueue::push(self, record);
    }
}

/// What a successful refresh flow did, with the exported PEM.
pub(crate) struct Refreshed {
    pub status: SuccessStatus,
    pub certificate_pem: String,
    pub chain_pem: String,
}

impl std::fmt::Debug for Refreshed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Refreshed")
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

/// How long a refresh flow took, and the certificate's refreshes and failures before it.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct FlowStats {
    pub duration: Duration,
    /// Failures in a row before this attempt.
    pub consecutive_failures: u32,
    /// Refreshes of this certificate since the agent started, before this one.
    pub cycle: u64,
}

/// A pending identity detection.
pub(crate) type IdentityFuture =
    Pin<Box<dyn Future<Output = Result<AgentIdentity, IdentityError>> + Send>>;

/// How long a failed detection is reused before detecting again.
const DETECTION_RETRY_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// The process identity, shared by discovery and automation.
#[derive(Clone)]
pub(crate) struct SharedIdentity {
    cell: Arc<OnceCell<AgentIdentity>>,
    last_failure: Arc<Mutex<Option<(Instant, IdentityError)>>>,
    detect: fn() -> IdentityFuture,
}

impl Default for SharedIdentity {
    fn default() -> Self {
        Self::with_detector(|| Box::pin(AgentIdentity::detect()))
    }
}

impl SharedIdentity {
    pub(crate) fn with_detector(detect: fn() -> IdentityFuture) -> Self {
        Self {
            cell: Arc::new(OnceCell::new()),
            last_failure: Arc::new(Mutex::new(None)),
            detect,
        }
    }

    /// Detects on first use. Only a success is kept: after a failure, callers get
    /// the same error until [`DETECTION_RETRY_INTERVAL`] passes, then it detects again.
    /// Each failed detection is logged.
    pub(crate) async fn get(&self) -> Result<&AgentIdentity, IdentityError> {
        self.cell
            .get_or_try_init(|| async {
                if let Some(e) = self.recent_failure() {
                    return Err(e);
                }
                let result = (self.detect)().await;
                if let Err(e) = &result {
                    // At most once per interval, so a lasting failure stays visible.
                    warn!("Telemetry identity: {e}");
                    *self.last_failure.lock().unwrap() = Some((Instant::now(), e.clone()));
                }
                result
            })
            .await
    }

    fn recent_failure(&self) -> Option<IdentityError> {
        let last = self.last_failure.lock().unwrap();
        last.as_ref()
            .filter(|(at, _)| at.elapsed() < DETECTION_RETRY_INTERVAL)
            .map(|(_, e)| e.clone())
    }

    #[cfg(test)]
    pub(crate) fn ready(identity: AgentIdentity) -> Self {
        let shared = Self::failing();
        shared.cell.set(identity).expect("new cell is empty");
        shared
    }

    #[cfg(test)]
    pub(crate) fn failing() -> Self {
        Self::with_detector(|| Box::pin(async { Err(IdentityError::NoIdentityFound) }))
    }
}

/// Shared by all certificate tasks. Clones share the identity, sequence, sink and run.
#[derive(Clone)]
pub(crate) struct AutomationTelemetry {
    identity: SharedIdentity,
    sequence: AutomationSequence,
    sink: Arc<dyn RecordSink>,
    /// Random per agent start, so a restart starts new refresh cycles.
    run_id: Option<Arc<str>>,
    /// The configured certificate ARNs, sorted: a certificate's index is its position.
    certificates: Option<Arc<[String]>>,
}

impl AutomationTelemetry {
    pub(crate) fn new(identity: SharedIdentity, sink: Arc<dyn RecordSink>) -> Self {
        Self {
            identity,
            sequence: AutomationSequence::default(),
            sink,
            run_id: run_id().map(Arc::from),
            certificates: None,
        }
    }

    /// Sends the count of `arns`, the certificates in the automation config, and
    /// each certificate's position among them by ARN, on every record.
    pub(crate) fn with_configured_certificates<'a>(
        mut self,
        arns: impl IntoIterator<Item = &'a String>,
    ) -> Self {
        let mut arns: Vec<String> = arns.into_iter().cloned().collect();
        arns.sort();
        self.certificates = Some(arns.into());
        self
    }

    /// Queues the record for one refresh flow. Never fails the flow; a record
    /// that can't be built is dropped, and the drain drops one that's too large.
    pub(crate) async fn report(
        &self,
        config: &CertificateConfig,
        result: &Result<Refreshed, RefreshError>,
        stats: FlowStats,
    ) {
        let arn = &config.certificate_arn;
        let event_time = now_ms();
        let Ok(identity) = self.identity.get().await else {
            return;
        };
        let record = match self
            .build(identity, config, result, stats, event_time)
            .await
        {
            Ok(record) => record,
            Err(e) => {
                warn!("Dropped automation telemetry for {arn}: {e}");
                return;
            }
        };
        self.sink.push(&record);
        info!(
            "Automation: produced 1 telemetry record for certificate refresh of {arn} and offered it for local queueing"
        );
    }

    async fn build(
        &self,
        identity: &AgentIdentity,
        config: &CertificateConfig,
        result: &Result<Refreshed, RefreshError>,
        stats: FlowStats,
        event_time: u64,
    ) -> Result<CertAutomationRecord, EnvelopeError> {
        let (outcome, (certificate_der, chain_der)) = match result {
            Ok(refreshed) => (
                RefreshOutcome::Succeeded {
                    status: refreshed.status,
                },
                leaf_and_chain(
                    certificate_blocks(&refreshed.certificate_pem)
                        .into_iter()
                        .next()
                        .flatten(),
                    certificate_blocks(&refreshed.chain_pem),
                ),
            ),
            Err(e) => (
                RefreshOutcome::Failed(failure(e)),
                certificate_on_disk(config).await,
            ),
        };
        let certificates = self.certificates.as_deref();
        CertAutomationRecord::with_cycle_context(
            &self.sequence,
            identity,
            &config.certificate_arn,
            certificate_der,
            chain_der,
            outcome,
            event_time,
            Some(u64::try_from(stats.duration.as_millis()).unwrap_or(u64::MAX)),
            Some(stats.consecutive_failures),
            certificates.and_then(|arns| u32::try_from(arns.len()).ok()),
            // Every certificate refreshes once per interval, so their Nth refreshes form cycle N.
            self.run_id
                .as_ref()
                .map(|id| format!("{id}-{}", stats.cycle)),
            certificates
                .and_then(|arns| arns.binary_search(&config.certificate_arn).ok())
                .and_then(|index| u32::try_from(index).ok()),
        )
    }
}

/// 128 random bits as hex, or `None` if the system RNG fails.
fn run_id() -> Option<String> {
    let mut bytes = [0u8; 16];
    if aws_lc_rs::rand::fill(&mut bytes).is_err() {
        warn!("Automation telemetry: the system RNG failed, so records carry no refresh cycle ID");
        return None;
    }
    Some(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn failure(e: &RefreshError) -> RenewalFailure {
    let replaced = |changed: bool| {
        if changed {
            FilesOnDisk::Replaced
        } else {
            FilesOnDisk::NotReplaced
        }
    };
    let (stage, code, files_on_disk) = match e {
        RefreshError::ExportFailed { source, .. } => (
            RenewalStage::Export,
            source.telemetry_code(),
            FilesOnDisk::NotReplaced,
        ),
        RefreshError::WriteFailed { source, .. } => {
            let store_error = source.downcast_ref::<StoreError>();
            let files_on_disk = match store_error {
                Some(StoreError::PartialUpdate(_)) => FilesOnDisk::PartlyReplaced,
                _ => FilesOnDisk::NotReplaced,
            };
            (RenewalStage::Write, write_code(store_error), files_on_disk)
        }
        // A command that ran out its time is TimeoutError on every path, as from the watcher.
        RefreshError::CommandFailed {
            files_changed,
            source,
            ..
        } if source.kind() == ErrorKind::TimedOut => (
            RenewalStage::Reload,
            FailureCode::TimeoutError,
            replaced(*files_changed),
        ),
        RefreshError::CommandFailed { files_changed, .. }
        | RefreshError::WatcherFailed { files_changed, .. } => (
            RenewalStage::Reload,
            FailureCode::CommandFailed,
            replaced(*files_changed),
        ),
        RefreshError::WatcherTimeout { files_changed, .. }
        | RefreshError::WatcherNoStatus { files_changed, .. } => (
            RenewalStage::Reload,
            FailureCode::TimeoutError,
            replaced(*files_changed),
        ),
        RefreshError::RequestFailed { files_changed, .. } => (
            RenewalStage::Reload,
            FailureCode::CommandFailed,
            replaced(*files_changed),
        ),
    };
    RenewalFailure {
        stage,
        code,
        files_on_disk,
    }
}

/// Errno-style code for a write failure, the same on every OS.
fn write_code(e: Option<&StoreError>) -> FailureCode {
    let io = match e {
        Some(StoreError::Io(io)) => io,
        Some(StoreError::PartialUpdate(inner)) => return write_code(Some(inner)),
        _ => return FailureCode::Other,
    };
    match io.kind() {
        ErrorKind::PermissionDenied => FailureCode::Eacces,
        ErrorKind::StorageFull => FailureCode::Enospc,
        ErrorKind::QuotaExceeded => FailureCode::Edquot,
        ErrorKind::ReadOnlyFilesystem => FailureCode::Erofs,
        ErrorKind::NotFound => FailureCode::Enoent,
        ErrorKind::InvalidInput => FailureCode::Einval,
        _ => FailureCode::Other,
    }
}

/// The leaf and chain from the certificate and chain files. Never reads the key file.
async fn certificate_on_disk(config: &CertificateConfig) -> (Option<Blob>, Option<Vec<Blob>>) {
    let mut certificate_file = read_certificate_blocks(&config.certificate_path)
        .await
        .into_iter();
    // The first block is the leaf, even when it doesn't decode.
    let leaf = certificate_file.next().flatten();
    let chain = match &config.chain_path {
        Some(chain_path) => read_certificate_blocks(chain_path).await,
        // Without a chain path the certificate file holds the leaf followed by the chain.
        None => certificate_file.collect(),
    };
    leaf_and_chain(leaf, chain)
}

/// `leaf` and, only with it, `chain` up to its first certificate the request
/// can't carry, if that leaves any.
fn leaf_and_chain(
    leaf: Option<Blob>,
    chain: Vec<Option<Blob>>,
) -> (Option<Blob>, Option<Vec<Blob>>) {
    match leaf {
        Some(leaf) => {
            let chain: Vec<Blob> = chain.into_iter().map_while(|der| der).collect();
            (Some(leaf), (!chain.is_empty()).then_some(chain))
        }
        // A chain without its leaf says nothing about the deployed certificate.
        None => (None, None),
    }
}

async fn read_certificate_blocks(path: &Path) -> Vec<Option<Blob>> {
    tokio::fs::read_to_string(path)
        .await
        .map(|pem| certificate_blocks(&pem))
        .unwrap_or_default()
}

/// The DER of each `CERTIFICATE` block in `pem`, in order: `None` for one the
/// request can't carry, which isn't strict base64, is empty or is over
/// [`MAX_CERTIFICATE_BYTES`].
fn certificate_blocks(pem: &str) -> Vec<Option<Blob>> {
    pem.split("-----BEGIN CERTIFICATE-----")
        .skip(1)
        .filter_map(|block| block.split_once("-----END CERTIFICATE-----"))
        .map(|(body, _)| body.split_whitespace().collect::<String>())
        .map(|body| {
            Base64::decode_vec(&body)
                .ok()
                .filter(|der| (1..=MAX_CERTIFICATE_BYTES).contains(&der.len()))
                .map(Blob)
        })
        .collect()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    /// Keeps every pushed record as JSON.
    #[derive(Default)]
    pub(crate) struct RecordingSink(Mutex<Vec<serde_json::Value>>);

    impl RecordingSink {
        pub(crate) fn records(&self) -> Vec<serde_json::Value> {
            self.0.lock().unwrap().clone()
        }
    }

    impl RecordSink for RecordingSink {
        fn push(&self, record: &dyn TelemetryRecord) {
            let json = serde_json::from_slice(&record.serialize().unwrap()).unwrap();
            self.0.lock().unwrap().push(json);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::RecordingSink;
    use super::*;
    use crate::discovery::test_support::{capture_logs, logged_on_this_thread};
    use crate::error::{AcmManagerError, WatcherFailureOutcome};
    use aws_workload_credentials_provider_common::telemetry::DeploymentType;
    use std::path::PathBuf;

    const LEAF: &str = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    const CHAIN: &str = "-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n\
                         -----BEGIN CERTIFICATE-----\r\nCCCC\r\n-----END CERTIFICATE-----\n";

    fn identity() -> AgentIdentity {
        AgentIdentity {
            host_id: "i-0abc".to_string(),
            deployment_type: DeploymentType::Ec2,
            region: "us-west-2".to_string(),
            boot_nonce: "boot-1".to_string(),
            ecs_network_mode: None,
        }
    }

    fn telemetry_with(sink: Arc<RecordingSink>) -> AutomationTelemetry {
        AutomationTelemetry::new(SharedIdentity::ready(identity()), sink)
    }

    fn telemetry() -> AutomationTelemetry {
        telemetry_with(Arc::default())
    }

    fn config(dir: &Path, chain_path: Option<PathBuf>) -> CertificateConfig {
        CertificateConfig {
            certificate_arn: "arn:aws:acm:us-west-2:111122223333:certificate/abc".to_string(),
            certificate_path: dir.join("cert.pem"),
            private_key_path: dir.join("key.pem"),
            chain_path,
            role_arn: "arn:aws:iam::111122223333:role/r".to_string(),
            cert_and_chain_permission: None,
            key_permission: None,
            refresh_command: None,
            watcher_id: None,
        }
    }

    fn der(base64: &str) -> Blob {
        Blob(Base64::decode_vec(base64).unwrap())
    }

    fn wire(record: &CertAutomationRecord) -> serde_json::Value {
        serde_json::from_slice(&TelemetryRecord::serialize(record).unwrap()).unwrap()
    }

    fn io_write_error(kind: ErrorKind) -> RefreshError {
        RefreshError::WriteFailed {
            certificate_arn: "arn".to_string(),
            source: StoreError::Io(std::io::Error::from(kind)).into(),
        }
    }

    fn pem(bodies: &[&str]) -> String {
        bodies
            .iter()
            .map(|body| format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n"))
            .collect()
    }

    #[test]
    fn certificate_blocks_keeps_only_certificate_blocks_in_order() {
        let pem =
            format!("{LEAF}-----BEGIN PRIVATE KEY-----\nDDDD\n-----END PRIVATE KEY-----\n{CHAIN}");
        assert_eq!(
            certificate_blocks(&pem),
            vec![Some(der("AAAA")), Some(der("BBBB")), Some(der("CCCC"))]
        );
    }

    #[test]
    fn certificate_blocks_marks_what_the_request_cant_carry() {
        let over = Base64::encode_string(&vec![0x30; MAX_CERTIFICATE_BYTES + 1]);
        let at_limit = Base64::encode_string(&vec![0x30; MAX_CERTIFICATE_BYTES]);
        // `AAB=` has non-zero padding bits, which strict base64 rejects.
        for body in ["@@@@", "AAA", "AA==AAAA", "A===", "AAB=", "", over.as_str()] {
            assert_eq!(certificate_blocks(&pem(&[body])), vec![None], "{body:.8}");
        }
        assert_eq!(certificate_blocks(&pem(&["AAA="])), vec![Some(der("AAA="))]);
        assert_eq!(
            certificate_blocks(&pem(&[&at_limit])),
            vec![Some(der(&at_limit))]
        );
    }

    #[test]
    fn a_chain_ends_before_its_first_certificate_the_request_cant_carry() {
        let chain = certificate_blocks(&pem(&["BBBB", "@@@@", "CCCC"]));
        assert_eq!(
            leaf_and_chain(Some(der("AAAA")), chain),
            (Some(der("AAAA")), Some(vec![der("BBBB")]))
        );
        let chain = certificate_blocks(&pem(&["@@@@", "CCCC"]));
        assert_eq!(
            leaf_and_chain(Some(der("AAAA")), chain),
            (Some(der("AAAA")), None)
        );
    }

    #[tokio::test]
    async fn a_leaf_on_disk_that_does_not_decode_is_not_replaced_by_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let bad_leaf = "-----BEGIN CERTIFICATE-----\nAAB=\n-----END CERTIFICATE-----\n";
        std::fs::write(dir.path().join("cert.pem"), format!("{bad_leaf}{CHAIN}")).unwrap();

        assert_eq!(
            certificate_on_disk(&config(dir.path(), None)).await,
            (None, None)
        );
    }

    #[tokio::test]
    async fn success_without_a_leaf_sends_no_chain() {
        let dir = tempfile::tempdir().unwrap();
        let result = Ok(Refreshed {
            status: SuccessStatus::Deployed,
            certificate_pem: "-----BEGIN CERTIFICATE-----\nAAB=\n-----END CERTIFICATE-----\n"
                .to_string(),
            chain_pem: CHAIN.to_string(),
        });

        let value = wire(
            &telemetry()
                .build(
                    &identity(),
                    &config(dir.path(), None),
                    &result,
                    FlowStats::default(),
                    7,
                )
                .await
                .unwrap(),
        );
        assert!(value.get("certificate_der").is_none());
        assert!(value.get("chain_der").is_none());
    }

    #[tokio::test]
    async fn success_uses_the_exported_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let result = Ok(Refreshed {
            status: SuccessStatus::Deployed,
            certificate_pem: LEAF.to_string(),
            chain_pem: CHAIN.to_string(),
        });

        let value = wire(
            &telemetry()
                .build(
                    &identity(),
                    &config(dir.path(), None),
                    &result,
                    FlowStats::default(),
                    7,
                )
                .await
                .unwrap(),
        );
        assert_eq!(value["certificate_der"], "AAAA");
        assert_eq!(value["chain_der"], serde_json::json!(["BBBB", "CCCC"]));
        assert_eq!(
            value["refresh_outcome"],
            serde_json::json!({ "result": "succeeded", "status": "deployed" })
        );
        assert_eq!(value["event_time"], 7);
    }

    #[tokio::test]
    async fn failure_reads_full_chain_file_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("cert.pem"), format!("{LEAF}{CHAIN}")).unwrap();
        let error = Err(RefreshError::CommandFailed {
            certificate_arn: "arn".to_string(),
            files_changed: true,
            source: std::io::Error::other("exit status 1"),
        });

        let value = wire(
            &telemetry()
                .build(
                    &identity(),
                    &config(dir.path(), None),
                    &error,
                    FlowStats::default(),
                    0,
                )
                .await
                .unwrap(),
        );
        assert_eq!(value["certificate_der"], "AAAA");
        assert_eq!(value["chain_der"], serde_json::json!(["BBBB", "CCCC"]));
        assert_eq!(
            value["refresh_outcome"],
            serde_json::json!({
                "result": "failed",
                "stage": "reload",
                "code": "CommandFailed",
                "files_on_disk": "replaced"
            })
        );
    }

    #[tokio::test]
    async fn failure_reads_separate_chain_file_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("cert.pem"), LEAF).unwrap();
        std::fs::write(dir.path().join("chain.pem"), CHAIN).unwrap();
        let error = Err(io_write_error(ErrorKind::PermissionDenied));

        let config = config(dir.path(), Some(dir.path().join("chain.pem")));
        let value = wire(
            &telemetry()
                .build(&identity(), &config, &error, FlowStats::default(), 0)
                .await
                .unwrap(),
        );
        assert_eq!(value["certificate_der"], "AAAA");
        assert_eq!(value["chain_der"], serde_json::json!(["BBBB", "CCCC"]));
        assert_eq!(value["refresh_outcome"]["code"], "EACCES");
        assert_eq!(value["refresh_outcome"]["files_on_disk"], "not_replaced");
    }

    #[tokio::test]
    async fn first_issuance_failure_has_no_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let error = Err(RefreshError::ExportFailed {
            certificate_arn: "arn".to_string(),
            source: AcmManagerError::InternalFailure("missing certificate field".into()),
        });

        let value = wire(
            &telemetry()
                .build(
                    &identity(),
                    &config(dir.path(), None),
                    &error,
                    FlowStats::default(),
                    0,
                )
                .await
                .unwrap(),
        );
        assert!(value.get("certificate_der").is_none());
        assert!(value.get("chain_der").is_none());
        assert_eq!(
            value["refresh_outcome"],
            serde_json::json!({
                "result": "failed",
                "stage": "export",
                "code": "AgentInternal",
                "files_on_disk": "not_replaced"
            })
        );
    }

    #[tokio::test]
    async fn chain_without_leaf_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("chain.pem"), CHAIN).unwrap();
        let config = config(dir.path(), Some(dir.path().join("chain.pem")));

        assert_eq!(certificate_on_disk(&config).await, (None, None));
    }

    #[test]
    fn refreshed_debug_omits_certificates() {
        let refreshed = Refreshed {
            status: SuccessStatus::Deployed,
            certificate_pem: LEAF.to_string(),
            chain_pem: CHAIN.to_string(),
        };
        assert!(!format!("{refreshed:?}").contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn write_codes_map_error_kinds_to_errno_names() {
        for (kind, code) in [
            (ErrorKind::PermissionDenied, FailureCode::Eacces),
            (ErrorKind::StorageFull, FailureCode::Enospc),
            (ErrorKind::QuotaExceeded, FailureCode::Edquot),
            (ErrorKind::ReadOnlyFilesystem, FailureCode::Erofs),
            (ErrorKind::NotFound, FailureCode::Enoent),
            (ErrorKind::InvalidInput, FailureCode::Einval),
            (ErrorKind::Interrupted, FailureCode::Other),
        ] {
            assert_eq!(failure(&io_write_error(kind)).code, code);
        }
        let update_failed = RefreshError::WriteFailed {
            certificate_arn: "arn".to_string(),
            source: StoreError::UpdateFailed("partial rename".into()).into(),
        };
        assert_eq!(failure(&update_failed).code, FailureCode::Other);
    }

    #[test]
    fn command_failure_reports_whether_this_attempt_replaced_the_files() {
        for (files_changed, files_on_disk) in [
            (true, FilesOnDisk::Replaced),
            (false, FilesOnDisk::NotReplaced),
        ] {
            let error = RefreshError::CommandFailed {
                certificate_arn: "arn".to_string(),
                files_changed,
                source: std::io::Error::other("exit status 1"),
            };
            assert_eq!(failure(&error).files_on_disk, files_on_disk);
        }
    }

    #[test]
    fn command_timeout_is_a_reload_timeout_like_the_watchers() {
        let mapped = failure(&RefreshError::CommandFailed {
            certificate_arn: "arn".to_string(),
            files_changed: true,
            source: std::io::Error::new(ErrorKind::TimedOut, "timed out"),
        });
        assert_eq!(mapped.stage, RenewalStage::Reload);
        assert_eq!(mapped.code, FailureCode::TimeoutError);
        assert_eq!(mapped.files_on_disk, FilesOnDisk::Replaced);
    }

    #[test]
    fn watcher_failures_use_closed_reload_telemetry_mappings() {
        for outcome in [
            WatcherFailureOutcome::Failure,
            WatcherFailureOutcome::NotFound,
            WatcherFailureOutcome::Superseded,
        ] {
            for (files_changed, files_on_disk) in [
                (true, FilesOnDisk::Replaced),
                (false, FilesOnDisk::NotReplaced),
            ] {
                let mapped = failure(&RefreshError::WatcherFailed {
                    certificate_arn: "arn".to_string(),
                    files_changed,
                    outcome,
                });
                assert_eq!(mapped.stage, RenewalStage::Reload);
                assert_eq!(mapped.code, FailureCode::CommandFailed);
                assert_eq!(mapped.files_on_disk, files_on_disk);
            }
        }
    }

    #[test]
    fn watcher_timeouts_use_reload_timeout_telemetry_mappings() {
        for (files_changed, files_on_disk) in [
            (true, FilesOnDisk::Replaced),
            (false, FilesOnDisk::NotReplaced),
        ] {
            for error in [
                RefreshError::WatcherTimeout {
                    certificate_arn: "arn".to_string(),
                    files_changed,
                },
                RefreshError::WatcherNoStatus {
                    certificate_arn: "arn".to_string(),
                    files_changed,
                },
            ] {
                let mapped = failure(&error);
                assert_eq!(mapped.stage, RenewalStage::Reload);
                assert_eq!(mapped.code, FailureCode::TimeoutError);
                assert_eq!(mapped.files_on_disk, files_on_disk);
            }
        }
    }

    #[test]
    fn request_failure_reports_whether_this_attempt_replaced_the_files() {
        for (files_changed, files_on_disk) in [
            (true, FilesOnDisk::Replaced),
            (false, FilesOnDisk::NotReplaced),
        ] {
            let error = RefreshError::RequestFailed {
                certificate_arn: "arn".to_string(),
                watcher_id: "watcher".to_string(),
                files_changed,
                source: std::io::Error::other("request failed"),
            };
            assert_eq!(failure(&error).files_on_disk, files_on_disk);
        }
    }

    #[test]
    fn export_failure_replaced_no_files() {
        let error = RefreshError::ExportFailed {
            certificate_arn: "arn".to_string(),
            source: AcmManagerError::InternalFailure("missing certificate field".into()),
        };
        assert_eq!(failure(&error).files_on_disk, FilesOnDisk::NotReplaced);
    }

    #[test]
    fn partial_write_reports_partly_replaced_files() {
        let partial = RefreshError::WriteFailed {
            certificate_arn: "arn".to_string(),
            source: StoreError::PartialUpdate(Box::new(StoreError::Io(std::io::Error::from(
                ErrorKind::StorageFull,
            ))))
            .into(),
        };
        let failure = failure(&partial);
        assert_eq!(failure.code, FailureCode::Enospc);
        assert_eq!(failure.files_on_disk, FilesOnDisk::PartlyReplaced);
        assert_eq!(
            super::failure(&io_write_error(ErrorKind::StorageFull)).files_on_disk,
            FilesOnDisk::NotReplaced
        );
    }

    fn unchanged() -> Result<Refreshed, RefreshError> {
        Ok(Refreshed {
            status: SuccessStatus::Unchanged,
            certificate_pem: LEAF.to_string(),
            chain_pem: CHAIN.to_string(),
        })
    }

    #[tokio::test]
    async fn report_queues_one_record_per_flow() {
        capture_logs();
        let log_count = logged_on_this_thread().len();
        let dir = tempfile::tempdir().unwrap();
        let sink = Arc::new(RecordingSink::default());
        let telemetry = telemetry_with(sink.clone());
        let config = config(dir.path(), None);

        telemetry
            .report(&config, &unchanged(), FlowStats::default())
            .await;
        telemetry
            .clone()
            .report(&config, &unchanged(), FlowStats::default())
            .await;

        let records = sink.records();
        assert_eq!(records.len(), 2);
        // Clones share one sequence, so the two records have different keys.
        assert_ne!(records[0]["idempotency_key"], records[1]["idempotency_key"]);
        let expected = format!(
            "Automation: produced 1 telemetry record for certificate refresh of {} and offered it for local queueing",
            config.certificate_arn
        );
        let logs = logged_on_this_thread();
        assert_eq!(
            logs[log_count..]
                .iter()
                .filter(|message| *message == &expected)
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn record_carries_flow_stats_and_configured_certificates() {
        let dir = tempfile::tempdir().unwrap();
        let config = config(dir.path(), None);
        let stats = FlowStats {
            duration: Duration::from_millis(1_500),
            consecutive_failures: 3,
            cycle: 4,
        };
        // First as given, second sorted, so an index in config order fails.
        let arns = [
            config.certificate_arn.clone(),
            "arn:aws:acm:us-west-2:111122223333:certificate/zzz".to_string(),
            "arn:aws:acm:us-west-2:111122223333:certificate/aaa".to_string(),
        ];

        let telemetry = telemetry().with_configured_certificates(&arns);
        let value = wire(
            &telemetry
                .build(&identity(), &config, &unchanged(), stats, 1)
                .await
                .unwrap(),
        );
        assert_eq!(value["refresh_duration_ms"], 1_500);
        assert_eq!(value["consecutive_failures"], 3);
        assert_eq!(value["total_configured_certs"], 3);
        assert_eq!(value["cert_index"], 1);
        let run_id = telemetry.run_id.as_deref().unwrap();
        assert_eq!(value["refresh_cycle_id"], format!("{run_id}-4"));
    }

    #[test]
    fn each_start_has_its_own_run_id() {
        let first = telemetry();
        let run_id = first.run_id.clone().unwrap();
        assert_eq!(run_id.len(), 32);
        assert!(run_id.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(first.clone().run_id, Some(run_id.clone()));
        assert_ne!(telemetry().run_id, Some(run_id));
    }

    #[tokio::test]
    async fn no_index_or_count_without_the_configured_certificates() {
        let dir = tempfile::tempdir().unwrap();
        let value = wire(
            &telemetry()
                .build(
                    &identity(),
                    &config(dir.path(), None),
                    &unchanged(),
                    FlowStats::default(),
                    1,
                )
                .await
                .unwrap(),
        );
        assert!(value.get("cert_index").is_none());
        assert!(value.get("total_configured_certs").is_none());
        assert!(value["refresh_cycle_id"].as_str().unwrap().ends_with("-0"));
    }

    #[tokio::test(start_paused = true)]
    async fn failed_detection_is_retried_after_the_interval() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        let shared = SharedIdentity::with_detector(|| {
            Box::pin(async {
                if CALLS.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err(IdentityError::NoIdentityFound)
                } else {
                    Ok(identity())
                }
            })
        });

        assert!(shared.get().await.is_err());
        // Within the interval the failure is reused without detecting again.
        assert!(shared.clone().get().await.is_err());
        assert_eq!(CALLS.load(Ordering::SeqCst), 1);

        tokio::time::advance(DETECTION_RETRY_INTERVAL).await;
        assert_eq!(shared.get().await.unwrap().host_id, "i-0abc");
        assert!(shared.get().await.is_ok());
        assert_eq!(CALLS.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn no_identity_queues_nothing() {
        capture_logs();
        let log_count = logged_on_this_thread().len();
        let dir = tempfile::tempdir().unwrap();
        let sink = Arc::new(RecordingSink::default());
        let telemetry = AutomationTelemetry::new(SharedIdentity::failing(), sink.clone());

        telemetry
            .report(
                &config(dir.path(), None),
                &unchanged(),
                FlowStats::default(),
            )
            .await;
        telemetry
            .report(
                &config(dir.path(), None),
                &unchanged(),
                FlowStats::default(),
            )
            .await;

        assert!(sink.records().is_empty());
        let logs = logged_on_this_thread();
        assert!(logs[log_count..]
            .iter()
            .all(|message| !message.starts_with("Automation: produced")));
    }
}
