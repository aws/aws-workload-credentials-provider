//! Telemetry record for one certificate automation flow.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use aws_workload_credentials_provider_common::telemetry::{
    AgentIdentity, AutomationFailure, AutomationRecord, AutomationResult, AutomationStage,
    AutomationSuccess, Blob, Capability, Entry, EnvelopeError, FilesOnDisk as RequestFilesOnDisk,
    PayloadEnvelope, PayloadType, RequestPart, TelemetryRecord,
};
use serde::{Deserialize, Serialize};

const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Refresh step a failure occurred in. `Verify` is reserved and not emitted yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RenewalStage {
    Export,
    Write,
    Reload,
    Verify,
}

/// Error code of a failed step. Closed so error text never reaches the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailureCode {
    // ExportCertificate errors.
    InvalidArnException,
    RequestInProgressException,
    ResourceNotFoundException,
    ThrottlingException,
    ValidationException,
    // ACM common errors.
    AccessDeniedException,
    ExpiredTokenException,
    IncompleteSignature,
    InternalFailure,
    MalformedHttpRequestException,
    NotAuthorized,
    OptInRequired,
    RequestAbortedException,
    RequestEntityTooLargeException,
    RequestTimeoutException,
    ServiceUnavailable,
    UnknownOperationException,
    UnrecognizedClientException,
    ValidationError,
    // SDK failures without a service code. TimeoutError also covers a reload
    // command that ran out its time.
    TimeoutError,
    ConnectionError,
    DispatchFailure,
    // The agent failed before or after the ACM call.
    AgentInternal,
    // Certificate file write errors.
    #[serde(rename = "EACCES")]
    Eacces,
    #[serde(rename = "ENOSPC")]
    Enospc,
    #[serde(rename = "EDQUOT")]
    Edquot,
    #[serde(rename = "EROFS")]
    Erofs,
    #[serde(rename = "ENOENT")]
    Enoent,
    #[serde(rename = "EINVAL")]
    Einval,
    // The refresh command failed.
    CommandFailed,
    Other,
}

impl FailureCode {
    /// Maps an ACM error code or SDK transport token. Unrecognized codes become `Other`.
    pub fn from_sdk_code(code: &str) -> Self {
        match code {
            "InvalidArnException" => Self::InvalidArnException,
            "RequestInProgressException" => Self::RequestInProgressException,
            "ResourceNotFoundException" => Self::ResourceNotFoundException,
            "ThrottlingException" => Self::ThrottlingException,
            "ValidationException" => Self::ValidationException,
            "AccessDeniedException" => Self::AccessDeniedException,
            "ExpiredTokenException" => Self::ExpiredTokenException,
            "IncompleteSignature" => Self::IncompleteSignature,
            "InternalFailure" => Self::InternalFailure,
            "MalformedHttpRequestException" => Self::MalformedHttpRequestException,
            "NotAuthorized" => Self::NotAuthorized,
            "OptInRequired" => Self::OptInRequired,
            "RequestAbortedException" => Self::RequestAbortedException,
            "RequestEntityTooLargeException" => Self::RequestEntityTooLargeException,
            "RequestTimeoutException" => Self::RequestTimeoutException,
            "ServiceUnavailable" => Self::ServiceUnavailable,
            "UnknownOperationException" => Self::UnknownOperationException,
            "UnrecognizedClientException" => Self::UnrecognizedClientException,
            "ValidationError" => Self::ValidationError,
            "TimeoutError" => Self::TimeoutError,
            "ConnectionError" => Self::ConnectionError,
            "DispatchFailure" => Self::DispatchFailure,
            _ => Self::Other,
        }
    }
}

/// Why a refresh flow failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewalFailure {
    /// Step that failed.
    pub stage: RenewalStage,
    /// Error code of the failed step.
    pub code: FailureCode,
    /// Whether this attempt replaced the certificate files before it failed.
    pub files_on_disk: FilesOnDisk,
}

/// Whether a failed attempt replaced the certificate files on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesOnDisk {
    NotReplaced,
    /// Some files were replaced, then a later write failed.
    PartlyReplaced,
    Replaced,
}

/// What a successful refresh flow changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuccessStatus {
    /// New files written and the refresh command ran.
    Deployed,
    /// Files unchanged, refresh command ran (first cycle or retry).
    Reloaded,
    /// Files unchanged, no refresh command ran.
    Unchanged,
    /// New files written, no refresh command configured.
    WrittenNotReloaded,
}

/// How a refresh flow ended, sent as `refresh_outcome` and tagged by `result`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum RefreshOutcome {
    Succeeded { status: SuccessStatus },
    Failed(RenewalFailure),
}

/// Process-wide `batch_sequence` counter shared by all certificate tasks, so
/// records never share an idempotency key. Clones share the same counter.
#[derive(Debug, Clone, Default)]
pub struct AutomationSequence(Arc<AtomicU64>);

impl AutomationSequence {
    /// `fetch_add` hands out each value once across threads, so `Relaxed` is enough.
    fn next(&self) -> u64 {
        self.0.fetch_add(1, Ordering::Relaxed)
    }
}

/// Telemetry record for one certificate automation flow. Serialize-only and
/// built through [`CertAutomationRecord::new`], so the routing identity is fixed.
#[derive(Debug, Serialize)]
pub struct CertAutomationRecord {
    #[serde(flatten)]
    envelope: PayloadEnvelope,
    /// ACM certificate the flow acted on.
    certificate_arn: String,
    /// DER of the leaf certificate on disk after the flow.
    #[serde(skip_serializing_if = "Option::is_none")]
    certificate_der: Option<Blob>,
    /// DER of the chain on disk after the flow, excluding the leaf.
    #[serde(skip_serializing_if = "Option::is_none")]
    chain_der: Option<Vec<Blob>>,
    /// How the flow ended.
    refresh_outcome: RefreshOutcome,
    /// When the flow ended, epoch milliseconds.
    event_time: u64,
    /// Wall-clock duration of the refresh flow in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_duration_ms: Option<u64>,
    /// Number of consecutive failures for this certificate before this attempt.
    #[serde(skip_serializing_if = "Option::is_none")]
    consecutive_failures: Option<u32>,
    /// Total certificates in the ACM automation configuration on this host.
    #[serde(skip_serializing_if = "Option::is_none")]
    total_configured_certs: Option<u32>,
    /// The agent run's ID and this certificate's refreshes before this one.
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_cycle_id: Option<String>,
    /// This certificate's position (0-based) among the configured ARNs, sorted.
    #[serde(skip_serializing_if = "Option::is_none")]
    cert_index: Option<u32>,
}

impl CertAutomationRecord {
    /// The fixed routing identity of an automation record.
    pub const CAPABILITY: Capability = Capability::Acm;
    pub const PAYLOAD_TYPE: PayloadType = PayloadType::CertAutomation;

    /// One flow is one record, so it is never split.
    const BATCH_INDEX: u32 = 0;

    /// Builds a record, taking the next sequence number from `sequence`.
    pub fn new(
        sequence: &AutomationSequence,
        identity: &AgentIdentity,
        certificate_arn: impl Into<String>,
        certificate_der: Option<Blob>,
        chain_der: Option<Vec<Blob>>,
        outcome: RefreshOutcome,
        event_time: u64,
    ) -> Result<Self, EnvelopeError> {
        Self::with_cycle_context(
            sequence,
            identity,
            certificate_arn,
            certificate_der,
            chain_der,
            outcome,
            event_time,
            None,
            None,
            None,
            None,
            None,
        )
    }

    /// Builds a record with refresh-cycle context for backend correlation.
    #[allow(clippy::too_many_arguments)]
    pub fn with_cycle_context(
        sequence: &AutomationSequence,
        identity: &AgentIdentity,
        certificate_arn: impl Into<String>,
        certificate_der: Option<Blob>,
        chain_der: Option<Vec<Blob>>,
        outcome: RefreshOutcome,
        event_time: u64,
        refresh_duration_ms: Option<u64>,
        consecutive_failures: Option<u32>,
        total_configured_certs: Option<u32>,
        refresh_cycle_id: Option<String>,
        cert_index: Option<u32>,
    ) -> Result<Self, EnvelopeError> {
        let envelope = PayloadEnvelope::new(
            Self::CAPABILITY,
            Self::PAYLOAD_TYPE,
            sequence.next(),
            Self::BATCH_INDEX,
            identity.host_id.clone(),
            identity.boot_nonce.clone(),
            AGENT_VERSION,
            identity.region.clone(),
            identity.deployment_type,
        )?;
        Ok(Self {
            envelope,
            certificate_arn: certificate_arn.into(),
            certificate_der,
            chain_der,
            refresh_outcome: outcome,
            event_time,
            refresh_duration_ms,
            consecutive_failures,
            total_configured_certs,
            refresh_cycle_id,
            cert_index,
        })
    }
}

impl TelemetryRecord for CertAutomationRecord {
    fn payload_type(&self) -> PayloadType {
        Self::PAYLOAD_TYPE
    }

    fn capability(&self) -> Capability {
        Self::CAPABILITY
    }

    fn serialize(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// The flow as one record of the request's `automation` member.
    fn request_part(&self) -> Option<RequestPart> {
        let record = AutomationRecord {
            certificate_arn: self.certificate_arn.clone(),
            event_time: self.event_time,
            result: (&self.refresh_outcome).into(),
            certificate_der: self.certificate_der.clone(),
            chain_der: self.chain_der.clone(),
            refresh_duration_milliseconds: self.refresh_duration_ms,
            consecutive_failures: self.consecutive_failures,
            configured_certificate_count: self.total_configured_certs,
            refresh_cycle_id: self.refresh_cycle_id.clone(),
            cert_index: self.cert_index,
        };
        Some(RequestPart::new(&self.envelope, Entry::Automation(record)))
    }

    fn idempotency_key(&self) -> &str {
        &self.envelope.idempotency_key
    }
}

impl From<RenewalStage> for AutomationStage {
    fn from(stage: RenewalStage) -> Self {
        match stage {
            RenewalStage::Export => Self::Export,
            RenewalStage::Write => Self::Write,
            RenewalStage::Reload => Self::Reload,
            RenewalStage::Verify => Self::Verify,
        }
    }
}

impl From<FilesOnDisk> for RequestFilesOnDisk {
    fn from(files: FilesOnDisk) -> Self {
        match files {
            FilesOnDisk::NotReplaced => Self::NotReplaced,
            FilesOnDisk::PartlyReplaced => Self::PartlyReplaced,
            FilesOnDisk::Replaced => Self::Replaced,
        }
    }
}

impl From<SuccessStatus> for AutomationSuccess {
    fn from(status: SuccessStatus) -> Self {
        match status {
            SuccessStatus::Deployed => Self::Deployed,
            SuccessStatus::Reloaded => Self::Reloaded,
            SuccessStatus::Unchanged => Self::Unchanged,
            SuccessStatus::WrittenNotReloaded => Self::WrittenNotReloaded,
        }
    }
}

impl FailureCode {
    /// The code's wire name, such as `CommandFailed` or `EACCES`: its JSON
    /// string without the quotes.
    fn wire_name(self) -> String {
        serde_json::to_string(&self)
            .expect("a unit variant serializes as a JSON string")
            .trim_matches('"')
            .to_string()
    }
}

impl From<&RefreshOutcome> for AutomationResult {
    fn from(outcome: &RefreshOutcome) -> Self {
        match outcome {
            RefreshOutcome::Succeeded { status } => Self::Success((*status).into()),
            RefreshOutcome::Failed(failure) => Self::Failure(AutomationFailure {
                stage: failure.stage.into(),
                code: failure.code.wire_name(),
                files_on_disk: Some(failure.files_on_disk.into()),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_workload_credentials_provider_common::telemetry::{DeploymentType, SCHEMA_VERSION};
    use base64ct::{Base64, Encoding};
    use std::collections::HashSet;

    const TEST_ARN: &str = "arn:aws:acm:us-west-2:111122223333:certificate/abc-123";
    const TEST_EVENT_TIME: u64 = 1_750_000_018_640;

    fn identity(host_id: &str, boot_nonce: &str) -> AgentIdentity {
        AgentIdentity {
            host_id: host_id.to_string(),
            deployment_type: DeploymentType::Ec2,
            region: "us-west-2".to_string(),
            boot_nonce: boot_nonce.to_string(),
            ecs_network_mode: None,
        }
    }

    fn der(base64: &str) -> Blob {
        Blob(Base64::decode_vec(base64).expect("valid base64"))
    }

    fn sample_record(
        sequence: &AutomationSequence,
        certificate_der: Option<Blob>,
        chain_der: Option<Vec<Blob>>,
        outcome: RefreshOutcome,
    ) -> CertAutomationRecord {
        CertAutomationRecord::new(
            sequence,
            &identity("i-0abc", "boot-11112222"),
            TEST_ARN,
            certificate_der,
            chain_der,
            outcome,
            TEST_EVENT_TIME,
        )
        .expect("valid telemetry envelope")
    }

    fn unchanged() -> RefreshOutcome {
        RefreshOutcome::Succeeded {
            status: SuccessStatus::Unchanged,
        }
    }

    /// Serializes through the trait, as the emitter does, and parses the JSON.
    fn wire_value(record: &CertAutomationRecord) -> serde_json::Value {
        serde_json::from_slice(&TelemetryRecord::serialize(record).expect("serialize"))
            .expect("parse")
    }

    #[test]
    fn test_renewal_stage_serialization() {
        for (stage, wire) in [
            (RenewalStage::Export, "\"export\""),
            (RenewalStage::Write, "\"write\""),
            (RenewalStage::Reload, "\"reload\""),
            (RenewalStage::Verify, "\"verify\""),
        ] {
            assert_eq!(serde_json::to_string(&stage).unwrap(), wire);
        }
    }

    #[test]
    fn test_success_status_serialization() {
        for (status, wire) in [
            (SuccessStatus::Deployed, "\"deployed\""),
            (SuccessStatus::Reloaded, "\"reloaded\""),
            (SuccessStatus::Unchanged, "\"unchanged\""),
            (
                SuccessStatus::WrittenNotReloaded,
                "\"written_not_reloaded\"",
            ),
        ] {
            assert_eq!(serde_json::to_string(&status).unwrap(), wire);
        }
    }

    #[test]
    fn test_failure_code_serialization() {
        for (code, wire) in [
            (
                FailureCode::AccessDeniedException,
                "\"AccessDeniedException\"",
            ),
            (FailureCode::TimeoutError, "\"TimeoutError\""),
            (FailureCode::AgentInternal, "\"AgentInternal\""),
            (FailureCode::Eacces, "\"EACCES\""),
            (FailureCode::Enospc, "\"ENOSPC\""),
            (FailureCode::Edquot, "\"EDQUOT\""),
            (FailureCode::Erofs, "\"EROFS\""),
            (FailureCode::Enoent, "\"ENOENT\""),
            (FailureCode::Einval, "\"EINVAL\""),
            (FailureCode::CommandFailed, "\"CommandFailed\""),
            (FailureCode::Other, "\"Other\""),
        ] {
            assert_eq!(serde_json::to_string(&code).unwrap(), wire);
        }
    }

    #[test]
    fn test_sdk_codes_map_to_failure_code() {
        for code in [
            "InvalidArnException",
            "RequestInProgressException",
            "ResourceNotFoundException",
            "ThrottlingException",
            "ValidationException",
            "AccessDeniedException",
            "ExpiredTokenException",
            "IncompleteSignature",
            "InternalFailure",
            "MalformedHttpRequestException",
            "NotAuthorized",
            "OptInRequired",
            "RequestAbortedException",
            "RequestEntityTooLargeException",
            "RequestTimeoutException",
            "ServiceUnavailable",
            "UnknownOperationException",
            "UnrecognizedClientException",
            "ValidationError",
            "TimeoutError",
            "ConnectionError",
            "DispatchFailure",
        ] {
            let mapped = FailureCode::from_sdk_code(code);
            assert_eq!(serde_json::to_value(mapped).unwrap(), code);
        }
    }

    #[test]
    fn test_unrecognized_sdk_code_becomes_other() {
        for code in [
            "SomeFutureException",
            "Unknown",
            "",
            "denied for arn:aws:iam::111122223333:role/x",
        ] {
            assert_eq!(FailureCode::from_sdk_code(code), FailureCode::Other);
        }
    }

    #[test]
    fn test_unknown_failure_code_does_not_decode() {
        assert!(serde_json::from_str::<FailureCode>("\"SomeFutureException\"").is_err());
    }

    #[test]
    fn test_success_record_wire() {
        let record = sample_record(
            &AutomationSequence::default(),
            Some(der("MIIE")),
            Some(vec![der("MIID")]),
            RefreshOutcome::Succeeded {
                status: SuccessStatus::Deployed,
            },
        );

        let value = wire_value(&record);
        assert_eq!(
            value["refresh_outcome"],
            serde_json::json!({ "result": "succeeded", "status": "deployed" })
        );
        assert_eq!(value["payload_type"], "cert_automation");
        assert_eq!(value["certificate_arn"], TEST_ARN);
        assert_eq!(value["certificate_der"], "MIIE");
        assert_eq!(value["chain_der"], serde_json::json!(["MIID"]));
        assert_eq!(value["event_time"], TEST_EVENT_TIME);
        assert_eq!(value["agent_version"], AGENT_VERSION);

        let json = serde_json::to_string(&record).expect("serialize");
        for camel in [
            "certificateArn",
            "certificateDer",
            "chainDer",
            "refreshOutcome",
            "payloadType",
        ] {
            assert!(!json.contains(camel), "camelCase leak: {camel}");
        }
    }

    #[test]
    fn test_failure_record_wire() {
        let record = sample_record(
            &AutomationSequence::default(),
            Some(der("MIIE")),
            None,
            RefreshOutcome::Failed(RenewalFailure {
                stage: RenewalStage::Write,
                code: FailureCode::Eacces,
                files_on_disk: FilesOnDisk::PartlyReplaced,
            }),
        );

        let value = wire_value(&record);
        assert_eq!(
            value["refresh_outcome"],
            serde_json::json!({
                "result": "failed",
                "stage": "write",
                "code": "EACCES",
                "files_on_disk": "partly_replaced"
            })
        );
        assert!(value.get("chain_der").is_none());
    }

    #[test]
    fn test_trait_contract_and_fixed_identity() {
        let record = sample_record(
            &AutomationSequence::default(),
            None,
            None,
            RefreshOutcome::Failed(RenewalFailure {
                stage: RenewalStage::Export,
                code: FailureCode::ThrottlingException,
                files_on_disk: FilesOnDisk::NotReplaced,
            }),
        );

        assert_eq!(record.payload_type(), PayloadType::CertAutomation);
        assert_eq!(record.capability(), Capability::Acm);
        assert_eq!(
            record.idempotency_key(),
            "i-0abc:boot-11112222:acm:cert_automation:0:0"
        );

        // Envelope fields are flattened, failure detail stays under refresh_outcome.
        let value = wire_value(&record);
        assert_eq!(value["schema_version"], SCHEMA_VERSION);
        assert_eq!(value["capability"], "acm");
        assert_eq!(value["host_id"], "i-0abc");
        assert_eq!(value["deployment_type"], "ec2");
        assert!(value.get("stage").is_none());
        assert!(value.get("code").is_none());
        assert_eq!(value["refresh_outcome"]["stage"], "export");
        assert_eq!(value["refresh_outcome"]["code"], "ThrottlingException");
        assert_eq!(value["refresh_outcome"]["files_on_disk"], "not_replaced");
        assert!(value.get("certificate_der").is_none());
    }

    #[test]
    fn test_success_record_wire_shape() {
        let record = sample_record(
            &AutomationSequence::default(),
            Some(der("AAAA")),
            Some(vec![der("BBBB"), der("CCCC")]),
            RefreshOutcome::Succeeded {
                status: SuccessStatus::WrittenNotReloaded,
            },
        );

        let value = wire_value(&record);
        assert_eq!(value["chain_der"], serde_json::json!(["BBBB", "CCCC"]));
        assert_eq!(value["refresh_outcome"]["status"], "written_not_reloaded");
        assert_eq!(value["batch_sequence"], 0);
        assert_eq!(value["batch_index"], 0);
        assert!(value.get("success_status").is_none());
        assert!(value.get("renewal_failure").is_none());
    }

    #[test]
    fn test_refresh_outcome_wire_per_status() {
        let sequence = AutomationSequence::default();
        for (status, wire) in [
            (SuccessStatus::Deployed, "deployed"),
            (SuccessStatus::Reloaded, "reloaded"),
            (SuccessStatus::Unchanged, "unchanged"),
            (SuccessStatus::WrittenNotReloaded, "written_not_reloaded"),
        ] {
            let outcome = RefreshOutcome::Succeeded { status };
            let value = wire_value(&sample_record(&sequence, None, None, outcome.clone()));
            assert_eq!(
                value["refresh_outcome"],
                serde_json::json!({ "result": "succeeded", "status": wire })
            );
            let decoded: RefreshOutcome =
                serde_json::from_value(value["refresh_outcome"].clone()).expect("decode outcome");
            assert_eq!(decoded, outcome);
        }
    }

    #[test]
    fn test_failure_outcome_decodes_from_wire() {
        let outcome = RefreshOutcome::Failed(RenewalFailure {
            stage: RenewalStage::Reload,
            code: FailureCode::CommandFailed,
            files_on_disk: FilesOnDisk::Replaced,
        });
        let record = sample_record(
            &AutomationSequence::default(),
            Some(der("MIIE")),
            None,
            outcome.clone(),
        );

        let value = wire_value(&record);
        assert_eq!(value["refresh_outcome"]["result"], "failed");
        assert_eq!(value["refresh_outcome"]["files_on_disk"], "replaced");
        let decoded: RefreshOutcome =
            serde_json::from_value(value["refresh_outcome"].clone()).expect("decode outcome");
        assert_eq!(decoded, outcome);
    }

    /// Validates the request part of a successful flow with cycle context:
    /// one automation record with the flow's certificates as DER.
    #[test]
    fn request_part_carries_the_flow() {
        let record = CertAutomationRecord::with_cycle_context(
            &AutomationSequence::default(),
            &identity("i-0abc", "boot-11112222"),
            TEST_ARN,
            Some(der("AAEC")),
            Some(vec![der("/w==")]),
            RefreshOutcome::Succeeded {
                status: SuccessStatus::Deployed,
            },
            TEST_EVENT_TIME,
            Some(842),
            Some(0),
            Some(10),
            Some("cycle-1".to_string()),
            Some(3),
        )
        .expect("valid telemetry envelope");

        let expected = RequestPart::new(
            &record.envelope,
            Entry::Automation(AutomationRecord {
                certificate_arn: TEST_ARN.to_string(),
                event_time: TEST_EVENT_TIME,
                result: AutomationResult::Success(AutomationSuccess::Deployed),
                certificate_der: Some(Blob(vec![0x00, 0x01, 0x02])),
                chain_der: Some(vec![Blob(vec![0xff])]),
                refresh_duration_milliseconds: Some(842),
                consecutive_failures: Some(0),
                configured_certificate_count: Some(10),
                refresh_cycle_id: Some("cycle-1".to_string()),
                cert_index: Some(3),
            }),
        );
        assert_eq!(record.request_part(), Some(expected));
    }

    /// The request's result for `outcome`.
    fn request_result(outcome: RefreshOutcome) -> AutomationResult {
        let record = sample_record(&AutomationSequence::default(), None, None, outcome);
        let expected_part = |result| {
            RequestPart::new(
                &record.envelope,
                Entry::Automation(AutomationRecord {
                    certificate_arn: TEST_ARN.to_string(),
                    event_time: TEST_EVENT_TIME,
                    result,
                    certificate_der: None,
                    chain_der: None,
                    refresh_duration_milliseconds: None,
                    consecutive_failures: None,
                    configured_certificate_count: None,
                    refresh_cycle_id: None,
                    cert_index: None,
                }),
            )
        };
        let result = AutomationResult::from(&record.refresh_outcome);
        // The rest of the record carries nothing for a flow without context.
        assert_eq!(record.request_part(), Some(expected_part(result.clone())));
        result
    }

    /// Validates the result for every success status.
    #[test]
    fn success_status_maps_to_the_request_result() {
        for (status, expected) in [
            (SuccessStatus::Deployed, AutomationSuccess::Deployed),
            (SuccessStatus::Reloaded, AutomationSuccess::Reloaded),
            (SuccessStatus::Unchanged, AutomationSuccess::Unchanged),
            (
                SuccessStatus::WrittenNotReloaded,
                AutomationSuccess::WrittenNotReloaded,
            ),
        ] {
            assert_eq!(
                request_result(RefreshOutcome::Succeeded { status }),
                AutomationResult::Success(expected),
                "{status:?}"
            );
        }
    }

    /// Validates the failure result for every stage: the stage, the code's
    /// wire name, and the files on disk.
    #[test]
    fn failure_maps_to_the_request_result() {
        for (stage, code, files, expected_stage, expected_code, expected_files) in [
            (
                RenewalStage::Export,
                FailureCode::ThrottlingException,
                FilesOnDisk::NotReplaced,
                AutomationStage::Export,
                "ThrottlingException",
                RequestFilesOnDisk::NotReplaced,
            ),
            (
                RenewalStage::Write,
                FailureCode::Eacces,
                FilesOnDisk::PartlyReplaced,
                AutomationStage::Write,
                "EACCES",
                RequestFilesOnDisk::PartlyReplaced,
            ),
            (
                RenewalStage::Reload,
                FailureCode::CommandFailed,
                FilesOnDisk::Replaced,
                AutomationStage::Reload,
                "CommandFailed",
                RequestFilesOnDisk::Replaced,
            ),
            (
                RenewalStage::Verify,
                FailureCode::Other,
                FilesOnDisk::NotReplaced,
                AutomationStage::Verify,
                "Other",
                RequestFilesOnDisk::NotReplaced,
            ),
        ] {
            let outcome = RefreshOutcome::Failed(RenewalFailure {
                stage,
                code,
                files_on_disk: files,
            });
            assert_eq!(
                request_result(outcome),
                AutomationResult::Failure(AutomationFailure {
                    stage: expected_stage,
                    code: expected_code.to_string(),
                    files_on_disk: Some(expected_files),
                }),
                "{stage:?}"
            );
        }
    }

    #[test]
    fn test_sequence_increments_per_record() {
        let sequence = AutomationSequence::default();
        let first = sample_record(&sequence, None, None, unchanged());
        let second = sample_record(&sequence, None, None, unchanged());

        assert_eq!(
            first.idempotency_key(),
            "i-0abc:boot-11112222:acm:cert_automation:0:0"
        );
        assert_eq!(
            second.idempotency_key(),
            "i-0abc:boot-11112222:acm:cert_automation:1:0"
        );
    }

    #[test]
    fn test_sequence_clone_shares_counter() {
        let sequence = AutomationSequence::default();
        let task_a = sequence.clone();
        let task_b = sequence.clone();

        assert_eq!(task_a.next(), 0);
        assert_eq!(task_b.next(), 1);
        assert_eq!(sequence.next(), 2);
    }

    #[test]
    fn test_concurrent_records_get_unique_keys() {
        const TASKS: u64 = 8;
        const RECORDS_PER_TASK: u64 = 50;
        let sequence = AutomationSequence::default();

        let keys: Vec<String> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..TASKS)
                .map(|_| {
                    let task_sequence = sequence.clone();
                    scope.spawn(move || {
                        (0..RECORDS_PER_TASK)
                            .map(|_| {
                                sample_record(&task_sequence, None, None, unchanged())
                                    .idempotency_key()
                                    .to_string()
                            })
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            handles
                .into_iter()
                .flat_map(|handle| handle.join().expect("task thread"))
                .collect()
        });

        let total = (TASKS * RECORDS_PER_TASK) as usize;
        let unique: HashSet<&String> = keys.iter().collect();
        assert_eq!(keys.len(), total);
        assert_eq!(unique.len(), total, "idempotency keys must not collide");
        assert_eq!(sequence.next(), total as u64);
    }

    fn new_with(identity: &AgentIdentity) -> Result<CertAutomationRecord, EnvelopeError> {
        CertAutomationRecord::new(
            &AutomationSequence::default(),
            identity,
            TEST_ARN,
            None,
            None,
            unchanged(),
            TEST_EVENT_TIME,
        )
    }

    #[test]
    fn test_new_rejects_empty_host_id() {
        assert_eq!(
            new_with(&identity("", "boot-11112222")).unwrap_err(),
            EnvelopeError::EmptyHostId
        );
    }

    #[test]
    fn test_new_rejects_bad_boot_nonce() {
        assert_eq!(
            new_with(&identity("i-0abc", "")).unwrap_err(),
            EnvelopeError::EmptyBootNonce
        );
        assert_eq!(
            new_with(&identity("i-0abc", "boot:11112222")).unwrap_err(),
            EnvelopeError::BootNonceContainsSeparator
        );
    }
}
