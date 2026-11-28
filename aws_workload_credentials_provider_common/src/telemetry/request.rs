//! The `PutCertificateTelemetry` request, as the service's Smithy model
//! defines it: camelCase field names, upper-case enum values, times in epoch
//! milliseconds, and absent optional fields left out. The sender encodes it as
//! CBOR to send and as JSON to log in a dry run.
//!
//! Each record contributes a [`RequestPart`]: its entry (a discovery batch or
//! one automation record), its idempotency key, and the identity for the
//! request's top-level fields. Each model limit is a constant here. The sender
//! checks every part against them before sending, because the service rejects
//! a whole request when one entry breaks a limit.

use serde::Serialize;

use super::payload::{Blob, DeploymentType, PayloadEnvelope, PayloadType};

/// Most entries in one request, per the model: automation records the drain
/// groups, or observations in a discovery batch, which the capability sizes
/// itself.
/// [`MAX_REQUEST_BYTES`](super::payload::MAX_REQUEST_BYTES) usually ends a
/// request first, but only this count caps records without certificates.
pub const MAX_ENTRIES: usize = 100;

/// The model's longest `computeId`, in characters: an EKS pod identity
/// `namespace/pod name/pod UID` reaches 354 (63, 253 and 36, plus two `/`).
const MAX_COMPUTE_ID_CHARS: usize = 512;

/// The model's largest `schemaVersion`.
const MAX_SCHEMA_VERSION: u32 = 999;

/// The model's longest `idempotencyKey`, in characters: the host ID plus 101.
const MAX_IDEMPOTENCY_KEY_CHARS: usize = 1024;

/// The model's longest `scanId`, in characters: `{host_id}:{epoch_secs}`.
const MAX_SCAN_ID_CHARS: usize = 768;

/// The model's largest `batchIndex` and `totalBatches`.
const MAX_BATCH_NUMBER: u32 = 9_999;

/// The model's largest `integer` (32-bit signed), such as a count.
const MAX_INTEGER: u32 = i32::MAX as u32;

/// The model's largest `long` (64-bit signed), such as a time.
const MAX_LONG: u64 = i64::MAX as u64;

/// The model's largest certificate, in DER bytes.
pub const MAX_CERTIFICATE_BYTES: usize = 16_384;

/// The model's longest `chainDer`. [`RequestPart::new`] keeps the first this
/// many certificates of a longer chain.
pub const MAX_CHAIN_CERTIFICATES: usize = 5;

/// The model's longest `sni`, in characters.
const MAX_SNI_CHARS: usize = 253;

/// The model's longest TLS parameter, such as `tlsVersion`, in characters.
const MAX_TLS_PARAMETER_CHARS: usize = 64;

/// The model's longest `certificateArn`, in characters.
const MAX_CERTIFICATE_ARN_CHARS: usize = 256;

/// The model's longest failure `code`, in characters.
const MAX_FAILURE_CODE_CHARS: usize = 64;

/// The model's longest `refreshCycleId`, in characters.
const MAX_REFRESH_CYCLE_ID_CHARS: usize = 256;

/// The request's input.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PutCertificateTelemetryInput {
    pub(crate) telemetry: CertificateTelemetry,
    pub(crate) compute_id: String,
    /// The first part's key. It stays the same across retries and resends, so
    /// the service can dedupe on it: the drain requeues the built request
    /// unchanged, and retries send the same bytes.
    pub(crate) idempotency_key: String,
    pub(crate) compute_type: ComputeType,
    pub(crate) os: Os,
    pub(crate) arch: Arch,
    pub(crate) schema_version: u32,
}

/// Exactly one of discovery or automation.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum CertificateTelemetry {
    Discovery(Discovery),
    Automation(Automation),
}

/// One discovery scan, or part of one.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Discovery {
    /// When the scan started, in epoch milliseconds, at least 1: the same on
    /// every batch of that scan.
    pub scan_time: u64,
    /// The same on every batch of that scan.
    pub scan_id: String,
    /// 0 to [`MAX_ENTRIES`]. Per the model, a scan with nothing to report
    /// sends its counts in one batch with no observations.
    pub observations: Vec<Observation>,
    /// This batch's place in the scan, counted from 1. [`RequestPart::new`]
    /// sets it to the envelope's `batch_index` plus 1, replacing what the
    /// record put here.
    pub batch_index: u32,
    /// How many batches the scan is sent in: the same on every batch.
    pub total_batches: u32,
    /// Whether the scan finished, rather than being cut off by its timeout.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_complete: Option<bool>,
    /// Targets (port and SNI) the scan probed. This count and those below are
    /// the same on every batch of a scan.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_targets_probed: Option<u32>,
    /// Targets that returned a certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub successful_probes: Option<u32>,
    /// Targets that failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed_probes: Option<u32>,
    /// Observations the agent dropped for its size limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dropped_observations: Option<u32>,
    /// Certificates in the host's automation configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configured_certificate_count: Option<u32>,
}

/// The result of probing one port and SNI.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Observation {
    pub port: u16,
    /// Absent when the probe used no SNI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    pub outcome: ProbeOutcome,
    /// Required when `outcome` is `SUCCESS`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_der: Option<Blob>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_der: Option<Vec<Blob>>,
    /// Whether the endpoint asked for a client certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtls_detected: Option<bool>,
    /// The TLS version the probe negotiated, such as `TLSv1.3`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_version: Option<String>,
    /// The cipher suite the probe negotiated, by its IANA name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher_suite: Option<String>,
    /// The signature scheme the server used in the handshake, by its IANA
    /// name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handshake_signature_scheme: Option<String>,
    /// The leaf certificate's public key algorithm.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_algorithm: Option<String>,
}

/// Results of certificate automation.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Automation {
    /// 1 to [`MAX_ENTRIES`].
    pub(crate) records: Vec<AutomationRecord>,
}

/// The result of one certificate automation flow.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutomationRecord {
    pub certificate_arn: String,
    /// When the agent recorded the result, in epoch milliseconds, at least 1.
    pub event_time: u64,
    pub result: AutomationResult,
    /// The certificate the agent deployed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_der: Option<Blob>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_der: Option<Vec<Blob>>,
    /// The export, write and reload flow's wall-clock time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_duration_milliseconds: Option<u64>,
    /// Failures for this certificate in a row before this attempt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consecutive_failures: Option<u32>,
    /// Certificates in the host's automation configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configured_certificate_count: Option<u32>,
    /// The same on every record of a refresh cycle. The service doesn't treat
    /// it as sensitive, so it must not be built from the compute ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_cycle_id: Option<String>,
    /// This certificate's place in the refresh cycle, counted from 0.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_index: Option<u32>,
}

/// Exactly one of success or failure.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AutomationResult {
    Success(AutomationSuccess),
    Failure(AutomationFailure),
}

/// Where automation failed, as a code: the model has no free-text field.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutomationFailure {
    pub stage: AutomationStage,
    pub code: String,
    /// What this attempt did to the certificate files before its step failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files_on_disk: Option<FilesOnDisk>,
}

/// What one automation attempt did to the certificate files. It describes
/// that attempt only: a retry can report `NotReplaced` while an earlier
/// attempt's files are on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FilesOnDisk {
    /// The attempt replaced no file.
    NotReplaced,
    /// A write failed after some files were replaced.
    PartlyReplaced,
    /// The attempt wrote new files, and a later step failed.
    Replaced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProbeOutcome {
    Success,
    ConnectionRefused,
    Timeout,
    NotTls,
    HandshakeError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AutomationSuccess {
    Deployed,
    Reloaded,
    Unchanged,
    WrittenNotReloaded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AutomationStage {
    Export,
    Write,
    Reload,
    Verify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) enum ComputeType {
    #[serde(rename = "EC2")]
    Ec2,
    #[serde(rename = "ECS")]
    Ecs,
    #[serde(rename = "EKS")]
    Eks,
    #[serde(rename = "LAMBDA")]
    Lambda,
    #[serde(rename = "ON_PREMISES")]
    OnPremises,
    #[serde(rename = "OTHER")]
    Other,
}

impl From<DeploymentType> for ComputeType {
    fn from(deployment_type: DeploymentType) -> Self {
        match deployment_type {
            DeploymentType::Ec2 => Self::Ec2,
            DeploymentType::Ecs => Self::Ecs,
            DeploymentType::Eks => Self::Eks,
            DeploymentType::Lambda => Self::Lambda,
            DeploymentType::OnPrem => Self::OnPremises,
            DeploymentType::Other => Self::Other,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) enum Os {
    #[serde(rename = "LINUX")]
    Linux,
    #[serde(rename = "WINDOWS")]
    Windows,
    #[serde(rename = "MACOS")]
    Macos,
    #[serde(rename = "OTHER")]
    Other,
}

impl Os {
    /// The value for an `std::env::consts::OS` name.
    fn from_rust(os: &str) -> Self {
        match os {
            "linux" => Self::Linux,
            "windows" => Self::Windows,
            "macos" => Self::Macos,
            _ => Self::Other,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) enum Arch {
    #[serde(rename = "X86_64")]
    X86_64,
    #[serde(rename = "ARM64")]
    Arm64,
    #[serde(rename = "OTHER")]
    Other,
}

impl Arch {
    /// The value for an `std::env::consts::ARCH` name.
    fn from_rust(arch: &str) -> Self {
        match arch {
            "x86_64" => Self::X86_64,
            "aarch64" => Self::Arm64,
            _ => Self::Other,
        }
    }
}

/// A record's entry in a request.
#[derive(Debug, Clone, PartialEq)]
pub enum Entry {
    /// A discovery batch, sent as a request of its own.
    Discovery(Discovery),
    /// One automation record, which the drain sends together with others.
    Automation(AutomationRecord),
}

impl Entry {
    /// The record type this entry belongs to.
    pub(crate) fn payload_type(&self) -> PayloadType {
        match self {
            Self::Discovery(_) => PayloadType::CertDiscovery,
            Self::Automation(_) => PayloadType::CertAutomation,
        }
    }
}

impl CertificateTelemetry {
    /// The record type of the entries this holds.
    pub(crate) fn payload_type(&self) -> PayloadType {
        match self {
            Self::Discovery(_) => PayloadType::CertDiscovery,
            Self::Automation(_) => PayloadType::CertAutomation,
        }
    }
}

/// The identity that fills a request's top-level fields.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Header {
    compute_id: String,
    compute_type: ComputeType,
    os: Os,
    arch: Arch,
    schema_version: u32,
}

/// What a record contributes to a request: its entry, its idempotency key,
/// and the identity of the agent that produced it.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestPart {
    pub(crate) entry: Entry,
    pub(crate) idempotency_key: String,
    pub(crate) header: Header,
}

impl RequestPart {
    /// `entry`, with the key and identity from `envelope`, whose `host_id` is
    /// the request's `computeId`. A discovery batch's `batch_index` is the
    /// envelope's plus 1. A chain longer than the model allows keeps its first
    /// [`MAX_CHAIN_CERTIFICATES`] certificates, as the model specifies, so it
    /// doesn't fail the request.
    pub fn new(envelope: &PayloadEnvelope, mut entry: Entry) -> Self {
        match &mut entry {
            Entry::Discovery(discovery) => {
                discovery.batch_index = envelope.batch_index.saturating_add(1);
                for observation in &mut discovery.observations {
                    keep_first_certificates(&mut observation.chain_der);
                }
            }
            Entry::Automation(record) => keep_first_certificates(&mut record.chain_der),
        }
        Self {
            entry,
            idempotency_key: envelope.idempotency_key.clone(),
            header: Header {
                compute_id: envelope.host_id.clone(),
                compute_type: envelope.deployment_type.into(),
                os: Os::from_rust(&envelope.os),
                arch: Arch::from_rust(&envelope.arch),
                schema_version: envelope.schema_version,
            },
        }
    }

    /// Why the service would reject a request with this part, if it would:
    /// the first of the model's limits it breaks.
    pub(crate) fn check(&self) -> Result<(), String> {
        check_chars("computeId", &self.header.compute_id, MAX_COMPUTE_ID_CHARS)?;
        check_chars(
            "idempotencyKey",
            &self.idempotency_key,
            MAX_IDEMPOTENCY_KEY_CHARS,
        )?;
        let schema_version = self.header.schema_version;
        if !(1..=MAX_SCHEMA_VERSION).contains(&schema_version) {
            return Err(format!(
                "schemaVersion is {schema_version}, outside the model's 1 to {MAX_SCHEMA_VERSION}"
            ));
        }
        match &self.entry {
            Entry::Discovery(discovery) => check_discovery(discovery),
            Entry::Automation(record) => check_automation(record),
        }
    }

    /// The request for this part alone.
    pub(crate) fn request(&self) -> PutCertificateTelemetryInput {
        let telemetry = match &self.entry {
            Entry::Discovery(discovery) => CertificateTelemetry::Discovery(discovery.clone()),
            Entry::Automation(record) => CertificateTelemetry::Automation(Automation {
                records: vec![record.clone()],
            }),
        };
        self.header.request(telemetry, self.idempotency_key.clone())
    }
}

impl Header {
    /// A request with this identity, `telemetry` and `idempotency_key`.
    pub(crate) fn request(
        &self,
        telemetry: CertificateTelemetry,
        idempotency_key: String,
    ) -> PutCertificateTelemetryInput {
        PutCertificateTelemetryInput {
            telemetry,
            compute_id: self.compute_id.clone(),
            idempotency_key,
            compute_type: self.compute_type,
            os: self.os,
            arch: self.arch,
            schema_version: self.schema_version,
        }
    }
}

/// Cuts `chain` to its first [`MAX_CHAIN_CERTIFICATES`] certificates.
fn keep_first_certificates(chain: &mut Option<Vec<Blob>>) {
    if let Some(chain) = chain {
        chain.truncate(MAX_CHAIN_CERTIFICATES);
    }
}

fn check_discovery(discovery: &Discovery) -> Result<(), String> {
    check_time("scanTime", discovery.scan_time)?;
    check_chars("scanId", &discovery.scan_id, MAX_SCAN_ID_CHARS)?;
    let (index, total) = (discovery.batch_index, discovery.total_batches);
    if !(1..=MAX_BATCH_NUMBER).contains(&total) || !(1..=total).contains(&index) {
        return Err(format!(
            "batch {index} of {total}: the model's are 1 to {MAX_BATCH_NUMBER}, the index no more than the total"
        ));
    }
    check_counts(&[
        ("totalTargetsProbed", discovery.total_targets_probed),
        ("successfulProbes", discovery.successful_probes),
        ("failedProbes", discovery.failed_probes),
        ("droppedObservations", discovery.dropped_observations),
        (
            "configuredCertificateCount",
            discovery.configured_certificate_count,
        ),
    ])?;
    let observations = discovery.observations.len();
    if observations > MAX_ENTRIES {
        return Err(format!(
            "{observations} observations, over the model's {MAX_ENTRIES}"
        ));
    }
    for (index, observation) in discovery.observations.iter().enumerate() {
        check_observation(observation).map_err(|why| format!("observation {index}: {why}"))?;
    }
    Ok(())
}

fn check_observation(observation: &Observation) -> Result<(), String> {
    if observation.port == 0 {
        return Err("port is 0, outside the model's 1 to 65535".to_string());
    }
    if let Some(sni) = &observation.sni {
        check_chars("sni", sni, MAX_SNI_CHARS)?;
    }
    if observation.outcome == ProbeOutcome::Success && observation.certificate_der.is_none() {
        return Err("a SUCCESS observation needs certificateDer".to_string());
    }
    let tls_parameters = [
        ("tlsVersion", &observation.tls_version),
        ("cipherSuite", &observation.cipher_suite),
        (
            "handshakeSignatureScheme",
            &observation.handshake_signature_scheme,
        ),
        ("keyAlgorithm", &observation.key_algorithm),
    ];
    for (name, value) in tls_parameters {
        if let Some(value) = value {
            check_chars(name, value, MAX_TLS_PARAMETER_CHARS)?;
        }
    }
    check_certificates(&observation.certificate_der, &observation.chain_der)
}

fn check_automation(record: &AutomationRecord) -> Result<(), String> {
    check_chars(
        "certificateArn",
        &record.certificate_arn,
        MAX_CERTIFICATE_ARN_CHARS,
    )?;
    if !is_acm_arn(&record.certificate_arn) {
        return Err("certificateArn isn't an ACM certificate ARN".to_string());
    }
    check_time("eventTime", record.event_time)?;
    if let Some(duration) = record.refresh_duration_milliseconds {
        if duration > MAX_LONG {
            return Err(format!(
                "refreshDurationMilliseconds is {duration}, over the model's {MAX_LONG}"
            ));
        }
    }
    check_counts(&[
        ("consecutiveFailures", record.consecutive_failures),
        (
            "configuredCertificateCount",
            record.configured_certificate_count,
        ),
        ("certIndex", record.cert_index),
    ])?;
    if let AutomationResult::Failure(failure) = &record.result {
        check_chars("the failure code", &failure.code, MAX_FAILURE_CODE_CHARS)?;
    }
    if let Some(refresh_cycle_id) = &record.refresh_cycle_id {
        check_chars(
            "refreshCycleId",
            refresh_cycle_id,
            MAX_REFRESH_CYCLE_ID_CHARS,
        )?;
    }
    check_certificates(&record.certificate_der, &record.chain_der)
}

/// Whether `value` is 1 to `max` characters, the model's length for `name`.
fn check_chars(name: &str, value: &str, max: usize) -> Result<(), String> {
    let chars = value.chars().count();
    if (1..=max).contains(&chars) {
        Ok(())
    } else {
        Err(format!(
            "{name} is {chars} characters, outside the model's 1 to {max}"
        ))
    }
}

/// Whether `time`, in epoch milliseconds, is in the model's 1 to the largest
/// `long`.
fn check_time(name: &str, time: u64) -> Result<(), String> {
    if (1..=MAX_LONG).contains(&time) {
        Ok(())
    } else {
        Err(format!(
            "{name} is {time}, outside the model's 1 to {MAX_LONG}"
        ))
    }
}

/// Whether each count is at most the model's largest `integer`.
fn check_counts(counts: &[(&str, Option<u32>)]) -> Result<(), String> {
    for &(name, count) in counts {
        if let Some(count) = count {
            if count > MAX_INTEGER {
                return Err(format!("{name} is {count}, over the model's {MAX_INTEGER}"));
            }
        }
    }
    Ok(())
}

/// Whether `arn` matches the model's pattern
/// `^arn:aws[a-z-]*:acm:[^:]*[^:\s][^:]*:[^:]*[^:\s][^:]*:certificate/[^/]+$`: a non-blank
/// region and account, and a `certificate/<id>` resource whose id has no `/`. Blank here is
/// Unicode whitespace (`char::is_whitespace`), which can be stricter than the pattern's `\s`.
fn is_acm_arn(arn: &str) -> bool {
    let Some(rest) = arn.strip_prefix("arn:aws") else {
        return false;
    };
    let Some(rest) = rest
        .trim_start_matches(|c: char| c.is_ascii_lowercase() || c == '-')
        .strip_prefix(":acm:")
    else {
        return false;
    };
    let mut parts = rest.splitn(3, ':');
    let (Some(region), Some(account), Some(resource)) = (parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let non_blank = |s: &str| s.chars().any(|c| !c.is_whitespace());
    let Some(id) = resource.strip_prefix("certificate/") else {
        return false;
    };
    non_blank(region) && non_blank(account) && !id.is_empty() && !id.contains('/')
}

fn check_certificates(leaf: &Option<Blob>, chain: &Option<Vec<Blob>>) -> Result<(), String> {
    if let Some(leaf) = leaf {
        check_certificate(leaf).map_err(|why| format!("certificateDer {why}"))?;
    }
    if let Some(chain) = chain {
        if chain.len() > MAX_CHAIN_CERTIFICATES {
            return Err(format!(
                "chainDer has {} certificates, over the model's {MAX_CHAIN_CERTIFICATES}",
                chain.len()
            ));
        }
        for (index, certificate) in chain.iter().enumerate() {
            check_certificate(certificate).map_err(|why| format!("chainDer {index} {why}"))?;
        }
    }
    Ok(())
}

fn check_certificate(certificate: &Blob) -> Result<(), String> {
    let bytes = certificate.0.len();
    if (1..=MAX_CERTIFICATE_BYTES).contains(&bytes) {
        Ok(())
    } else {
        Err(format!(
            "is {bytes} bytes, outside the model's 1 to {MAX_CERTIFICATE_BYTES}"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::payload::{to_cbor, Capability, PayloadType};

    const ARN: &str = "arn:aws:acm:us-west-2:111122223333:certificate/a";

    fn header() -> Header {
        Header {
            compute_id: "i-1".to_string(),
            compute_type: ComputeType::Ec2,
            os: Os::Linux,
            arch: Arch::Arm64,
            schema_version: 1,
        }
    }

    fn envelope(host_id: &str, deployment_type: DeploymentType) -> PayloadEnvelope {
        PayloadEnvelope::new(
            Capability::Acm,
            PayloadType::CertAutomation,
            0,
            0,
            host_id,
            "boot-1",
            "4.0.0",
            "us-west-2",
            deployment_type,
        )
        .unwrap()
    }

    fn deployed() -> AutomationRecord {
        AutomationRecord {
            certificate_arn: ARN.to_string(),
            event_time: 1_793_315_962_000,
            result: AutomationResult::Success(AutomationSuccess::Deployed),
            certificate_der: Some(Blob(vec![0x30, 0x82])),
            chain_der: None,
            refresh_duration_milliseconds: None,
            consecutive_failures: None,
            configured_certificate_count: None,
            refresh_cycle_id: None,
            cert_index: None,
        }
    }

    fn failed() -> AutomationRecord {
        AutomationRecord {
            event_time: 1_793_315_962_500,
            result: AutomationResult::Failure(AutomationFailure {
                stage: AutomationStage::Reload,
                code: "EACCES".to_string(),
                files_on_disk: None,
            }),
            certificate_der: None,
            ..deployed()
        }
    }

    fn observed() -> Observation {
        Observation {
            port: 443,
            sni: Some("example.com".to_string()),
            outcome: ProbeOutcome::Success,
            certificate_der: Some(Blob(vec![0x30, 0x82])),
            chain_der: Some(vec![Blob(vec![0x30, 0x01])]),
            mtls_detected: Some(true),
            tls_version: None,
            cipher_suite: None,
            handshake_signature_scheme: None,
            key_algorithm: None,
        }
    }

    fn discovery(observations: Vec<Observation>) -> Discovery {
        Discovery {
            scan_time: 1_793_315_962_000,
            scan_id: "i-1:1793315962".to_string(),
            observations,
            batch_index: 1,
            total_batches: 1,
            scan_complete: None,
            total_targets_probed: None,
            successful_probes: None,
            failed_probes: None,
            dropped_observations: None,
            configured_certificate_count: None,
        }
    }

    #[test]
    fn a_discovery_request_as_json_has_the_models_names_and_values() {
        let negotiated = Observation {
            tls_version: Some("TLSv1.3".to_string()),
            cipher_suite: Some("TLS_AES_128_GCM_SHA256".to_string()),
            handshake_signature_scheme: Some("ecdsa_secp256r1_sha256".to_string()),
            key_algorithm: Some("EC".to_string()),
            ..observed()
        };
        let timed_out = Observation {
            port: 8443,
            sni: None,
            outcome: ProbeOutcome::Timeout,
            certificate_der: None,
            chain_der: None,
            mtls_detected: None,
            ..observed()
        };
        let scan = Discovery {
            batch_index: 2,
            total_batches: 3,
            scan_complete: Some(true),
            total_targets_probed: Some(10),
            successful_probes: Some(3),
            failed_probes: Some(7),
            dropped_observations: Some(0),
            configured_certificate_count: Some(5),
            ..discovery(vec![negotiated, timed_out])
        };
        let request = Header {
            compute_type: ComputeType::OnPremises,
            os: Os::Windows,
            arch: Arch::X86_64,
            ..header()
        }
        .request(CertificateTelemetry::Discovery(scan), "key-1".to_string());
        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            concat!(
                r#"{"telemetry":{"discovery":{"scanTime":1793315962000,"scanId":"i-1:1793315962","#,
                r#""observations":[{"port":443,"sni":"example.com","outcome":"SUCCESS","#,
                r#""certificateDer":"MII=","chainDer":["MAE="],"mtlsDetected":true,"#,
                r#""tlsVersion":"TLSv1.3","cipherSuite":"TLS_AES_128_GCM_SHA256","#,
                r#""handshakeSignatureScheme":"ecdsa_secp256r1_sha256","keyAlgorithm":"EC"},"#,
                r#"{"port":8443,"outcome":"TIMEOUT"}],"batchIndex":2,"totalBatches":3,"#,
                r#""scanComplete":true,"totalTargetsProbed":10,"successfulProbes":3,"#,
                r#""failedProbes":7,"droppedObservations":0,"configuredCertificateCount":5}},"#,
                r#""computeId":"i-1","idempotencyKey":"key-1","computeType":"ON_PREMISES","#,
                r#""os":"WINDOWS","arch":"X86_64","schemaVersion":1}"#,
            )
        );
    }

    #[test]
    fn an_automation_request_as_json_has_the_models_names_and_values() {
        let refreshed = AutomationRecord {
            refresh_duration_milliseconds: Some(1_250),
            consecutive_failures: Some(0),
            configured_certificate_count: Some(5),
            refresh_cycle_id: Some("cycle-1".to_string()),
            cert_index: Some(2),
            ..deployed()
        };
        let reload_failed = AutomationRecord {
            result: AutomationResult::Failure(AutomationFailure {
                stage: AutomationStage::Reload,
                code: "EACCES".to_string(),
                files_on_disk: Some(FilesOnDisk::Replaced),
            }),
            ..failed()
        };
        let request = header().request(
            CertificateTelemetry::Automation(Automation {
                records: vec![refreshed, reload_failed],
            }),
            "key-1".to_string(),
        );
        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            format!(
                concat!(
                    r#"{{"telemetry":{{"automation":{{"records":["#,
                    r#"{{"certificateArn":"{arn}","eventTime":1793315962000,"#,
                    r#""result":{{"success":"DEPLOYED"}},"certificateDer":"MII=","#,
                    r#""refreshDurationMilliseconds":1250,"consecutiveFailures":0,"#,
                    r#""configuredCertificateCount":5,"refreshCycleId":"cycle-1","certIndex":2}},"#,
                    r#"{{"certificateArn":"{arn}","eventTime":1793315962500,"#,
                    r#""result":{{"failure":{{"stage":"RELOAD","code":"EACCES","filesOnDisk":"REPLACED"}}}}}}]}}}},"#,
                    r#""computeId":"i-1","idempotencyKey":"key-1","computeType":"EC2","#,
                    r#""os":"LINUX","arch":"ARM64","schemaVersion":1}}"#,
                ),
                arn = ARN
            )
        );
    }

    /// The protocol's encoding: structures and unions as maps keyed by member
    /// name, absent members left out, enums as text, and times as plain
    /// integers.
    #[test]
    fn a_request_as_cbor_is_the_rpc_v2_cbor_encoding() {
        let request = header().request(
            CertificateTelemetry::Automation(Automation {
                records: vec![failed()],
            }),
            "key-1".to_string(),
        );
        let cbor = [
            &[0xa7, 0x69][..],
            b"telemetry",
            &[0xa1, 0x6a],
            b"automation",
            &[0xa1, 0x67],
            b"records",
            // One record, a map of three members.
            &[0x81, 0xa3, 0x6e],
            b"certificateArn",
            &[0x78, 48],
            ARN.as_bytes(),
            &[0x69],
            b"eventTime",
            &[0x1b],
            &1_793_315_962_500u64.to_be_bytes(),
            &[0x66],
            b"result",
            &[0xa1, 0x67],
            b"failure",
            &[0xa2, 0x65],
            b"stage",
            &[0x66],
            b"RELOAD",
            &[0x64],
            b"code",
            &[0x66],
            b"EACCES",
            &[0x69],
            b"computeId",
            &[0x63],
            b"i-1",
            &[0x6e],
            b"idempotencyKey",
            &[0x65],
            b"key-1",
            &[0x6b],
            b"computeType",
            &[0x63],
            b"EC2",
            &[0x62],
            b"os",
            &[0x65],
            b"LINUX",
            &[0x64],
            b"arch",
            &[0x65],
            b"ARM64",
            &[0x6d],
            b"schemaVersion",
            &[0x01],
        ]
        .concat();
        assert_eq!(to_cbor(&request).unwrap(), cbor);
    }

    /// Each enum's values, as JSON text.
    fn values<T: Serialize>(variants: &[T]) -> Vec<String> {
        variants
            .iter()
            .map(|variant| {
                serde_json::to_value(variant)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect()
    }

    #[test]
    fn enum_values_are_the_models() {
        use ProbeOutcome::*;
        assert_eq!(
            values(&[Success, ConnectionRefused, Timeout, NotTls, HandshakeError]),
            [
                "SUCCESS",
                "CONNECTION_REFUSED",
                "TIMEOUT",
                "NOT_TLS",
                "HANDSHAKE_ERROR"
            ]
        );
        assert_eq!(
            values(&[
                AutomationSuccess::Deployed,
                AutomationSuccess::Reloaded,
                AutomationSuccess::Unchanged,
                AutomationSuccess::WrittenNotReloaded,
            ]),
            ["DEPLOYED", "RELOADED", "UNCHANGED", "WRITTEN_NOT_RELOADED"]
        );
        assert_eq!(
            values(&[
                AutomationStage::Export,
                AutomationStage::Write,
                AutomationStage::Reload,
                AutomationStage::Verify,
            ]),
            ["EXPORT", "WRITE", "RELOAD", "VERIFY"]
        );
        assert_eq!(
            values(&[
                FilesOnDisk::NotReplaced,
                FilesOnDisk::PartlyReplaced,
                FilesOnDisk::Replaced,
            ]),
            ["NOT_REPLACED", "PARTLY_REPLACED", "REPLACED"]
        );
        assert_eq!(
            values(&[
                ComputeType::Ec2,
                ComputeType::Ecs,
                ComputeType::Eks,
                ComputeType::Lambda,
                ComputeType::OnPremises,
                ComputeType::Other,
            ]),
            ["EC2", "ECS", "EKS", "LAMBDA", "ON_PREMISES", "OTHER"]
        );
        assert_eq!(
            values(&[Os::Linux, Os::Windows, Os::Macos, Os::Other]),
            ["LINUX", "WINDOWS", "MACOS", "OTHER"]
        );
        assert_eq!(
            values(&[Arch::X86_64, Arch::Arm64, Arch::Other]),
            ["X86_64", "ARM64", "OTHER"]
        );
    }

    #[test]
    fn the_envelopes_identity_maps_to_the_models_values() {
        let cases = [
            (DeploymentType::Ec2, ComputeType::Ec2),
            (DeploymentType::Ecs, ComputeType::Ecs),
            (DeploymentType::Eks, ComputeType::Eks),
            (DeploymentType::Lambda, ComputeType::Lambda),
            (DeploymentType::OnPrem, ComputeType::OnPremises),
            (DeploymentType::Other, ComputeType::Other),
        ];
        for (deployment_type, compute_type) in cases {
            assert_eq!(ComputeType::from(deployment_type), compute_type);
        }
        let oses = ["linux", "windows", "macos", "freebsd"].map(Os::from_rust);
        assert_eq!(oses, [Os::Linux, Os::Windows, Os::Macos, Os::Other]);
        let arches = ["x86_64", "aarch64", "riscv64"].map(Arch::from_rust);
        assert_eq!(arches, [Arch::X86_64, Arch::Arm64, Arch::Other]);
    }

    #[test]
    fn a_part_takes_its_key_and_identity_from_the_envelope() {
        let mut envelope = envelope("0f1e2d3c4b5a", DeploymentType::Ecs);
        envelope.os = "windows".to_string();
        envelope.arch = "aarch64".to_string();
        envelope.schema_version = 2;
        let part = RequestPart::new(&envelope, Entry::Automation(deployed()));
        assert_eq!(part.idempotency_key, envelope.idempotency_key);
        assert_eq!(
            part.header,
            Header {
                compute_id: "0f1e2d3c4b5a".to_string(),
                compute_type: ComputeType::Ecs,
                os: Os::Windows,
                arch: Arch::Arm64,
                schema_version: 2,
            }
        );
        let request = part.request();
        assert_eq!(request.idempotency_key, envelope.idempotency_key);
        assert_eq!(request.schema_version, 2);
    }

    #[test]
    fn a_discovery_part_counts_its_batch_from_the_envelopes_plus_one() {
        let mut envelope = envelope("i-1", DeploymentType::Ec2);
        envelope.batch_index = 2;
        let scan = Discovery {
            batch_index: 7,
            total_batches: 3,
            ..discovery(vec![observed()])
        };
        let part = RequestPart::new(&envelope, Entry::Discovery(scan));
        let Entry::Discovery(scan) = &part.entry else {
            panic!("a discovery part");
        };
        assert_eq!(scan.batch_index, 3);
        assert_eq!(part.check(), Ok(()));

        // The largest index doesn't wrap to 0 or panic; check() refuses it.
        envelope.batch_index = u32::MAX;
        let part = RequestPart::new(&envelope, Entry::Discovery(discovery(vec![observed()])));
        assert!(part
            .check()
            .is_err_and(|why| why.starts_with("batch 4294967295 of")));
    }

    #[test]
    fn a_part_keeps_the_first_certificates_of_a_long_chain() {
        let chain = |n: u8| Some((0..n).map(|i| Blob(vec![i])).collect::<Vec<_>>());
        let envelope = envelope("i-1", DeploymentType::Ec2);
        for (given, kept) in [(8, 5), (5, 5), (2, 2)] {
            let record = AutomationRecord {
                chain_der: chain(given),
                ..deployed()
            };
            let part = RequestPart::new(&envelope, Entry::Automation(record));
            let Entry::Automation(record) = part.entry else {
                panic!("an automation part");
            };
            assert_eq!(record.chain_der, chain(kept), "automation, {given} given");

            let observation = Observation {
                chain_der: chain(given),
                ..observed()
            };
            let scan = discovery(vec![observed(), observation]);
            let part = RequestPart::new(&envelope, Entry::Discovery(scan));
            let Entry::Discovery(scan) = part.entry else {
                panic!("a discovery part");
            };
            assert_eq!(scan.observations[0], observed());
            assert_eq!(
                scan.observations[1].chain_der,
                chain(kept),
                "discovery, {given} given"
            );
        }
    }

    fn automation_part(change: impl FnOnce(&mut AutomationRecord)) -> RequestPart {
        let mut record = deployed();
        change(&mut record);
        RequestPart {
            entry: Entry::Automation(record),
            idempotency_key: "key-1".to_string(),
            header: header(),
        }
    }

    fn scan_part(change: impl FnOnce(&mut Discovery)) -> RequestPart {
        let mut scan = discovery(vec![observed()]);
        change(&mut scan);
        RequestPart {
            entry: Entry::Discovery(scan),
            idempotency_key: "key-1".to_string(),
            header: header(),
        }
    }

    fn discovery_part(change: impl FnOnce(&mut Vec<Observation>)) -> RequestPart {
        scan_part(|scan| change(&mut scan.observations))
    }

    #[test]
    fn check_finds_the_first_model_limit_a_part_breaks() {
        let arn_of = |chars: usize| format!("{ARN}{}", "x".repeat(chars - ARN.len()));
        let failure = |code: &str| {
            AutomationResult::Failure(AutomationFailure {
                stage: AutomationStage::Write,
                code: code.to_string(),
                files_on_disk: None,
            })
        };
        let certificate = |bytes: usize| Some(Blob(vec![0x30; bytes]));
        let cases: Vec<(&str, RequestPart, Option<&str>)> = vec![
            ("automation", automation_part(|_| {}), None),
            (
                "GovCloud ARN",
                automation_part(|r| r.certificate_arn = ARN.replace("aws", "aws-us-gov")),
                None,
            ),
            (
                "IAM ARN",
                automation_part(|r| r.certificate_arn = "arn:aws:iam::111122223333:role/a".into()),
                Some("certificateArn isn't an ACM certificate ARN"),
            ),
            (
                "ACM later in the ARN",
                automation_part(|r| r.certificate_arn = "arn:aws:s3:::acm:bucket".into()),
                Some("certificateArn isn't an ACM certificate ARN"),
            ),
            (
                "ARN prefix only",
                automation_part(|r| r.certificate_arn = "arn:aws".into()),
                Some("certificateArn isn't an ACM certificate ARN"),
            ),
            (
                "ACM prefix with no certificate",
                automation_part(|r| {
                    r.certificate_arn = "arn:aws-cn:acm: This is not a valid ARN either!".into()
                }),
                Some("certificateArn isn't an ACM certificate ARN"),
            ),
            (
                "empty certificate id",
                automation_part(|r| {
                    r.certificate_arn = "arn:aws:acm:us-west-2:111122223333:certificate/".into()
                }),
                Some("certificateArn isn't an ACM certificate ARN"),
            ),
            (
                "certificate id with a slash",
                automation_part(|r| {
                    r.certificate_arn = "arn:aws:acm:us-west-2:111122223333:certificate/a/b".into()
                }),
                Some("certificateArn isn't an ACM certificate ARN"),
            ),
            (
                "blank region",
                automation_part(|r| {
                    r.certificate_arn = "arn:aws:acm: :111122223333:certificate/a".into()
                }),
                Some("certificateArn isn't an ACM certificate ARN"),
            ),
            (
                "empty region before an extra segment",
                automation_part(|r| {
                    r.certificate_arn = "arn:aws:acm::x:111122223333:certificate/a".into()
                }),
                Some("certificateArn isn't an ACM certificate ARN"),
            ),
            (
                "no account",
                automation_part(|r| {
                    r.certificate_arn = "arn:aws:acm:us-west-2::certificate/a".into()
                }),
                Some("certificateArn isn't an ACM certificate ARN"),
            ),
            (
                "not a certificate resource",
                automation_part(|r| {
                    r.certificate_arn = "arn:aws:acm:us-west-2:111122223333:key/a".into()
                }),
                Some("certificateArn isn't an ACM certificate ARN"),
            ),
            (
                "certificate id with a colon",
                automation_part(|r| {
                    r.certificate_arn = "arn:aws:acm:us-west-2:111122223333:certificate/a:b".into()
                }),
                None,
            ),
            (
                "no ARN",
                automation_part(|r| r.certificate_arn.clear()),
                Some("certificateArn is 0 characters"),
            ),
            (
                "longest ARN",
                automation_part(|r| r.certificate_arn = arn_of(256)),
                None,
            ),
            (
                "ARN too long",
                automation_part(|r| r.certificate_arn = arn_of(257)),
                Some("certificateArn is 257 characters"),
            ),
            ("event time 1", automation_part(|r| r.event_time = 1), None),
            (
                "event time 0",
                automation_part(|r| r.event_time = 0),
                Some("eventTime is 0"),
            ),
            (
                "latest event time",
                automation_part(|r| r.event_time = 9_223_372_036_854_775_807),
                None,
            ),
            (
                "event time past a long",
                automation_part(|r| r.event_time = 9_223_372_036_854_775_808),
                Some("eventTime is 9223372036854775808"),
            ),
            (
                "longest refresh duration",
                automation_part(|r| {
                    r.refresh_duration_milliseconds = Some(9_223_372_036_854_775_807)
                }),
                None,
            ),
            (
                "refresh duration past a long",
                automation_part(|r| {
                    r.refresh_duration_milliseconds = Some(9_223_372_036_854_775_808)
                }),
                Some("refreshDurationMilliseconds is 9223372036854775808"),
            ),
            (
                "largest automation counts",
                automation_part(|r| {
                    r.consecutive_failures = Some(2_147_483_647);
                    r.configured_certificate_count = Some(2_147_483_647);
                    r.cert_index = Some(2_147_483_647);
                }),
                None,
            ),
            (
                "consecutive failures past an integer",
                automation_part(|r| r.consecutive_failures = Some(2_147_483_648)),
                Some("consecutiveFailures is 2147483648"),
            ),
            (
                "configured certificates past an integer",
                automation_part(|r| r.configured_certificate_count = Some(2_147_483_648)),
                Some("configuredCertificateCount is 2147483648"),
            ),
            (
                "cert index past an integer",
                automation_part(|r| r.cert_index = Some(2_147_483_648)),
                Some("certIndex is 2147483648"),
            ),
            (
                "shortest failure code",
                automation_part(|r| r.result = failure("E")),
                None,
            ),
            (
                "longest failure code",
                automation_part(|r| r.result = failure(&"E".repeat(64))),
                None,
            ),
            (
                "no failure code",
                automation_part(|r| r.result = failure("")),
                Some("the failure code is 0 characters"),
            ),
            (
                "failure code too long",
                automation_part(|r| r.result = failure(&"E".repeat(65))),
                Some("the failure code is 65 characters"),
            ),
            (
                "longest refresh cycle ID",
                automation_part(|r| r.refresh_cycle_id = Some("c".repeat(256))),
                None,
            ),
            (
                "empty refresh cycle ID",
                automation_part(|r| r.refresh_cycle_id = Some(String::new())),
                Some("refreshCycleId is 0 characters"),
            ),
            (
                "refresh cycle ID too long",
                automation_part(|r| r.refresh_cycle_id = Some("c".repeat(257))),
                Some("refreshCycleId is 257 characters"),
            ),
            (
                "smallest certificate",
                automation_part(|r| r.certificate_der = certificate(1)),
                None,
            ),
            (
                "largest certificate",
                automation_part(|r| r.certificate_der = certificate(16_384)),
                None,
            ),
            (
                "empty certificate",
                automation_part(|r| r.certificate_der = certificate(0)),
                Some("certificateDer is 0 bytes"),
            ),
            (
                "certificate too large",
                automation_part(|r| r.certificate_der = certificate(16_385)),
                Some("certificateDer is 16385 bytes"),
            ),
            (
                "empty chain",
                automation_part(|r| r.chain_der = Some(Vec::new())),
                None,
            ),
            (
                "longest chain",
                automation_part(|r| r.chain_der = Some(vec![Blob(vec![0x30]); 5])),
                None,
            ),
            (
                "chain too long",
                automation_part(|r| r.chain_der = Some(vec![Blob(vec![0x30]); 6])),
                Some("chainDer has 6 certificates"),
            ),
            (
                "empty chain certificate",
                automation_part(|r| r.chain_der = Some(vec![Blob(vec![0x30]), Blob(Vec::new())])),
                Some("chainDer 1 is 0 bytes"),
            ),
            ("discovery", discovery_part(|_| {}), None),
            ("scan time 1", scan_part(|s| s.scan_time = 1), None),
            (
                "scan time 0",
                scan_part(|s| s.scan_time = 0),
                Some("scanTime is 0"),
            ),
            (
                "latest scan time",
                scan_part(|s| s.scan_time = 9_223_372_036_854_775_807),
                None,
            ),
            (
                "scan time past a long",
                scan_part(|s| s.scan_time = 9_223_372_036_854_775_808),
                Some("scanTime is 9223372036854775808"),
            ),
            (
                "largest discovery counts",
                scan_part(|s| {
                    s.total_targets_probed = Some(2_147_483_647);
                    s.successful_probes = Some(2_147_483_647);
                    s.failed_probes = Some(2_147_483_647);
                    s.dropped_observations = Some(2_147_483_647);
                    s.configured_certificate_count = Some(2_147_483_647);
                }),
                None,
            ),
            (
                "targets probed past an integer",
                scan_part(|s| s.total_targets_probed = Some(2_147_483_648)),
                Some("totalTargetsProbed is 2147483648"),
            ),
            (
                "successful probes past an integer",
                scan_part(|s| s.successful_probes = Some(2_147_483_648)),
                Some("successfulProbes is 2147483648"),
            ),
            (
                "failed probes past an integer",
                scan_part(|s| s.failed_probes = Some(2_147_483_648)),
                Some("failedProbes is 2147483648"),
            ),
            (
                "dropped observations past an integer",
                scan_part(|s| s.dropped_observations = Some(2_147_483_648)),
                Some("droppedObservations is 2147483648"),
            ),
            (
                "configured certificates in a scan past an integer",
                scan_part(|s| s.configured_certificate_count = Some(2_147_483_648)),
                Some("configuredCertificateCount is 2147483648"),
            ),
            (
                "longest scan ID",
                scan_part(|s| s.scan_id = "s".repeat(768)),
                None,
            ),
            (
                "no scan ID",
                scan_part(|s| s.scan_id.clear()),
                Some("scanId is 0 characters"),
            ),
            (
                "scan ID too long",
                scan_part(|s| s.scan_id = "s".repeat(769)),
                Some("scanId is 769 characters"),
            ),
            (
                "last of the most batches",
                scan_part(|s| (s.batch_index, s.total_batches) = (9_999, 9_999)),
                None,
            ),
            (
                "batch 0",
                scan_part(|s| s.batch_index = 0),
                Some("batch 0 of 1"),
            ),
            (
                "batch past the total",
                scan_part(|s| s.batch_index = 2),
                Some("batch 2 of 1"),
            ),
            (
                "no batches",
                scan_part(|s| (s.batch_index, s.total_batches) = (0, 0)),
                Some("batch 0 of 0"),
            ),
            (
                "too many batches",
                scan_part(|s| s.total_batches = 10_000),
                Some("batch 1 of 10000"),
            ),
            (
                "most observations",
                discovery_part(|o| *o = vec![observed(); 100]),
                None,
            ),
            ("counts only", discovery_part(Vec::clear), None),
            (
                "too many observations",
                discovery_part(|o| *o = vec![observed(); 101]),
                Some("101 observations"),
            ),
            ("port 1", discovery_part(|o| o[0].port = 1), None),
            ("port 65535", discovery_part(|o| o[0].port = 65_535), None),
            (
                "port 0",
                discovery_part(|o| o[0].port = 0),
                Some("observation 0: port is 0"),
            ),
            (
                "shortest SNI",
                discovery_part(|o| o[0].sni = Some("a".to_string())),
                None,
            ),
            (
                "longest SNI",
                discovery_part(|o| o[0].sni = Some("a".repeat(253))),
                None,
            ),
            (
                "empty SNI",
                discovery_part(|o| o[0].sni = Some(String::new())),
                Some("observation 0: sni is 0 characters"),
            ),
            (
                "SNI too long",
                discovery_part(|o| o[0].sni = Some("a".repeat(254))),
                Some("observation 0: sni is 254 characters"),
            ),
            (
                "longest TLS parameters",
                discovery_part(|o| {
                    o[0].tls_version = Some("v".repeat(64));
                    o[0].cipher_suite = Some("c".repeat(64));
                    o[0].handshake_signature_scheme = Some("h".repeat(64));
                    o[0].key_algorithm = Some("k".repeat(64));
                }),
                None,
            ),
            (
                "empty TLS version",
                discovery_part(|o| o[0].tls_version = Some(String::new())),
                Some("observation 0: tlsVersion is 0 characters"),
            ),
            (
                "cipher suite too long",
                discovery_part(|o| o[0].cipher_suite = Some("c".repeat(65))),
                Some("observation 0: cipherSuite is 65 characters"),
            ),
            (
                "handshake signature scheme too long",
                discovery_part(|o| o[0].handshake_signature_scheme = Some("h".repeat(65))),
                Some("observation 0: handshakeSignatureScheme is 65 characters"),
            ),
            (
                "empty key algorithm",
                discovery_part(|o| o[0].key_algorithm = Some(String::new())),
                Some("observation 0: keyAlgorithm is 0 characters"),
            ),
            (
                "SUCCESS without a certificate",
                discovery_part(|o| o[0].certificate_der = None),
                Some("observation 0: a SUCCESS observation needs certificateDer"),
            ),
            (
                "TIMEOUT without a certificate",
                discovery_part(|o| {
                    o[0].outcome = ProbeOutcome::Timeout;
                    o[0].certificate_der = None;
                }),
                None,
            ),
            (
                "observation certificate too large",
                discovery_part(|o| o[0].chain_der = Some(vec![Blob(vec![0x30; 16_385])])),
                Some("observation 0: chainDer 0 is 16385 bytes"),
            ),
        ];
        for (name, part, expected) in cases {
            let result = part.check();
            match expected {
                None => assert_eq!(result, Ok(()), "{name}"),
                Some(why) => assert!(
                    result.as_ref().is_err_and(|err| err.starts_with(why)),
                    "{name}: {result:?}"
                ),
            }
        }

        for (chars, ok) in [(0, false), (1, true), (512, true), (513, false)] {
            let mut part = automation_part(|_| {});
            part.header.compute_id = "i".repeat(chars);
            assert_eq!(part.check().is_ok(), ok, "computeId of {chars} characters");
        }
        for (chars, ok) in [(0, false), (1, true), (1024, true), (1025, false)] {
            let mut part = automation_part(|_| {});
            part.idempotency_key = "k".repeat(chars);
            assert_eq!(
                part.check().is_ok(),
                ok,
                "idempotencyKey of {chars} characters"
            );
        }
        for (version, ok) in [(0, false), (1, true), (999, true), (1_000, false)] {
            let mut part = automation_part(|_| {});
            part.header.schema_version = version;
            assert_eq!(part.check().is_ok(), ok, "schemaVersion {version}");
        }
    }

    /// Validates that the longest ECS task ARN passes the model's limits as
    /// the `computeId` (340 characters), in the idempotency key (429) and in a
    /// scan ID (361). The ARN has the longest known partition and region pair
    /// (`aws-iso-f`, `us-isof-south-1`), a 255-character cluster name, the
    /// ECS maximum, and a 32-character task ID. The key has the longest ACM
    /// payload type, `cert_automation`, a UUID boot nonce and the largest
    /// batch sequence and index; the scan ID has the largest epoch.
    #[test]
    fn check_accepts_the_longest_task_arn() {
        let task_arn = format!(
            "arn:aws-iso-f:ecs:us-isof-south-1:111122223333:task/{}/{}",
            "c".repeat(255),
            "0".repeat(32)
        );
        let envelope = |payload_type, batch_index| {
            PayloadEnvelope::new(
                Capability::Acm,
                payload_type,
                u64::MAX,
                batch_index,
                task_arn.as_str(),
                "a1b2c3d4-5678-90ab-cdef-1234567890ab",
                "4.0.0",
                "us-isof-south-1",
                DeploymentType::Ecs,
            )
            .unwrap()
        };

        let automation = RequestPart::new(
            &envelope(PayloadType::CertAutomation, u32::MAX),
            Entry::Automation(deployed()),
        );
        assert_eq!(automation.header.compute_id, task_arn);
        assert_eq!(automation.header.compute_id.len(), 340);
        assert_eq!(automation.idempotency_key.len(), 429);
        assert_eq!(automation.check(), Ok(()));

        let scan_id = format!("{task_arn}:{}", u64::MAX);
        assert_eq!(scan_id.len(), 361);
        let scan = Discovery {
            scan_id,
            total_batches: MAX_BATCH_NUMBER,
            ..discovery(vec![observed()])
        };
        let discovery = RequestPart::new(
            &envelope(PayloadType::CertDiscovery, MAX_BATCH_NUMBER - 1),
            Entry::Discovery(scan),
        );
        assert_eq!(discovery.header.compute_id, task_arn);
        assert_eq!(discovery.check(), Ok(()));
    }
}
