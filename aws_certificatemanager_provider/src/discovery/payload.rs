//! Telemetry payload types for the certificate discovery record.

use aws_workload_credentials_provider_common::telemetry::{
    self as request, Capability, Discovery, Entry, PayloadEnvelope, PayloadType, RequestPart,
    TelemetryRecord,
};
use serde::{Deserialize, Serialize};

use crate::telemetry::certificates::{certificates, is_sendable};

/// Maximum observations per `PutCertificateTelemetry` request: the service
/// model's entry limit. Scans with more observations produce multiple
/// requests, which share `scanId` and are numbered by `batchIndex` of
/// `totalBatches`.
pub const MAX_OBSERVATIONS_PER_BATCH: usize = request::MAX_ENTRIES;
pub const BATCH_SIZE_SOFT_LIMIT: usize = 240_000;
pub const BATCH_SIZE_HARD_LIMIT: usize = 256_000;

/// Outcome of a single TLS probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeOutcome {
    Success,
    ConnectionRefused,
    Timeout,
    NotTls,
    HandshakeError,
}

impl ProbeOutcome {
    /// Only successful probes produce telemetry records.
    pub fn is_reportable(&self) -> bool {
        matches!(self, ProbeOutcome::Success)
    }
}

/// A single probe observation for one (port, SNI) combination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    pub outcome: ProbeOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_der: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_der: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtls_detected: Option<bool>,
    /// Negotiated TLS version (e.g. "TLSv1.3"). Populated when the probe
    /// engine exposes connection metadata; `None` until then.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_version: Option<String>,
    /// Negotiated cipher suite (e.g. "TLS_AES_256_GCM_SHA384").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher_suite: Option<String>,
    /// TLS handshake signature scheme (e.g. "ecdsa_secp256r1_sha256").
    /// This is the scheme used to sign the key exchange, not the algorithm
    /// that signed the leaf certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handshake_signature_scheme: Option<String>,
    /// Public key algorithm of the leaf certificate (e.g. "EC", "RSA").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_algorithm: Option<String>,
}

/// Discovery-specific batch metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchInfo {
    pub total_batches: usize,
}

/// Complete telemetry payload for one discovery batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertDiscoveryRecord {
    #[serde(flatten)]
    pub envelope: PayloadEnvelope,
    pub cycle_id: String,
    /// The cycle start in epoch milliseconds, sent as `scanTime`.
    #[serde(skip)]
    pub cycle_start_ms: u64,
    pub cycle_timestamp: String,
    pub cycle_duration_ms: u64,
    pub batch_info: BatchInfo,
    /// Did the scan finish normally? `false` when interrupted by timeout.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_complete: Option<bool>,
    /// Total (port × SNI) targets attempted, including failures.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_targets_probed: Option<u32>,
    /// Targets that returned a certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub successful_probes: Option<u32>,
    /// Targets that failed (refused, timeout, not TLS, handshake error).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed_probes: Option<u32>,
    /// Observations dropped as unsendable (no leaf, or over the size limit).
    /// Always set, 0 included, on a completed scan; absent on a timed-out scan,
    /// whose count is unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dropped_observations: Option<u32>,
    /// Number of certificates in the ACM automation configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configured_cert_count: Option<u32>,
    pub observations: Vec<Observation>,
}

impl TelemetryRecord for CertDiscoveryRecord {
    fn payload_type(&self) -> PayloadType {
        self.envelope.payload_type
    }

    fn capability(&self) -> Capability {
        self.envelope.capability
    }

    fn serialize(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// The batch as the request's `discovery` member. The cycle ID is the
    /// `scanId`, and the batch is counted from 1. The cycle timestamp and
    /// duration have no field in the request and aren't sent.
    fn request_part(&self) -> Option<RequestPart> {
        let discovery = Discovery {
            scan_time: self.cycle_start_ms,
            scan_id: self.cycle_id.clone(),
            observations: self.observations.iter().map(request_observation).collect(),
            batch_index: self.envelope.batch_index.saturating_add(1),
            total_batches: u32::try_from(self.batch_info.total_batches).unwrap_or(u32::MAX),
            scan_complete: self.scan_complete,
            total_targets_probed: self.total_targets_probed,
            successful_probes: self.successful_probes,
            failed_probes: self.failed_probes,
            dropped_observations: self.dropped_observations,
            configured_certificate_count: self.configured_cert_count,
        };
        Some(RequestPart::new(
            &self.envelope,
            Entry::Discovery(discovery),
        ))
    }

    fn idempotency_key(&self) -> &str {
        &self.envelope.idempotency_key
    }
}

/// An observation as the request carries it, its certificates as DER.
fn request_observation(observation: &Observation) -> request::Observation {
    let (certificate_der, chain_der) = certificates(
        observation.certificate_der.as_deref(),
        observation.chain_der.as_deref(),
    );
    request::Observation {
        port: observation.port,
        sni: observation.sni.clone(),
        outcome: observation.outcome.into(),
        certificate_der,
        chain_der,
        mtls_detected: observation.mtls_detected,
        tls_version: observation.tls_version.clone(),
        cipher_suite: observation.cipher_suite.clone(),
        handshake_signature_scheme: observation.handshake_signature_scheme.clone(),
        key_algorithm: observation.key_algorithm.clone(),
    }
}

impl From<ProbeOutcome> for request::ProbeOutcome {
    fn from(outcome: ProbeOutcome) -> Self {
        match outcome {
            ProbeOutcome::Success => Self::Success,
            ProbeOutcome::ConnectionRefused => Self::ConnectionRefused,
            ProbeOutcome::Timeout => Self::Timeout,
            ProbeOutcome::NotTls => Self::NotTls,
            ProbeOutcome::HandshakeError => Self::HandshakeError,
        }
    }
}

pub fn generate_cycle_id(primary_id: &str, cycle_start_epoch_secs: u64) -> String {
    format!("{}:{}", primary_id, cycle_start_epoch_secs)
}

/// Filters to reportable observations, splits into batches of up to
/// [`MAX_OBSERVATIONS_PER_BATCH`] observations and [`BATCH_SIZE_SOFT_LIMIT`]
/// estimated bytes.
/// Drops individual observations exceeding the batch soft limit (240KB), and
/// those without a leaf the request can carry (over the service model's
/// limit, empty or not valid base64), since the request is rejected whole for
/// one.
pub fn batch_observations(observations: Vec<Observation>) -> (Vec<Vec<Observation>>, usize) {
    let mut batches: Vec<Vec<Observation>> = Vec::new();
    let mut current_batch: Vec<Observation> = Vec::new();
    let mut current_size: usize = 0;
    let mut dropped_count: usize = 0;

    let reportable: Vec<Observation> = observations
        .into_iter()
        .filter(|obs| obs.outcome.is_reportable())
        .collect();

    for obs in reportable {
        // The model requires a leaf on a SUCCESS observation, the only
        // reportable outcome, and rejects the whole request without one.
        if !obs.certificate_der.as_deref().is_some_and(is_sendable) {
            dropped_count += 1;
            continue;
        }
        let obs_size = estimate_observation_size(&obs);

        if obs_size > BATCH_SIZE_SOFT_LIMIT {
            dropped_count += 1;
            continue;
        }

        if (current_size + obs_size > BATCH_SIZE_SOFT_LIMIT
            || current_batch.len() >= MAX_OBSERVATIONS_PER_BATCH)
            && !current_batch.is_empty()
        {
            batches.push(current_batch);
            current_batch = Vec::new();
            current_size = 0;
        }

        current_size += obs_size;
        current_batch.push(obs);
    }

    if !current_batch.is_empty() {
        batches.push(current_batch);
    }

    (batches, dropped_count)
}

/// Estimates serialized JSON size of an observation for batch splitting.
///
/// This intentionally under-estimates instead of serializing each observation
/// during batching. The 16KB gap between the soft limit (240KB) and hard limit
/// (256KB) absorbs the difference.
///
/// Base constants:
/// - 150 bytes: JSON overhead for fixed field names, braces, colons, quotes
///   (`"port":`, `"outcome":`, `"mtls_detected":`, `"tls_version":`, etc.)
/// - 5 bytes: port number digits (max u16 = 65535)
/// - 20 bytes: outcome string (longest: `"connection_refused"` = 19 chars + quotes)
fn estimate_observation_size(obs: &Observation) -> usize {
    let mut size: usize = 150; // fixed JSON structure overhead (incl. TLS metadata keys)
    size += 5; // port number digits
    if let Some(sni) = &obs.sni {
        size += sni.len() + 10; // SNI value + `"sni":"..."` key/quotes
    }
    size += 20; // outcome enum string
    if let Some(cert) = &obs.certificate_der {
        size += cert.len(); // base64 leaf cert (typically 1-4KB)
    }
    if let Some(chain) = &obs.chain_der {
        for entry in chain {
            size += entry.len(); // base64 intermediate certs
        }
    }
    if let Some(v) = &obs.tls_version {
        size += v.len() + 20;
    }
    if let Some(v) = &obs.cipher_suite {
        size += v.len() + 20;
    }
    if let Some(v) = &obs.handshake_signature_scheme {
        size += v.len() + 25;
    }
    if let Some(v) = &obs.key_algorithm {
        size += v.len() + 20;
    }
    size
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_workload_credentials_provider_common::telemetry::request::MAX_CERTIFICATE_BYTES;
    use aws_workload_credentials_provider_common::telemetry::{
        Blob, DeploymentType, SCHEMA_VERSION,
    };
    use base64ct::{Base64, Encoding};

    fn sample_envelope(batch_sequence: u64, batch_index: u32) -> PayloadEnvelope {
        PayloadEnvelope::new(
            Capability::Acm,
            PayloadType::CertDiscovery,
            batch_sequence,
            batch_index,
            "i-0abc",
            "boot-11112222",
            env!("CARGO_PKG_VERSION"),
            "us-west-2",
            DeploymentType::Ec2,
        )
        .expect("valid telemetry envelope")
    }

    #[test]
    fn test_probe_outcome_serialization() {
        assert_eq!(
            serde_json::to_string(&ProbeOutcome::Success).unwrap(),
            "\"success\""
        );
        assert_eq!(
            serde_json::to_string(&ProbeOutcome::ConnectionRefused).unwrap(),
            "\"connection_refused\""
        );
        assert_eq!(
            serde_json::to_string(&ProbeOutcome::Timeout).unwrap(),
            "\"timeout\""
        );
        assert_eq!(
            serde_json::to_string(&ProbeOutcome::NotTls).unwrap(),
            "\"not_tls\""
        );
        assert_eq!(
            serde_json::to_string(&ProbeOutcome::HandshakeError).unwrap(),
            "\"handshake_error\""
        );
    }

    #[test]
    fn test_probe_outcome_reportable() {
        assert!(ProbeOutcome::Success.is_reportable());
        assert!(!ProbeOutcome::ConnectionRefused.is_reportable());
        assert!(!ProbeOutcome::Timeout.is_reportable());
        assert!(!ProbeOutcome::NotTls.is_reportable());
        assert!(!ProbeOutcome::HandshakeError.is_reportable());
    }

    #[test]
    fn test_shared_idempotency_key() {
        let envelope = sample_envelope(42, 0);
        assert_eq!(
            envelope.idempotency_key,
            "i-0abc:boot-11112222:acm:cert_discovery:42:0"
        );
    }

    /// Validates that cycle IDs combine the host ID and cycle timestamp with
    /// a colon separator.
    #[test]
    fn test_cycle_id_generation() {
        let id = generate_cycle_id("i-0abc", 1722297600);
        assert_eq!(id, "i-0abc:1722297600");
    }

    #[test]
    fn test_batch_filters_non_success() {
        let observations = vec![
            Observation {
                port: 443,
                sni: None,
                outcome: ProbeOutcome::Success,
                certificate_der: Some("cert".into()),
                chain_der: None,
                mtls_detected: None,
                tls_version: None,
                cipher_suite: None,
                handshake_signature_scheme: None,
                key_algorithm: None,
            },
            Observation {
                port: 8443,
                sni: None,
                outcome: ProbeOutcome::ConnectionRefused,
                certificate_der: None,
                chain_der: None,
                mtls_detected: None,
                tls_version: None,
                cipher_suite: None,
                handshake_signature_scheme: None,
                key_algorithm: None,
            },
        ];

        let (batches, dropped) = batch_observations(observations);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].len(), 1);
        assert_eq!(batches[0][0].port, 443);
        assert_eq!(dropped, 0);
    }

    /// Validates the observation limit: it is the model's 100, a scan of 250
    /// small observations splits into batches of 100, 100 and 50, and a scan
    /// of exactly 100 is one batch.
    #[test]
    fn test_batch_count_guard() {
        assert_eq!(MAX_OBSERVATIONS_PER_BATCH, 100);
        let small = |count: u16| (0..count).map(|port| observation_with_leaf(port + 1, 3));

        let (batches, dropped) = batch_observations(small(250).collect());
        let sizes: Vec<usize> = batches.iter().map(Vec::len).collect();
        assert_eq!(sizes, [100, 100, 50]);
        assert_eq!(dropped, 0);

        let (batches, _) = batch_observations(small(100).collect());
        assert_eq!(batches.len(), 1);
    }

    /// Validates that the byte limit ends a batch before the observation
    /// limit: 25 observations with the largest leaf the model allows, each
    /// estimated at about 22 KB, split into batches of 10, 10 and 5, each
    /// estimated within [`BATCH_SIZE_SOFT_LIMIT`].
    #[test]
    fn byte_limit_ends_a_batch_before_the_observation_limit() {
        let (batches, dropped) = batch_observations(
            (0..25)
                .map(|port| observation_with_leaf(port + 1, MAX_CERTIFICATE_BYTES))
                .collect(),
        );
        let sizes: Vec<usize> = batches.iter().map(Vec::len).collect();
        assert_eq!(sizes, [10, 10, 5]);
        assert_eq!(dropped, 0);
        for batch in &batches {
            let estimated: usize = batch.iter().map(estimate_observation_size).sum();
            assert!(estimated <= BATCH_SIZE_SOFT_LIMIT, "{estimated}");
        }
    }

    #[test]
    fn test_drops_oversized() {
        // Over BATCH_SIZE_SOFT_LIMIT (240KB) with a leaf within the model's
        // limit, so only the soft limit drops it.
        let huge_sni = "a".repeat(250_000);
        let observations = vec![
            Observation {
                port: 443,
                sni: Some(huge_sni),
                outcome: ProbeOutcome::Success,
                certificate_der: Some("MIIB".into()),
                chain_der: None,
                mtls_detected: None,
                tls_version: None,
                cipher_suite: None,
                handshake_signature_scheme: None,
                key_algorithm: None,
            },
            Observation {
                port: 8443,
                sni: None,
                outcome: ProbeOutcome::Success,
                certificate_der: Some("MIIB".into()),
                chain_der: None,
                mtls_detected: None,
                tls_version: None,
                cipher_suite: None,
                handshake_signature_scheme: None,
                key_algorithm: None,
            },
        ];

        let (batches, dropped) = batch_observations(observations);
        assert_eq!(dropped, 1);
        assert_eq!(batches[0][0].port, 8443);
    }

    /// A successful observation whose leaf is `leaf_len` bytes of DER.
    fn observation_with_leaf(port: u16, leaf_len: usize) -> Observation {
        Observation {
            port,
            sni: None,
            outcome: ProbeOutcome::Success,
            certificate_der: Some(Base64::encode_string(&vec![0x30; leaf_len])),
            chain_der: None,
            mtls_detected: None,
            tls_version: None,
            cipher_suite: None,
            handshake_signature_scheme: None,
            key_algorithm: None,
        }
    }

    /// Validates that a successful observation is dropped and counted when the
    /// request can't carry its leaf, which the model requires on a success:
    /// one byte over the limit, missing, empty or not valid base64. A leaf at
    /// the limit is kept.
    #[test]
    fn observation_without_a_sendable_leaf_is_dropped() {
        let with_leaf = |port, leaf: Option<&str>| Observation {
            certificate_der: leaf.map(str::to_string),
            ..observation_with_leaf(port, 1)
        };
        let (batches, dropped) = batch_observations(vec![
            observation_with_leaf(443, MAX_CERTIFICATE_BYTES),
            observation_with_leaf(8443, MAX_CERTIFICATE_BYTES + 1),
            with_leaf(8444, None),
            with_leaf(8445, Some("")),
            with_leaf(8446, Some("@@@@")),
        ]);
        assert_eq!(dropped, 4);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].len(), 1);
        assert_eq!(batches[0][0].port, 443);
    }

    /// Validates the request part of the second batch of two: the cycle ID as
    /// `scanId`, the cycle start in milliseconds as `scanTime`, the batch
    /// counted from 1, the scan metadata, and the observation with its
    /// certificates as DER and its TLS metadata.
    #[test]
    fn request_part_carries_the_batch() {
        let envelope = sample_envelope(42, 1);
        let record = CertDiscoveryRecord {
            envelope: envelope.clone(),
            cycle_id: "i-0abc:1722297600".to_string(),
            cycle_start_ms: 1_722_297_600_123,
            cycle_timestamp: "2024-07-30T00:00:00Z".to_string(),
            cycle_duration_ms: 4523,
            batch_info: BatchInfo { total_batches: 2 },
            scan_complete: Some(true),
            total_targets_probed: Some(10),
            successful_probes: Some(3),
            failed_probes: Some(7),
            dropped_observations: Some(2),
            configured_cert_count: Some(5),
            observations: vec![Observation {
                port: 443,
                sni: Some("api.example.com".to_string()),
                outcome: ProbeOutcome::Success,
                certificate_der: Some("AAEC".to_string()),
                chain_der: Some(vec!["/w==".to_string()]),
                mtls_detected: Some(false),
                tls_version: Some("TLSv1.3".to_string()),
                cipher_suite: Some("TLS_AES_256_GCM_SHA384".to_string()),
                handshake_signature_scheme: Some("ecdsa_secp256r1_sha256".to_string()),
                key_algorithm: Some("EC".to_string()),
            }],
        };

        let expected = RequestPart::new(
            &envelope,
            Entry::Discovery(Discovery {
                scan_time: 1_722_297_600_123,
                scan_id: "i-0abc:1722297600".to_string(),
                observations: vec![request::Observation {
                    port: 443,
                    sni: Some("api.example.com".to_string()),
                    outcome: request::ProbeOutcome::Success,
                    certificate_der: Some(Blob(vec![0x00, 0x01, 0x02])),
                    chain_der: Some(vec![Blob(vec![0xff])]),
                    mtls_detected: Some(false),
                    tls_version: Some("TLSv1.3".to_string()),
                    cipher_suite: Some("TLS_AES_256_GCM_SHA384".to_string()),
                    handshake_signature_scheme: Some("ecdsa_secp256r1_sha256".to_string()),
                    key_algorithm: Some("EC".to_string()),
                }],
                batch_index: 2,
                total_batches: 2,
                scan_complete: Some(true),
                total_targets_probed: Some(10),
                successful_probes: Some(3),
                failed_probes: Some(7),
                dropped_observations: Some(2),
                configured_certificate_count: Some(5),
            }),
        );
        assert_eq!(record.request_part(), Some(expected));
    }

    /// Validates the request's outcome for every probe outcome.
    #[test]
    fn probe_outcome_maps_to_the_request_outcome() {
        for (outcome, expected) in [
            (ProbeOutcome::Success, request::ProbeOutcome::Success),
            (
                ProbeOutcome::ConnectionRefused,
                request::ProbeOutcome::ConnectionRefused,
            ),
            (ProbeOutcome::Timeout, request::ProbeOutcome::Timeout),
            (ProbeOutcome::NotTls, request::ProbeOutcome::NotTls),
            (
                ProbeOutcome::HandshakeError,
                request::ProbeOutcome::HandshakeError,
            ),
        ] {
            assert_eq!(
                request::ProbeOutcome::from(outcome),
                expected,
                "{outcome:?}"
            );
        }
    }

    #[test]
    fn test_empty_observations() {
        let (batches, dropped) = batch_observations(vec![]);
        assert!(batches.is_empty());
        assert_eq!(dropped, 0);
    }

    #[test]
    fn test_observation_serialization() {
        let obs = Observation {
            port: 443,
            sni: Some("api.customer.com".to_string()),
            outcome: ProbeOutcome::Success,
            certificate_der: Some("MIIE...==".to_string()),
            chain_der: Some(vec!["MIID...==".to_string()]),
            mtls_detected: Some(true),
            tls_version: Some("TLSv1.3".to_string()),
            cipher_suite: Some("TLS_AES_256_GCM_SHA384".to_string()),
            handshake_signature_scheme: Some("ecdsa_secp256r1_sha256".to_string()),
            key_algorithm: Some("EC".to_string()),
        };

        let json = serde_json::to_value(&obs).unwrap();
        assert_eq!(json["port"], 443);
        assert_eq!(json["outcome"], "success");
        assert_eq!(json["mtls_detected"], true);
        assert_eq!(json["tls_version"], "TLSv1.3");
        assert_eq!(json["cipher_suite"], "TLS_AES_256_GCM_SHA384");
        assert_eq!(json["handshake_signature_scheme"], "ecdsa_secp256r1_sha256");
        assert_eq!(json["key_algorithm"], "EC");
        assert!(json.get("mtlsDetected").is_none());
        assert!(json.get("tlsVersion").is_none());
    }

    #[test]
    fn test_observation_omits_none_tls_fields() {
        let obs = Observation {
            port: 443,
            sni: None,
            outcome: ProbeOutcome::Success,
            certificate_der: None,
            chain_der: None,
            mtls_detected: None,
            tls_version: None,
            cipher_suite: None,
            handshake_signature_scheme: None,
            key_algorithm: None,
        };
        let json = serde_json::to_value(&obs).unwrap();
        assert!(json.get("tls_version").is_none());
        assert!(json.get("cipher_suite").is_none());
        assert!(json.get("handshake_signature_scheme").is_none());
        assert!(json.get("key_algorithm").is_none());
    }

    /// Validates serialized record fields and the `TelemetryRecord` trait
    /// values for a discovery record with no observations.
    #[test]
    fn test_full_record_serialization_and_trait_contract() {
        let envelope = sample_envelope(42, 0);
        let idempotency_key = envelope.idempotency_key.clone();
        let record = CertDiscoveryRecord {
            envelope,
            cycle_id: "i-0abc:1722297600".to_string(),
            cycle_start_ms: 1_722_297_600_000,
            cycle_timestamp: "2026-07-29T22:00:03Z".to_string(),
            cycle_duration_ms: 4523,
            batch_info: BatchInfo { total_batches: 1 },
            scan_complete: Some(true),
            total_targets_probed: Some(10),
            successful_probes: Some(3),
            failed_probes: Some(7),
            dropped_observations: Some(2),
            configured_cert_count: Some(5),
            observations: vec![],
        };

        let bytes = TelemetryRecord::serialize(&record).expect("serialize discovery record");
        let json: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");

        assert_eq!(json["schema_version"], SCHEMA_VERSION);
        assert_eq!(json["capability"], "acm");
        assert_eq!(json["payload_type"], "cert_discovery");
        assert_eq!(json["batch_sequence"], 42);
        assert_eq!(json["batch_index"], 0);
        assert_eq!(json["agent_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(json["os"], std::env::consts::OS);
        assert_eq!(json["arch"], std::env::consts::ARCH);
        assert_eq!(json["region"], "us-west-2");
        assert_eq!(json["deployment_type"], "ec2");
        assert_eq!(json["host_id"], "i-0abc");
        assert_eq!(json["boot_nonce"], "boot-11112222");
        assert_eq!(json["idempotency_key"], idempotency_key);
        assert_eq!(json["cycle_id"], "i-0abc:1722297600");
        assert_eq!(json["cycle_timestamp"], "2026-07-29T22:00:03Z");
        assert_eq!(json["cycle_duration_ms"], 4523);
        assert_eq!(json["batch_info"]["total_batches"], 1);
        assert!(json["batch_info"].get("batch_index").is_none());
        assert!(json["batch_info"].get("idempotency_key").is_none());
        // Metadata fields present when set.
        assert_eq!(json["scan_complete"], true);
        assert_eq!(json["total_targets_probed"], 10);
        assert_eq!(json["successful_probes"], 3);
        assert_eq!(json["failed_probes"], 7);
        assert_eq!(json["dropped_observations"], 2);
        assert_eq!(json["configured_cert_count"], 5);
        assert!(json.get("account_id").is_none());
        assert!(json.get("payloadType").is_none());

        assert_eq!(record.payload_type(), PayloadType::CertDiscovery);
        assert_eq!(record.capability(), Capability::Acm);
        assert_eq!(record.idempotency_key(), idempotency_key);
    }

    #[test]
    fn test_estimate_size_minimal_observation() {
        let obs = Observation {
            port: 443,
            sni: None,
            outcome: ProbeOutcome::Success,
            certificate_der: None,
            chain_der: None,
            mtls_detected: None,
            tls_version: None,
            cipher_suite: None,
            handshake_signature_scheme: None,
            key_algorithm: None,
        };
        let size = estimate_observation_size(&obs);
        // Base (150) + port (5) + outcome (20) = 175
        assert_eq!(size, 175);
    }

    #[test]
    fn test_estimate_size_full_observation() {
        let obs = Observation {
            port: 8443,
            sni: Some("api.example.com".to_string()),
            outcome: ProbeOutcome::Success,
            certificate_der: Some("AAAA".to_string()),
            chain_der: Some(vec!["BB".to_string(), "CC".to_string()]),
            mtls_detected: Some(true),
            tls_version: Some("TLSv1.3".to_string()),
            cipher_suite: Some("TLS_AES_256_GCM_SHA384".to_string()),
            handshake_signature_scheme: Some("ecdsa_secp256r1_sha256".to_string()),
            key_algorithm: Some("EC".to_string()),
        };
        let size = estimate_observation_size(&obs);
        // Approximate — accounts for renamed/resized TLS metadata fields.
        assert!(size >= 340 && size <= 360, "size was {}", size);
    }

    #[test]
    fn test_estimate_size_with_empty_chain() {
        let obs = Observation {
            port: 443,
            sni: None,
            outcome: ProbeOutcome::Success,
            certificate_der: Some("cert-data".to_string()),
            chain_der: Some(vec![]),
            mtls_detected: None,
            tls_version: None,
            cipher_suite: None,
            handshake_signature_scheme: None,
            key_algorithm: None,
        };
        let size = estimate_observation_size(&obs);
        // Base (150) + port (5) + outcome (20) + cert (9) = 184
        assert_eq!(size, 184);
    }
}
