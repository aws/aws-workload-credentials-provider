//! The telemetry payload contract shared by every capability.
//!
//! Wire values (`Capability`, `PayloadType`, `DeploymentType`) and envelope
//! field names must not change once released. Closed sets are snake_case enums,
//! so a typo fails to compile instead of misrouting a payload.

use std::fmt;

use base64ct::{Base64, Encoding};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::request::RequestPart;

/// Telemetry payload schema version. Bumped only for breaking envelope changes;
/// additive changes (new fields, new record types) keep the same version.
pub const SCHEMA_VERSION: u32 = 1;

/// Capability that owns a payload. The telemetry service routes on the wire
/// values (`secrets_manager`, `acm`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    SecretsManager,
    Acm,
}

impl Capability {
    /// Wire value, for the idempotency key and logging.
    pub fn as_str(self) -> &'static str {
        match self {
            Capability::SecretsManager => "secrets_manager",
            Capability::Acm => "acm",
        }
    }
}

/// Record type the telemetry service routes on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadType {
    /// Metrics, events, and logs (Secrets Manager and ACM).
    MetricsBatch,
    /// ACM certificate discovery observations.
    CertDiscovery,
    /// ACM certificate automation outcomes.
    CertAutomation,
}

impl PayloadType {
    /// Wire value, for the idempotency key and logging.
    pub fn as_str(self) -> &'static str {
        match self {
            PayloadType::MetricsBatch => "metrics_batch",
            PayloadType::CertDiscovery => "cert_discovery",
            PayloadType::CertAutomation => "cert_automation",
        }
    }
}

/// Best-effort compute environment; `Other` covers the rest. An enum so wire
/// values can't drift (`on_prem` vs `onprem`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentType {
    Ec2,
    Ecs,
    Eks,
    Lambda,
    OnPrem,
    Other,
}

/// Most bytes one encoded request may take (CBOR when sent, JSON in a dry
/// run). The sender rejects a larger request; the drain drops a record too
/// large for a request of its own and groups automation records up to this
/// size. This is well under the service's 1 MB limit, which applies with
/// certificates in base64 (a third larger). One automation record or
/// observation at the service model's limits (a 16,384-byte certificate and 5
/// chain certificates) is about 132 KB as JSON and less as CBOR, so it fits in
/// a request of its own.
pub const MAX_REQUEST_BYTES: usize = 256_000;

/// Why a value couldn't be encoded as CBOR.
pub(crate) type CborError = ciborium::ser::Error<std::io::Error>;

/// A telemetry record ready to send. Every payload type implements it, so the
/// emitter can serialize and route a record without knowing its type.
pub trait TelemetryRecord: Send + Sync {
    fn payload_type(&self) -> PayloadType;
    fn capability(&self) -> Capability;
    /// Full JSON payload (envelope + body), which a dry run logs for a record
    /// type without a [`Self::request_part`].
    fn serialize(&self) -> Result<Vec<u8>, serde_json::Error>;
    /// The record's part of a `PutCertificateTelemetry` request: its entry,
    /// plus the idempotency key and identity from its envelope. Build it with
    /// [`RequestPart::new`] from the envelope whose key
    /// [`Self::idempotency_key`] returns, since that key becomes the request's
    /// `idempotencyKey`, and with an entry of [`Self::payload_type`]. The
    /// sender rejects a part with another key or entry type. `None` for a
    /// record type the request can't carry, which the sender rejects outside
    /// a dry run.
    fn request_part(&self) -> Option<RequestPart> {
        None
    }
    /// Stable dedup key, set at creation and unchanged across retries. See [`idempotency_key`].
    fn idempotency_key(&self) -> &str;
}

/// `value` as CBOR. Smithy RPC v2 CBOR keys a structure by its member names
/// and leaves out absent members, so an optional field needs
/// `#[serde(skip_serializing_if = "Option::is_none")]`; it sends a blob as a
/// byte string, so a blob field needs [`Blob`].
pub(crate) fn to_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, CborError> {
    let mut cbor = Vec::new();
    ciborium::into_writer(value, &mut cbor)?;
    Ok(cbor)
}

/// A Smithy blob, such as a certificate's DER: a byte string in CBOR, as the
/// protocol sends it, and base64 in JSON, so a dry run's JSON stays text. It
/// reads back from either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blob(pub Vec<u8>);

impl Serialize for Blob {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&Base64::encode_string(&self.0))
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for Blob {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BlobVisitor;

        impl Visitor<'_> for BlobVisitor {
            type Value = Blob;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("base64 text or a byte string")
            }

            fn visit_str<E: de::Error>(self, base64: &str) -> Result<Blob, E> {
                Base64::decode_vec(base64).map(Blob).map_err(E::custom)
            }

            fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> Result<Blob, E> {
                Ok(Blob(bytes.to_vec()))
            }

            fn visit_byte_buf<E: de::Error>(self, bytes: Vec<u8>) -> Result<Blob, E> {
                Ok(Blob(bytes))
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(BlobVisitor)
        } else {
            // Unlike `deserialize_bytes`, ciborium's `deserialize_byte_buf` reads
            // a byte string of any length, in one segment or several.
            deserializer.deserialize_byte_buf(BlobVisitor)
        }
    }
}

/// Separator joining the idempotency-key components.
const KEY_SEPARATOR: char = ':';

/// Error building a [`PayloadEnvelope`].
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    /// `host_id` was empty (identity detection must have produced a value).
    EmptyHostId,
    /// `boot_nonce` was empty (loses the across-restart uniqueness guarantee).
    EmptyBootNonce,
    /// `boot_nonce` contained the key separator. Keeping it separator-free is
    /// what lets `host_id` safely contain colons.
    BootNonceContainsSeparator,
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnvelopeError::EmptyHostId => write!(f, "host_id must be non-empty"),
            EnvelopeError::EmptyBootNonce => write!(f, "boot_nonce must be non-empty"),
            EnvelopeError::BootNonceContainsSeparator => {
                write!(f, "boot_nonce must not contain '{KEY_SEPARATOR}'")
            }
        }
    }
}

impl std::error::Error for EnvelopeError {}

/// Metadata on every telemetry payload. Records embed it with
/// `#[serde(flatten)]` and add their own body. Unlike the `*Input` config
/// types, it allows unknown fields, for forward compatibility.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PayloadEnvelope {
    /// Payload schema version. See [`SCHEMA_VERSION`].
    pub schema_version: u32,

    /// Owning capability.
    pub capability: Capability,

    /// Record type the service routes on.
    pub payload_type: PayloadType,

    /// Monotonic per-process flush counter, for gap detection. It resets on
    /// restart, hence `boot_nonce` in the key.
    pub batch_sequence: u64,

    /// Which piece of a size-split flush this is (0-based). A separate field so
    /// the service never parses it out of `idempotency_key`.
    pub batch_index: u32,

    /// Agent semantic version.
    pub agent_version: String,

    /// Operating system (`std::env::consts::OS`, e.g. `linux`, `windows`).
    pub os: String,

    /// CPU architecture (`std::env::consts::ARCH`, e.g. `x86_64`, `aarch64`).
    pub arch: String,

    /// AWS region the agent reports from.
    pub region: String,

    /// Best-effort compute environment.
    pub deployment_type: DeploymentType,

    /// Agent instance ID, non-empty and first in the key. The `identity` module
    /// resolves it.
    pub host_id: String,

    /// Per-process nonce (UUID) set once at startup; distinguishes runs since
    /// `batch_sequence` resets on restart.
    pub boot_nonce: String,

    /// Stable dedup key. See [`idempotency_key`].
    pub idempotency_key: String,
}

impl PayloadEnvelope {
    /// Fills `schema_version`/`os`/`arch` from constants and computes the key.
    /// Rejects empty `host_id`, and empty/separator-containing `boot_nonce`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        capability: Capability,
        payload_type: PayloadType,
        batch_sequence: u64,
        batch_index: u32,
        host_id: impl Into<String>,
        boot_nonce: impl Into<String>,
        agent_version: impl Into<String>,
        region: impl Into<String>,
        deployment_type: DeploymentType,
    ) -> Result<Self, EnvelopeError> {
        let host_id = host_id.into();
        if host_id.is_empty() {
            return Err(EnvelopeError::EmptyHostId);
        }
        let boot_nonce = boot_nonce.into();
        if boot_nonce.is_empty() {
            return Err(EnvelopeError::EmptyBootNonce);
        }
        if boot_nonce.contains(KEY_SEPARATOR) {
            return Err(EnvelopeError::BootNonceContainsSeparator);
        }
        let idempotency_key = idempotency_key(
            &host_id,
            &boot_nonce,
            capability,
            payload_type,
            batch_sequence,
            batch_index,
        );
        Ok(Self {
            schema_version: SCHEMA_VERSION,
            capability,
            payload_type,
            batch_sequence,
            batch_index,
            agent_version: agent_version.into(),
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            region: region.into(),
            deployment_type,
            host_id,
            boot_nonce,
            idempotency_key,
        })
    }
}

/// Stable idempotency key:
/// `{host_id}:{boot_nonce}:{capability}:{payload_type}:{batch_sequence}:{batch_index}`.
///
/// Uniqueness comes from `boot_nonce` and `batch_sequence`, not the clock, so a
/// repeated or rewound clock can't cause a collision. The service treats the key
/// as opaque; every component is also an envelope field. `host_id` may contain
/// the separator (ARNs). That is safe because every other component is
/// separator-free ([`PayloadEnvelope::new`] checks `boot_nonce`).
pub fn idempotency_key(
    host_id: &str,
    boot_nonce: &str,
    capability: Capability,
    payload_type: PayloadType,
    batch_sequence: u64,
    batch_index: u32,
) -> String {
    format!(
        "{host_id}:{boot_nonce}:{}:{}:{batch_sequence}:{batch_index}",
        capability.as_str(),
        payload_type.as_str()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal record to exercise the trait contract.
    #[derive(Serialize)]
    struct FakeRecord {
        #[serde(flatten)]
        envelope: PayloadEnvelope,
        batch: FakeBody,
    }

    #[derive(Serialize)]
    struct FakeBody {
        value: u64,
    }

    impl FakeRecord {
        fn sample() -> Self {
            let envelope = PayloadEnvelope::new(
                Capability::SecretsManager,
                PayloadType::MetricsBatch,
                42,
                0,
                "i-0abc123def456789a",
                "boot-11112222",
                "3.1.1",
                "us-west-2",
                DeploymentType::Ec2,
            )
            .expect("non-empty host_id");
            Self {
                envelope,
                batch: FakeBody { value: 7 },
            }
        }
    }

    impl TelemetryRecord for FakeRecord {
        fn payload_type(&self) -> PayloadType {
            self.envelope.payload_type
        }
        fn capability(&self) -> Capability {
            self.envelope.capability
        }
        fn serialize(&self) -> Result<Vec<u8>, serde_json::Error> {
            serde_json::to_vec(self)
        }
        fn idempotency_key(&self) -> &str {
            &self.envelope.idempotency_key
        }
    }

    #[test]
    fn idempotency_key_format() {
        assert_eq!(
            idempotency_key(
                "i-0abc123def456789a",
                "boot-11112222",
                Capability::SecretsManager,
                PayloadType::MetricsBatch,
                42,
                0
            ),
            "i-0abc123def456789a:boot-11112222:secrets_manager:metrics_batch:42:0"
        );
    }

    #[test]
    fn idempotency_key_disambiguates_payload_types() {
        // Same host, nonce, capability, sequence, and index but different payload
        // types must not collide.
        let discovery = idempotency_key(
            "i-0abc",
            "boot-1",
            Capability::Acm,
            PayloadType::CertDiscovery,
            0,
            0,
        );
        let automation = idempotency_key(
            "i-0abc",
            "boot-1",
            Capability::Acm,
            PayloadType::CertAutomation,
            0,
            0,
        );
        assert_ne!(discovery, automation);
    }

    #[test]
    fn idempotency_key_stable_within_same_second() {
        // Two flushes in the same second must not collide: uniqueness comes
        // from batch_sequence, not the clock.
        let first = idempotency_key(
            "i-0abc",
            "boot-1",
            Capability::SecretsManager,
            PayloadType::MetricsBatch,
            5,
            0,
        );
        let second = idempotency_key(
            "i-0abc",
            "boot-1",
            Capability::SecretsManager,
            PayloadType::MetricsBatch,
            6,
            0,
        );
        assert_ne!(first, second);
    }

    #[test]
    fn new_rejects_empty_host_id() {
        let err = PayloadEnvelope::new(
            Capability::SecretsManager,
            PayloadType::MetricsBatch,
            0,
            0,
            "",
            "boot-1",
            "3.1.1",
            "us-west-2",
            DeploymentType::Ec2,
        )
        .unwrap_err();
        assert_eq!(err, EnvelopeError::EmptyHostId);
    }

    #[test]
    fn new_rejects_bad_boot_nonce() {
        let empty = PayloadEnvelope::new(
            Capability::SecretsManager,
            PayloadType::MetricsBatch,
            0,
            0,
            "i-0abc",
            "",
            "3.1.1",
            "us-west-2",
            DeploymentType::Ec2,
        )
        .unwrap_err();
        assert_eq!(empty, EnvelopeError::EmptyBootNonce);

        // A colon in host_id is allowed (ECS/Lambda ARNs); a colon in the
        // agent-generated boot_nonce is a construction bug and is rejected.
        let sep = PayloadEnvelope::new(
            Capability::SecretsManager,
            PayloadType::MetricsBatch,
            0,
            0,
            "arn:aws:ecs:us-west-2:123456789012:task/abc",
            "boot:nonce",
            "3.1.1",
            "us-west-2",
            DeploymentType::Ec2,
        )
        .unwrap_err();
        assert_eq!(sep, EnvelopeError::BootNonceContainsSeparator);
    }

    #[test]
    fn new_allows_colon_in_host_id() {
        // An ECS task ARN, the documented host_id source on ECS, is accepted.
        let env = PayloadEnvelope::new(
            Capability::SecretsManager,
            PayloadType::MetricsBatch,
            7,
            0,
            "arn:aws:ecs:us-west-2:123456789012:task/abc",
            "boot-9f2a",
            "3.1.1",
            "us-west-2",
            DeploymentType::Ecs,
        )
        .expect("ARN host_id is valid");
        assert!(env
            .idempotency_key
            .ends_with(":secrets_manager:metrics_batch:7:0"));
    }

    #[test]
    fn as_str_matches_serialized_wire_value() {
        // as_str() (used in the key) and the serde wire value (used in the
        // fields) declare the same string separately, so they must match.
        for capability in [Capability::SecretsManager, Capability::Acm] {
            assert_eq!(
                serde_json::to_string(&capability).unwrap(),
                format!("\"{}\"", capability.as_str())
            );
        }
        for payload_type in [
            PayloadType::MetricsBatch,
            PayloadType::CertDiscovery,
            PayloadType::CertAutomation,
        ] {
            assert_eq!(
                serde_json::to_string(&payload_type).unwrap(),
                format!("\"{}\"", payload_type.as_str())
            );
        }
    }

    #[test]
    fn record_serializes_with_flattened_envelope() {
        let record = FakeRecord::sample();
        // Trait method, disambiguated from the derived serde `serialize`.
        let bytes = TelemetryRecord::serialize(&record).expect("serialize");
        let json: serde_json::Value = serde_json::from_slice(&bytes).expect("valid json");

        // Envelope fields appear at the top level (flattened), not nested.
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["capability"], "secrets_manager");
        assert_eq!(json["payload_type"], "metrics_batch");
        assert_eq!(json["deployment_type"], "ec2");
        assert_eq!(json["batch_sequence"], 42);
        assert_eq!(json["batch_index"], 0);
        assert_eq!(json["host_id"], "i-0abc123def456789a");
        assert_eq!(
            json["idempotency_key"],
            "i-0abc123def456789a:boot-11112222:secrets_manager:metrics_batch:42:0"
        );
        // Body sits under its own key.
        assert_eq!(json["batch"]["value"], 7);
    }

    #[test]
    fn envelope_round_trips() {
        let record = FakeRecord::sample();
        let bytes = serde_json::to_vec(&record.envelope).unwrap();
        let back: PayloadEnvelope = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(record.envelope, back);
    }

    #[test]
    fn cbor_keys_members_by_name_leaves_out_absent_ones_and_sends_a_blob_as_bytes() {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Observation {
            port: u16,
            #[serde(skip_serializing_if = "Option::is_none")]
            sni: Option<String>,
            certificate_der: Blob,
        }
        let observation = Observation {
            port: 443,
            sni: None,
            certificate_der: Blob(vec![0x30, 0x82]),
        };
        // A two-member map: "port" 443, then "certificateDer" and a
        // two-byte byte string.
        let cbor = [
            &[0xa2, 0x64][..],
            b"port",
            &[0x19, 0x01, 0xbb, 0x6e],
            b"certificateDer",
            &[0x42, 0x30, 0x82],
        ]
        .concat();
        assert_eq!(to_cbor(&observation).unwrap(), cbor);
        // JSON carries the blob as base64 text.
        assert_eq!(
            serde_json::to_string(&observation).unwrap(),
            r#"{"port":443,"certificateDer":"MII="}"#
        );
    }

    #[test]
    fn a_blob_reads_back_from_json_and_cbor() {
        let blob = Blob(vec![0x30, 0x82, 0x01]);
        let json = serde_json::to_string(&blob).unwrap();
        assert_eq!(serde_json::from_str::<Blob>(&json).unwrap(), blob);
        let cbor = to_cbor(&blob).unwrap();
        assert_eq!(ciborium::from_reader::<Blob, _>(&cbor[..]).unwrap(), blob);
        assert!(serde_json::from_str::<Blob>(r#""not base64!""#).is_err());

        // Over ciborium's 4096-byte read buffer, as a certificate chain can be.
        let large = Blob(vec![0x30; 4097]);
        let cbor = to_cbor(&large).unwrap();
        assert_eq!(ciborium::from_reader::<Blob, _>(&cbor[..]).unwrap(), large);
        // An indefinite-length byte string, in two segments.
        let segments: &[u8] = &[0x5f, 0x42, 0x01, 0x02, 0x41, 0x03, 0xff];
        assert_eq!(
            ciborium::from_reader::<Blob, _>(segments).unwrap(),
            Blob(vec![0x01, 0x02, 0x03])
        );
    }

    #[test]
    fn trait_accessors_match_envelope() {
        let record = FakeRecord::sample();
        assert_eq!(record.payload_type(), PayloadType::MetricsBatch);
        assert_eq!(record.capability(), Capability::SecretsManager);
        assert_eq!(
            record.idempotency_key(),
            "i-0abc123def456789a:boot-11112222:secrets_manager:metrics_batch:42:0"
        );
    }
}
