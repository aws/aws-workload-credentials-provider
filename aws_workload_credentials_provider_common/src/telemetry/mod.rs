//! Telemetry building blocks shared by the agent's capabilities. Each
//! capability runs in its own process with its own client. Only the ACM
//! capability sends telemetry today.

pub mod drain;
pub mod identity;
pub mod metrics;
pub mod payload;
pub mod queue;
pub mod request;
pub mod sender;

pub use drain::TelemetryQueue;
pub use identity::{AgentIdentity, IdentityError};
pub use metrics::{
    Counter, CumulativeHistogram, Gauge, Label, LabeledCounter, LabeledHistogram, Metric,
    MetricValue,
};
pub use payload::{
    Blob, Capability, DeploymentType, EnvelopeError, PayloadEnvelope, PayloadType, TelemetryRecord,
    MAX_REQUEST_BYTES, SCHEMA_VERSION,
};
pub use queue::BoundedQueue;
pub use request::{
    AutomationFailure, AutomationRecord, AutomationResult, AutomationStage, AutomationSuccess,
    Discovery, Entry, FilesOnDisk, Observation, ProbeOutcome, RequestPart, MAX_ENTRIES,
};
pub use sender::{SendError, TelemetrySender};

// Re-exported so consumers use `telemetry::TelemetryConfig`; the raw
// `TelemetryConfigInput` stays private to `config`.
pub use crate::config::types::TelemetryConfig;
