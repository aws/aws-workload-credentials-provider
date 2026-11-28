//! ACM certificate automation telemetry records.

pub(crate) mod automation;
pub(crate) mod certificates;
pub mod payload;

pub use payload::{
    AutomationSequence, CertAutomationRecord, FailureCode, FilesOnDisk, RefreshOutcome,
    RenewalFailure, RenewalStage, SuccessStatus,
};
