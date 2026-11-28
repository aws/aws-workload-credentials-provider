//! Certificate discovery module.

pub mod config;
mod engine;
pub mod payload;
pub mod scheduler;
pub mod telemetry;

pub use config::DiscoveryConfig;
pub(crate) use engine::{probe_targets_for, select_resolver, ProbeStats, SelectedResolver};
#[cfg(test)]
pub(crate) use engine::{probe_targets_with, test_support};
pub use payload::{CertDiscoveryRecord, Observation, ProbeOutcome};
pub use scheduler::run_discovery_loop;
pub use telemetry::{LogOnlySubmitter, SenderSubmitter, TelemetrySubmitter};
