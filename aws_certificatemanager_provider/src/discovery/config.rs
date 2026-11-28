//! Configuration types for the certificate discovery module.
//!
//! The canonical types (`DiscoveryConfigInput`, `DiscoveryConfig`) live in
//! `aws_workload_credentials_provider_common::config::types` so the config
//! parser can reach them through `AcmConfigInput`. This module re-exports
//! them for convenience within the provider crate.

pub use aws_workload_credentials_provider_common::config::types::{
    DiscoveryConfig, DiscoveryConfigInput,
};
