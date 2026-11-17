//! Configuration validation module for the AWS Workload Credentials Provider.
//!
//! This module provides comprehensive validation for TOML configuration files,
//! supporting both legacy flat format (ASM-only) and nested multi-capability format.
//!
//! # Features
//!
//! - TOML syntax validation with descriptive error messages
//! - Type and range validation for configuration fields
//! - ARN format validation for certificates and IAM roles
//! - File path validation for certificate deployment
//! - Cross-field validation for configuration consistency
//! - Collect-all-errors strategy for comprehensive feedback

// Allow unused code during development - validators will be implemented in subsequent commits
#![allow(dead_code)]
#![allow(unused_imports)]

mod error;
pub mod error_messages;
pub(crate) mod field_validators;
#[cfg(unix)]
pub mod sudoers;
#[cfg(unix)]
pub mod systemd;
pub mod types;
pub mod validator;
pub mod watcher_config;

pub use error::{ErrorCollector, ValidationError, ValidationErrorCode, ValidationErrors};
pub use field_validators::{validate_watcher_directories, validate_watcher_id};
pub use types::{WatcherDirectories, DEFAULT_WATCHER_CONFIG_DIR, DEFAULT_WATCHER_REQUESTS_DIR};
