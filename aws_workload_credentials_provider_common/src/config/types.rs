//! Configuration data models and format detection.
//!
//! This module contains (ordered from highest to lowest level):
//! - Validated configuration types (ValidatedConfig, LoggingConfig, SecretsManagerConfig, AcmConfig)
//! - Component configuration types (CacheConfig, SecurityConfig, CertificateConfig)
//! - Enums (LogLevel)
//! - Raw TOML deserialization structures (ConfigInput, CapabilitiesConfig, etc.)

use serde::Deserialize;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::str::FromStr;

use crate::fs_permissions::PathPermission;
#[cfg(windows)]
use crate::fs_permissions::{Rights, TrusteeType};

use super::error::{ValidationError, ValidationErrorCode};

// ============================================================================
// Validated Configuration Types
// ============================================================================

/// Validated configuration result.
#[derive(Debug, Clone)]
pub struct ValidatedConfig {
    /// Logging configuration
    pub logging: LoggingConfig,
    /// AWS Secrets Manager configuration
    pub secrets_manager: SecretsManagerConfig,
    /// ACM configuration (optional)
    pub acm: Option<AcmConfig>,
}

/// Logging configuration for the provider.
#[derive(Debug, Clone)]
pub struct LoggingConfig {
    /// The level of logging the provider provides (debug, info, warn, error, or none)
    pub log_level: LogLevel,

    /// Where logs are written (file or stdout)
    pub log_to_file: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            log_level: LogLevel::Info,
            log_to_file: true,
        }
    }
}

/// AWS Secrets Manager capability configuration.
#[derive(Debug, Clone)]
pub struct SecretsManagerConfig {
    /// Whether the Secrets Manager capability is enabled
    pub enabled: bool,

    /// The port for the local HTTP server
    pub http_port: u16,

    /// Cache configuration
    pub cache: CacheConfig,

    /// Security configuration
    pub security: SecurityConfig,

    /// The prefix for path-based requests
    pub path_prefix: String,

    /// The maximum number of simultaneous connections
    pub max_conn: usize,

    /// The maximum number of assumed roles for cross-account access.
    pub max_roles: usize,

    /// The AWS Region for Secrets Manager requests (None uses SDK default)
    pub region: Option<String>,

    /// Whether to serve cached data on transient refresh errors
    pub ignore_transient_errors: bool,

    /// Whether to validate AWS credentials at startup
    pub validate_credentials: bool,

    /// Pre-fetch configuration for warming the cache at startup
    pub prefetch: PrefetchConfig,

    /// Optional path to a credentials file for file-based credential loading
    pub credentials_file_path: Option<PathBuf>,
}

impl Default for SecretsManagerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            http_port: 2773,
            cache: CacheConfig::default(),
            security: SecurityConfig::default(),
            path_prefix: "/v1/".to_string(),
            max_conn: 800,
            max_roles: 20,
            region: None,
            ignore_transient_errors: true,
            validate_credentials: true,
            prefetch: PrefetchConfig::default(),
            credentials_file_path: None,
        }
    }
}

/// ACM (Certificate Manager) capability configuration.
#[derive(Debug, Default, Clone)]
pub struct AcmConfig {
    /// Whether the ACM capability is enabled
    pub enabled: bool,

    /// Certificate configurations keyed by certificate ARN
    pub certificates: HashMap<String, CertificateConfig>,
}

/// Cache configuration for Secrets Manager capability.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// The time to live (TTL) of a cached secret in seconds
    pub ttl_seconds: u16,

    /// Maximum number of secrets that can be stored in the cache
    pub cache_size: NonZeroUsize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            ttl_seconds: 300,
            cache_size: NonZeroUsize::new(1000).unwrap(),
        }
    }
}

/// Security configuration for Secrets Manager capability.
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// List of request headers checked for the SSRF token
    pub ssrf_headers: Vec<String>,

    /// List of environment variable names to search for the SSRF token
    pub ssrf_env_variables: Vec<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            ssrf_headers: vec![
                "X-Aws-Parameters-Secrets-Token".to_string(),
                "X-Vault-Token".to_string(),
            ],
            ssrf_env_variables: vec![
                "AWS_TOKEN".to_string(),
                "AWS_SESSION_TOKEN".to_string(),
                "AWS_CONTAINER_AUTHORIZATION_TOKEN".to_string(),
            ],
        }
    }
}

/// Pre-fetch configuration for warming the cache at startup.
#[derive(Debug, Clone)]
pub struct PrefetchConfig {
    /// Maximum fraction of cache to fill per caching client (0.1 - 1.0).
    pub cache_buffer_ratio: f32,

    /// Maximum random jitter in seconds before starting prefetch (0 - 10).
    /// Helps prevent fleet-wide synchronized API calls. Default is 0 (no jitter).
    pub max_jitter_seconds: u64,

    /// Tag-based filtering: each entry is a { key, role_arn? } tuple.
    pub filter_tags: Vec<TagFilter>,

    /// Explicit secrets to pre-fetch.
    pub secrets: Vec<SecretPrefetchConfig>,
}

impl Default for PrefetchConfig {
    fn default() -> Self {
        Self {
            cache_buffer_ratio: 0.8,
            max_jitter_seconds: 0,
            filter_tags: Vec::new(),
            secrets: Vec::new(),
        }
    }
}

impl PrefetchConfig {
    /// Returns true if there are any secrets or tag filters configured.
    pub fn is_enabled(&self) -> bool {
        !self.filter_tags.is_empty() || !self.secrets.is_empty()
    }
}

/// A single tag filter entry for tag-based pre-fetching.
#[derive(Debug, Clone)]
pub struct TagFilter {
    pub key: String,
    pub role_arn: Option<String>,
}

/// A single secret to pre-fetch.
#[derive(Debug, Clone)]
pub struct SecretPrefetchConfig {
    pub secret_id: String,
    pub role_arn: Option<String>,
}

/// Individual certificate configuration for ACM.
#[derive(Debug, Clone)]
pub struct CertificateConfig {
    /// ARN of the ACM certificate to retrieve
    pub certificate_arn: String,

    /// Absolute path where the certificate will be written
    pub certificate_path: PathBuf,

    /// Absolute path where the private key will be written
    pub private_key_path: PathBuf,

    /// Optional path where the certificate chain will be written.
    /// When None, the chain is appended to certificate_path to produce a fullchain file.
    pub chain_path: Option<PathBuf>,

    /// IAM role ARN to assume when retrieving the certificate
    pub role_arn: String,

    /// Optional, update permissions of cert files, otherwise leaves default owner only permission
    pub cert_and_chain_permission: Option<PathPermission>,

    /// Optional, update permission of key file, otherwise leaves default owner only permission
    pub key_permission: Option<PathPermission>,

    /// Optional command to execute after certificate refresh
    pub refresh_command: Option<String>,
}

// ============================================================================
// Enums
// ============================================================================

/// Log levels supported by the provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogLevel {
    Debug,
    #[default]
    Info,
    Warn,
    Error,
    None,
}

impl FromStr for LogLevel {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "debug" => Ok(LogLevel::Debug),
            "info" => Ok(LogLevel::Info),
            "warn" => Ok(LogLevel::Warn),
            "error" => Ok(LogLevel::Error),
            "none" => Ok(LogLevel::None),
            _ => Err(ValidationError::with_guidance(
                "log_level".to_string(),
                ValidationErrorCode::InvalidLogLevel,
                crate::config::error_messages::INVALID_LOG_LEVEL_ERR_MSG.to_string(),
                format!("Got: '{}'", s),
            )),
        }
    }
}

// ============================================================================
// Raw TOML Deserialization Structures
// ============================================================================

/// Unified configuration format supporting both flat and nested keys.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ConfigInput {
    // Flat Secrets Manager keys at root level (for backward compatibility)
    pub log_level: Option<String>,
    pub log_to_file: Option<bool>,
    pub http_port: Option<toml::Value>,
    pub ttl_seconds: Option<toml::Value>,
    pub cache_size: Option<toml::Value>,
    pub ssrf_headers: Option<Vec<String>>,
    pub ssrf_env_variables: Option<Vec<String>>,
    pub path_prefix: Option<String>,
    pub max_conn: Option<toml::Value>,
    pub max_roles: Option<toml::Value>,
    pub region: Option<String>,
    pub ignore_transient_errors: Option<bool>,
    pub validate_credentials: Option<bool>,
    #[serde(default)]
    pub prefetch: Option<PrefetchConfigInput>,
    pub credentials_file_path: Option<PathBuf>,

    // Nested capabilities
    pub capabilities: Option<CapabilitiesConfig>,

    // Nested logging
    pub logging: Option<LoggingConfigInput>,
}

/// Capabilities section containing Secrets Manager and ACM configurations.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CapabilitiesConfig {
    pub secrets_manager: Option<SecretsManagerConfigInput>,
    pub acm: Option<AcmConfigInput>,
}

/// Secrets Manager configuration in nested format.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SecretsManagerConfigInput {
    pub enabled: Option<bool>,
    pub http_port: Option<u16>,
    pub cache: Option<CacheConfigInput>,
    pub security: Option<SecurityConfigInput>,
    pub path_prefix: Option<String>,
    pub max_conn: Option<usize>,
    pub max_roles: Option<usize>,
    pub region: Option<String>,
    pub ignore_transient_errors: Option<bool>,
    pub validate_credentials: Option<bool>,
    #[serde(default)]
    pub prefetch: Option<PrefetchConfigInput>,
    pub credentials_file_path: Option<PathBuf>,
}

/// Cache configuration in nested format.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CacheConfigInput {
    pub ttl_seconds: Option<u16>,
    pub cache_size: Option<usize>,
}

/// Security configuration in nested format.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfigInput {
    pub ssrf_headers: Option<Vec<String>>,
    pub ssrf_env_variables: Option<Vec<String>>,
}

/// Logging configuration in nested format.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfigInput {
    pub log_level: Option<String>,
    pub log_to_file: Option<bool>,
}

/// Pre-fetch configuration input from TOML.
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct PrefetchConfigInput {
    pub cache_buffer_ratio: Option<f32>,
    pub max_jitter_seconds: Option<u64>,
    #[serde(default)]
    pub filter_tags: Vec<TagFilterInput>,
    #[serde(default)]
    pub secrets: Vec<SecretPrefetchConfigInput>,
}

/// Tag filter input from TOML.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct TagFilterInput {
    pub key: String,
    pub role_arn: Option<String>,
}

/// Secret prefetch input from TOML.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SecretPrefetchConfigInput {
    pub secret_id: String,
    pub role_arn: Option<String>,
}

/// ACM configuration in nested format.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AcmConfigInput {
    pub enabled: Option<bool>,
    pub certificates: Option<Vec<CertificateConfigInput>>,
    pub default_certificate_permission: Option<PermissionConfig>,
    pub default_key_permission: Option<PermissionConfig>,
}

#[cfg(unix)]
#[derive(Clone, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct PermissionConfig {
    pub mode: String,
}

#[cfg(windows)]
#[derive(Clone, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct PermissionConfig {
    pub trustee_type: TrusteeType,
    pub trustee_name: String,
    pub rights: Rights,
}

/// Individual certificate configuration for ACM.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateConfigInput {
    pub certificate_arn: Option<String>,
    pub certificate_path: Option<String>,
    pub private_key_path: Option<String>,
    pub chain_path: Option<String>,
    pub role_arn: Option<String>,
    pub refresh_command: Option<String>,
    pub certificate_and_chain_permission: Option<PermissionConfig>,
    pub key_permission: Option<PermissionConfig>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secrets_manager_config_defaults() {
        let config = SecretsManagerConfig::default();
        assert!(config.enabled);
        assert_eq!(config.http_port, 2773);
        assert_eq!(config.cache.ttl_seconds, 300);
        assert_eq!(config.cache.cache_size.get(), 1000);
        assert_eq!(config.max_conn, 800);
        assert!(config.ignore_transient_errors);
        assert!(config.validate_credentials);
    }

    #[test]
    fn test_acm_config_defaults() {
        let config = AcmConfig::default();
        assert!(!config.enabled);
        assert!(config.certificates.is_empty());
    }

    #[test]
    fn test_log_level_parse_valid() {
        assert_eq!("debug".parse::<LogLevel>().unwrap(), LogLevel::Debug);
        assert_eq!("info".parse::<LogLevel>().unwrap(), LogLevel::Info);
        assert_eq!("warn".parse::<LogLevel>().unwrap(), LogLevel::Warn);
        assert_eq!("error".parse::<LogLevel>().unwrap(), LogLevel::Error);
        assert_eq!("none".parse::<LogLevel>().unwrap(), LogLevel::None);

        // Case-insensitive
        assert_eq!("DEBUG".parse::<LogLevel>().unwrap(), LogLevel::Debug);
        assert_eq!("Info".parse::<LogLevel>().unwrap(), LogLevel::Info);
    }

    #[test]
    fn test_log_level_parse_invalid() {
        let result = "invalid".parse::<LogLevel>();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ValidationErrorCode::InvalidLogLevel);
        assert_eq!(err.field, "log_level");
        assert_eq!(
            err.message,
            crate::config::error_messages::INVALID_LOG_LEVEL_ERR_MSG
        );
        assert_eq!(err.guidance, Some("Got: 'invalid'".to_string()));
    }

    #[test]
    fn test_log_level_default() {
        assert_eq!(LogLevel::default(), LogLevel::Info);
    }

    #[test]
    fn test_logging_config_default() {
        let config = LoggingConfig::default();
        assert_eq!(config.log_level, LogLevel::Info);
        assert!(config.log_to_file);
    }
}
