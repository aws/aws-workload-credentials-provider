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

/// Validated configuration result. Callers start from
/// `ValidatedConfig::default()` and override what they need.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ValidatedConfig {
    /// Logging configuration
    pub logging: LoggingConfig,
    /// AWS Secrets Manager configuration
    pub secrets_manager: SecretsManagerConfig,
    /// ACM configuration (optional)
    pub acm: Option<AcmConfig>,
    /// Non-fatal findings from validation, to be logged once the logger is
    /// initialized. Validation runs before any logger exists, so a `log`
    /// call made during validation would be dropped.
    pub warnings: Vec<String>,
    /// Telemetry configuration (opt-in, per capability)
    pub telemetry: TelemetryConfig,
}

/// What telemetry the customer consented to send, and whether to dry-run it.
/// All fields default to `false`. `secrets_manager_enabled` and `acm_enabled`
/// come from `[telemetry.<capability>] enabled`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TelemetryConfig {
    /// Whether `[telemetry.secrets_manager]` is enabled. Nothing sends Secrets
    /// Manager telemetry, so it has no effect.
    pub secrets_manager_enabled: bool,

    /// ACM telemetry enabled (opt-in, default off). Covers automation records
    /// and everything else the ACM process sends, except discovery records.
    pub acm_enabled: bool,

    /// Whether certificate discovery is on (`[capabilities.acm] enabled` and
    /// `[capabilities.acm.discovery] enabled`). Turning discovery on is the
    /// customer's consent to send its records, so this, not `acm_enabled`,
    /// gates them. Set from the ACM config, not `[telemetry]`.
    pub acm_discovery_enabled: bool,

    /// Log each request's JSON instead of sending it, so an operator can audit
    /// the output before enabling. A request holds one discovery batch or up to
    /// 100 automation records. Each request is one line in
    /// `acm_provider_telemetry_dryrun.log` in the log directory, or on the
    /// console when `log_to_file` is false, whatever `log_level` is.
    pub dry_run: bool,
}

/// Logging configuration for the provider.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct LoggingConfig {
    /// The level of logging the provider provides (debug, info, warn, error, or none)
    pub log_level: LogLevel,

    /// Where logs are written (file or stdout)
    pub log_to_file: bool,

    /// Whether `[telemetry] dry_run` is on. The logger then logs telemetry
    /// records at any `log_level`, to their own file when `log_to_file` is set.
    /// Set from `[telemetry]`, not `[logging]`.
    pub telemetry_dry_run: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            log_level: LogLevel::Info,
            log_to_file: true,
            telemetry_dry_run: false,
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

    /// Region failover configuration (disabled unless a default or per-secret failover region is set)
    pub failover: FailoverConfig,
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
            failover: FailoverConfig::default(),
        }
    }
}

/// Default directory holding the generated per-watcher configuration files.
///
/// The watcher configuration and the refresh request directories live on
/// separate volumes, because mount options apply per volume: the configuration
/// volume is read-write for the provider and read-only for the watcher's
/// container.
#[cfg(unix)]
pub const DEFAULT_WATCHER_CONFIG_DIR: &str = "/shared/wcp-watchers/config";

/// Default directory holding the per-watcher refresh request directories.
#[cfg(unix)]
pub const DEFAULT_WATCHER_REQUESTS_DIR: &str = "/shared/wcp-watchers/requests";

/// Default directory holding the generated per-watcher configuration files.
///
/// A dedicated root, not a subtree of `%PROGRAMDATA%`: these directories are
/// mount points shared with a customer's container, and `C:\ProgramData` is
/// populated by the OS, Microsoft components and third-party installers. The
/// `wcp-watchers` segment is lowercase because Windows Server lowercases
/// bind-mount target paths, so an uppercase segment would not round-trip.
#[cfg(windows)]
pub const DEFAULT_WATCHER_CONFIG_DIR: &str = r"C:\shared\wcp-watchers\config";

/// Default directory holding the per-watcher refresh request directories.
#[cfg(windows)]
pub const DEFAULT_WATCHER_REQUESTS_DIR: &str = r"C:\shared\wcp-watchers\requests";

/// The resolved pair of shared watcher directories returned by
/// [`validate_watcher_directories`](crate::config::validate_watcher_directories).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatcherDirectories {
    /// Directory holding the generated per-watcher configuration files.
    pub config_dir: PathBuf,
    /// Directory holding the per-watcher refresh request directories.
    pub requests_dir: PathBuf,
    /// Checks that passed without being verified (the Windows mount-mode
    /// gap), one message per directory. The caller logs them once its
    /// logger is initialized.
    pub warnings: Vec<String>,
}

/// ACM (Certificate Manager) capability configuration.
#[derive(Debug, Clone)]
pub struct AcmConfig {
    /// Whether the ACM capability is enabled
    pub enabled: bool,

    /// Certificate configurations keyed by certificate ARN
    pub certificates: HashMap<String, CertificateConfig>,

    /// Discovery configuration (`None` means discovery is not configured)
    pub discovery: Option<DiscoveryConfig>,
    /// Directory the provider writes the generated per-watcher configuration
    /// files to, shared read-only with the watcher's container.
    pub watcher_config_dir: PathBuf,

    /// Directory holding the per-watcher refresh request directories, shared
    /// read-write with the watcher's container.
    pub watcher_requests_dir: PathBuf,
}

/// Default time budget for one discovery cycle.
pub const DEFAULT_DISCOVERY_TIMEOUT_SECS: u64 = 300;
/// Default TLS ports probed when no targets are configured.
pub const DEFAULT_DISCOVERY_PORTS: &[u16] = &[443, 8443, 4443];

/// Validated discovery configuration for the certificate discovery capability.
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Whether discovery is enabled. In the config file, turning it on also
    /// consents to sending what it finds: the validator sets
    /// `TelemetryConfig::acm_discovery_enabled` from it.
    pub enabled: bool,
    /// Max time for one discovery cycle in seconds.
    pub timeout_secs: u64,
    /// Port → SNI hostnames. Each port is probed once without SNI,
    /// then once per hostname.
    pub discovery_targets: HashMap<u16, Vec<String>>,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            timeout_secs: DEFAULT_DISCOVERY_TIMEOUT_SECS,
            discovery_targets: DEFAULT_DISCOVERY_PORTS
                .iter()
                .map(|&port| (port, Vec::new()))
                .collect(),
        }
    }
}

impl Default for AcmConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            certificates: HashMap::new(),
            watcher_config_dir: PathBuf::from(DEFAULT_WATCHER_CONFIG_DIR),
            watcher_requests_dir: PathBuf::from(DEFAULT_WATCHER_REQUESTS_DIR),
            discovery: None,
        }
    }
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

/// Region failover configuration for Secrets Manager requests.
#[derive(Debug, Clone)]
pub struct FailoverConfig {
    /// The AWS Region to fail over to when the primary region fails, for secrets without a per-secret region
    pub default_failover_region: Option<String>,

    /// The timeout in milliseconds for a single Secrets Manager operation, including any credential refresh it triggers (2000 - 25000, default 3000)
    pub operation_timeout_ms: u64,

    /// Per-secret failover region, keyed by secret ARN (overrides default_failover_region)
    pub secret_to_region_map: HashMap<String, String>,
}

impl Default for FailoverConfig {
    fn default() -> Self {
        Self {
            default_failover_region: None,
            operation_timeout_ms: 3000,
            secret_to_region_map: HashMap::new(),
        }
    }
}

impl FailoverConfig {
    /// Returns true if a default or any per-secret failover region is configured.
    pub fn is_enabled(&self) -> bool {
        self.default_failover_region.is_some() || !self.secret_to_region_map.is_empty()
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

    /// Optional ID of the watcher that handles this certificate's refresh.
    ///
    /// When set, `refresh_command` is required and is carried into that
    /// watcher's configuration rather than executed by the provider.
    pub watcher_id: Option<String>,
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
    pub failover: Option<FailoverConfigInput>,

    // Nested capabilities
    pub capabilities: Option<CapabilitiesConfig>,

    // Nested logging
    pub logging: Option<LoggingConfigInput>,

    // Top-level telemetry section
    pub telemetry: Option<TelemetryConfigInput>,
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
    pub failover: Option<FailoverConfigInput>,
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

/// Telemetry configuration in TOML (`[telemetry]` section). Each capability has
/// its own switch, mirroring `[capabilities.X]`. Certificate discovery is the
/// exception: turning it on (`[capabilities.acm.discovery] enabled`) is the
/// consent for its records, and `[telemetry.acm]` doesn't affect them.
/// `dry_run` applies to them too.
///
/// ```toml
/// [telemetry]
/// dry_run = false
///
/// [telemetry.acm]
/// enabled = true
/// ```
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct TelemetryConfigInput {
    pub secrets_manager: Option<TelemetryCapabilityInput>,
    pub acm: Option<TelemetryCapabilityInput>,
    pub dry_run: Option<bool>,
}

/// Per-capability telemetry switch in TOML (`[telemetry.<capability>]`).
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct TelemetryCapabilityInput {
    pub enabled: Option<bool>,
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

/// Failover configuration input from TOML.
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct FailoverConfigInput {
    pub default_failover_region: Option<String>,
    pub operation_timeout_ms: Option<u64>,
    #[serde(default)]
    pub secret_to_region_map: HashMap<String, String>,
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
    /// Override for the generated watcher configuration directory.
    /// Defaults to [`DEFAULT_WATCHER_CONFIG_DIR`] when omitted.
    pub watcher_config_dir: Option<String>,
    /// Override for the watcher refresh request directory.
    /// Defaults to [`DEFAULT_WATCHER_REQUESTS_DIR`] when omitted.
    pub watcher_requests_dir: Option<String>,
    pub discovery: Option<DiscoveryConfigInput>,
}

/// Raw TOML input for the certificate discovery capability.
///
/// When `enabled = true` and no `discovery_targets` are provided, the default
/// ports (443, 8443, 4443) are probed without SNI. Turning discovery on also
/// consents to sending what it finds to the telemetry service;
/// `[telemetry.acm]` doesn't affect it.
///
/// ```toml
/// [capabilities.acm.discovery]
/// enabled = true
/// timeout_secs_override = 300
///
/// [capabilities.acm.discovery.discovery_targets]
/// 443 = ["api.example.com", "www.example.com"]
/// 8443 = []
/// ```
#[derive(Debug, Deserialize, Default, Clone)]
// No `deny_unknown_fields`: unknown keys are ignored so newer config keys can
// ship before the binary that reads them.
pub struct DiscoveryConfigInput {
    pub enabled: Option<bool>,
    pub timeout_secs_override: Option<u64>,
    pub discovery_targets: Option<HashMap<u16, Vec<String>>>,
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
    /// ID of the watcher that runs this certificate's `refresh_command`.
    /// When set, `refresh_command` is required.
    pub watcher_id: Option<String>,
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
        assert_eq!(
            config.watcher_config_dir,
            PathBuf::from(DEFAULT_WATCHER_CONFIG_DIR)
        );
        assert_eq!(
            config.watcher_requests_dir,
            PathBuf::from(DEFAULT_WATCHER_REQUESTS_DIR)
        );
        assert!(config.discovery.is_none());
    }

    /// Discovery defaults to off, the default timeout and three default ports.
    #[test]
    fn test_discovery_config_defaults() {
        let config = DiscoveryConfig::default();

        assert!(!config.enabled);
        assert_eq!(config.timeout_secs, DEFAULT_DISCOVERY_TIMEOUT_SECS);
        assert_eq!(
            config.discovery_targets,
            HashMap::from([(443, Vec::new()), (4443, Vec::new()), (8443, Vec::new())])
        );
    }

    #[test]
    fn test_telemetry_config_defaults() {
        let config = TelemetryConfig::default();
        assert!(!config.secrets_manager_enabled);
        assert!(!config.acm_enabled);
        assert!(!config.acm_discovery_enabled);
        assert!(!config.dry_run);
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
