//! Main configuration validator entry point.
//!
//! This module provides the ConfigValidator which orchestrates all config validation
//! steps and produces either a validated configuration or a collection of errors.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::error::{ErrorCollector, ValidationError, ValidationErrorCode, ValidationErrors};
use super::error_messages::{
    BAD_MAX_CONN_MSG, BAD_MAX_ROLES_MSG, BAD_PREFIX_MSG, EMPTY_ENV_LIST_MSG, EMPTY_SSRF_LIST_MSG,
    FLAT_KEY_WITH_CAPABILITIES_ERR_MSG, INVALID_CACHE_BUFFER_RATIO_MSG, INVALID_CACHE_SIZE_ERR_MSG,
    INVALID_FAILOVER_REGION_MSG, INVALID_HTTP_PORT_ERR_MSG, INVALID_MAX_JITTER_MSG,
    INVALID_OPERATION_TIMEOUT_MSG, INVALID_TTL_SECONDS_ERR_MSG,
    MISSING_REFRESH_COMMAND_FOR_WATCHER_ERR_MSG,
};
use super::field_validators::{
    validate_permission_config, validate_refresh_command, validate_watcher_directories,
    validate_watcher_id, ArnValidator, CertificateBlockPaths, CrossFieldValidator,
    FilePathValidator, RangeValidator,
};
use super::types::{
    AcmConfig, AcmConfigInput, CapabilitiesConfig, CertificateConfig, CertificateConfigInput,
    ConfigInput, DiscoveryConfig, DiscoveryConfigInput, FailoverConfig, FailoverConfigInput,
    LogLevel, LoggingConfig, LoggingConfigInput, PrefetchConfig, PrefetchConfigInput,
    SecretPrefetchConfig, SecretsManagerConfig, SecretsManagerConfigInput, TagFilter,
    TelemetryConfig, TelemetryConfigInput, ValidatedConfig, DEFAULT_DISCOVERY_PORTS,
    DEFAULT_DISCOVERY_TIMEOUT_SECS, DEFAULT_WATCHER_CONFIG_DIR, DEFAULT_WATCHER_REQUESTS_DIR,
};
use super::watcher_config;
use crate::filesystem::{FileSystem, RealFileSystem};

use crate::fs_permissions::PathPermission;

/// Maximum number of certificates allowed in the configuration.
const MAX_CERTIFICATES: usize = 50;

/// Maximum number of ports in discovery_targets.
const MAX_DISCOVERY_PORTS: usize = 32;

/// Maximum number of SNI hostnames per port.
const MAX_DISCOVERY_SNI_PER_PORT: usize = 32;

/// Minimum timeout for a discovery cycle.
const MIN_DISCOVERY_TIMEOUT_SECS: u64 = 60;

/// Main configuration validator.
///
/// Orchestrates all config validation steps and produces either a validated
/// configuration or a collection of all config validation errors.
pub struct ConfigValidator<F: FileSystem = RealFileSystem> {
    filesystem: Arc<F>,
}

impl ConfigValidator<RealFileSystem> {
    /// Create a new ConfigValidator with the real filesystem.
    pub fn new() -> Self {
        Self {
            filesystem: Arc::new(RealFileSystem),
        }
    }
}

impl<F: FileSystem> ConfigValidator<F> {
    /// Create a new ConfigValidator with a custom filesystem (for testing).
    pub fn with_filesystem(filesystem: Arc<F>) -> Self {
        Self { filesystem }
    }

    /// Validate a configuration file at the given path.
    ///
    /// If `file_path` is None, returns the default configuration with ASM enabled and ACM disabled.
    /// Returns a validated configuration on success, or all config validation errors on failure.
    pub fn validate(&self, file_path: Option<&str>) -> Result<ValidatedConfig, ValidationErrors> {
        match file_path {
            None => {
                // No config file - use defaults
                Ok(ValidatedConfig {
                    warnings: Vec::new(),
                    ..Default::default()
                })
            }
            Some(path) => {
                // Read file and validate
                let content = self
                    .filesystem
                    .read_to_string(Path::new(path))
                    .map_err(|e| {
                        ValidationErrors::from_error(ValidationError::new(
                            "".to_string(),
                            ValidationErrorCode::FileReadError,
                            format!("Failed to read config file '{}': {}", path, e),
                        ))
                    })?;
                self.validate_toml_config_str(&content)
            }
        }
    }

    /// Validates a TOML configuration string.
    fn validate_toml_config_str(
        &self,
        toml_str: &str,
    ) -> Result<ValidatedConfig, ValidationErrors> {
        let mut collector = ErrorCollector::new();

        // Parse toml_str
        let mut raw_config: ConfigInput = match toml::from_str(toml_str) {
            Ok(config) => config,
            Err(e) => {
                collector.add(ValidationError::new(
                    "".to_string(),
                    ValidationErrorCode::TomlSyntaxError,
                    format!("Failed to parse config: {}", e),
                ));
                return Err(ValidationErrors::from_vec(collector.errors().to_vec()));
            }
        };

        let has_logging: bool = raw_config.logging.as_ref().is_some();
        let is_nested_config: bool = has_logging || raw_config.capabilities.as_ref().is_some();

        // If any nested config exists, reject flat keys
        if is_nested_config {
            self.reject_flat_keys(&raw_config, &mut collector);
        }

        let capabilities: CapabilitiesConfig = raw_config.capabilities.take().unwrap_or_default();

        // Validate logging config
        let logging_input = if has_logging {
            raw_config.logging.take()
        } else {
            Some(LoggingConfigInput {
                log_level: raw_config.log_level.clone(),
                log_to_file: raw_config.log_to_file,
            })
        };
        let mut logging: LoggingConfig =
            self.validate_logging_config(logging_input, &mut collector);

        let has_capabilities_secrets_manager: bool = capabilities.secrets_manager.is_some();

        // Validate ASM config
        let secrets_manager: SecretsManagerConfig = if has_capabilities_secrets_manager {
            self.validate_secrets_manager_config(capabilities.secrets_manager, &mut collector)
        } else if !is_nested_config {
            self.validate_secrets_manager_config_with_flat_keys(&raw_config, &mut collector)
        } else {
            SecretsManagerConfig::default()
        };

        // Validate ACM config
        let mut warnings = Vec::new();
        let acm: Option<AcmConfig> =
            self.validate_acm_config(capabilities.acm, &mut collector, &mut warnings);

        // Validate telemetry config (top-level [telemetry] section)
        let telemetry: TelemetryConfig =
            self.validate_telemetry_config(raw_config.telemetry.take(), acm.as_ref());
        logging.telemetry_dry_run = telemetry.dry_run;

        if !collector.is_empty() {
            Err(ValidationErrors::from_vec(collector.errors().to_vec()))
        } else {
            Ok(ValidatedConfig {
                logging,
                secrets_manager,
                acm,
                telemetry,
                warnings,
            })
        }
    }

    /// Checks ConfigInput for any flat keys and rejects them.
    fn reject_flat_keys(&self, config_file: &ConfigInput, collector: &mut ErrorCollector) {
        let mut reject = |field: &str, is_set: bool, guidance: &str| {
            if is_set {
                collector.add(ValidationError::with_guidance(
                    field.to_string(),
                    ValidationErrorCode::FormatConflict,
                    FLAT_KEY_WITH_CAPABILITIES_ERR_MSG.to_string(),
                    format!("Use '{}' instead of '{}'.", guidance, field),
                ));
            }
        };

        reject(
            "http_port",
            config_file.http_port.is_some(),
            "capabilities.secrets_manager.http_port",
        );
        reject(
            "ttl_seconds",
            config_file.ttl_seconds.is_some(),
            "capabilities.secrets_manager.cache.ttl_seconds",
        );
        reject(
            "cache_size",
            config_file.cache_size.is_some(),
            "capabilities.secrets_manager.cache.cache_size",
        );
        reject(
            "max_conn",
            config_file.max_conn.is_some(),
            "capabilities.secrets_manager.max_conn",
        );
        reject(
            "region",
            config_file.region.is_some(),
            "capabilities.secrets_manager.region",
        );
        reject(
            "ssrf_headers",
            config_file.ssrf_headers.is_some(),
            "capabilities.secrets_manager.security.ssrf_headers",
        );
        reject(
            "ssrf_env_variables",
            config_file.ssrf_env_variables.is_some(),
            "capabilities.secrets_manager.security.ssrf_env_variables",
        );
        reject(
            "path_prefix",
            config_file.path_prefix.is_some(),
            "capabilities.secrets_manager.path_prefix",
        );
        reject(
            "ignore_transient_errors",
            config_file.ignore_transient_errors.is_some(),
            "capabilities.secrets_manager.ignore_transient_errors",
        );
        reject(
            "validate_credentials",
            config_file.validate_credentials.is_some(),
            "capabilities.secrets_manager.validate_credentials",
        );
        reject(
            "credentials_file_path",
            config_file.credentials_file_path.is_some(),
            "capabilities.secrets_manager.credentials_file_path",
        );
        reject(
            "prefetch",
            config_file.prefetch.is_some(),
            "capabilities.secrets_manager.prefetch",
        );
        reject(
            "failover",
            config_file.failover.is_some(),
            "capabilities.secrets_manager.failover",
        );
        reject(
            "log_level",
            config_file.log_level.is_some(),
            "logging.log_level",
        );
        reject(
            "log_to_file",
            config_file.log_to_file.is_some(),
            "logging.destination",
        );
    }

    /// Validate logging configuration from nested [logging] section.
    fn validate_logging_config(
        &self,
        logging_config_input: Option<LoggingConfigInput>,
        collector: &mut ErrorCollector,
    ) -> LoggingConfig {
        let logging_config_input = logging_config_input.unwrap_or_default();
        let mut logging_config = LoggingConfig::default();

        if let Some(ref log_level_str) = logging_config_input.log_level {
            match log_level_str.parse::<LogLevel>() {
                Ok(log_level) => logging_config.log_level = log_level,
                Err(e) => collector.add(e),
            }
        }

        if let Some(ref log_to_file) = logging_config_input.log_to_file {
            logging_config.log_to_file = *log_to_file;
        }

        logging_config
    }

    /// Validate the `[telemetry]` section. Its switches are plain opt-in
    /// booleans, so nothing is rejected. Discovery consent comes from the ACM
    /// config: discovery on means its records may be sent.
    fn validate_telemetry_config(
        &self,
        telemetry_config_input: Option<TelemetryConfigInput>,
        acm: Option<&AcmConfig>,
    ) -> TelemetryConfig {
        let input = telemetry_config_input.unwrap_or_default();
        TelemetryConfig {
            secrets_manager_enabled: input
                .secrets_manager
                .and_then(|c| c.enabled)
                .unwrap_or(false),
            acm_enabled: input.acm.and_then(|c| c.enabled).unwrap_or(false),
            acm_discovery_enabled: acm.is_some_and(|acm| {
                acm.enabled && acm.discovery.as_ref().is_some_and(|d| d.enabled)
            }),
            dry_run: input.dry_run.unwrap_or(false),
        }
    }

    /// Validate ASM configuration section.
    fn validate_secrets_manager_config(
        &self,
        secrets_manager_config_input: Option<SecretsManagerConfigInput>,
        collector: &mut ErrorCollector,
    ) -> SecretsManagerConfig {
        let secrets_manager_config_input = secrets_manager_config_input.unwrap_or_default();
        let mut secrets_manager_config = SecretsManagerConfig::default();

        if let Some(enabled) = secrets_manager_config_input.enabled {
            secrets_manager_config.enabled = enabled;
        }

        if let Some(http_port) = secrets_manager_config_input.http_port {
            match Self::validate_http_port(
                "capabilities.secrets_manager.http_port",
                http_port as usize,
            ) {
                Ok(()) => secrets_manager_config.http_port = http_port,
                Err(e) => collector.add(e),
            }
        }

        // Validate cache configuration
        if let Some(cache_config_file) = secrets_manager_config_input.cache {
            if let Some(ttl_seconds) = cache_config_file.ttl_seconds {
                if let Err(e) = RangeValidator::validate_range(
                    "capabilities.secrets_manager.cache.ttl_seconds",
                    ttl_seconds as usize,
                    0,
                    3600,
                    INVALID_TTL_SECONDS_ERR_MSG,
                ) {
                    collector.add(e);
                } else {
                    secrets_manager_config.cache.ttl_seconds = ttl_seconds;
                }
            }

            if let Some(cache_size) = cache_config_file.cache_size {
                if let Err(e) = RangeValidator::validate_range(
                    "capabilities.secrets_manager.cache.cache_size",
                    cache_size,
                    1,
                    1000,
                    INVALID_CACHE_SIZE_ERR_MSG,
                ) {
                    collector.add(e);
                } else if let Some(size) = NonZeroUsize::new(cache_size) {
                    secrets_manager_config.cache.cache_size = size;
                }
            }
        }

        // Validate security configuration
        if let Some(security_config_file) = secrets_manager_config_input.security {
            if let Some(ssrf_headers) = security_config_file.ssrf_headers {
                match Self::validate_non_empty_list(
                    "capabilities.secrets_manager.security.ssrf_headers",
                    &ssrf_headers,
                    EMPTY_SSRF_LIST_MSG,
                ) {
                    Ok(()) => secrets_manager_config.security.ssrf_headers = ssrf_headers,
                    Err(e) => collector.add(e),
                }
            }

            if let Some(ssrf_env_variables) = security_config_file.ssrf_env_variables {
                match Self::validate_non_empty_list(
                    "capabilities.secrets_manager.security.ssrf_env_variables",
                    &ssrf_env_variables,
                    EMPTY_ENV_LIST_MSG,
                ) {
                    Ok(()) => {
                        secrets_manager_config.security.ssrf_env_variables = ssrf_env_variables
                    }
                    Err(e) => collector.add(e),
                }
            }
        }

        if let Some(path_prefix) = secrets_manager_config_input.path_prefix {
            match Self::validate_path_prefix(
                "capabilities.secrets_manager.path_prefix",
                &path_prefix,
            ) {
                Ok(()) => secrets_manager_config.path_prefix = path_prefix,
                Err(e) => collector.add(e),
            }
        }

        if let Some(max_conn) = secrets_manager_config_input.max_conn {
            if let Err(e) = RangeValidator::validate_range(
                "capabilities.secrets_manager.max_conn",
                max_conn,
                1,
                1000,
                BAD_MAX_CONN_MSG,
            ) {
                collector.add(e);
            } else {
                secrets_manager_config.max_conn = max_conn;
            }
        }

        if let Some(max_roles) = secrets_manager_config_input.max_roles {
            if let Err(e) = RangeValidator::validate_range(
                "capabilities.secrets_manager.max_roles",
                max_roles,
                1,
                20,
                BAD_MAX_ROLES_MSG,
            ) {
                collector.add(e);
            } else {
                secrets_manager_config.max_roles = max_roles;
            }
        }

        if let Some(region) = secrets_manager_config_input.region {
            secrets_manager_config.region = Some(region);
        }

        if let Some(ignore_transient_errors) = secrets_manager_config_input.ignore_transient_errors
        {
            secrets_manager_config.ignore_transient_errors = ignore_transient_errors;
        }

        if let Some(validate_credentials) = secrets_manager_config_input.validate_credentials {
            secrets_manager_config.validate_credentials = validate_credentials;
        }

        if let Some(path) = secrets_manager_config_input.credentials_file_path {
            warn_if_credentials_file_missing(&path);
            secrets_manager_config.credentials_file_path = Some(path);
        }

        if let Some(prefetch_input) = secrets_manager_config_input.prefetch {
            secrets_manager_config.prefetch = Self::validate_prefetch_config(
                "capabilities.secrets_manager.prefetch",
                prefetch_input,
                collector,
            );
        }

        if let Some(failover_input) = secrets_manager_config_input.failover {
            secrets_manager_config.failover = Self::validate_failover_config(
                "capabilities.secrets_manager.failover",
                failover_input,
                secrets_manager_config.region.as_deref(),
                collector,
            );
        }

        secrets_manager_config
    }

    /// Validate http_port: must be 0 (disabled) or in 1024..=65535.
    fn validate_http_port(field_name: &str, value: usize) -> Result<(), ValidationError> {
        if value == 0 {
            return Ok(());
        }
        RangeValidator::validate_range(field_name, value, 1024, 65535, INVALID_HTTP_PORT_ERR_MSG)
    }

    /// Validate that a string list is non-empty.
    fn validate_non_empty_list(
        field_name: &str,
        list: &[String],
        msg: &str,
    ) -> Result<(), ValidationError> {
        if list.is_empty() {
            return Err(ValidationError::new(
                field_name.to_string(),
                ValidationErrorCode::InvalidValue,
                msg.to_string(),
            ));
        }
        Ok(())
    }

    /// Validate that a path prefix starts with '/'.
    fn validate_path_prefix(field_name: &str, prefix: &str) -> Result<(), ValidationError> {
        if !prefix.starts_with('/') {
            return Err(ValidationError::new(
                field_name.to_string(),
                ValidationErrorCode::InvalidValue,
                BAD_PREFIX_MSG.to_string(),
            ));
        }
        Ok(())
    }

    /// Validate prefetch configuration fields.
    fn validate_prefetch_config(
        prefix: &str,
        input: PrefetchConfigInput,
        collector: &mut ErrorCollector,
    ) -> PrefetchConfig {
        let mut config = PrefetchConfig::default();

        if let Some(ratio) = input.cache_buffer_ratio {
            if !(0.1..=1.0).contains(&ratio) {
                collector.add(ValidationError::new(
                    format!("{}.cache_buffer_ratio", prefix),
                    ValidationErrorCode::InvalidValue,
                    INVALID_CACHE_BUFFER_RATIO_MSG.to_string(),
                ));
            } else {
                config.cache_buffer_ratio = ratio;
            }
        }

        if let Some(jitter) = input.max_jitter_seconds {
            if jitter > 10 {
                collector.add(ValidationError::new(
                    format!("{}.max_jitter_seconds", prefix),
                    ValidationErrorCode::InvalidValue,
                    INVALID_MAX_JITTER_MSG.to_string(),
                ));
            } else {
                config.max_jitter_seconds = jitter;
            }
        }

        config.filter_tags = input
            .filter_tags
            .into_iter()
            .map(|t| TagFilter {
                key: t.key,
                role_arn: t.role_arn,
            })
            .collect();

        config.secrets = input
            .secrets
            .into_iter()
            .map(|s| SecretPrefetchConfig {
                secret_id: s.secret_id,
                role_arn: s.role_arn,
            })
            .collect();

        config
    }

    /// Validate failover configuration fields.
    fn validate_failover_config(
        prefix: &str,
        input: FailoverConfigInput,
        primary_region: Option<&str>,
        collector: &mut ErrorCollector,
    ) -> FailoverConfig {
        let mut config = FailoverConfig::default();

        // A failover region must be set and differ from the primary region.
        let is_usable_region = |region: &str| !region.is_empty() && Some(region) != primary_region;

        if let Some(timeout) = input.operation_timeout_ms {
            // The minimum leaves room for a credential refresh, which runs inside the same timeout
            match RangeValidator::validate_range(
                &format!("{}.operation_timeout_ms", prefix),
                timeout as usize,
                2000,
                25000,
                INVALID_OPERATION_TIMEOUT_MSG,
            ) {
                Ok(()) => config.operation_timeout_ms = timeout,
                Err(e) => collector.add(e),
            }
        }

        if let Some(region) = input.default_failover_region {
            if is_usable_region(&region) {
                config.default_failover_region = Some(region);
            } else {
                collector.add(ValidationError::with_guidance(
                    format!("{}.default_failover_region", prefix),
                    ValidationErrorCode::InvalidValue,
                    INVALID_FAILOVER_REGION_MSG.to_string(),
                    format!("Got: '{}'", region),
                ));
            }
        }

        for (arn, region) in input.secret_to_region_map {
            if is_usable_region(&region) {
                config.secret_to_region_map.insert(arn, region);
            } else {
                collector.add(ValidationError::with_guidance(
                    format!("{}.secret_to_region_map.{}", prefix, arn),
                    ValidationErrorCode::InvalidValue,
                    INVALID_FAILOVER_REGION_MSG.to_string(),
                    format!("Got: '{}'", region),
                ));
            }
        }

        config
    }

    /// Validate ASM configuration with flat keys (legacy format).
    fn validate_secrets_manager_config_with_flat_keys(
        &self,
        config_file: &ConfigInput,
        collector: &mut ErrorCollector,
    ) -> SecretsManagerConfig {
        let mut secrets_manager_config = SecretsManagerConfig::default();

        // Parse flat keys
        if let Some(ref val) = config_file.http_port {
            match toml_value_to_string("http_port", val) {
                Ok(ref s) if s == "0" => secrets_manager_config.http_port = 0,
                Ok(s) => match RangeValidator::parse_and_validate_range(
                    "http_port",
                    &s,
                    1024,
                    65535,
                    INVALID_HTTP_PORT_ERR_MSG,
                ) {
                    Ok(http_port) => secrets_manager_config.http_port = http_port as u16,
                    Err(e) => collector.add(e),
                },
                Err(e) => collector.add(e),
            }
        }

        if let Some(ref val) = config_file.ttl_seconds {
            match toml_value_to_string("ttl_seconds", val) {
                Ok(s) => match RangeValidator::parse_and_validate_range(
                    "ttl_seconds",
                    &s,
                    0,
                    3600,
                    INVALID_TTL_SECONDS_ERR_MSG,
                ) {
                    Ok(ttl) => secrets_manager_config.cache.ttl_seconds = ttl as u16,
                    Err(e) => collector.add(e),
                },
                Err(e) => collector.add(e),
            }
        }

        if let Some(ref val) = config_file.cache_size {
            match toml_value_to_string("cache_size", val) {
                Ok(s) => match RangeValidator::parse_and_validate_range(
                    "cache_size",
                    &s,
                    1,
                    1000,
                    INVALID_CACHE_SIZE_ERR_MSG,
                ) {
                    Ok(cache_size) => {
                        if let Some(size) = NonZeroUsize::new(cache_size) {
                            secrets_manager_config.cache.cache_size = size;
                        }
                    }
                    Err(e) => collector.add(e),
                },
                Err(e) => collector.add(e),
            }
        }

        if let Some(ref val) = config_file.max_conn {
            match toml_value_to_string("max_conn", val) {
                Ok(s) => match RangeValidator::parse_and_validate_range(
                    "max_conn",
                    &s,
                    1,
                    1000,
                    BAD_MAX_CONN_MSG,
                ) {
                    Ok(max_conn) => secrets_manager_config.max_conn = max_conn,
                    Err(e) => collector.add(e),
                },
                Err(e) => collector.add(e),
            }
        }

        if let Some(ref val) = config_file.max_roles {
            match toml_value_to_string("max_roles", val) {
                Ok(s) => match RangeValidator::parse_and_validate_range(
                    "max_roles",
                    &s,
                    1,
                    20,
                    BAD_MAX_ROLES_MSG,
                ) {
                    Ok(max_roles) => secrets_manager_config.max_roles = max_roles,
                    Err(e) => collector.add(e),
                },
                Err(e) => collector.add(e),
            }
        }

        if let Some(ref ssrf_headers) = config_file.ssrf_headers {
            match Self::validate_non_empty_list("ssrf_headers", ssrf_headers, EMPTY_SSRF_LIST_MSG) {
                Ok(()) => secrets_manager_config.security.ssrf_headers = ssrf_headers.clone(),
                Err(e) => collector.add(e),
            }
        }

        if let Some(ref ssrf_env_variables) = config_file.ssrf_env_variables {
            match Self::validate_non_empty_list(
                "ssrf_env_variables",
                ssrf_env_variables,
                EMPTY_ENV_LIST_MSG,
            ) {
                Ok(()) => {
                    secrets_manager_config.security.ssrf_env_variables = ssrf_env_variables.clone()
                }
                Err(e) => collector.add(e),
            }
        }

        if let Some(ref path_prefix) = config_file.path_prefix {
            match Self::validate_path_prefix("path_prefix", path_prefix) {
                Ok(()) => secrets_manager_config.path_prefix = path_prefix.clone(),
                Err(e) => collector.add(e),
            }
        }

        if let Some(ref region) = config_file.region {
            secrets_manager_config.region = Some(region.clone());
        }

        if let Some(ignore_transient_errors) = config_file.ignore_transient_errors {
            secrets_manager_config.ignore_transient_errors = ignore_transient_errors;
        }

        if let Some(validate_credentials) = config_file.validate_credentials {
            secrets_manager_config.validate_credentials = validate_credentials;
        }

        if let Some(path) = config_file.credentials_file_path.clone() {
            warn_if_credentials_file_missing(&path);
            secrets_manager_config.credentials_file_path = Some(path);
        }

        if let Some(prefetch_input) = config_file.prefetch.clone() {
            secrets_manager_config.prefetch =
                Self::validate_prefetch_config("prefetch", prefetch_input, collector);
        }

        if let Some(failover_input) = config_file.failover.clone() {
            secrets_manager_config.failover = Self::validate_failover_config(
                "failover",
                failover_input,
                secrets_manager_config.region.as_deref(),
                collector,
            );
        }

        secrets_manager_config
    }

    /// Validate ACM configuration section.
    fn validate_acm_config(
        &self,
        opt_acm_config_input: Option<AcmConfigInput>,
        collector: &mut ErrorCollector,
        warnings: &mut Vec<String>,
    ) -> Option<AcmConfig> {
        let acm_config_input: AcmConfigInput = opt_acm_config_input?;

        let acm_enabled: bool = acm_config_input.enabled.unwrap_or(false);
        let cert_config_inputs: Vec<CertificateConfigInput> =
            acm_config_input.certificates.unwrap_or_default();

        // Watcher directories are validated only for an enabled container
        // config (at least one certificate declares a watcher_id). Such a
        // config is validated at provider startup inside the container, after all
        // required volumes are mounted. The provider writes the watcher configs
        // and enqueues refresh requests, so it requires both directories on
        // read-write mounts. On Windows the mount mode can't be read yet, so
        // that check passes and adds to `warnings`, which the caller logs
        // after its logger starts (see `validate_watcher_directories`).
        // Other configs take the configured values (or defaults) as-is.
        let is_container_config = cert_config_inputs.iter().any(|c| c.watcher_id.is_some());
        let config_override = acm_config_input.watcher_config_dir.as_deref();
        let requests_override = acm_config_input.watcher_requests_dir.as_deref();
        let (watcher_config_dir, watcher_requests_dir) = if is_container_config && acm_enabled {
            match validate_watcher_directories(
                self.filesystem.as_ref(),
                // The provider writes the watcher configs: config must not read_only.
                false,
                "capabilities.acm.watcher_config_dir",
                config_override,
                "capabilities.acm.watcher_requests_dir",
                requests_override,
            ) {
                Ok(dirs) => {
                    warnings.extend(dirs.warnings);
                    (dirs.config_dir, dirs.requests_dir)
                }
                Err(errors) => {
                    for e in errors {
                        collector.add(e);
                    }
                    (
                        PathBuf::from(DEFAULT_WATCHER_CONFIG_DIR),
                        PathBuf::from(DEFAULT_WATCHER_REQUESTS_DIR),
                    )
                }
            }
        } else {
            (
                PathBuf::from(config_override.unwrap_or(DEFAULT_WATCHER_CONFIG_DIR)),
                PathBuf::from(requests_override.unwrap_or(DEFAULT_WATCHER_REQUESTS_DIR)),
            )
        };

        if cert_config_inputs.len() > MAX_CERTIFICATES {
            collector.add(ValidationError::new(
                "capabilities.acm.certificates",
                ValidationErrorCode::ValueOutOfRange,
                format!(
                    "Too many certificates configured: {} exceeds maximum of {}",
                    cert_config_inputs.len(),
                    MAX_CERTIFICATES
                ),
            ));
        }

        // Validate the default cert and key permissions
        let default_key_permission = match acm_config_input.default_key_permission {
            None => None,
            Some(perm_cfg) => match validate_permission_config(
                "capabilities.acm.default_key_permission",
                &perm_cfg,
            ) {
                Err(e) => {
                    collector.add(e);
                    None
                }
                Ok(perm) => Some(perm),
            },
        };
        let default_cert_permission = match acm_config_input.default_certificate_permission {
            None => None,
            Some(perm_cfg) => match validate_permission_config(
                "capabilities.acm.default_certificate_permission",
                &perm_cfg,
            ) {
                Err(e) => {
                    collector.add(e);
                    None
                }
                Ok(perm) => Some(perm),
            },
        };

        // Validate each certificate
        let mut certificates: HashMap<String, CertificateConfig> = HashMap::new();

        for (index, cert_config) in cert_config_inputs.iter().enumerate() {
            if let Some(cert) = self.validate_certificate(
                index,
                cert_config,
                collector,
                &default_cert_permission,
                &default_key_permission,
            ) {
                let arn = cert.certificate_arn.clone();
                match certificates.entry(arn) {
                    Entry::Occupied(entry) => {
                        collector.add(ValidationError::new(
                            format!("capabilities.acm.certificates[{}].certificate_arn", index),
                            ValidationErrorCode::DuplicateCertificateArn,
                            format!("Duplicate certificate_arn: '{}'", entry.key()),
                        ));
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(cert);
                    }
                }
            }
        }

        // Validate path uniqueness across blocks
        let block_paths: Vec<CertificateBlockPaths> = certificates
            .values()
            .map(|cert| CertificateBlockPaths {
                certificate_path: &cert.certificate_path,
                private_key_path: &cert.private_key_path,
                chain_path: cert.chain_path.as_deref(),
            })
            .collect();

        let cross_errors = CrossFieldValidator::validate_paths_unique(&block_paths);
        for e in cross_errors {
            collector.add(e);
        }

        let discovery =
            Self::validate_discovery_config(acm_config_input.discovery.as_ref(), collector);

        Some(AcmConfig {
            enabled: acm_enabled,
            certificates,
            watcher_config_dir,
            watcher_requests_dir,
            discovery,
        })
    }

    /// Validate the discovery configuration section.
    fn validate_discovery_config(
        input: Option<&DiscoveryConfigInput>,
        collector: &mut ErrorCollector,
    ) -> Option<DiscoveryConfig> {
        let input = input?;
        let mut has_discovery_errors = false;
        let enabled = input.enabled.unwrap_or(false);
        let field_prefix = "capabilities.acm.discovery";

        let timeout_secs = input
            .timeout_secs_override
            .unwrap_or(DEFAULT_DISCOVERY_TIMEOUT_SECS);
        if timeout_secs < MIN_DISCOVERY_TIMEOUT_SECS {
            has_discovery_errors = true;
            collector.add(ValidationError::new(
                format!("{}.timeout_secs_override", field_prefix),
                ValidationErrorCode::ValueOutOfRange,
                format!(
                    "Timeout must be at least {} seconds, got {}",
                    MIN_DISCOVERY_TIMEOUT_SECS, timeout_secs
                ),
            ));
        }

        let discovery_targets = match &input.discovery_targets {
            Some(targets) => {
                if targets.len() > MAX_DISCOVERY_PORTS {
                    has_discovery_errors = true;
                    collector.add(ValidationError::new(
                        format!("{}.discovery_targets", field_prefix),
                        ValidationErrorCode::ValueOutOfRange,
                        format!(
                            "Too many ports: {} exceeds maximum of {}",
                            targets.len(),
                            MAX_DISCOVERY_PORTS
                        ),
                    ));
                }

                let mut validated: HashMap<u16, Vec<String>> = HashMap::new();
                for (&port, hostnames) in targets {
                    if port == 0 {
                        has_discovery_errors = true;
                        collector.add(ValidationError::new(
                            format!("{}.discovery_targets[{}]", field_prefix, port),
                            ValidationErrorCode::InvalidValue,
                            "Port 0 is not valid".to_string(),
                        ));
                        continue;
                    }

                    let valid: Vec<String> = hostnames
                        .iter()
                        .filter(|h| !h.is_empty())
                        .cloned()
                        .collect::<std::collections::HashSet<_>>()
                        .into_iter()
                        .collect();

                    if valid.len() > MAX_DISCOVERY_SNI_PER_PORT {
                        has_discovery_errors = true;
                        collector.add(ValidationError::new(
                            format!("{}.discovery_targets[{}]", field_prefix, port),
                            ValidationErrorCode::ValueOutOfRange,
                            format!(
                                "Too many SNI hostnames: {} exceeds maximum of {}",
                                valid.len(),
                                MAX_DISCOVERY_SNI_PER_PORT
                            ),
                        ));
                        continue;
                    }

                    validated.insert(port, valid);
                }

                if validated.is_empty() && !has_discovery_errors {
                    DEFAULT_DISCOVERY_PORTS
                        .iter()
                        .map(|&p| (p, Vec::new()))
                        .collect()
                } else {
                    validated
                }
            }
            None => DEFAULT_DISCOVERY_PORTS
                .iter()
                .map(|&p| (p, Vec::new()))
                .collect(),
        };

        Some(DiscoveryConfig {
            enabled,
            timeout_secs,
            discovery_targets,
        })
    }

    /// Validate a single certificate configuration.
    fn validate_certificate(
        &self,
        index: usize,
        certificate_config_input: &CertificateConfigInput,
        collector: &mut ErrorCollector,
        default_cert_permission: &Option<PathPermission>,
        default_key_permission: &Option<PathPermission>,
    ) -> Option<CertificateConfig> {
        let field_prefix = format!("capabilities.acm.certificates[{}]", index);

        // Check required fields — collect all missing field errors before bailing
        let certificate_arn = certificate_config_input.certificate_arn.clone();
        let certificate_path = certificate_config_input.certificate_path.clone();
        let private_key_path = certificate_config_input.private_key_path.clone();
        let chain_path = certificate_config_input.chain_path.clone();
        let role_arn = certificate_config_input.role_arn.clone();

        let mut missing = false;
        for (field, val) in [
            ("certificate_arn", &certificate_arn),
            ("certificate_path", &certificate_path),
            ("private_key_path", &private_key_path),
            ("role_arn", &role_arn),
        ] {
            if val.is_none() {
                missing = true;
                collector.add(ValidationError::new(
                    format!("{}.{}", field_prefix, field),
                    ValidationErrorCode::MissingRequiredField,
                    format!("{} is required", field),
                ));
            }
        }
        if missing {
            return None;
        }

        // Safe to unwrap (verified all are Some above)
        let certificate_arn = certificate_arn.unwrap();
        let certificate_path = PathBuf::from(certificate_path.unwrap());
        let private_key_path = PathBuf::from(private_key_path.unwrap());
        let chain_path = chain_path.map(PathBuf::from);
        let role_arn = role_arn.unwrap();

        // Validate ARN format
        if let Err(e) = ArnValidator::validate_certificate_arn(
            &format!("{}.certificate_arn", field_prefix),
            &certificate_arn,
        ) {
            collector.add(e);
        }

        // Validate file paths
        let path_validator = FilePathValidator::new(self.filesystem.clone());

        if let Err(e) = path_validator.validate(
            &format!("{}.certificate_path", field_prefix),
            &certificate_path,
        ) {
            collector.add(e);
        }

        if let Err(e) = path_validator.validate(
            &format!("{}.private_key_path", field_prefix),
            &private_key_path,
        ) {
            collector.add(e);
        }

        if let Some(ref chain) = chain_path {
            if let Err(e) = path_validator.validate(&format!("{}.chain_path", field_prefix), chain)
            {
                collector.add(e);
            }
        }

        // Validate role_arn
        if let Err(e) =
            ArnValidator::validate_iam_role_arn(&format!("{}.role_arn", field_prefix), &role_arn)
        {
            collector.add(e);
        }

        // Validate optional refresh_command
        let refresh_command = certificate_config_input.refresh_command.clone();
        let mut refresh_command_valid = false;
        if let Some(ref cmd) = refresh_command {
            match validate_refresh_command(&format!("{}.refresh_command", field_prefix), cmd) {
                Ok(()) => refresh_command_valid = true,
                Err(e) => collector.add(e),
            }
        }

        // Validate optional watcher_id. Duplicate watcher_id values across
        // certificate blocks are allowed: one watcher handles many
        // certificates.
        let watcher_id = certificate_config_input.watcher_id.clone();
        if let Some(ref id) = watcher_id {
            if let Err(e) = validate_watcher_id(&format!("{}.watcher_id", field_prefix), id) {
                collector.add(e);
            }

            // The command is carried into the watcher's config and request
            // files never carry one, so a missing command can't be recovered
            // later.
            if refresh_command.is_none() {
                collector.add(ValidationError::new(
                    format!("{}.refresh_command", field_prefix),
                    ValidationErrorCode::MissingRequiredField,
                    MISSING_REFRESH_COMMAND_FOR_WATCHER_ERR_MSG,
                ));
            }

            // The watcher's rules are stricter on Unix, so check them here
            // rather than fail when the provider writes the watcher's config.
            if let (true, Some(cmd)) = (refresh_command_valid, &refresh_command) {
                let mut errors = Vec::new();
                watcher_config::validate_command(
                    &format!("{}.refresh_command", field_prefix),
                    &watcher_config::split_command(cmd),
                    &mut errors,
                );
                for e in errors {
                    collector.add(e);
                }
            }
        }

        // Validate optional certificate_and_chain_permission
        let cert_permission_cfg = &certificate_config_input.certificate_and_chain_permission;
        let cert_and_chain_permission = match cert_permission_cfg {
            None => default_cert_permission.clone(),
            Some(perm_cfg) => {
                match validate_permission_config(
                    &format!("{}.certificate_and_chain_permission", field_prefix),
                    perm_cfg,
                ) {
                    Err(e) => {
                        collector.add(e);
                        None
                    }
                    Ok(perm) => Some(perm),
                }
            }
        };

        // Validate optional key_permission
        let key_permission_cfg = &certificate_config_input.key_permission;
        let key_permission = match key_permission_cfg {
            None => default_key_permission.clone(),
            Some(perm_cfg) => {
                match validate_permission_config(
                    &format!("{}.key_permission", field_prefix),
                    perm_cfg,
                ) {
                    Err(e) => {
                        collector.add(e);
                        None
                    }
                    Ok(perm) => Some(perm),
                }
            }
        };

        Some(CertificateConfig {
            certificate_arn,
            certificate_path,
            private_key_path,
            chain_path,
            role_arn,
            refresh_command,
            cert_and_chain_permission,
            key_permission,
            watcher_id,
        })
    }
}

impl Default for ConfigValidator<RealFileSystem> {
    fn default() -> Self {
        Self::new()
    }
}

fn warn_if_credentials_file_missing(path: &std::path::Path) {
    if !path.is_file() {
        log::warn!(
            "Configured credentials_file_path does not exist yet: {}. \
             The agent will watch for it to appear.",
            path.display()
        );
    }
}

/// Convert a toml::Value to its string representation for parsing.
/// Handles both string values ("2773") and integer values (2773).
/// Returns an error for unexpected types (bool, float, etc.).
fn toml_value_to_string(field_name: &str, val: &toml::Value) -> Result<String, ValidationError> {
    match val {
        toml::Value::String(s) => Ok(s.clone()),
        toml::Value::Integer(i) => Ok(i.to_string()),
        other => Err(ValidationError::with_guidance(
            field_name.to_string(),
            ValidationErrorCode::InvalidType,
            format!("Expected a string or integer for '{}'.", field_name),
            format!("Got: {}", other.type_str()),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::MAX_CERTIFICATES;
    use crate::config::error::ValidationErrorCode;
    use crate::config::types::{
        LogLevel, DEFAULT_WATCHER_CONFIG_DIR, DEFAULT_WATCHER_REQUESTS_DIR,
    };
    use crate::config::validator::ConfigValidator;
    use crate::filesystem::MockFileSystem;
    use crate::fs_permissions::PathPermission;
    #[cfg(windows)]
    use crate::fs_permissions::{Rights, TrusteeType};
    use std::path::PathBuf;
    use std::sync::Arc;

    fn mock_fs() -> Arc<MockFileSystem> {
        Arc::new(
            MockFileSystem::new()
                .with_dir("/etc/ssl/certs")
                .with_dir("/etc/ssl/private")
                .with_dir("c:\\etc\\ssl\\certs")
                .with_dir("c:\\etc\\ssl\\private")
                // Default watcher dirs (platform-specific) on read-write
                // mounts, as the provider requires.
                .with_dir(DEFAULT_WATCHER_CONFIG_DIR)
                .with_dir(DEFAULT_WATCHER_REQUESTS_DIR)
                // Override watcher dirs used by override tests, read-write.
                .with_dir("/mnt/wcp/config")
                .with_dir("/mnt/wcp/requests")
                .with_dir(r"C:\mnt\wcp\config")
                .with_dir(r"C:\mnt\wcp\requests"),
        )
    }

    fn test_paths(suffix: &str) -> (String, String, String) {
        #[cfg(unix)]
        {
            (
                format!("/etc/ssl/certs/server{suffix}.crt"),
                format!("/etc/ssl/private/server{suffix}.key"),
                format!("/etc/ssl/certs/chain{suffix}.pem"),
            )
        }
        #[cfg(windows)]
        {
            (
                format!("c:\\etc\\ssl\\certs\\server{suffix}.crt"),
                format!("c:\\etc\\ssl\\private\\server{suffix}.key"),
                format!("c:\\etc\\ssl\\certs\\chain{suffix}.pem"),
            )
        }
    }

    fn test_dirs() -> (&'static str, &'static str) {
        #[cfg(unix)]
        {
            ("/etc/ssl/certs", "/etc/ssl/private")
        }
        #[cfg(windows)]
        {
            ("c:\\etc\\ssl\\certs", "c:\\etc\\ssl\\private")
        }
    }

    // returns a path permission string and the associated PathPermission that should be constructed from the config
    fn test_perm_config(perm_descr: &str) -> (String, Option<PathPermission>) {
        #[cfg(windows)]
        {
            match perm_descr {
                "EveryoneRead" => (
                    "{trustee_name=\"Everyone\", trustee_type=\"Group\", rights=\"Read\"}"
                        .to_owned(),
                    Some(PathPermission {
                        trustee_type: TrusteeType::Group,
                        trustee_name: "Everyone".to_owned(),
                        rights: Rights::Read,
                    }),
                ),
                "EveryoneReadAlterCase" => (
                    "{trustee_name=\"Everyone\", trustee_type=\"group\", rights=\"READ\"}"
                        .to_owned(),
                    Some(PathPermission {
                        trustee_type: TrusteeType::Group,
                        trustee_name: "Everyone".to_owned(),
                        rights: Rights::Read,
                    }),
                ),
                "EveryoneReadWrongCase" => (
                    "{trustee_name=\"Everyone\", trustee_type=\"gROUp\", rights=\"reaD\"}"
                        .to_owned(),
                    Some(PathPermission {
                        trustee_type: TrusteeType::Group,
                        trustee_name: "Everyone".to_owned(),
                        rights: Rights::Read,
                    }),
                ),
                "AdminOwnerFullAccess" => (
                    "{trustee_name=\"Administrators\", trustee_type=\"Group\", rights=\"Read\"}"
                        .to_owned(),
                    Some(PathPermission {
                        trustee_type: TrusteeType::Group,
                        trustee_name: "Administrators".to_owned(),
                        rights: Rights::Read,
                    }),
                ),
                "AdminOwnerFullAccessAlterCase" => (
                    "{trustee_name=\"Administrators\", trustee_type=\"GROUP\", rights=\"read\"}"
                        .to_owned(),
                    Some(PathPermission {
                        trustee_type: TrusteeType::Group,
                        trustee_name: "Administrators".to_owned(),
                        rights: Rights::Read,
                    }),
                ),
                _ => ("invalid toml config entry".to_owned(), None),
            }
        }
        #[cfg(unix)]
        {
            match perm_descr {
                "EveryoneRead" => (
                    "{mode=\"444\"}".to_owned(),
                    Some(PathPermission { mode: 0o444 }),
                ),
                "AdminOwnerFullAccess" => (
                    "{mode=\"700\"}".to_owned(),
                    Some(PathPermission { mode: 0o700 }),
                ),
                _ => ("invalid toml config entry".to_owned(), None),
            }
        }
    }

    mod defaults {
        use super::*;

        #[test]
        fn test_empty_config_uses_defaults() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let result = validator.validate_toml_config_str("");
            assert!(result.is_ok());
            let config = result.unwrap();
            assert!(config.secrets_manager.enabled);
            assert_eq!(config.secrets_manager.http_port, 2773);
            assert!(config.acm.is_none());
        }

        #[test]
        fn test_validate_with_none() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let result = validator.validate(None);
            assert!(result.is_ok());
            let config = result.unwrap();
            assert!(config.secrets_manager.enabled);
            assert!(config.acm.is_none());
        }

        #[test]
        fn test_validate_with_file_path() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let result = validator.validate(Some("/some/config.toml"));
            assert!(result.is_ok());
        }
    }

    mod legacy_format {
        use super::*;

        #[test]
        fn test_valid_all_keys() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"
                log_level = "info"
                log_to_file = true
                http_port = "2773"
                ttl_seconds = "300"
                cache_size = "100"
                max_conn = "5"
                max_roles = "10"
                path_prefix = "/v1"
                region = "eu-west-1"
                ssrf_headers = ["X-Vault-Token"]
                ssrf_env_variables = ["AWS_TOKEN"]
                ignore_transient_errors = true
                validate_credentials = false

                [prefetch]
                cache_buffer_ratio = 0.6
                max_jitter_seconds = 2
                secrets = [{ secret_id = "my-secret" }]
                filter_tags = [{ key = "Env" }]
            "#;
            let result = validator.validate_toml_config_str(toml);
            assert!(result.is_ok(), "Errors: {}", result.unwrap_err());
            let config = result.unwrap();
            assert!(config.logging.log_to_file);
            assert_eq!(config.secrets_manager.cache.cache_size.get(), 100);
            assert_eq!(config.secrets_manager.max_conn, 5);
            assert_eq!(config.secrets_manager.max_roles, 10);
            assert_eq!(config.secrets_manager.path_prefix, "/v1");
            assert_eq!(config.secrets_manager.region, Some("eu-west-1".to_string()));
            assert_eq!(
                config.secrets_manager.security.ssrf_headers,
                vec!["X-Vault-Token"]
            );
            assert_eq!(
                config.secrets_manager.security.ssrf_env_variables,
                vec!["AWS_TOKEN"]
            );
            assert!(config.secrets_manager.ignore_transient_errors);
            assert!(!config.secrets_manager.validate_credentials);
            assert!(config.secrets_manager.prefetch.is_enabled());
            assert_eq!(config.secrets_manager.prefetch.cache_buffer_ratio, 0.6);
            assert_eq!(config.secrets_manager.prefetch.max_jitter_seconds, 2);
            assert_eq!(config.secrets_manager.prefetch.secrets.len(), 1);
            assert_eq!(config.secrets_manager.prefetch.filter_tags.len(), 1);
        }

        #[test]
        fn test_integer_values() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"
                http_port = 8080
                ttl_seconds = 300
                cache_size = 500
                max_conn = 10
            "#;
            let result = validator.validate_toml_config_str(toml);
            assert!(result.is_ok());
            let config = result.unwrap();
            assert_eq!(config.secrets_manager.http_port, 8080);
            assert_eq!(config.secrets_manager.cache.ttl_seconds, 300);
            assert_eq!(config.secrets_manager.cache.cache_size.get(), 500);
            assert_eq!(config.secrets_manager.max_conn, 10);
        }

        #[test]
        fn test_http_port_zero_allowed() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"http_port = "0""#;
            let result = validator.validate_toml_config_str(toml);
            assert!(result.is_ok());
            assert_eq!(result.unwrap().secrets_manager.http_port, 0);
        }

        #[test]
        fn test_invalid_http_port() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"http_port = "80""#;
            let result = validator.validate_toml_config_str(toml);
            assert!(result.is_err());
            let errors = result.unwrap_err();
            assert_eq!(errors.len(), 1);
            assert_eq!(errors.errors[0].code, ValidationErrorCode::ValueOutOfRange);
        }

        #[test]
        fn test_invalid_log_level() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"log_level = "verbose""#;
            let result = validator.validate_toml_config_str(toml);
            assert!(result.is_err());
            let errors = result.unwrap_err();
            assert_eq!(errors.errors[0].code, ValidationErrorCode::InvalidLogLevel);
        }

        #[test]
        fn test_invalid_toml_type() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"http_port = true"#;
            let result = validator.validate_toml_config_str(toml);
            assert!(result.is_err());
            let errors = result.unwrap_err();
            assert_eq!(errors.errors[0].code, ValidationErrorCode::InvalidType);
        }

        #[test]
        fn test_empty_ssrf_headers() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"ssrf_headers = []"#;
            let result = validator.validate_toml_config_str(toml);
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .errors
                .iter()
                .any(|e| e.code == ValidationErrorCode::InvalidValue));
        }

        #[test]
        fn test_empty_ssrf_env_variables() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"ssrf_env_variables = []"#;
            let result = validator.validate_toml_config_str(toml);
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .errors
                .iter()
                .any(|e| e.code == ValidationErrorCode::InvalidValue));
        }

        #[test]
        fn test_path_prefix_missing_leading_slash() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"path_prefix = "v1""#;
            let result = validator.validate_toml_config_str(toml);
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .errors
                .iter()
                .any(|e| e.code == ValidationErrorCode::InvalidValue));
        }

        #[test]
        fn test_prefetch_with_secrets() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"
                [prefetch]
                secrets = [
                  { secret_id = "my-secret" },
                  { secret_id = "other-secret", role_arn = "arn:aws:iam::123456789012:role/MyRole" },
                ]
            "#;
            let result = validator.validate_toml_config_str(toml);
            assert!(result.is_ok(), "Errors: {}", result.unwrap_err());
            let config = result.unwrap();
            assert!(config.secrets_manager.prefetch.is_enabled());
            assert_eq!(config.secrets_manager.prefetch.secrets.len(), 2);
            assert_eq!(
                config.secrets_manager.prefetch.secrets[0].secret_id,
                "my-secret"
            );
            assert!(config.secrets_manager.prefetch.secrets[0]
                .role_arn
                .is_none());
            assert_eq!(
                config.secrets_manager.prefetch.secrets[1]
                    .role_arn
                    .as_deref(),
                Some("arn:aws:iam::123456789012:role/MyRole")
            );
        }

        #[test]
        fn test_prefetch_with_filter_tags() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"
                [prefetch]
                filter_tags = [
                  { key = "Environment" },
                  { key = "Team", role_arn = "arn:aws:iam::123456789012:role/MyRole" },
                ]
            "#;
            let result = validator.validate_toml_config_str(toml);
            assert!(result.is_ok(), "Errors: {}", result.unwrap_err());
            let config = result.unwrap();
            assert!(config.secrets_manager.prefetch.is_enabled());
            assert_eq!(config.secrets_manager.prefetch.filter_tags.len(), 2);
            assert_eq!(
                config.secrets_manager.prefetch.filter_tags[0].key,
                "Environment"
            );
            assert_eq!(
                config.secrets_manager.prefetch.filter_tags[1]
                    .role_arn
                    .as_deref(),
                Some("arn:aws:iam::123456789012:role/MyRole")
            );
        }

        #[test]
        fn test_prefetch_cache_buffer_ratio_valid() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            for ratio in ["0.1", "0.5", "0.8", "1.0"] {
                let toml = format!(
                    "[prefetch]\ncache_buffer_ratio = {}\nsecrets = [{{ secret_id = \"test\" }}]",
                    ratio
                );
                let result = validator.validate_toml_config_str(&toml);
                assert!(
                    result.is_ok(),
                    "ratio {} should be valid: {}",
                    ratio,
                    result.unwrap_err()
                );
            }
        }

        #[test]
        fn test_prefetch_cache_buffer_ratio_invalid() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            for ratio in ["0.0", "0.09", "1.1"] {
                let toml = format!(
                    "[prefetch]\ncache_buffer_ratio = {}\nsecrets = [{{ secret_id = \"test\" }}]",
                    ratio
                );
                let result = validator.validate_toml_config_str(&toml);
                assert!(result.is_err(), "ratio {} should be invalid", ratio);
            }
        }

        #[test]
        fn test_prefetch_max_jitter_valid_boundary() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = "[prefetch]\nmax_jitter_seconds = 10\nsecrets = [{ secret_id = \"test\" }]";
            let result = validator.validate_toml_config_str(toml);
            assert!(result.is_ok(), "Errors: {}", result.unwrap_err());
            assert_eq!(
                result.unwrap().secrets_manager.prefetch.max_jitter_seconds,
                10
            );
        }

        #[test]
        fn test_prefetch_max_jitter_invalid() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = "[prefetch]\nmax_jitter_seconds = 11\nsecrets = [{ secret_id = \"test\" }]";
            let result = validator.validate_toml_config_str(toml);
            assert!(result.is_err());
        }

        #[test]
        fn test_prefetch_empty_is_disabled() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = "[prefetch]";
            let result = validator.validate_toml_config_str(toml);
            assert!(result.is_ok(), "Errors: {}", result.unwrap_err());
            assert!(!result.unwrap().secrets_manager.prefetch.is_enabled());
        }

        #[test]
        fn test_prefetch_defaults() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = "";
            let result = validator.validate_toml_config_str(toml);
            assert!(result.is_ok(), "Errors: {}", result.unwrap_err());
            let config = result.unwrap();
            assert!(!config.secrets_manager.prefetch.is_enabled());
            assert_eq!(config.secrets_manager.prefetch.cache_buffer_ratio, 0.8);
            assert_eq!(config.secrets_manager.prefetch.max_jitter_seconds, 0);
        }

        // A legacy [failover] section is read when the whole config uses flat keys.
        #[test]
        fn test_failover_valid_legacy() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"
                region = "us-east-1"

                [failover]
                default_failover_region = "us-west-2"
            "#;
            let result = validator.validate_toml_config_str(toml);
            assert!(result.is_ok(), "Errors: {}", result.unwrap_err());
            let failover = result.unwrap().secrets_manager.failover;
            assert!(failover.is_enabled());
            assert_eq!(
                failover.default_failover_region,
                Some("us-west-2".to_string())
            );
        }
    }

    mod nested_secrets_manager {
        use super::*;

        const ARN_1: &str = "arn:aws:secretsmanager:us-east-1:123456789012:secret:secret-1-AbCdEf";
        const ARN_2: &str = "arn:aws:secretsmanager:us-east-1:123456789012:secret:secret-2-GhIjKl";

        #[test]
        fn test_valid_all_fields() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"
                [capabilities.secrets_manager]
                enabled = true
                http_port = 5000
                path_prefix = "/secrets"
                max_conn = 50
                max_roles = 15
                region = "us-west-2"
                ignore_transient_errors = true
                validate_credentials = false

                [capabilities.secrets_manager.cache]
                ttl_seconds = 1800
                cache_size = 200

                [capabilities.secrets_manager.security]
                ssrf_headers = ["X-Custom"]
                ssrf_env_variables = ["MY_TOKEN"]

                [capabilities.secrets_manager.prefetch]
                cache_buffer_ratio = 0.5
                max_jitter_seconds = 3
                secrets = [{ secret_id = "my-secret", role_arn = "arn:aws:iam::123456789012:role/R" }]
                filter_tags = [{ key = "Env" }]
            "#;
            let result = validator.validate_toml_config_str(toml);
            assert!(result.is_ok(), "Errors: {}", result.unwrap_err());
            let config = result.unwrap();
            assert_eq!(config.secrets_manager.http_port, 5000);
            assert_eq!(config.secrets_manager.path_prefix, "/secrets");
            assert_eq!(config.secrets_manager.max_conn, 50);
            assert_eq!(config.secrets_manager.max_roles, 15);
            assert_eq!(config.secrets_manager.region, Some("us-west-2".to_string()));
            assert!(config.secrets_manager.ignore_transient_errors);
            assert!(!config.secrets_manager.validate_credentials);
            assert_eq!(config.secrets_manager.cache.ttl_seconds, 1800);
            assert_eq!(config.secrets_manager.cache.cache_size.get(), 200);
            assert_eq!(
                config.secrets_manager.security.ssrf_headers,
                vec!["X-Custom"]
            );
            assert_eq!(
                config.secrets_manager.security.ssrf_env_variables,
                vec!["MY_TOKEN"]
            );
            assert!(config.secrets_manager.prefetch.is_enabled());
            assert_eq!(config.secrets_manager.prefetch.cache_buffer_ratio, 0.5);
            assert_eq!(config.secrets_manager.prefetch.max_jitter_seconds, 3);
            assert_eq!(config.secrets_manager.prefetch.secrets.len(), 1);
            assert_eq!(
                config.secrets_manager.prefetch.secrets[0].secret_id,
                "my-secret"
            );
            assert_eq!(config.secrets_manager.prefetch.filter_tags.len(), 1);
            assert_eq!(config.secrets_manager.prefetch.filter_tags[0].key, "Env");
        }

        #[test]
        fn test_invalid_http_port() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"
                [capabilities.secrets_manager]
                http_port = 80
            "#;
            let result = validator.validate_toml_config_str(toml);
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .errors
                .iter()
                .any(|e| e.code == ValidationErrorCode::ValueOutOfRange));
        }

        #[test]
        fn test_http_port_zero_allowed() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"
                [capabilities.secrets_manager]
                http_port = 0
            "#;
            let result = validator.validate_toml_config_str(toml);
            assert!(result.is_ok());
            assert_eq!(result.unwrap().secrets_manager.http_port, 0);
        }

        #[test]
        fn test_logging_section() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"
                [logging]
                log_level = "warn"
                log_to_file = true

                [capabilities.secrets_manager]
                enabled = true
            "#;
            let result = validator.validate_toml_config_str(toml);
            assert!(result.is_ok());
            let config = result.unwrap();
            assert_eq!(config.logging.log_level, LogLevel::Warn);
            assert!(config.logging.log_to_file);
        }

        #[test]
        fn test_empty_ssrf_headers() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"
                [capabilities.secrets_manager.security]
                ssrf_headers = []
            "#;
            let result = validator.validate_toml_config_str(toml);
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .errors
                .iter()
                .any(|e| e.code == ValidationErrorCode::InvalidValue));
        }

        #[test]
        fn test_empty_ssrf_env_variables() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"
                [capabilities.secrets_manager.security]
                ssrf_env_variables = []
            "#;
            let result = validator.validate_toml_config_str(toml);
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .errors
                .iter()
                .any(|e| e.code == ValidationErrorCode::InvalidValue));
        }

        #[test]
        fn test_path_prefix_missing_leading_slash() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"
                [capabilities.secrets_manager]
                path_prefix = "no_slash"
            "#;
            let result = validator.validate_toml_config_str(toml);
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .errors
                .iter()
                .any(|e| e.code == ValidationErrorCode::InvalidValue));
        }

        // No failover section leaves failover disabled with the default timeout.
        #[test]
        fn test_failover_defaults() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"
                [capabilities.secrets_manager]
                region = "us-east-1"
            "#;
            let config = validator.validate_toml_config_str(toml).unwrap();
            let failover = &config.secrets_manager.failover;
            assert!(!failover.is_enabled());
            assert_eq!(failover.operation_timeout_ms, 3000);
        }

        // A full failover section is read into FailoverConfig.
        #[test]
        fn test_failover_valid_nested() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = format!(
                r#"
                [capabilities.secrets_manager]
                region = "us-east-1"

                [capabilities.secrets_manager.failover]
                default_failover_region = "us-west-2"
                operation_timeout_ms = 2000

                [capabilities.secrets_manager.failover.secret_to_region_map]
                "{ARN_1}" = "eu-west-1"
                "{ARN_2}" = "ap-northeast-1"
            "#
            );
            let result = validator.validate_toml_config_str(&toml);
            assert!(result.is_ok(), "Errors: {}", result.unwrap_err());
            let failover = result.unwrap().secrets_manager.failover;
            assert!(failover.is_enabled());
            assert_eq!(
                failover.default_failover_region,
                Some("us-west-2".to_string())
            );
            assert_eq!(failover.operation_timeout_ms, 2000);
            assert_eq!(failover.secret_to_region_map[ARN_1], "eu-west-1");
            assert_eq!(failover.secret_to_region_map[ARN_2], "ap-northeast-1");
        }

        // A misspelled key fails the whole config instead of silently leaving failover disabled.
        #[test]
        fn test_failover_unknown_key_rejected() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"
                [capabilities.secrets_manager]
                region = "us-east-1"

                [capabilities.secrets_manager.failover]
                default_failover_regoin = "us-west-2"
            "#;
            let errors = validator.validate_toml_config_str(toml).unwrap_err();
            assert_eq!(errors.len(), 1);
            assert_eq!(errors.errors[0].code, ValidationErrorCode::TomlSyntaxError);
        }

        // An empty default failover region, or one that matches the primary region, is rejected.
        #[test]
        fn test_failover_unusable_default_region_rejected() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            for region in ["", "us-east-1"] {
                let toml = format!(
                    r#"
                    [capabilities.secrets_manager]
                    region = "us-east-1"

                    [capabilities.secrets_manager.failover]
                    default_failover_region = "{region}"
                "#
                );
                let errors = validator.validate_toml_config_str(&toml).unwrap_err();
                assert_eq!(errors.len(), 1, "{region}");
                assert_eq!(errors.errors[0].code, ValidationErrorCode::InvalidValue);
                assert_eq!(
                    errors.errors[0].field,
                    "capabilities.secrets_manager.failover.default_failover_region"
                );
            }
        }

        // An unusable per-secret region is reported against its ARN; usable entries are not.
        #[test]
        fn test_failover_unusable_map_region_rejected() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = format!(
                r#"
                [capabilities.secrets_manager]
                region = "us-east-1"

                [capabilities.secrets_manager.failover.secret_to_region_map]
                "{ARN_1}" = "eu-west-1"
                "{ARN_2}" = "us-east-1"
            "#
            );
            let errors = validator.validate_toml_config_str(&toml).unwrap_err();
            assert_eq!(errors.len(), 1);
            assert_eq!(errors.errors[0].code, ValidationErrorCode::InvalidValue);
            assert_eq!(
                errors.errors[0].field,
                format!("capabilities.secrets_manager.failover.secret_to_region_map.{ARN_2}")
            );
        }

        // Per-secret failover regions enable failover without a default failover region.
        #[test]
        fn test_failover_map_without_default() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = format!(
                r#"
                [capabilities.secrets_manager]
                region = "us-east-1"

                [capabilities.secrets_manager.failover.secret_to_region_map]
                "{ARN_1}" = "eu-west-1"
            "#
            );
            let result = validator.validate_toml_config_str(&toml);
            assert!(result.is_ok(), "Errors: {}", result.unwrap_err());
            let failover = result.unwrap().secrets_manager.failover;
            assert!(failover.is_enabled());
            assert_eq!(failover.default_failover_region, None);
            assert_eq!(failover.secret_to_region_map[ARN_1], "eu-west-1");
        }

        // The operation timeout accepts 2000 to 25000; anything outside is rejected.
        #[test]
        fn test_failover_operation_timeout_bounds() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            for (value, valid) in [
                (2000, true),
                (25000, true),
                (1999, false),
                (100, false),
                (25001, false),
            ] {
                let toml = format!(
                    r#"
                    [capabilities.secrets_manager]
                    region = "us-east-1"

                    [capabilities.secrets_manager.failover]
                    default_failover_region = "us-west-2"
                    operation_timeout_ms = {value}
                "#
                );
                match validator.validate_toml_config_str(&toml) {
                    Ok(config) => {
                        assert!(valid, "{value} should be rejected");
                        assert_eq!(config.secrets_manager.failover.operation_timeout_ms, value);
                    }
                    Err(errors) => {
                        assert!(!valid, "{value} should be accepted: {errors}");
                        assert_eq!(errors.errors[0].code, ValidationErrorCode::ValueOutOfRange);
                    }
                }
            }
        }

        // A non-integer operation timeout fails TOML parsing.
        #[test]
        fn test_failover_operation_timeout_not_an_integer() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            for value in [r#""abc""#, "2000.5", "true"] {
                let toml = format!(
                    r#"
                    [capabilities.secrets_manager]
                    region = "us-east-1"

                    [capabilities.secrets_manager.failover]
                    default_failover_region = "us-west-2"
                    operation_timeout_ms = {value}
                "#
                );
                let errors = validator.validate_toml_config_str(&toml).unwrap_err();
                assert_eq!(errors.len(), 1, "{value}");
                assert_eq!(
                    errors.errors[0].code,
                    ValidationErrorCode::TomlSyntaxError,
                    "{value}"
                );
            }
        }
    }

    mod nested_acm {
        use super::*;

        #[test]
        fn test_valid_all_fields() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let (cert, key, chain) = test_paths("");
            let (cert_perm_cfg, cert_perm) = test_perm_config("EveryoneRead");
            let (key_perm_cfg, key_perm) = test_perm_config("AdminOwnerFullAccess");
            let toml = format!(
                r#"
                [capabilities.acm]
                enabled = true

                [[capabilities.acm.certificates]]
                certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"
                role_arn = "arn:aws:iam::123456789012:role/MyRole"
                certificate_path = '{cert}'
                private_key_path = '{key}'
                chain_path = '{chain}'
                certificate_and_chain_permission = {cert_perm_cfg}
                key_permission = {key_perm_cfg}
            "#
            );
            let result = validator.validate_toml_config_str(&toml);
            assert!(result.is_ok(), "Errors: {}", result.unwrap_err());
            let config = result.unwrap();
            let acm = config.acm.unwrap();
            assert!(acm.enabled);
            assert_eq!(acm.certificates.len(), 1);
            assert_eq!(acm.certificates["arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"].cert_and_chain_permission, cert_perm);
            assert_eq!(acm.certificates["arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"].key_permission, key_perm);
        }

        #[test]
        #[cfg(windows)]
        fn test_valid_all_fields_different_case_permission_enums() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let (cert, key, chain) = test_paths("");
            let (cert_perm_cfg, cert_perm) = test_perm_config("EveryoneReadAlterCase");
            let (key_perm_cfg, key_perm) = test_perm_config("AdminOwnerFullAccessAlterCase");
            let toml = format!(
                r#"
                [capabilities.acm]
                enabled = true

                [[capabilities.acm.certificates]]
                certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"
                role_arn = "arn:aws:iam::123456789012:role/MyRole"
                certificate_path = '{cert}'
                private_key_path = '{key}'
                chain_path = '{chain}'
                certificate_and_chain_permission = {cert_perm_cfg}
                key_permission = {key_perm_cfg}
            "#
            );
            let result = validator.validate_toml_config_str(&toml);
            assert!(result.is_ok(), "Errors: {}", result.unwrap_err());
            let config = result.unwrap();
            let acm = config.acm.unwrap();
            assert!(acm.enabled);
            assert_eq!(acm.certificates.len(), 1);
            assert_eq!(acm.certificates["arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"].cert_and_chain_permission, cert_perm);
            assert_eq!(acm.certificates["arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"].key_permission, key_perm);
        }

        #[test]
        #[cfg(windows)]
        fn test_invalid_wrong_case_permission_enums() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let (cert, key, chain) = test_paths("");
            let (cert_perm_cfg, cert_perm) = test_perm_config("EveryoneReadWrongCase");
            let (key_perm_cfg, key_perm) = test_perm_config("AdminOwnerFullAccessAlterCase");
            let toml = format!(
                r#"
                [capabilities.acm]
                enabled = true

                [[capabilities.acm.certificates]]
                certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"
                role_arn = "arn:aws:iam::123456789012:role/MyRole"
                certificate_path = '{cert}'
                private_key_path = '{key}'
                chain_path = '{chain}'
                certificate_and_chain_permission = {cert_perm_cfg}
                key_permission = {key_perm_cfg}
            "#
            );
            let result = validator.validate_toml_config_str(&toml);
            assert!(result.is_err());
            let errors = result.unwrap_err();
            let syntax: Vec<_> = errors
                .errors
                .iter()
                .filter(|e| e.code == ValidationErrorCode::TomlSyntaxError)
                .collect();
            assert_eq!(syntax.len(), 1);
        }

        #[test]
        // per certificate permissions override the defaults
        fn test_valid_all_fields_default_permissions() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let (cert, key, chain) = test_paths("");
            // default_cert_perm will be overridden by per-cert certificate_and_chain_permission
            let (default_cert_perm_cfg, _default_cert_perm) =
                test_perm_config("AdminOwnerFullAccess");
            let (default_key_perm_cfg, default_key_perm) = test_perm_config("AdminOwnerFullAccess");
            // per-cert override for certificate_and_chain_permission
            let (cert_perm_cfg, cert_perm) = test_perm_config("EveryoneRead");
            let toml = format!(
                r#"
                [capabilities.acm]
                enabled = true
                default_certificate_permission = {default_cert_perm_cfg}
                default_key_permission = {default_key_perm_cfg}

                [[capabilities.acm.certificates]]
                certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"
                role_arn = "arn:aws:iam::123456789012:role/MyRole"
                certificate_path = '{cert}'
                private_key_path = '{key}'
                chain_path = '{chain}'
                certificate_and_chain_permission = {cert_perm_cfg}
            "#
            );
            let result = validator.validate_toml_config_str(&toml);
            assert!(result.is_ok(), "Errors: {}", result.unwrap_err());
            let config = result.unwrap();
            let acm = config.acm.unwrap();
            assert!(acm.enabled);
            assert_eq!(acm.certificates.len(), 1);
            // per certificate cert file permission overrides default cert permission config
            assert_eq!(acm.certificates["arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"].cert_and_chain_permission, cert_perm);
            // key permission uses default key permission config as there is no per certificate config set
            assert_eq!(acm.certificates["arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"].key_permission, default_key_perm);
        }

        #[cfg(windows)]
        #[test]
        fn test_valid_all_fields_diff_formatting() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let (cert, key, chain) = test_paths("");
            let (cert_perm_cfg, cert_perm) = test_perm_config("EveryoneRead");
            let toml = format!(
                r#"
                [capabilities.acm]
                enabled = true

                [[capabilities.acm.certificates]]
                certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"
                role_arn = "arn:aws:iam::123456789012:role/MyRole"
                certificate_path = '{cert}'
                private_key_path = '{key}'
                chain_path = '{chain}'
                certificate_and_chain_permission = {cert_perm_cfg}
                key_permission.trustee_name = "Everyone"
                key_permission.trustee_type = "Group"
                key_permission.rights = "Read"
            "#
            );
            let result = validator.validate_toml_config_str(&toml);
            assert!(result.is_ok(), "Errors: {}", result.unwrap_err());
            let config = result.unwrap();
            let acm = config.acm.unwrap();
            assert!(acm.enabled);
            assert_eq!(acm.certificates.len(), 1);
            assert_eq!(acm.certificates["arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"].cert_and_chain_permission, cert_perm);
            assert_eq!(acm.certificates["arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"].key_permission, cert_perm);
        }

        #[test]
        fn test_enabled_false() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"
                [capabilities.acm]
                enabled = false
            "#;
            let result = validator.validate_toml_config_str(toml);
            assert!(result.is_ok());
            let acm = result.unwrap().acm.unwrap();
            assert!(!acm.enabled);
            assert!(acm.certificates.is_empty());
        }

        #[test]
        fn test_missing_required_field() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let (cert, _key, _chain) = test_paths("");
            let toml = format!(
                r#"
                [capabilities.acm]
                enabled = true

                [[capabilities.acm.certificates]]
                certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"
                certificate_path = '{cert}'
                # missing private_key_path and chain_path
            "#
            );
            let result = validator.validate_toml_config_str(&toml);
            assert!(result.is_err());
            let errors = result.unwrap_err();
            let missing: Vec<_> = errors
                .errors
                .iter()
                .filter(|e| e.code == ValidationErrorCode::MissingRequiredField)
                .collect();
            assert_eq!(missing.len(), 2);
            assert!(missing
                .iter()
                .any(|e| e.field.ends_with("private_key_path")));
            assert!(missing.iter().any(|e| e.field.ends_with("role_arn")));
        }

        #[test]
        fn test_invalid_certificate_arn() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let (cert, key, chain) = test_paths("");
            let toml = format!(
                r#"
                [capabilities.acm]
                enabled = true

                [[capabilities.acm.certificates]]
                certificate_arn = "not-an-arn"
                role_arn = "arn:aws:iam::123456789012:role/MyRole"
                certificate_path = '{cert}'
                private_key_path = '{key}'
                chain_path = '{chain}'
            "#
            );
            let result = validator.validate_toml_config_str(&toml);
            assert!(result.is_err());
            let errors = result.unwrap_err();
            assert!(errors
                .errors
                .iter()
                .any(|e| e.code == ValidationErrorCode::InvalidCertificateArn));
        }

        #[test]
        fn test_invalid_role_arn() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let (cert, key, chain) = test_paths("");
            let toml = format!(
                r#"
                [capabilities.acm]
                enabled = true

                [[capabilities.acm.certificates]]
                certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"
                role_arn = "not-a-role-arn"
                certificate_path = '{cert}'
                private_key_path = '{key}'
                chain_path = '{chain}'
            "#
            );
            let result = validator.validate_toml_config_str(&toml);
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .errors
                .iter()
                .any(|e| e.code == ValidationErrorCode::InvalidRoleArn));
        }

        #[test]
        fn test_relative_path_rejected() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let (_cert, key, chain) = test_paths("");
            let toml = format!(
                r#"
                [capabilities.acm]
                enabled = true

                [[capabilities.acm.certificates]]
                certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"
                role_arn = "arn:aws:iam::123456789012:role/MyRole"
                certificate_path = "relative/path/cert.pem"
                private_key_path = '{key}'
                chain_path = '{chain}'
            "#
            );
            let result = validator.validate_toml_config_str(&toml);
            assert!(result.is_err());
            let errors = result.unwrap_err();
            assert!(errors
                .errors
                .iter()
                .any(|e| e.code == ValidationErrorCode::RelativePath));
        }

        #[test]
        fn test_duplicate_paths_within_block() {
            let (cert, _key, chain) = test_paths("");
            let (cert_dir, key_dir) = test_dirs();
            let toml = format!(
                r#"
            [capabilities.acm]
            enabled = true
            
            [[capabilities.acm.certificates]]
            certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"
            role_arn = "arn:aws:iam::123456789012:role/MyRole"
            certificate_path = '{cert}'
            private_key_path = '{cert}'
            chain_path = '{chain}'
            "#
            );
            let fs = Arc::new(MockFileSystem::new().with_dir(cert_dir).with_dir(key_dir));
            let validator = ConfigValidator::with_filesystem(fs);
            let result = validator.validate_toml_config_str(&toml);
            assert!(result.is_err());
            let errors = result.unwrap_err();
            assert!(errors
                .errors
                .iter()
                .any(|e| e.code == ValidationErrorCode::ConflictingPaths));
        }

        #[test]
        fn test_duplicate_certificate_arns() {
            let arn = "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012";
            let (cert, key, chain) = test_paths("");
            let (cert2, key2, chain2) = test_paths("2");
            let (cert_dir, key_dir) = test_dirs();

            let toml = format!(
                r#"
                [capabilities.acm]
                enabled = true

                [[capabilities.acm.certificates]]
                certificate_arn = "{arn}"
                role_arn = "arn:aws:iam::123456789012:role/MyRole"
                certificate_path = '{cert}'
                private_key_path = '{key}'
                chain_path = '{chain}'

                [[capabilities.acm.certificates]]
                certificate_arn = "{arn}"
                role_arn = "arn:aws:iam::123456789012:role/MyRole"
                certificate_path = '{cert2}'
                private_key_path = '{key2}'
                chain_path = '{chain2}'
            "#
            );
            let fs = Arc::new(MockFileSystem::new().with_dir(cert_dir).with_dir(key_dir));
            let validator = ConfigValidator::with_filesystem(fs);
            let result = validator.validate_toml_config_str(&toml);
            assert!(result.is_err());
            let errors = result.unwrap_err();
            assert!(errors
                .errors
                .iter()
                .any(|e| e.message.contains("Duplicate certificate_arn")));
        }

        #[test]
        fn test_refresh_command() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let (cert, key, chain) = test_paths("");
            let toml = format!(
                r#"
                [capabilities.acm]
                enabled = true

                [[capabilities.acm.certificates]]
                certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"
                role_arn = "arn:aws:iam::123456789012:role/MyRole"
                certificate_path = '{cert}'
                private_key_path = '{key}'
                chain_path = '{chain}'
                refresh_command = "/bin/systemctl reload nginx"
            "#
            );
            let result = validator.validate_toml_config_str(&toml);
            assert!(result.is_ok(), "Errors: {}", result.unwrap_err());
            let cert = result
                .unwrap()
                .acm
                .unwrap()
                .certificates
                .into_values()
                .next()
                .unwrap();
            assert_eq!(
                cert.refresh_command,
                Some("/bin/systemctl reload nginx".to_string())
            );
            // refresh_command without watcher_id stays provider-executed
            assert_eq!(cert.watcher_id, None);
        }

        #[test]
        fn test_empty_refresh_command() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let (cert, key, chain) = test_paths("");
            let toml = format!(
                r#"
                [capabilities.acm]
                enabled = true

                [[capabilities.acm.certificates]]
                certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"
                role_arn = "arn:aws:iam::123456789012:role/MyRole"
                certificate_path = '{cert}'
                private_key_path = '{key}'
                chain_path = '{chain}'
                refresh_command = "  "
            "#
            );
            let result = validator.validate_toml_config_str(&toml);
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .errors
                .iter()
                .any(|e| e.code == ValidationErrorCode::EmptyCommand));
        }

        #[test]
        fn test_too_many_certificates() {
            let (cert_dir, key_dir) = test_dirs();
            let fs = Arc::new(MockFileSystem::new().with_dir(cert_dir).with_dir(key_dir));
            let validator = ConfigValidator::with_filesystem(fs);

            let mut certs = String::new();
            for i in 0..MAX_CERTIFICATES + 1 {
                let id = format!("{:08}-1234-1234-1234-123456789012", i);
                certs.push_str(&format!(
                    r#"
                [[capabilities.acm.certificates]]
                certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/{id}"
                role_arn = "arn:aws:iam::123456789012:role/MyRole"
                certificate_path = '{cert_dir}/server{i}.crt'
                private_key_path = '{key_dir}/server{i}.key'
                "#,
                    cert_dir = cert_dir,
                    key_dir = key_dir,
                ));
            }

            let toml = format!(
                r#"
                [capabilities.acm]
                enabled = true
                {certs}
            "#
            );
            let result = validator.validate_toml_config_str(&toml);
            assert!(result.is_err());
            let errors = result.unwrap_err();
            assert!(errors
                .errors
                .iter()
                .any(|e| e.code == ValidationErrorCode::ValueOutOfRange
                    && e.message.contains("Too many certificates")));
        }

        #[test]
        fn test_max_certificates_accepted() {
            let (cert_dir, key_dir) = test_dirs();
            let fs = Arc::new(MockFileSystem::new().with_dir(cert_dir).with_dir(key_dir));
            let validator = ConfigValidator::with_filesystem(fs);

            let mut certs = String::new();
            for i in 0..MAX_CERTIFICATES {
                let id = format!("{:08}-1234-1234-1234-123456789012", i);
                certs.push_str(&format!(
                    r#"
                [[capabilities.acm.certificates]]
                certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/{id}"
                role_arn = "arn:aws:iam::123456789012:role/MyRole"
                certificate_path = '{cert_dir}/server{i}.crt'
                private_key_path = '{key_dir}/server{i}.key'
                "#,
                    cert_dir = cert_dir,
                    key_dir = key_dir,
                ));
            }

            let toml = format!(
                r#"
                [capabilities.acm]
                enabled = true
                {certs}
            "#
            );
            let result = validator.validate_toml_config_str(&toml);
            assert!(
                result.is_ok(),
                "Expected 50 certificates to be accepted, got: {:?}",
                result.unwrap_err()
            );
        }

        /// A program path a watcher accepts here: watcher commands need an
        /// absolute program path, and `/bin/...` isn't absolute on Windows.
        #[cfg(unix)]
        const WATCHER_PROGRAM: &str = "/bin/systemctl";
        #[cfg(windows)]
        const WATCHER_PROGRAM: &str = "C:/tools/systemctl.exe";

        /// A single certificate block, with `extra` appended inside it.
        fn acm_toml_with(extra: &str) -> String {
            let (cert, key, chain) = test_paths("");
            format!(
                r#"
                [capabilities.acm]
                enabled = true

                [[capabilities.acm.certificates]]
                certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"
                role_arn = "arn:aws:iam::123456789012:role/MyRole"
                certificate_path = '{cert}'
                private_key_path = '{key}'
                chain_path = '{chain}'
                {extra}
            "#
            )
        }

        #[test]
        fn test_watcher_id_accepted_and_surfaced() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = acm_toml_with(&format!(
                r#"refresh_command = "{WATCHER_PROGRAM} reload nginx"
                watcher_id = "tls-sidecar""#,
            ));
            let result = validator.validate_toml_config_str(&toml);
            assert!(result.is_ok(), "Errors: {}", result.unwrap_err());
            let cert = result
                .unwrap()
                .acm
                .unwrap()
                .certificates
                .into_values()
                .next()
                .unwrap();
            assert_eq!(cert.watcher_id, Some("tls-sidecar".to_string()));
            assert_eq!(
                cert.refresh_command,
                Some(format!("{WATCHER_PROGRAM} reload nginx"))
            );
        }

        #[test]
        fn test_watcher_id_without_refresh_command_rejected() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = acm_toml_with(r#"watcher_id = "tls-sidecar""#);
            let result = validator.validate_toml_config_str(&toml);
            assert!(result.is_err());
            let errors = result.unwrap_err();
            assert!(
                errors.errors.iter().any(|e| {
                    e.code == ValidationErrorCode::MissingRequiredField
                        && e.field == "capabilities.acm.certificates[0].refresh_command"
                }),
                "Errors: {}",
                errors
            );
        }

        #[test]
        #[cfg(windows)]
        fn test_watcher_accepts_same_commands_as_windows_install() {
            // Parity with an EC2 Windows installation: a watcher accepts any
            // command that passes the general Windows refresh_command rules.
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = acm_toml_with(
                r#"refresh_command = "nginx -s reload"
                watcher_id = "tls-sidecar""#,
            );
            let errors = validator
                .validate_toml_config_str(&toml)
                .err()
                .map(|e| e.errors)
                .unwrap_or_default();
            assert!(
                !errors
                    .iter()
                    .any(|e| e.code == ValidationErrorCode::InvalidCommand),
                "{errors:?}"
            );
        }

        #[test]
        #[cfg(windows)]
        fn test_watcher_accepts_a_quoted_windows_path_with_spaces() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = acm_toml_with(
                r#"refresh_command = '"C:\Program Files\nginx\nginx.exe" -s reload'
                watcher_id = "tls-sidecar""#,
            );
            let errors = validator
                .validate_toml_config_str(&toml)
                .err()
                .map(|e| e.errors)
                .unwrap_or_default();
            assert!(
                !errors
                    .iter()
                    .any(|e| e.code == ValidationErrorCode::InvalidCommand),
                "{errors:?}"
            );
        }

        #[test]
        #[cfg(windows)]
        fn test_unverified_windows_mount_mode_surfaced_as_warnings() {
            // The Windows mount-mode gap passes validation but is returned on
            // ValidatedConfig, so main.rs can log it after the logger starts.
            let fs = Arc::new(
                MockFileSystem::new()
                    .with_dir("c:\\etc\\ssl\\certs")
                    .with_dir("c:\\etc\\ssl\\private")
                    .with_dir_mount_mode_error(
                        DEFAULT_WATCHER_CONFIG_DIR,
                        std::io::ErrorKind::Unsupported,
                    )
                    .with_dir_mount_mode_error(
                        DEFAULT_WATCHER_REQUESTS_DIR,
                        std::io::ErrorKind::Unsupported,
                    ),
            );
            let validator = ConfigValidator::with_filesystem(fs);
            let toml = acm_toml_with(
                r#"refresh_command = "/bin/systemctl reload nginx"
                watcher_id = "tls-sidecar""#,
            );
            let validated = validator.validate_toml_config_str(&toml).unwrap();
            assert_eq!(validated.warnings.len(), 2, "{:?}", validated.warnings);
            assert!(validated.warnings[0].contains("capabilities.acm.watcher_config_dir"));
            assert!(validated.warnings[1].contains("capabilities.acm.watcher_requests_dir"));
        }

        #[test]
        fn test_watcher_config_has_no_warnings_when_mount_mode_verified() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = acm_toml_with(
                r#"refresh_command = "/bin/systemctl reload nginx"
                watcher_id = "tls-sidecar""#,
            );
            let validated = validator.validate_toml_config_str(&toml).unwrap();
            assert!(validated.warnings.is_empty(), "{:?}", validated.warnings);
        }

        #[test]
        fn test_invalid_watcher_id_rejected() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = acm_toml_with(
                r#"refresh_command = "/bin/systemctl reload nginx"
                watcher_id = "../escape""#,
            );
            let result = validator.validate_toml_config_str(&toml);
            assert!(result.is_err());
            let errors = result.unwrap_err();
            assert!(
                errors.errors.iter().any(|e| {
                    e.code == ValidationErrorCode::InvalidWatcherId
                        && e.field == "capabilities.acm.certificates[0].watcher_id"
                }),
                "Errors: {}",
                errors
            );
        }

        #[test]
        fn test_watcher_directories_default_when_omitted() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = acm_toml_with(r#"refresh_command = "/bin/systemctl reload nginx""#);
            let result = validator.validate_toml_config_str(&toml);
            assert!(result.is_ok(), "Errors: {}", result.unwrap_err());
            let acm = result.unwrap().acm.unwrap();
            assert_eq!(
                acm.watcher_config_dir,
                PathBuf::from(DEFAULT_WATCHER_CONFIG_DIR)
            );
            assert_eq!(
                acm.watcher_requests_dir,
                PathBuf::from(DEFAULT_WATCHER_REQUESTS_DIR)
            );
        }

        #[test]
        fn test_watcher_directories_override_honored() {
            #[cfg(unix)]
            let (config_dir, requests_dir) = ("/mnt/wcp/config", "/mnt/wcp/requests");
            #[cfg(windows)]
            let (config_dir, requests_dir) = (r"C:\mnt\wcp\config", r"C:\mnt\wcp\requests");

            let validator = ConfigValidator::with_filesystem(mock_fs());
            let (cert, key, chain) = test_paths("");
            let toml = format!(
                r#"
                [capabilities.acm]
                enabled = true
                watcher_config_dir = '{config_dir}'
                watcher_requests_dir = '{requests_dir}'

                [[capabilities.acm.certificates]]
                certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"
                role_arn = "arn:aws:iam::123456789012:role/MyRole"
                certificate_path = '{cert}'
                private_key_path = '{key}'
                chain_path = '{chain}'
                refresh_command = "{WATCHER_PROGRAM} reload nginx"
                watcher_id = "tls-sidecar"
            "#
            );
            let result = validator.validate_toml_config_str(&toml);
            assert!(result.is_ok(), "Errors: {}", result.unwrap_err());
            let acm = result.unwrap().acm.unwrap();
            assert_eq!(acm.watcher_config_dir, PathBuf::from(config_dir));
            assert_eq!(acm.watcher_requests_dir, PathBuf::from(requests_dir));
        }

        #[test]
        fn test_relative_config_watcher_directory_rejected() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let (cert, key, chain) = test_paths("");
            let toml = format!(
                r#"
                [capabilities.acm]
                enabled = true
                watcher_config_dir = 'relative/config'

                [[capabilities.acm.certificates]]
                certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"
                role_arn = "arn:aws:iam::123456789012:role/MyRole"
                certificate_path = '{cert}'
                private_key_path = '{key}'
                chain_path = '{chain}'
                refresh_command = "/bin/systemctl reload nginx"
                watcher_id = "tls-sidecar"
            "#
            );
            let result = validator.validate_toml_config_str(&toml);
            assert!(result.is_err());
            let errors = result.unwrap_err();
            assert!(
                errors.errors.iter().any(|e| {
                    e.code == ValidationErrorCode::RelativePath
                        && e.field == "capabilities.acm.watcher_config_dir"
                }),
                "Errors: {}",
                errors
            );
        }

        #[test]
        fn test_container_config_both_bad_watcher_dirs_rejected() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let (cert, key, chain) = test_paths("");
            let toml = format!(
                r#"
                [capabilities.acm]
                enabled = true
                watcher_config_dir = ''
                watcher_requests_dir = 'relative/requests'

                [[capabilities.acm.certificates]]
                certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"
                role_arn = "arn:aws:iam::123456789012:role/MyRole"
                certificate_path = '{cert}'
                private_key_path = '{key}'
                chain_path = '{chain}'
                refresh_command = "/bin/systemctl reload nginx"
                watcher_id = "tls-sidecar"
            "#
            );
            let result = validator.validate_toml_config_str(&toml);
            assert!(result.is_err());
            let errors = result.unwrap_err();
            assert!(
                errors.errors.iter().any(|e| {
                    e.code == ValidationErrorCode::RelativePath
                        && e.field == "capabilities.acm.watcher_requests_dir"
                }),
                "Errors: {}",
                errors
            );
            assert!(
                errors.errors.iter().any(|e| {
                    e.code == ValidationErrorCode::InvalidValue
                        && e.field == "capabilities.acm.watcher_config_dir"
                }),
                "Errors: {}",
                errors
            );
        }

        #[test]
        fn test_certificates_may_share_a_watcher_id() {
            let (cert, key, chain) = test_paths("");
            let (cert2, key2, chain2) = test_paths("2");
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = format!(
                r#"
                [capabilities.acm]
                enabled = true

                [[capabilities.acm.certificates]]
                certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/11111111-1234-1234-1234-123456789012"
                role_arn = "arn:aws:iam::123456789012:role/MyRole"
                certificate_path = '{cert}'
                private_key_path = '{key}'
                chain_path = '{chain}'
                refresh_command = "{WATCHER_PROGRAM} reload nginx"
                watcher_id = "tls-sidecar"

                [[capabilities.acm.certificates]]
                certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/22222222-1234-1234-1234-123456789012"
                role_arn = "arn:aws:iam::123456789012:role/MyRole"
                certificate_path = '{cert2}'
                private_key_path = '{key2}'
                chain_path = '{chain2}'
                refresh_command = "{WATCHER_PROGRAM} reload envoy"
                watcher_id = "tls-sidecar"
            "#
            );
            let result = validator.validate_toml_config_str(&toml);
            assert!(result.is_ok(), "Errors: {}", result.unwrap_err());
            let acm = result.unwrap().acm.unwrap();
            assert_eq!(acm.certificates.len(), 2);
            assert!(acm
                .certificates
                .values()
                .all(|c| c.watcher_id.as_deref() == Some("tls-sidecar")));
        }

        #[test]
        fn test_certificates_may_be_mixed_usage_watcher_id_and_non_watcher_id() {
            let (cert, key, chain) = test_paths("");
            let (cert2, key2, chain2) = test_paths("2");
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = format!(
                r#"
                [capabilities.acm]
                enabled = true

                [[capabilities.acm.certificates]]
                certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/11111111-1234-1234-1234-123456789012"
                role_arn = "arn:aws:iam::123456789012:role/MyRole"
                certificate_path = '{cert}'
                private_key_path = '{key}'
                chain_path = '{chain}'
                refresh_command = "{WATCHER_PROGRAM} reload nginx"
                watcher_id = "tls-sidecar" # WCP will send request to watcher, watcher will run command

                [[capabilities.acm.certificates]]
                certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/22222222-1234-1234-1234-123456789012"
                role_arn = "arn:aws:iam::123456789012:role/MyRole"
                certificate_path = '{cert2}'
                private_key_path = '{key2}'
                chain_path = '{chain2}'
                refresh_command = "{WATCHER_PROGRAM} reload envoy" # WCP will call command directly
            "#
            );
            let result = validator.validate_toml_config_str(&toml);
            assert!(result.is_ok(), "Errors: {}", result.unwrap_err());
            let acm = result.unwrap().acm.unwrap();
            assert_eq!(acm.certificates.len(), 2);
            assert!(acm
                .certificates
                .get("arn:aws:acm:us-east-1:123456789012:certificate/11111111-1234-1234-1234-123456789012")
                .unwrap().watcher_id.as_deref() == Some("tls-sidecar"));
            assert!(acm
                .certificates
                .get("arn:aws:acm:us-east-1:123456789012:certificate/22222222-1234-1234-1234-123456789012")
                .unwrap().watcher_id.as_deref() == None);
        }

        #[test]
        fn test_container_config_missing_watcher_dir_rejected() {
            // Container config (watcher_id set) whose watcher directories are
            // not present: existence must be enforced at startup.
            let (cert_dir, key_dir) = test_dirs();
            let fs = Arc::new(MockFileSystem::new().with_dir(cert_dir).with_dir(key_dir));
            let validator = ConfigValidator::with_filesystem(fs);
            let toml = acm_toml_with(
                r#"refresh_command = "/bin/systemctl reload nginx"
                watcher_id = "tls-sidecar""#,
            );
            let result = validator.validate_toml_config_str(&toml);
            assert!(result.is_err());
            let errors = result.unwrap_err();
            assert!(
                errors
                    .errors
                    .iter()
                    .any(|e| e.code == ValidationErrorCode::WatcherDirectoryNotFound),
                "Errors: {}",
                errors
            );
        }

        /// Validates a default-dirs container config against `fs` and asserts
        /// it is refused with a wrong-mount-mode error on `field`.
        fn assert_container_config_wrong_mount_mode(fs: MockFileSystem, field: &str) {
            let validator = ConfigValidator::with_filesystem(Arc::new(fs));
            let toml = acm_toml_with(
                r#"refresh_command = "/bin/systemctl reload nginx"
                watcher_id = "tls-sidecar""#,
            );
            let errors = validator.validate_toml_config_str(&toml).unwrap_err();
            assert!(
                errors.errors.iter().any(|e| e.code
                    == ValidationErrorCode::WatcherDirectoryWrongMountMode
                    && e.field == field),
                "Errors: {}",
                errors
            );
        }

        #[test]
        fn test_container_config_read_only_watcher_config_dir_rejected() {
            // The provider writes the watcher configs, so a read-only config
            // mount is refused.
            let (cert_dir, key_dir) = test_dirs();
            assert_container_config_wrong_mount_mode(
                MockFileSystem::new()
                    .with_dir(cert_dir)
                    .with_dir(key_dir)
                    .with_read_only_dir(DEFAULT_WATCHER_CONFIG_DIR)
                    .with_dir(DEFAULT_WATCHER_REQUESTS_DIR),
                "capabilities.acm.watcher_config_dir",
            );
        }

        #[test]
        fn test_container_config_read_only_watcher_requests_dir_rejected() {
            // The provider enqueues refresh requests, so a read-only requests
            // mount is refused.
            let (cert_dir, key_dir) = test_dirs();
            assert_container_config_wrong_mount_mode(
                MockFileSystem::new()
                    .with_dir(cert_dir)
                    .with_dir(key_dir)
                    .with_dir(DEFAULT_WATCHER_CONFIG_DIR)
                    .with_read_only_dir(DEFAULT_WATCHER_REQUESTS_DIR),
                "capabilities.acm.watcher_requests_dir",
            );
        }

        #[test]
        fn test_container_config_same_path_rejected() {
            // Config dir and requests dir resolve to the same path.
            #[cfg(unix)]
            let shared_dir = "/mnt/shared";
            #[cfg(windows)]
            let shared_dir = r"C:\mnt\shared";

            let (cert_dir, key_dir) = test_dirs();
            let fs = Arc::new(
                MockFileSystem::new()
                    .with_dir(cert_dir)
                    .with_dir(key_dir)
                    .with_dir(shared_dir),
            );
            let validator = ConfigValidator::with_filesystem(fs);
            let (cert, key, chain) = test_paths("");
            let toml = format!(
                r#"
                [capabilities.acm]
                enabled = true
                watcher_config_dir = '{shared_dir}'
                watcher_requests_dir = '{shared_dir}'

                [[capabilities.acm.certificates]]
                certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"
                role_arn = "arn:aws:iam::123456789012:role/MyRole"
                certificate_path = '{cert}'
                private_key_path = '{key}'
                chain_path = '{chain}'
                refresh_command = "/bin/systemctl reload nginx"
                watcher_id = "tls-sidecar"
            "#
            );
            let result = validator.validate_toml_config_str(&toml);
            assert!(result.is_err());
            let errors = result.unwrap_err();
            assert!(
                errors.errors.iter().any(|e| {
                    e.code == ValidationErrorCode::ConflictingPaths
                        && e.field == "capabilities.acm.watcher_requests_dir"
                }),
                "Errors: {}",
                errors
            );
        }

        #[test]
        fn test_non_container_config_skips_dir_checks() {
            // ACM enabled but NO watcher_id: the watcher directories are not
            // registered yet validation still succeeds, because non-container
            // configs skip the existence/distinctness/mount checks.
            let (cert_dir, key_dir) = test_dirs();
            let fs = Arc::new(MockFileSystem::new().with_dir(cert_dir).with_dir(key_dir));
            let validator = ConfigValidator::with_filesystem(fs);
            let toml = acm_toml_with(r#"refresh_command = "/bin/systemctl reload nginx""#);
            let result = validator.validate_toml_config_str(&toml);
            assert!(result.is_ok(), "Errors: {}", result.unwrap_err());
            let acm = result.unwrap().acm.unwrap();
            assert_eq!(
                acm.watcher_config_dir,
                PathBuf::from(DEFAULT_WATCHER_CONFIG_DIR)
            );
            assert_eq!(
                acm.watcher_requests_dir,
                PathBuf::from(DEFAULT_WATCHER_REQUESTS_DIR)
            );
        }

        #[test]
        fn test_non_container_config_bad_watcher_dir_accepted() {
            // ACM enabled but NO watcher_id: watcher-dir overrides are carried
            // as-is, without format or filesystem checks.
            #[cfg(unix)]
            let traversal_dir = "/shared/../etc";
            #[cfg(windows)]
            let traversal_dir = r"C:\shared\..\etc";

            let (cert_dir, key_dir) = test_dirs();
            let fs = Arc::new(MockFileSystem::new().with_dir(cert_dir).with_dir(key_dir));
            let validator = ConfigValidator::with_filesystem(fs);
            let (cert, key, chain) = test_paths("");
            let toml = format!(
                r#"
                [capabilities.acm]
                enabled = true
                watcher_config_dir = 'relative/config'
                watcher_requests_dir = '{traversal_dir}'

                [[capabilities.acm.certificates]]
                certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"
                role_arn = "arn:aws:iam::123456789012:role/MyRole"
                certificate_path = '{cert}'
                private_key_path = '{key}'
                chain_path = '{chain}'
                refresh_command = "/bin/systemctl reload nginx"
            "#
            );
            let result = validator.validate_toml_config_str(&toml);
            assert!(result.is_ok(), "Errors: {}", result.unwrap_err());
            let acm = result.unwrap().acm.unwrap();
            assert_eq!(acm.watcher_config_dir, PathBuf::from("relative/config"));
            assert_eq!(acm.watcher_requests_dir, PathBuf::from(traversal_dir));
        }

        #[test]
        fn test_container_config_acm_disabled_skips_dir_checks() {
            // A watcher_id is declared but ACM is disabled: no watcher-dir
            // checks run, even with a bad override and no mounted dirs.
            let (cert_dir, key_dir) = test_dirs();
            let fs = Arc::new(MockFileSystem::new().with_dir(cert_dir).with_dir(key_dir));
            let validator = ConfigValidator::with_filesystem(fs);
            let (cert, key, chain) = test_paths("");
            let toml = format!(
                r#"
                [capabilities.acm]
                enabled = false
                watcher_config_dir = 'relative/config'

                [[capabilities.acm.certificates]]
                certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"
                role_arn = "arn:aws:iam::123456789012:role/MyRole"
                certificate_path = '{cert}'
                private_key_path = '{key}'
                chain_path = '{chain}'
                refresh_command = "{WATCHER_PROGRAM} reload nginx"
                watcher_id = "tls-sidecar"
            "#
            );
            let result = validator.validate_toml_config_str(&toml);
            assert!(result.is_ok(), "Errors: {}", result.unwrap_err());
            let acm = result.unwrap().acm.unwrap();
            assert!(!acm.enabled);
            assert_eq!(acm.watcher_config_dir, PathBuf::from("relative/config"));
            assert_eq!(
                acm.watcher_requests_dir,
                PathBuf::from(DEFAULT_WATCHER_REQUESTS_DIR)
            );
        }

        #[test]
        fn test_container_config_acm_enabled_omitted_skips_dir_checks() {
            // `enabled` omitted defaults to false: no watcher-dir checks run,
            // and the defaults are carried.
            let (cert_dir, key_dir) = test_dirs();
            let fs = Arc::new(MockFileSystem::new().with_dir(cert_dir).with_dir(key_dir));
            let validator = ConfigValidator::with_filesystem(fs);
            let (cert, key, chain) = test_paths("");
            let toml = format!(
                r#"
                [capabilities.acm]

                [[capabilities.acm.certificates]]
                certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"
                role_arn = "arn:aws:iam::123456789012:role/MyRole"
                certificate_path = '{cert}'
                private_key_path = '{key}'
                chain_path = '{chain}'
                refresh_command = "{WATCHER_PROGRAM} reload nginx"
                watcher_id = "tls-sidecar"
            "#
            );
            let result = validator.validate_toml_config_str(&toml);
            assert!(result.is_ok(), "Errors: {}", result.unwrap_err());
            let acm = result.unwrap().acm.unwrap();
            assert!(!acm.enabled);
            assert_eq!(
                acm.watcher_config_dir,
                PathBuf::from(DEFAULT_WATCHER_CONFIG_DIR)
            );
            assert_eq!(
                acm.watcher_requests_dir,
                PathBuf::from(DEFAULT_WATCHER_REQUESTS_DIR)
            );
        }
    }

    mod validation_errors {
        use super::*;

        #[test]
        fn test_mixed_format_rejected() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"
                log_level = "debug"
                http_port = "2773"

                [capabilities.secrets_manager]
                enabled = true
            "#;
            let result = validator.validate_toml_config_str(toml);
            assert!(result.is_err());
            let errors = result.unwrap_err();
            assert!(errors.errors.iter().any(|e| e.field == "log_level"));
            assert!(errors.errors.iter().any(|e| e.field == "http_port"));
        }

        // A root [failover] next to nested config is rejected instead of being silently ignored.
        #[test]
        fn test_flat_failover_with_nested_rejected() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"
                [capabilities.secrets_manager]
                region = "us-east-1"

                [failover]
                default_failover_region = "us-west-2"
            "#;
            let errors = validator.validate_toml_config_str(toml).unwrap_err();
            assert_eq!(errors.len(), 1);
            assert_eq!(errors.errors[0].field, "failover");
            assert_eq!(errors.errors[0].code, ValidationErrorCode::FormatConflict);
        }

        // A root [prefetch] next to nested config is rejected instead of being silently ignored.
        #[test]
        fn test_flat_prefetch_with_nested_rejected() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"
                [capabilities.secrets_manager]
                region = "us-east-1"

                [prefetch]
                secrets = [{ secret_id = "MySecret" }]
            "#;
            let errors = validator.validate_toml_config_str(toml).unwrap_err();
            assert_eq!(errors.len(), 1);
            assert_eq!(errors.errors[0].field, "prefetch");
            assert_eq!(errors.errors[0].code, ValidationErrorCode::FormatConflict);
        }

        #[test]
        fn test_invalid_toml_syntax() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"
                log_level = "debug
            "#; // Missing closing quote
            let result = validator.validate_toml_config_str(toml);
            assert!(result.is_err());
            let errors = result.unwrap_err();
            assert_eq!(errors.errors[0].code, ValidationErrorCode::TomlSyntaxError);
        }

        #[test]
        fn test_multiple_errors_collected() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"
                log_level = "invalid"
                http_port = "80"
                ttl_seconds = "9999"
            "#;
            let result = validator.validate_toml_config_str(toml);
            assert!(result.is_err());
            let errors = result.unwrap_err();
            assert_eq!(errors.len(), 3);
        }
    }

    mod telemetry {
        use super::*;

        #[test]
        fn test_telemetry_section_parsed() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"
                [telemetry]
                dry_run = true

                [telemetry.secrets_manager]
                enabled = true

                [telemetry.acm]
                enabled = true

                [capabilities.secrets_manager]
                enabled = true
            "#;
            let config = validator.validate_toml_config_str(toml).unwrap();
            assert!(config.telemetry.secrets_manager_enabled);
            assert!(config.telemetry.acm_enabled);
            assert!(config.telemetry.dry_run);
            assert!(config.logging.telemetry_dry_run);
        }

        #[test]
        fn test_telemetry_partial_section_defaults_rest() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"
                [telemetry.secrets_manager]
                enabled = true
            "#;
            let config = validator.validate_toml_config_str(toml).unwrap();
            assert!(config.telemetry.secrets_manager_enabled);
            assert!(!config.telemetry.acm_enabled);
            assert!(!config.telemetry.dry_run);
            assert!(!config.logging.telemetry_dry_run);
        }

        #[test]
        fn test_telemetry_absent_defaults_all_false() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"
                [capabilities.secrets_manager]
                enabled = true
            "#;
            let config = validator.validate_toml_config_str(toml).unwrap();
            assert_eq!(
                config.telemetry,
                crate::config::types::TelemetryConfig::default()
            );
        }

        #[test]
        fn test_telemetry_unknown_key_rejected() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"
                [telemetry]
                bogus_key = true
            "#;
            let result = validator.validate_toml_config_str(toml);
            let errors = result.unwrap_err();
            // Exactly one error, so it is the unknown key and not an unrelated one.
            assert_eq!(errors.len(), 1);
            assert_eq!(errors.errors[0].code, ValidationErrorCode::TomlSyntaxError);
        }

        #[test]
        fn test_telemetry_unknown_nested_key_rejected() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"
                [telemetry.secrets_manager]
                enabled = true
                sampling_rate = 0.5
            "#;
            let result = validator.validate_toml_config_str(toml);
            let errors = result.unwrap_err();
            assert_eq!(errors.errors[0].code, ValidationErrorCode::TomlSyntaxError);
        }

        #[test]
        fn test_telemetry_wrong_typed_value_rejected() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"
                [telemetry.secrets_manager]
                enabled = "yes"
            "#;
            let result = validator.validate_toml_config_str(toml);
            let errors = result.unwrap_err();
            assert_eq!(errors.errors[0].code, ValidationErrorCode::TomlSyntaxError);
        }

        #[test]
        fn test_telemetry_coexists_with_legacy_flat_keys() {
            // `[telemetry]` is a top-level section, so it must not trip the nested-vs-flat
            // detection that rejects legacy root-level Secrets Manager keys.
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"
                http_port = 2775

                [telemetry.secrets_manager]
                enabled = true
            "#;
            let config = validator.validate_toml_config_str(toml).unwrap();
            assert_eq!(config.secrets_manager.http_port, 2775);
            assert!(config.telemetry.secrets_manager_enabled);
        }

        #[test]
        fn test_turning_discovery_on_consents_to_its_records() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"
                [capabilities.acm]
                enabled = true

                [capabilities.acm.discovery]
                enabled = true

                [telemetry.acm]
                enabled = false
            "#;
            let config = validator.validate_toml_config_str(toml).unwrap();
            assert!(config.telemetry.acm_discovery_enabled);
            assert!(!config.telemetry.acm_enabled);
        }

        #[test]
        fn test_no_discovery_consent_unless_acm_and_discovery_are_on() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let acm_off = r#"
                [capabilities.acm]
                enabled = false

                [capabilities.acm.discovery]
                enabled = true
            "#;
            let discovery_off = r#"
                [capabilities.acm]
                enabled = true

                [capabilities.acm.discovery]
                enabled = false

                [telemetry.acm]
                enabled = true
            "#;
            let no_discovery = r#"
                [capabilities.acm]
                enabled = true
            "#;
            for toml in [acm_off, discovery_off, no_discovery] {
                let config = validator.validate_toml_config_str(toml).unwrap();
                assert!(!config.telemetry.acm_discovery_enabled, "{toml}");
            }
        }
    }

    mod discovery {
        use super::*;

        /// Enabling discovery applies the default timeout and ports.
        #[test]
        fn test_discovery_defaults_when_enabled() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"
                [capabilities.acm]
                enabled = true

                [capabilities.acm.discovery]
                enabled = true
            "#;
            let result = validator.validate_toml_config_str(toml);
            assert!(result.is_ok(), "Errors: {}", result.unwrap_err());
            let acm = result.unwrap().acm.unwrap();
            let discovery = acm.discovery.unwrap();
            assert!(discovery.enabled);
            assert_eq!(discovery.timeout_secs, 300);
            assert_eq!(discovery.discovery_targets.len(), 3);
            assert!(discovery.discovery_targets.contains_key(&443));
            assert!(discovery.discovery_targets.contains_key(&8443));
            assert!(discovery.discovery_targets.contains_key(&4443));
        }

        /// An empty target map gets the default ports even with an unrelated error collected.
        #[test]
        fn test_discovery_empty_targets_use_defaults_with_unrelated_errors() {
            let input = crate::config::types::DiscoveryConfigInput {
                discovery_targets: Some(std::collections::HashMap::new()),
                ..Default::default()
            };
            let mut collector = crate::config::error::ErrorCollector::new();
            collector.add(crate::config::error::ValidationError::new(
                "unrelated",
                ValidationErrorCode::InvalidValue,
                "unrelated validation error",
            ));

            let discovery = ConfigValidator::<MockFileSystem>::validate_discovery_config(
                Some(&input),
                &mut collector,
            )
            .expect("discovery config is present");

            assert_eq!(discovery.discovery_targets.len(), 3);
            assert!(discovery.discovery_targets.contains_key(&443));
            assert!(discovery.discovery_targets.contains_key(&8443));
            assert!(discovery.discovery_targets.contains_key(&4443));
        }

        /// An empty discovery section leaves discovery disabled.
        #[test]
        fn test_discovery_disabled_by_default() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"
                [capabilities.acm]
                enabled = true

                [capabilities.acm.discovery]
            "#;
            let result = validator.validate_toml_config_str(toml);
            assert!(result.is_ok(), "Errors: {}", result.unwrap_err());
            let discovery = result.unwrap().acm.unwrap().discovery.unwrap();
            assert!(!discovery.enabled);
        }

        /// No discovery section leaves discovery unset.
        #[test]
        fn test_no_discovery_section() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"
                [capabilities.acm]
                enabled = true
            "#;
            let result = validator.validate_toml_config_str(toml);
            assert!(result.is_ok());
            assert!(result.unwrap().acm.unwrap().discovery.is_none());
        }

        /// Custom ports and SNI hostnames are kept.
        #[test]
        fn test_discovery_custom_targets() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"
                [capabilities.acm]
                enabled = true

                [capabilities.acm.discovery]
                enabled = true

                [capabilities.acm.discovery.discovery_targets]
                443 = ["api.example.com", "web.example.com"]
                8443 = []
            "#;
            let result = validator.validate_toml_config_str(toml);
            assert!(result.is_ok(), "Errors: {}", result.unwrap_err());
            let discovery = result.unwrap().acm.unwrap().discovery.unwrap();
            assert_eq!(discovery.discovery_targets.len(), 2);
            assert_eq!(discovery.discovery_targets[&443].len(), 2);
            assert_eq!(discovery.discovery_targets[&8443].len(), 0);
        }

        /// A configured timeout replaces the default.
        #[test]
        fn test_discovery_timeout_override() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"
                [capabilities.acm]
                enabled = true

                [capabilities.acm.discovery]
                enabled = true
                timeout_secs_override = 900
            "#;
            let result = validator.validate_toml_config_str(toml);
            assert!(result.is_ok(), "Errors: {}", result.unwrap_err());
            assert_eq!(
                result.unwrap().acm.unwrap().discovery.unwrap().timeout_secs,
                900
            );
        }

        /// A timeout below the minimum is a range error on the timeout field.
        #[test]
        fn test_discovery_timeout_below_minimum() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"
                [capabilities.acm]
                enabled = true

                [capabilities.acm.discovery]
                timeout_secs_override = 10
            "#;
            let result = validator.validate_toml_config_str(toml);
            assert!(result.is_err());
            let errors = result.unwrap_err();
            assert!(errors
                .errors
                .iter()
                .any(|e| e.code == ValidationErrorCode::ValueOutOfRange
                    && e.field.contains("timeout")));
        }

        /// More ports than allowed is a validation error.
        #[test]
        fn test_discovery_too_many_ports() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let ports: Vec<String> = (1..=50).map(|i| format!("{} = []", 1000 + i)).collect();
            let toml = format!(
                r#"
                [capabilities.acm]
                enabled = true

                [capabilities.acm.discovery]
                enabled = true

                [capabilities.acm.discovery.discovery_targets]
                {}
            "#,
                ports.join("\n                ")
            );
            let result = validator.validate_toml_config_str(&toml);
            assert!(result.is_err());
            let errors = result.unwrap_err();
            assert!(errors
                .errors
                .iter()
                .any(|e| e.message.contains("Too many ports")));
        }

        /// Port 0 is rejected even alongside a valid port.
        #[test]
        fn test_discovery_port_zero_rejected() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"
                [capabilities.acm]
                enabled = true

                [capabilities.acm.discovery]
                enabled = true

                [capabilities.acm.discovery.discovery_targets]
                0 = []
                443 = []
            "#;
            let result = validator.validate_toml_config_str(toml);
            assert!(result.is_err());
            let errors = result.unwrap_err();
            assert!(errors.errors.iter().any(|e| e.message.contains("Port 0")));
        }

        /// Empty SNI hostnames are dropped and valid ones kept.
        #[test]
        fn test_discovery_empty_sni_hostnames_filtered() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"
                [capabilities.acm]
                enabled = true

                [capabilities.acm.discovery.discovery_targets]
                443 = ["", "api.example.com", ""]
            "#;

            let config = validator
                .validate_toml_config_str(toml)
                .expect("empty SNI hostnames should be filtered");
            let discovery = config.acm.unwrap().discovery.unwrap();

            assert_eq!(
                discovery.discovery_targets[&443],
                vec!["api.example.com".to_string()]
            );
        }

        /// 33 SNI hostnames on port 443 is a range error naming 33 and the limit, 32.
        #[test]
        fn test_discovery_too_many_sni_rejected() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let hostnames = (0..33)
                .map(|i| format!(r#""api-{i}.example.com""#))
                .collect::<Vec<_>>()
                .join(", ");
            let toml = format!(
                r#"
                [capabilities.acm]
                enabled = true

                [capabilities.acm.discovery.discovery_targets]
                443 = [{hostnames}]
            "#
            );

            let errors = validator
                .validate_toml_config_str(&toml)
                .expect_err("33 distinct SNI hostnames should exceed the per-port cap");
            let error = errors
                .errors
                .iter()
                .find(|error| error.field == "capabilities.acm.discovery.discovery_targets[443]")
                .expect("SNI cap error should identify port 443");

            assert_eq!(error.code, ValidationErrorCode::ValueOutOfRange);
            assert!(error.message.contains("33"));
            assert!(error.message.contains("32"));
        }

        /// Unknown discovery fields are ignored, for forward compatibility.
        #[test]
        fn test_discovery_unknown_field_tolerated() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let toml = r#"
                [capabilities.acm]
                enabled = true

                [capabilities.acm.discovery]
                enabled = true
                bogus_field = "should be ignored"
            "#;
            let result = validator.validate_toml_config_str(toml);
            assert!(result.is_ok(), "Errors: {}", result.unwrap_err());
            assert!(result.unwrap().acm.unwrap().discovery.unwrap().enabled);
        }

        /// Enabling discovery doesn't stop an ACM certificate config from validating.
        #[test]
        fn test_discovery_does_not_break_existing_acm() {
            let validator = ConfigValidator::with_filesystem(mock_fs());
            let (cert, key, chain) = test_paths("");
            let toml = format!(
                r#"
                [capabilities.acm]
                enabled = true

                [[capabilities.acm.certificates]]
                certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"
                role_arn = "arn:aws:iam::123456789012:role/MyRole"
                certificate_path = '{cert}'
                private_key_path = '{key}'
                chain_path = '{chain}'

                [capabilities.acm.discovery]
                enabled = true
            "#
            );
            let result = validator.validate_toml_config_str(&toml);
            assert!(result.is_ok(), "Errors: {}", result.unwrap_err());
            let acm = result.unwrap().acm.unwrap();
            assert!(acm.enabled);
            assert_eq!(acm.certificates.len(), 1);
            assert!(acm.discovery.unwrap().enabled);
        }
    }
}
