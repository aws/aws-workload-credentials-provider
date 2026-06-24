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
    INVALID_HTTP_PORT_ERR_MSG, INVALID_MAX_JITTER_MSG, INVALID_TTL_SECONDS_ERR_MSG,
};
use super::field_validators::{
    validate_permission_config, validate_refresh_command, ArnValidator, CertificateBlockPaths,
    CrossFieldValidator, FilePathValidator, RangeValidator,
};
use super::types::{
    AcmConfig, AcmConfigInput, CapabilitiesConfig, CertificateConfig, CertificateConfigInput,
    ConfigInput, LogLevel, LoggingConfig, LoggingConfigInput, PrefetchConfig, PrefetchConfigInput,
    SecretPrefetchConfig, SecretsManagerConfig, SecretsManagerConfigInput, TagFilter,
    ValidatedConfig,
};
use crate::filesystem::{FileSystem, RealFileSystem};

use crate::fs_permissions::PathPermission;

/// Maximum number of certificates allowed in the configuration.
const MAX_CERTIFICATES: usize = 50;

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
                    logging: Default::default(),
                    secrets_manager: SecretsManagerConfig::default(),
                    acm: None,
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
        let logging: LoggingConfig = self.validate_logging_config(logging_input, &mut collector);

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
        let acm: Option<AcmConfig> = self.validate_acm_config(capabilities.acm, &mut collector);

        if !collector.is_empty() {
            Err(ValidationErrors::from_vec(collector.errors().to_vec()))
        } else {
            Ok(ValidatedConfig {
                logging,
                secrets_manager,
                acm,
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

        secrets_manager_config
    }

    /// Validate ACM configuration section.
    fn validate_acm_config(
        &self,
        opt_acm_config_input: Option<AcmConfigInput>,
        collector: &mut ErrorCollector,
    ) -> Option<AcmConfig> {
        let acm_config_input: AcmConfigInput = opt_acm_config_input?;

        let acm_enabled: bool = acm_config_input.enabled.unwrap_or(false);
        let cert_config_inputs: Vec<CertificateConfigInput> =
            acm_config_input.certificates.unwrap_or_default();

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

        Some(AcmConfig {
            enabled: acm_enabled,
            certificates,
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
        if let Some(ref cmd) = refresh_command {
            if let Err(e) =
                validate_refresh_command(&format!("{}.refresh_command", field_prefix), cmd)
            {
                collector.add(e);
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
    use crate::config::types::LogLevel;
    use crate::config::validator::ConfigValidator;
    use crate::filesystem::MockFileSystem;
    use crate::fs_permissions::PathPermission;
    #[cfg(windows)]
    use crate::fs_permissions::{Rights, TrusteeType};
    use std::sync::Arc;

    fn mock_fs() -> Arc<MockFileSystem> {
        Arc::new(
            MockFileSystem::new()
                .with_dir("/etc/ssl/certs")
                .with_dir("/etc/ssl/private")
                .with_dir("c:\\etc\\ssl\\certs")
                .with_dir("c:\\etc\\ssl\\private"),
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
    }

    mod nested_secrets_manager {
        use super::*;

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
}
