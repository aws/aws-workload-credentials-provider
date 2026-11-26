//! User-visible validation error messages.
//!
//! This module contains all user-facing error messages for configuration validation.
//! Messages are organized by validation domain for easy maintenance.

// ============================================================================
// Generic
// ============================================================================

/// Generic error message for unexpected configuration errors.
pub const GENERIC_CONFIG_ERR_MSG: &str =
    "There was an unexpected error in loading the configuration file.";

/// Error message for flat keys (legacy config) used alongside capabilities (nested config) section.
pub const FLAT_KEY_WITH_CAPABILITIES_ERR_MSG: &str =
    "The configuration file format isn't valid. Flat keys can't be used in conjunction with nested sections ('logging' or 'capabilities').";

// ============================================================================
// Logging
// ============================================================================

/// Error message for invalid log level values.
pub const INVALID_LOG_LEVEL_ERR_MSG: &str =
    "The log level specified in the configuration file isn't valid. The log level must be DEBUG, INFO, WARN, ERROR, or NONE.";

// ============================================================================
// ASM
// ============================================================================

/// Error message for invalid HTTP port values.
pub const INVALID_HTTP_PORT_ERR_MSG: &str =
    "The HTTP port specified in the configuration file isn't valid. The HTTP port must be in the range 1024 to 65535.";

/// Error message for invalid TTL values.
pub const INVALID_TTL_SECONDS_ERR_MSG: &str =
    "The TTL in seconds specified in the configuration file isn't valid. The TTL in seconds must be in the range 0 to 3600.";

/// Error message for invalid cache size values.
pub const INVALID_CACHE_SIZE_ERR_MSG: &str =
    "The cache size specified in the configuration file isn't valid. The cache size must be in the range 1 to 1000.";

/// Error message for invalid max connections values.
pub const BAD_MAX_CONN_MSG: &str =
    "The maximum number of connections specified in the configuration file isn't valid. The maximum number of connections must be in the range 1 to 1000.";

/// Error message for empty SSRF headers list.
pub const EMPTY_SSRF_LIST_MSG: &str =
    "The list of SSRF headers in the configuration file can't be empty.";

/// Error message for empty SSRF environment variables list.
pub const EMPTY_ENV_LIST_MSG: &str =
    "The list of SSRF environment variables in the configuration file can't be empty.";

/// Error message for invalid path prefix.
pub const BAD_PREFIX_MSG: &str =
    "The path prefix specified in the configuration file must begin with /.";

/// Error message for invalid max roles values.
pub const BAD_MAX_ROLES_MSG: &str =
    "The maximum number of roles specified in the configuration file isn't valid. The maximum number of roles must be in the range 1 to 20.";

/// Error message for invalid cache buffer ratio.
pub const INVALID_CACHE_BUFFER_RATIO_MSG: &str =
    "The cache buffer ratio specified in the configuration file isn't valid. The cache buffer ratio must be in the range 0.1 to 1.0.";

/// Error message for invalid max jitter seconds.
pub const INVALID_MAX_JITTER_MSG: &str =
    "The max jitter seconds specified in the configuration file isn't valid. The max jitter seconds must be in the range 0 to 10.";

/// Error message for invalid failover operation timeout.
pub const INVALID_OPERATION_TIMEOUT_MSG: &str =
    "The operation timeout in milliseconds specified in the configuration file isn't valid. The operation timeout in milliseconds must be in the range 2000 to 25000.";

/// Error message for an invalid failover region.
pub const INVALID_FAILOVER_REGION_MSG: &str =
    "The failover region specified in the configuration file isn't valid. The failover region can't be empty or the same as the primary region.";

// ============================================================================
// ACM
// ============================================================================

/// Error message for invalid certificate ARN.
pub const INVALID_CERTIFICATE_ARN_ERR_MSG: &str =
    "The certificate ARN specified in the configuration file isn't valid.";

/// Error message for invalid IAM role ARN.
pub const INVALID_IAM_ROLE_ARN_ERR_MSG: &str =
    "The IAM role ARN specified in the configuration file isn't valid.";

/// Error message for invalid file path.
pub const INVALID_FILE_PATH_ERR_MSG: &str =
    "The file path specified in the configuration file isn't valid.";

/// Error message for empty refresh command.
pub const EMPTY_REFRESH_COMMAND_ERR_MSG: &str = "The refresh command cannot be empty.";
#[cfg(unix)]
pub const INVALID_REFRESH_COMMAND_ERR_MSG: &str = "The refresh command must be an absolute path containing only characters (alphanumeric / - _ . spaces = + @).";
#[cfg(windows)]
pub const INVALID_REFRESH_COMMAND_ERR_MSG: &str = "The refresh command may only contain alphanumeric characters, spaces, and the following: - _ . \\ / : \" (double quote) = + @ ~";

/// Error message for duplicate certificate paths.
pub const DUPLICATE_CERTIFICATE_PATH_ERR_MSG: &str =
    "Certificate paths must be unique within and across certificate blocks.";

// ============================================================================
// ACM watcher
// ============================================================================

/// Error message for an invalid watcher ID.
///
/// A watcher ID is used to derive a directory name, so it must be a single
/// safe path segment.
#[cfg(unix)]
pub const INVALID_WATCHER_ID_ERR_MSG: &str =
    "The watcher ID specified in the configuration file isn't valid. The watcher ID must be 1 to 64 characters long, must start with a lowercase letter or a digit, and may only contain lowercase letters, digits, periods, hyphens, and underscores.";
#[cfg(windows)]
pub const INVALID_WATCHER_ID_ERR_MSG: &str =
    "The watcher ID specified in the configuration file isn't valid. The watcher ID must be 1 to 64 characters long, must start with a lowercase letter or a digit, and may only contain lowercase letters, digits, periods, hyphens, and underscores. It can't end with a period, and the part before the first period can't be a reserved Windows device name (con, prn, aux, nul, com1 to com9, or lpt1 to lpt9).";

/// Error message for a certificate that sets a watcher ID without a refresh command.
pub const MISSING_REFRESH_COMMAND_FOR_WATCHER_ERR_MSG: &str =
    "A certificate that specifies watcher_id must also specify refresh_command. The refresh command is carried into the watcher's configuration and can't be supplied later.";

/// Error message for an invalid watcher directory.
pub const INVALID_WATCHER_DIRECTORY_ERR_MSG: &str =
    "The watcher directory specified in the configuration file isn't valid.";

/// Error message for a watcher config whose schema version the reader doesn't support.
pub const UNSUPPORTED_WATCHER_SCHEMA_VERSION_ERR_MSG: &str =
    "The watcher configuration's schema version isn't supported. Upgrade the watcher to at least the provider's version.";

/// Error message for a watcher config written for a different watcher.
pub const WATCHER_ID_MISMATCH_ERR_MSG: &str =
    "The watcher configuration belongs to a different watcher.";

/// Error message for a watcher config without any reload entry.
pub const MISSING_RELOAD_ENTRY_ERR_MSG: &str =
    "The watcher configuration must contain at least one reload entry.";

/// Error message for a reload entry without certificates.
pub const RELOAD_WITHOUT_CERTIFICATES_ERR_MSG: &str =
    "Each reload entry in the watcher configuration must list at least one certificate ARN.";

/// Error message for a reload command element outside the allowed characters,
/// a quoted element, or a program path that isn't absolute.
pub const INVALID_RELOAD_COMMAND_ERR_MSG: &str =
    "Each reload command element must use only the characters allowed in a refresh command, can't be quoted, and the first element must be an absolute path.";

/// Error message for a watcher directory that does not exist.
///
/// Container configs are validated at provider startup inside the container,
/// after all required volumes are mounted, so the directory is expected to
/// exist at that point.
pub const WATCHER_DIRECTORY_NOT_FOUND_ERR_MSG: &str =
    "The watcher directory specified in the configuration file must exist and be a directory. It is expected to be mounted into the container before the provider starts.";

/// Error message for a watcher directory that could not be resolved for a
/// reason other than not existing, for example because a parent directory
/// can't be searched by the user the process runs as.
pub const WATCHER_DIRECTORY_INACCESSIBLE_ERR_MSG: &str =
    "The watcher directory specified in the configuration file couldn't be accessed. Check that the directory and each of its parent directories are accessible to the user the process runs as.";

/// Error message for the two watcher directories resolving to the same path.
pub const WATCHER_DIRECTORIES_NOT_DISTINCT_ERR_MSG: &str =
    "The watcher config directory and the watcher requests directory must be distinct paths.";

/// Error message for a watcher directory whose mount has the wrong access
/// mode (read-only vs read-write) for the validating process.
pub const WATCHER_DIRECTORY_WRONG_MOUNT_MODE_ERR_MSG: &str =
    "The watcher directory specified in the configuration is mounted with the wrong access mode. The watcher config directory must be mounted read-write for the provider and read-only for the watcher, and the watcher requests directory must be mounted read-write for both.";

/// Error message for a watcher directory whose mount access mode could not be
/// determined, so the required mount mode cannot be verified.
pub const WATCHER_DIRECTORY_MOUNT_UNKNOWN_ERR_MSG: &str =
    "The access mode (read-only or read-write) of the mount holding the watcher directory specified in the configuration couldn't be determined, so the required mount mode can't be verified.";

pub const EMPTY_TRUSTEE_NAME_ERR_MSG: &str =
    "The trustee name specified in the permission configuration can't be empty.";
