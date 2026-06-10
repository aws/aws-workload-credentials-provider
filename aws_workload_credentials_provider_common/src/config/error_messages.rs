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

pub const EMPTY_TRUSTEE_NAME_ERR_MSG: &str =
    "The trustee name specified in the permission configuration can't be empty.";
