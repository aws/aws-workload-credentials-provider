//! Field-level validators for configuration values.
//!
//! This module contains validators for:
//! - Range validation (generic numeric range checking)
//! - ARN validation (certificate and IAM role ARNs)
//! - File path validation (absolute paths, parent directory existence)
//! - Refresh command validation (non-empty check)
//! - Watcher validation (watcher ID path segment, watcher directory paths)
//! - Cross-field validation (path uniqueness within and across certificate blocks)

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};

use regex::Regex;

use super::error::{ValidationError, ValidationErrorCode};
use super::error_messages::{
    DUPLICATE_CERTIFICATE_PATH_ERR_MSG, EMPTY_REFRESH_COMMAND_ERR_MSG, EMPTY_TRUSTEE_NAME_ERR_MSG,
    INVALID_CERTIFICATE_ARN_ERR_MSG, INVALID_FILE_PATH_ERR_MSG, INVALID_IAM_ROLE_ARN_ERR_MSG,
    INVALID_REFRESH_COMMAND_ERR_MSG, INVALID_WATCHER_DIRECTORY_ERR_MSG, INVALID_WATCHER_ID_ERR_MSG,
    WATCHER_DIRECTORIES_NOT_DISTINCT_ERR_MSG, WATCHER_DIRECTORY_INACCESSIBLE_ERR_MSG,
    WATCHER_DIRECTORY_MOUNT_UNKNOWN_ERR_MSG, WATCHER_DIRECTORY_NOT_FOUND_ERR_MSG,
    WATCHER_DIRECTORY_WRONG_MOUNT_MODE_ERR_MSG,
};
use super::types::{
    PermissionConfig, WatcherDirectories, DEFAULT_WATCHER_CONFIG_DIR, DEFAULT_WATCHER_REQUESTS_DIR,
};
use crate::filesystem::FileSystem;
use crate::fs_permissions::PathPermission;

#[cfg(windows)]
use crate::fs_permissions::{Rights, TrusteeType};

/// Validates numeric ranges.
pub struct RangeValidator;

impl RangeValidator {
    /// Validate a value is within the given range [min, max].
    pub fn validate_range(
        field_name: &str,
        value: usize,
        min: usize,
        max: usize,
        error_msg: &str,
    ) -> Result<(), ValidationError> {
        if value < min || value > max {
            return Err(ValidationError::with_guidance(
                field_name.to_string(),
                ValidationErrorCode::ValueOutOfRange,
                error_msg.to_string(),
                format!("Got: {}", value),
            ));
        }
        Ok(())
    }

    /// Parse and validate a value from string within the given range.
    pub fn parse_and_validate_range(
        field_name: &str,
        value: &str,
        min: usize,
        max: usize,
        error_msg: &str,
    ) -> Result<usize, ValidationError> {
        let parsed: usize = value.parse().map_err(|_| {
            ValidationError::with_guidance(
                field_name.to_string(),
                ValidationErrorCode::InvalidType,
                error_msg.to_string(),
                format!("Got: '{}'", value),
            )
        })?;
        Self::validate_range(field_name, parsed, min, max, error_msg)?;
        Ok(parsed)
    }
}

static CERTIFICATE_ARN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^arn:[\w-]+:acm:[\w-]+:\d{12}:certificate/[\w+=,.@/-]+$").unwrap()
});

static IAM_ROLE_ARN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^arn:[\w-]+:iam::\d{12}:role/[\w+=,.@/-]+$").unwrap());

/// Unix: absolute path with only safe characters.
/// Rejects sudoers metacharacters (, \ ! # : \n \r) to prevent injection.
#[cfg(unix)]
static REFRESH_COMMAND_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^/[a-zA-Z0-9/_\-\. =+@]+$").unwrap());

/// Windows: letters, digits, spaces, and the characters needed for common
/// reload commands (paths, flags, quoted executables). Rejects shell
/// combinators (`;` `&` `|`), redirects (`<` `>`), variable expansion
/// (`$` `%` `` ` ``), subexpressions (`()` `{}`), globs (`*` `?`), and
/// PowerShell single-quote string delimiters.
#[cfg(windows)]
static REFRESH_COMMAND_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^[a-zA-Z0-9 \-_.\\/:"=+@~]+$"#).unwrap());

/// Validates ARN formats for certificates and IAM roles.
pub struct ArnValidator;

impl ArnValidator {
    /// Validate an ACM certificate ARN.
    ///
    /// Expected format: `arn:{partition}:acm:{region}:{account-id}:certificate/{certificate-id}`
    pub fn validate_certificate_arn(field_name: &str, arn: &str) -> Result<(), ValidationError> {
        if !CERTIFICATE_ARN_RE.is_match(arn) {
            return Err(ValidationError::with_guidance(
                field_name.to_string(),
                ValidationErrorCode::InvalidCertificateArn,
                INVALID_CERTIFICATE_ARN_ERR_MSG.to_string(),
                format!("Expected format: arn:{{partition}}:acm:{{region}}:{{account-id}}:certificate/{{certificate-id}}, got: '{}'", arn),
            ));
        }
        Ok(())
    }

    /// Validate an IAM role ARN.
    ///
    /// Expected format: `arn:{partition}:iam::{account-id}:role/{role-name}`
    pub fn validate_iam_role_arn(field_name: &str, arn: &str) -> Result<(), ValidationError> {
        if !IAM_ROLE_ARN_RE.is_match(arn) {
            return Err(ValidationError::with_guidance(
                field_name.to_string(),
                ValidationErrorCode::InvalidRoleArn,
                INVALID_IAM_ROLE_ARN_ERR_MSG.to_string(),
                format!("Expected format: arn:{{partition}}:iam::{{account-id}}:role/{{role-name}}, got: '{}'", arn),
            ));
        }
        Ok(())
    }
}

/// Validates file paths for certificate deployment.
pub struct FilePathValidator<F: FileSystem> {
    filesystem: Arc<F>,
}

impl<F: FileSystem> FilePathValidator<F> {
    pub fn new(filesystem: Arc<F>) -> Self {
        Self { filesystem }
    }

    /// Validates a file path for certificate output files.
    ///
    /// Ensures the path is:
    /// - Valid UTF-8 and free of control characters
    /// - Absolute
    /// - Parent directory exists
    /// - Parent directory resolves to itself (no symlinks or `..` indirection)
    ///
    /// Both are rejected because the parent directory is written into the
    /// root-owned systemd drop-in: a newline would start a new directive, and
    /// a non-UTF-8 name cannot be written as the same directory.
    ///
    /// Note: Does not check if the file itself exists (it will be created).
    pub fn validate(&self, field_name: &str, path: &Path) -> Result<(), ValidationError> {
        let Some(path_str) = path.to_str() else {
            return Err(ValidationError::with_guidance(
                field_name.to_string(),
                ValidationErrorCode::UnsafePath,
                INVALID_FILE_PATH_ERR_MSG.to_string(),
                format!("Path must be valid UTF-8, got: {:?}", path),
            ));
        };
        if path_str.chars().any(char::is_control) {
            return Err(ValidationError::with_guidance(
                field_name.to_string(),
                ValidationErrorCode::UnsafePath,
                INVALID_FILE_PATH_ERR_MSG.to_string(),
                format!("Path must not contain control characters, got: {:?}", path),
            ));
        }

        // Check if path is absolute
        if !path.is_absolute() {
            return Err(ValidationError::with_guidance(
                field_name.to_string(),
                ValidationErrorCode::RelativePath,
                INVALID_FILE_PATH_ERR_MSG.to_string(),
                format!("Path must be absolute, got: '{}'", path.display()),
            ));
        }

        // Check parent directory exists
        let parent = match self.filesystem.parent(path) {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => {
                return Err(ValidationError::with_guidance(
                    field_name.to_string(),
                    ValidationErrorCode::ParentDirectoryNotFound,
                    INVALID_FILE_PATH_ERR_MSG.to_string(),
                    format!("Path must include a filename, got: '{}'", path.display()),
                ));
            }
        };

        if !self.filesystem.exists(&parent) {
            return Err(ValidationError::with_guidance(
                field_name.to_string(),
                ValidationErrorCode::ParentDirectoryNotFound,
                INVALID_FILE_PATH_ERR_MSG.to_string(),
                format!("Parent directory '{}' does not exist.", parent.display()),
            ));
        }

        // Canonicalize parent to detect symlinks and ".." components
        match self.filesystem.canonicalize(&parent) {
            Ok(canonical) if canonical == parent => {} // Path is safe
            Ok(canonical) => {
                return Err(ValidationError::with_guidance(
                    field_name.to_string(),
                    ValidationErrorCode::UnsafePath,
                    INVALID_FILE_PATH_ERR_MSG.to_string(),
                    format!(
                        "Parent directory '{}' resolves to a different path '{}'. Use the canonical path directly.",
                        parent.display(),
                        canonical.display()
                    ),
                ));
            }
            Err(e) => {
                return Err(ValidationError::with_guidance(
                    field_name.to_string(),
                    ValidationErrorCode::UnsafePath,
                    INVALID_FILE_PATH_ERR_MSG.to_string(),
                    format!(
                        "Unable to verify parent directory '{}': {}",
                        parent.display(),
                        e
                    ),
                ));
            }
        }

        Ok(())
    }
}

/// Validates a refresh command for a certificate.
///
/// Validates a refresh command.
///
/// On Unix: must be an absolute path (`/...`) with only safe characters.
/// Rejects sudoers metacharacters to prevent injection.
///
/// On Windows: must not contain newlines or null bytes.
pub fn validate_refresh_command(field_name: &str, command: &str) -> Result<(), ValidationError> {
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return Err(ValidationError::new(
            field_name.to_string(),
            ValidationErrorCode::EmptyCommand,
            EMPTY_REFRESH_COMMAND_ERR_MSG.to_string(),
        ));
    }
    if !REFRESH_COMMAND_RE.is_match(trimmed) {
        return Err(ValidationError::with_guidance(
            field_name.to_string(),
            ValidationErrorCode::InvalidCommand,
            INVALID_REFRESH_COMMAND_ERR_MSG.to_string(),
            format!("Got: '{}'", trimmed),
        ));
    }
    Ok(())
}

/// A watcher ID: a single, non-empty path segment starting with an
/// alphanumeric character, at most 64 characters long.
/// lowercase, numerals, and ._- (three special characters) permitted
static WATCHER_ID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9._-]{0,63}$").unwrap());

/// Validates a certificate's watcher ID.
///
/// The watcher ID is used to derive the per-watcher directory names under the
/// shared watcher directories, so it must be a single path segment: no path
/// separators, no `.`/`..`, no whitespace.
pub fn validate_watcher_id(field_name: &str, watcher_id: &str) -> Result<(), ValidationError> {
    if !WATCHER_ID_RE.is_match(watcher_id) {
        return Err(ValidationError::with_guidance(
            field_name.to_string(),
            ValidationErrorCode::InvalidWatcherId,
            INVALID_WATCHER_ID_ERR_MSG.to_string(),
            format!("Got: '{}'", watcher_id),
        ));
    }
    #[cfg(windows)]
    if let Some(reason) = windows_watcher_id_check(watcher_id) {
        return Err(ValidationError::with_guidance(
            field_name.to_string(),
            ValidationErrorCode::InvalidWatcherId,
            INVALID_WATCHER_ID_ERR_MSG.to_string(),
            format!("Got: '{}' ({})", watcher_id, reason),
        ));
    }
    Ok(())
}

/// Windows reserved device names, in lowercase because [`WATCHER_ID_RE`]
/// only admits lowercase IDs.
#[cfg(windows)]
const WINDOWS_RESERVED_NAMES: &[&str] = &[
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

/// Returns why an ID that passed [`WATCHER_ID_RE`] can't be a Windows
/// directory name, or `None` if it can.
///
/// Windows strips a trailing period, so `tls.` and `tls` name the same
/// directory. A reserved name followed by any extension still names the
/// device (`nul.txt` and `nul.tar.gz` are both `NUL`)
#[cfg(windows)]
fn windows_watcher_id_check(watcher_id: &str) -> Option<&'static str> {
    if watcher_id.ends_with('.') {
        return Some("must not end with a period");
    }
    let stem = watcher_id.split('.').next().unwrap_or(watcher_id);
    if WINDOWS_RESERVED_NAMES.contains(&stem) {
        return Some("reserved Windows device name");
    }
    None
}

/// Validates a single shared watcher directory: the path must be non-empty,
/// already in canonical form (absolute, with no `..` or symlinked components),
/// and an existing directory. Used by [`validate_watcher_directories`].
///
/// A relative path is rejected as `RelativePath` before the filesystem is
/// touched, so the result never depends on the process CWD. A path that
/// can't be canonicalized is `WatcherDirectoryNotFound` if it does not exist,
/// and `WatcherDirectoryInaccessible` carrying the io error text otherwise
/// (for example permission denied on a parent directory).
///
/// Canonical form is checked with [`Path`] equality, so redundant separators
/// and non-leading `.` components, which name the same directory, are accepted.
fn validate_watcher_directory<F: FileSystem>(
    filesystem: &F,
    field_name: &str,
    dir: &Path,
) -> Result<(), ValidationError> {
    if dir.as_os_str().is_empty() {
        return Err(ValidationError::with_guidance(
            field_name.to_string(),
            ValidationErrorCode::InvalidValue,
            INVALID_WATCHER_DIRECTORY_ERR_MSG.to_string(),
            "The directory can't be empty.".to_string(),
        ));
    }

    if !dir.is_absolute() {
        return Err(ValidationError::with_guidance(
            field_name.to_string(),
            ValidationErrorCode::RelativePath,
            INVALID_WATCHER_DIRECTORY_ERR_MSG.to_string(),
            format!("Path must be absolute, got: '{}'", dir.display()),
        ));
    }

    match filesystem.canonicalize(dir) {
        Ok(canonical) if canonical == dir => {}
        Ok(canonical) => {
            return Err(ValidationError::with_guidance(
                field_name.to_string(),
                ValidationErrorCode::UnsafePath,
                INVALID_WATCHER_DIRECTORY_ERR_MSG.to_string(),
                format!(
                    "The directory must be in canonical form (absolute, with no '..' or symlinked components), got: '{}', which resolves to '{}'.",
                    dir.display(),
                    canonical.display()
                ),
            ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ValidationError::with_guidance(
                field_name.to_string(),
                ValidationErrorCode::WatcherDirectoryNotFound,
                WATCHER_DIRECTORY_NOT_FOUND_ERR_MSG.to_string(),
                format!("The directory '{}' does not exist.", dir.display()),
            ));
        }
        Err(e) => {
            return Err(ValidationError::with_guidance(
                field_name.to_string(),
                ValidationErrorCode::WatcherDirectoryInaccessible,
                WATCHER_DIRECTORY_INACCESSIBLE_ERR_MSG.to_string(),
                format!("Could not resolve the directory '{}': {}", dir.display(), e),
            ));
        }
    }

    if !filesystem.is_dir(dir) {
        return Err(ValidationError::with_guidance(
            field_name.to_string(),
            ValidationErrorCode::WatcherDirectoryNotFound,
            WATCHER_DIRECTORY_NOT_FOUND_ERR_MSG.to_string(),
            format!("'{}' is not a directory.", dir.display()),
        ));
    }

    Ok(())
}

/// Validates the pair of shared watcher directories: the directory holding the
/// generated per-watcher configuration files and the directory holding the
/// per-watcher refresh request directories.
///
/// Shared by the WCP config validator and the Watcher's own config
/// validation. Each caller passes `validate_config_read_only` for its side and
/// the field labels used in the returned errors:
///
/// - The WCP provider passes `false`: it writes the per-watcher configs, so the
///   config directory must be on a read-write mount.
/// - The watcher passes `true`: it only reads its config, so the config
///   directory must be on a read-only mount.
///
/// The requests directory must be on a read-write mount for both sides: the
/// provider creates and renames requests in `<requests>/<id>/inbox`, and the
/// watcher deletes the requests it picks up.
///
/// Intended for validation at container startup, after all required volumes
/// are mounted, so both directories must exist.
///
/// Each directory is the override when given, otherwise the platform default
/// ([`DEFAULT_WATCHER_CONFIG_DIR`] / [`DEFAULT_WATCHER_REQUESTS_DIR`]). The
/// resolved paths are checked in order:
///
/// 1. Each directory must be non-empty, absolute, in canonical form (no `..`
///    or symlinked components), and an existing directory. A missing
///    directory is `WatcherDirectoryNotFound`; any other resolution error is
///    `WatcherDirectoryInaccessible` with the io error text. Errors for both
///    directories are collected; if either fails, the pair is not compared.
/// 2. Distinctness: the two directories must differ. Both are canonical, so
///    they are compared directly. If they are the same, the mount-mode check
///    is skipped.
/// 3. Mount mode: the config directory's mount must be read-only if
///    `validate_config_read_only` is set and read-write otherwise; the
///    requests directory's mount must always be read-write (both read via
///    [`FileSystem::is_read_only_mount`]). A directory whose
///    mode cannot be read is an error, not a pass, so the check is never
///    silently skipped. Errors for both directories are collected.
///
///    Windows gap: on Windows only, a lookup that fails with
///    [`std::io::ErrorKind::Unsupported`] (what the real filesystem returns
///    there, having no Windows implementation) passes that directory's mode
///    check and adds a message naming the directory to
///    [`WatcherDirectories::warnings`]. The function does not log it itself:
///    validation runs before the caller's logger is initialized. Any other
///    error on Windows, and any error on Unix (`Unsupported` included), still
///    fails.
///
/// The device id (`st_dev`) is deliberately not compared: bind mounts and
/// Kubernetes `subPath` volumes share the source filesystem's device id, so
/// "different device" neither proves nor disproves separate mounts.
///
/// Returns the resolved paths on success, or every error collected by the
/// first failing stage.
pub fn validate_watcher_directories<F: FileSystem>(
    filesystem: &F,
    validate_config_read_only: bool,
    config_field: &str,
    config_override: Option<&str>,
    requests_field: &str,
    requests_override: Option<&str>,
) -> Result<WatcherDirectories, Vec<ValidationError>> {
    let config_dir = PathBuf::from(config_override.unwrap_or(DEFAULT_WATCHER_CONFIG_DIR));
    let requests_dir = PathBuf::from(requests_override.unwrap_or(DEFAULT_WATCHER_REQUESTS_DIR));
    let mut errors = Vec::new();

    // 1. Each directory: canonical, existing directory. Validate both so
    // that errors for both are reported.
    for (field, dir) in [
        (config_field, config_dir.as_path()),
        (requests_field, requests_dir.as_path()),
    ] {
        if let Err(e) = validate_watcher_directory(filesystem, field, dir) {
            errors.push(e);
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }

    // 2. Distinctness. The paths are already canonical, so they compare
    // directly.
    if config_dir == requests_dir {
        errors.push(ValidationError::with_guidance(
            requests_field.to_string(),
            ValidationErrorCode::ConflictingPaths,
            WATCHER_DIRECTORIES_NOT_DISTINCT_ERR_MSG.to_string(),
            format!(
                "'{}' and '{}' are the same directory.",
                config_dir.display(),
                requests_dir.display()
            ),
        ));
        // One directory can't satisfy two mount modes; skip the mode check to
        // avoid a confusing second error.
        return Err(errors);
    }

    // 3. Mount mode. A failed lookup is reported per directory rather than
    // treated as either mode (fail closed), except the Windows `Unsupported`
    // gap, which passes and returns a warning for the caller to log.
    // The requests directory is always read-write.
    let mut warnings = Vec::new();
    for (field, dir, expect_read_only) in [
        (config_field, &config_dir, validate_config_read_only),
        (requests_field, &requests_dir, false),
    ] {
        match filesystem.is_read_only_mount(dir) {
            Ok(read_only) => {
                if read_only != expect_read_only {
                    errors.push(ValidationError::with_guidance(
                        field.to_string(),
                        ValidationErrorCode::WatcherDirectoryWrongMountMode,
                        WATCHER_DIRECTORY_WRONG_MOUNT_MODE_ERR_MSG.to_string(),
                        format!(
                            "'{}' is on a {} mount, but this process requires a {} mount. Mount it {} into this container.",
                            dir.display(),
                            mount_mode_name(read_only),
                            mount_mode_name(expect_read_only),
                            mount_mode_name(expect_read_only)
                        ),
                    ));
                }
            }
            Err(e) if is_unverifiable_windows_mount_mode(&e, cfg!(windows)) => {
                // The Windows gap: accept this directory's mode check and
                // return a warning for the caller to log. Logging here would
                // be lost, because validation runs before the logger is
                // initialized. See `is_unverifiable_windows_mount_mode`.
                warnings.push(format!(
                    "{}: could not verify the mount access mode of '{}' on Windows ({}); accepting it without checking that it is mounted {}.",
                    field,
                    dir.display(),
                    e,
                    mount_mode_name(expect_read_only)
                ));
            }
            Err(e) => {
                errors.push(ValidationError::with_guidance(
                    field.to_string(),
                    ValidationErrorCode::WatcherDirectoryMountUnknown,
                    WATCHER_DIRECTORY_MOUNT_UNKNOWN_ERR_MSG.to_string(),
                    format!(
                        "Could not read the mount access mode of '{}': {}",
                        dir.display(),
                        e
                    ),
                ));
            }
        }
    }

    if errors.is_empty() {
        Ok(WatcherDirectories {
            config_dir,
            requests_dir,
            warnings,
        })
    } else {
        Err(errors)
    }
}

/// Whether a failed mount-mode lookup is the known Windows gap, which is
/// warned about and accepted instead of rejected.
///
/// [`crate::filesystem::RealFileSystem`] has no Windows implementation of
/// [`FileSystem::is_read_only_mount`] and returns
/// [`std::io::ErrorKind::Unsupported`] there. Until a real one exists, Windows
/// accepts exactly that error kind so container configs can run. Every other
/// error kind on Windows, and every error on other platforms (`Unsupported`
/// included), fails closed.
///
/// `on_windows` is `cfg!(windows)` at the call site; it is a parameter so both
/// platform decisions are unit-tested on any host.
fn is_unverifiable_windows_mount_mode(error: &std::io::Error, on_windows: bool) -> bool {
    on_windows && error.kind() == std::io::ErrorKind::Unsupported
}

/// `"read-only"` or `"read-write"`, used in mount-mode error guidance.
fn mount_mode_name(read_only: bool) -> &'static str {
    if read_only {
        "read-only"
    } else {
        "read-write"
    }
}

#[cfg(unix)]
pub fn validate_permission_config(
    field_name: &str,
    permission_config: &PermissionConfig,
) -> Result<PathPermission, ValidationError> {
    let mode_u32 = u32::from_str_radix(&permission_config.mode, 8).map_err(|_| {
        ValidationError::with_guidance(
            field_name.to_string(),
            ValidationErrorCode::InvalidValue,
            "The permission mode specified in the configuration file isn't valid. The mode must be a valid octal value.".to_string(),
            format!("Got: '{}'", permission_config.mode),
        )
    })?;
    if mode_u32 > 0o777 {
        return Err(ValidationError::with_guidance(
            field_name.to_string(),
            ValidationErrorCode::ValueOutOfRange,
            "The permission mode specified in the configuration file isn't valid. The mode must be in the range 0 to 777 (octal).".to_string(),
            format!("Got: '{}'", permission_config.mode),
        ));
    }
    Ok(PathPermission { mode: mode_u32 })
}

#[cfg(windows)]
pub fn validate_permission_config(
    field_name: &str,
    permission_config: &PermissionConfig,
) -> Result<PathPermission, ValidationError> {
    let trustee_name = permission_config.trustee_name.trim();
    if trustee_name.is_empty() {
        return Err(ValidationError::new(
            field_name.to_string(),
            ValidationErrorCode::InvalidValue,
            EMPTY_TRUSTEE_NAME_ERR_MSG.to_string(),
        ));
    }

    Ok(PathPermission {
        trustee_type: permission_config.trustee_type.clone(),
        trustee_name: trustee_name.to_owned(),
        rights: permission_config.rights.clone(),
    })
}

/// Validates cross-field relationships in configuration.
pub struct CrossFieldValidator;

/// Helper struct for tracking certificate block paths.
pub struct CertificateBlockPaths<'a> {
    pub certificate_path: &'a Path,
    pub private_key_path: &'a Path,
    pub chain_path: Option<&'a Path>,
}

impl CrossFieldValidator {
    /// Validate that all paths are unique within and across certificate blocks.
    pub fn validate_paths_unique(blocks: &[CertificateBlockPaths]) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        let mut seen_paths: HashSet<&Path> = HashSet::new();

        for (index, block) in blocks.iter().enumerate() {
            let field_prefix = format!("capabilities.acm.certificates[{}]", index);

            if !seen_paths.insert(block.certificate_path) {
                errors.push(ValidationError::with_guidance(
                    format!("{}.certificate_path", field_prefix),
                    ValidationErrorCode::ConflictingPaths,
                    DUPLICATE_CERTIFICATE_PATH_ERR_MSG.to_string(),
                    format!(
                        "certificate_path '{}' is used more than once",
                        block.certificate_path.display()
                    ),
                ));
            }

            if !seen_paths.insert(block.private_key_path) {
                errors.push(ValidationError::with_guidance(
                    format!("{}.private_key_path", field_prefix),
                    ValidationErrorCode::ConflictingPaths,
                    DUPLICATE_CERTIFICATE_PATH_ERR_MSG.to_string(),
                    format!(
                        "private_key_path '{}' is used more than once",
                        block.private_key_path.display()
                    ),
                ));
            }

            if let Some(chain) = block.chain_path {
                if !seen_paths.insert(chain) {
                    errors.push(ValidationError::with_guidance(
                        format!("{}.chain_path", field_prefix),
                        ValidationErrorCode::ConflictingPaths,
                        DUPLICATE_CERTIFICATE_PATH_ERR_MSG.to_string(),
                        format!("chain_path '{}' is used more than once", chain.display()),
                    ));
                }
            }
        }

        errors
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::MockFileSystem;

    #[test]
    fn test_validate_range_valid() {
        assert!(RangeValidator::validate_range("test", 0, 0, 3600, "err").is_ok());
        assert!(RangeValidator::validate_range("test", 1, 1, 1000, "err").is_ok());
        assert!(RangeValidator::validate_range("test", 1000, 1, 1000, "err").is_ok());
    }

    #[test]
    fn test_validate_range_invalid() {
        assert!(RangeValidator::validate_range("test", 0, 1, 1000, "err").is_err());
        assert!(RangeValidator::validate_range("test", 1001, 1, 1000, "err").is_err());
    }

    #[test]
    fn test_parse_and_validate_range_valid() {
        assert_eq!(
            RangeValidator::parse_and_validate_range("test", "0", 0, 3600, "err").unwrap(),
            0
        );
        assert_eq!(
            RangeValidator::parse_and_validate_range("test", "3600", 0, 3600, "err").unwrap(),
            3600
        );
    }

    #[test]
    fn test_parse_and_validate_range_invalid() {
        assert!(RangeValidator::parse_and_validate_range("test", "abc", 0, 3600, "err").is_err());
        assert!(RangeValidator::parse_and_validate_range("test", "3601", 0, 3600, "err").is_err());
    }

    #[test]
    fn test_validate_certificate_arn_valid() {
        let arn =
            "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012";
        assert!(ArnValidator::validate_certificate_arn("test", arn).is_ok());
    }

    #[test]
    fn test_validate_certificate_arn_invalid() {
        assert!(ArnValidator::validate_certificate_arn("test", "not-an-arn").is_err());
        // Wrong service
        assert!(ArnValidator::validate_certificate_arn(
            "test",
            "arn:aws:iam::123456789012:role/MyRole"
        )
        .is_err());
        // Invalid account ID
        assert!(ArnValidator::validate_certificate_arn(
            "test",
            "arn:aws:acm:us-east-1:12345:certificate/test"
        )
        .is_err());
    }

    #[test]
    fn test_validate_iam_role_arn_valid() {
        assert!(ArnValidator::validate_iam_role_arn(
            "test",
            "arn:aws:iam::123456789012:role/MyRole"
        )
        .is_ok());
    }

    #[test]
    fn test_validate_iam_role_arn_invalid() {
        assert!(ArnValidator::validate_iam_role_arn("test", "not-an-arn").is_err());
        // Wrong service
        assert!(ArnValidator::validate_iam_role_arn(
            "test",
            "arn:aws:acm:us-east-1:123456789012:certificate/test"
        )
        .is_err());
        // Non-empty region (IAM is global)
        assert!(ArnValidator::validate_iam_role_arn(
            "test",
            "arn:aws:iam:us-east-1:123456789012:role/MyRole"
        )
        .is_err());
    }

    #[test]
    fn test_file_path_validator_relative_path() {
        let fs = Arc::new(MockFileSystem::new());
        let validator = FilePathValidator::new(fs);

        let result = validator.validate("test", Path::new("relative/path.pem"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ValidationErrorCode::RelativePath);
    }

    #[cfg(unix)]
    #[test]
    fn test_file_path_validator_rejects_control_characters() {
        // Parent directories exist, so only the control-character check fails.
        let injected = "/tmp/holder\nUser=root\nExecStartPre=/tmp/pwn.sh\n#";
        let fs = MockFileSystem::new()
            .with_dir(injected)
            .with_dir("/etc/a\rb")
            .with_dir("/etc/a\0b")
            .with_dir("/etc/a\tb");
        let validator = FilePathValidator::new(Arc::new(fs));

        for path in [
            format!("{injected}/cert.pem"),
            "/etc/a\rb/cert.pem".to_string(),
            "/etc/a\0b/cert.pem".to_string(),
            "/etc/a\tb/cert.pem".to_string(),
            "/etc/certs/cert\n.pem".to_string(),
        ] {
            let err = validator
                .validate("test", Path::new(&path))
                .expect_err(&format!("expected {path:?} to be rejected"));
            assert_eq!(err.code, ValidationErrorCode::UnsafePath, "{path:?}");
            assert!(err.guidance.unwrap().contains("control characters"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_file_path_validator_rejects_non_utf8() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        // Rejected before the parent is looked up, so the mock needs no
        // directory.
        let validator = FilePathValidator::new(Arc::new(MockFileSystem::new()));

        let path = Path::new(OsStr::from_bytes(b"/etc/a\xffb/cert.pem"));
        let err = validator
            .validate("test", path)
            .expect_err("a non-UTF-8 path must be rejected");
        assert_eq!(err.code, ValidationErrorCode::UnsafePath);
        assert!(err.guidance.unwrap().contains("valid UTF-8"));
    }

    #[cfg(unix)]
    #[test]
    fn test_file_path_validator_parent_not_found() {
        let fs = MockFileSystem::new().with_dir("/etc");
        let validator = FilePathValidator::new(Arc::new(fs));

        let result = validator.validate("test", Path::new("/nonexistent/cert.pem"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ValidationErrorCode::ParentDirectoryNotFound);
    }

    #[cfg(unix)]
    #[test]
    fn test_file_path_validator_valid() {
        let fs = MockFileSystem::new().with_dir("/etc/certs");
        let validator = FilePathValidator::new(Arc::new(fs));

        assert!(validator
            .validate("test", Path::new("/etc/certs/cert.pem"))
            .is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn test_file_path_validator_rejects_traversal() {
        use crate::filesystem::RealFileSystem;
        use tempfile::TempDir;

        let tmp = TempDir::new().unwrap();
        let ssl_dir = tmp.path().join("ssl");
        let certs_dir = ssl_dir.join("certs");
        std::fs::create_dir_all(&certs_dir).unwrap();

        let validator = FilePathValidator::new(Arc::new(RealFileSystem));
        let canonical_tmp = std::fs::canonicalize(tmp.path()).unwrap();

        // Single ../ that resolves back to same directory
        let path = canonical_tmp.join("ssl/../ssl/certs/cert.pem");
        let result = validator.validate("test", &path);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ValidationErrorCode::UnsafePath);

        // Multiple ../../ that escapes and re-enters
        let path = canonical_tmp.join("ssl/certs/../../ssl/certs/cert.pem");
        let result = validator.validate("test", &path);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ValidationErrorCode::UnsafePath);
    }

    #[cfg(unix)]
    #[test]
    fn test_file_path_validator_rejects_symlinked_parent() {
        use crate::filesystem::RealFileSystem;
        use tempfile::TempDir;

        let tmp = TempDir::new().unwrap();
        let real_dir = tmp.path().join("real");
        std::fs::create_dir(&real_dir).unwrap();
        let link_dir = tmp.path().join("link");
        std::os::unix::fs::symlink(&real_dir, &link_dir).unwrap();

        let validator = FilePathValidator::new(Arc::new(RealFileSystem));

        let path = link_dir.join("cert.pem");
        let result = validator.validate("test", &path);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ValidationErrorCode::UnsafePath);
        assert!(err
            .guidance
            .unwrap()
            .contains("resolves to a different path"));
    }

    #[cfg(unix)]
    #[test]
    fn test_file_path_validator_accepts_canonical_path() {
        use crate::filesystem::RealFileSystem;
        use tempfile::TempDir;

        let tmp = TempDir::new().unwrap();
        let real_dir = tmp.path().join("certs");
        std::fs::create_dir(&real_dir).unwrap();

        let validator = FilePathValidator::new(Arc::new(RealFileSystem));

        // Use the canonicalized tmp path to ensure it matches what canonicalize() returns
        let canonical_dir = std::fs::canonicalize(&real_dir).unwrap();
        let path = canonical_dir.join("cert.pem");
        assert!(validator.validate("test", &path).is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn test_file_path_validator_parent_not_found() {
        let fs = MockFileSystem::new().with_dir("c:\\etc");
        let validator = FilePathValidator::new(Arc::new(fs));

        let result = validator.validate("test", Path::new("c:\\nonexistent\\cert.pem"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ValidationErrorCode::ParentDirectoryNotFound);
    }

    #[cfg(windows)]
    #[test]
    fn test_file_path_validator_valid() {
        let fs = MockFileSystem::new().with_dir("c:\\etc\\certs");
        let validator = FilePathValidator::new(Arc::new(fs));

        assert!(validator
            .validate("test", Path::new("c:\\etc\\certs\\cert.pem"))
            .is_ok());
    }

    #[test]
    fn test_validate_refresh_command_empty() {
        let result = validate_refresh_command("test", "");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ValidationErrorCode::EmptyCommand);
    }

    #[test]
    fn test_validate_refresh_command_whitespace() {
        let result = validate_refresh_command("test", "   ");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ValidationErrorCode::EmptyCommand);
    }

    #[cfg(unix)]
    #[test]
    fn test_validate_refresh_command_valid() {
        assert!(validate_refresh_command("test", "/usr/sbin/nginx -s reload").is_ok());
        assert!(validate_refresh_command("test", "/opt/reload.sh").is_ok());
        assert!(validate_refresh_command("test", "/bin/systemctl reload apache2").is_ok());
        assert!(validate_refresh_command("test", "/usr/bin/my-script_v2.sh --flag=value").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn test_validate_refresh_command_relative_path() {
        let result = validate_refresh_command("test", "systemctl reload nginx");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code,
            ValidationErrorCode::InvalidCommand
        );
    }

    #[test]
    fn test_validate_refresh_command_newline_injection() {
        let result = validate_refresh_command(
            "test",
            "/usr/bin/cmd\naws-workload-credentials-provider ALL=(ALL) NOPASSWD: ALL",
        );
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code,
            ValidationErrorCode::InvalidCommand
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_validate_refresh_command_sudoers_metacharacters() {
        // Comma — could grant multiple commands
        let result = validate_refresh_command("test", "/usr/bin/cmd, /bin/bash");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code,
            ValidationErrorCode::InvalidCommand
        );

        // Backslash
        assert!(validate_refresh_command("test", "/usr/bin/cmd\\arg").is_err());

        // Exclamation mark
        assert!(validate_refresh_command("test", "/usr/bin/cmd !root").is_err());

        // Hash
        assert!(validate_refresh_command("test", "/usr/bin/cmd #comment").is_err());
    }

    #[cfg(windows)]
    #[test]
    fn test_validate_refresh_command_windows_valid() {
        assert!(validate_refresh_command("test", "Restart-Service Apache2.4").is_ok());
        assert!(validate_refresh_command("test", "nginx -s reload").is_ok());
        assert!(validate_refresh_command("test", "httpd.exe -k restart").is_ok());
        assert!(validate_refresh_command(
            "test",
            r#""C:\Program Files\nginx\nginx.exe" -s reload"#
        )
        .is_ok());
        assert!(validate_refresh_command("test", "httpd.exe --flag=value").is_ok());
        assert!(validate_refresh_command("test", "app.exe +option @config").is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn test_validate_refresh_command_windows_rejects_injection() {
        // Shell combinators
        assert!(validate_refresh_command("test", "Restart-Service A; Remove-Item C:\\").is_err());
        assert!(validate_refresh_command("test", "a && b").is_err());
        assert!(validate_refresh_command("test", "a | b").is_err());
        // Redirects
        assert!(validate_refresh_command("test", "cmd > out").is_err());
        // Globs
        assert!(validate_refresh_command("test", "del C:\\tmp\\*").is_err());
        // Subexpressions / variable expansion
        assert!(validate_refresh_command("test", "$(Invoke-Expression something)").is_err());
        // Single-quote delimiter (PowerShell string)
        assert!(validate_refresh_command("test", "Restart-Service 'My Service'").is_err());
    }

    #[test]
    fn test_validate_refresh_command_carriage_return() {
        let result = validate_refresh_command("test", "/usr/bin/cmd\rinjection");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code,
            ValidationErrorCode::InvalidCommand
        );
    }

    #[test]
    fn test_validate_watcher_id_valid() {
        let max_length = "a".repeat(64);
        for id in [
            "tls",
            "nginx-sidecar",
            "watcher_1",
            "a",
            "1",
            "web.tier-2_a",
            max_length.as_str(),
        ] {
            assert!(
                validate_watcher_id("test", id).is_ok(),
                "expected '{}' to be accepted",
                id
            );
        }
    }

    #[test]
    fn test_validate_watcher_id_invalid() {
        let too_long = "a".repeat(65);
        for id in [
            "",                // empty
            " ",               // whitespace only
            "a b",             // embedded whitespace
            "A",               // uppercase
            "aAa",             // uppercase anywhere in id
            ".",               // current directory
            "..",              // parent directory
            "../escape",       // traversal
            "a/b",             // unix separator
            "a\\b",            // windows separator
            "/absolute",       // absolute path
            "-leading-hyphen", // must start alphanumeric
            "_leading",        // must start alphanumeric
            ".hidden",         // must start alphanumeric
            "watcher\nid",     // newline
            "watcher:id",      // disallowed punctuation
            too_long.as_str(), // too long
            "watcher\u{0}id",  // null byte
            "unicode🔒",       // invalid unicode
        ] {
            let err = validate_watcher_id("test", id)
                .expect_err(&format!("expected '{}' to be rejected", id));
            assert_eq!(err.code, ValidationErrorCode::InvalidWatcherId);
            assert_eq!(err.field, "test");
        }
    }

    #[cfg(windows)]
    #[test]
    fn test_validate_watcher_id_windows_reserved_names() {
        for id in [
            "tls.",
            "a.b.",
            "con",
            "prn",
            "aux",
            "nul",
            "com1",
            "com9",
            "lpt1",
            "lpt9",
            "nul.txt",
            "nul.tar.gz",
            "con.",
            "com¹",
            "lpt³",
        ] {
            let err = validate_watcher_id("test", id)
                .expect_err(&format!("expected '{}' to be rejected", id));
            assert_eq!(err.code, ValidationErrorCode::InvalidWatcherId);
            assert_eq!(err.field, "test");
        }
        // Reserved names only match the whole part before the first period.
        for id in [
            "console",
            "connector",
            "nul-tls",
            "com0",
            "com10",
            "lpt0",
            "tls.con",
            "a.nul.b",
        ] {
            assert!(
                validate_watcher_id("test", id).is_ok(),
                "expected '{}' to be accepted",
                id
            );
        }
    }

    #[test]
    fn test_validate_watcher_directory_valid() {
        #[cfg(unix)]
        let dirs = ["/shared/wcp-watchers/config", "/shared"];
        #[cfg(windows)]
        let dirs = [r"C:\shared\wcp-watchers\config", r"C:\shared"];

        for dir in dirs {
            let fs = MockFileSystem::new().with_dir(dir);
            assert!(
                validate_watcher_directory(&fs, "test", Path::new(dir)).is_ok(),
                "expected '{}' to be accepted",
                dir
            );
        }
    }

    /// Asserts that validating `dir` against `fs` fails with `code` on the
    /// "test" field, and returns the error for further checks.
    fn assert_watcher_directory_err(
        fs: &MockFileSystem,
        dir: &str,
        code: ValidationErrorCode,
    ) -> ValidationError {
        let err = validate_watcher_directory(fs, "test", Path::new(dir)).unwrap_err();
        assert_eq!(err.code, code, "dir '{}': {:?}", dir, err);
        assert_eq!(err.field, "test");
        err
    }

    #[test]
    fn test_validate_watcher_directory_empty() {
        assert_watcher_directory_err(
            &MockFileSystem::new(),
            "",
            ValidationErrorCode::InvalidValue,
        );
    }

    #[test]
    fn test_validate_watcher_directory_missing() {
        assert_watcher_directory_err(
            &MockFileSystem::new(),
            WATCHER_CONFIG_DIR,
            ValidationErrorCode::WatcherDirectoryNotFound,
        );
    }

    #[test]
    fn test_validate_watcher_directory_relative_rejected() {
        let err = assert_watcher_directory_err(
            &MockFileSystem::new(),
            RELATIVE_DIR,
            ValidationErrorCode::RelativePath,
        );
        assert_eq!(err.message, INVALID_WATCHER_DIRECTORY_ERR_MSG);
        let guidance = err.guidance.unwrap_or_default();
        assert!(guidance.contains(RELATIVE_DIR), "{}", guidance);
    }

    #[test]
    fn test_validate_watcher_directory_relative_real_fs_independent_of_cwd() {
        use crate::filesystem::RealFileSystem;

        // "." exists under any CWD and would canonicalize to the CWD;
        // RELATIVE_DIR normally doesn't exist. Both are rejected the same way.
        for dir in [".", RELATIVE_DIR] {
            let err =
                validate_watcher_directory(&RealFileSystem, "test", Path::new(dir)).unwrap_err();
            assert_eq!(
                err.code,
                ValidationErrorCode::RelativePath,
                "dir '{}': {:?}",
                dir,
                err
            );
        }
    }

    #[test]
    fn test_validate_watcher_directory_canonicalize_error_not_reported_missing() {
        let fs = MockFileSystem::new()
            .with_canonicalize_error(WATCHER_CONFIG_DIR, std::io::ErrorKind::PermissionDenied);
        let err = assert_watcher_directory_err(
            &fs,
            WATCHER_CONFIG_DIR,
            ValidationErrorCode::WatcherDirectoryInaccessible,
        );
        assert_eq!(err.message, WATCHER_DIRECTORY_INACCESSIBLE_ERR_MSG);
        let guidance = err.guidance.unwrap_or_default();
        assert!(guidance.contains(WATCHER_CONFIG_DIR), "{}", guidance);
        assert!(
            guidance.contains("mock: canonicalize failed"),
            "{}",
            guidance
        );
        assert!(!guidance.contains("does not exist"), "{}", guidance);
    }

    #[test]
    fn test_validate_watcher_directory_canonicalize_error_kind_mapping() {
        use std::io::ErrorKind;

        // Only NotFound is reported as missing; every other kind keeps the io
        // error text.
        let cases = [
            (
                ErrorKind::NotFound,
                ValidationErrorCode::WatcherDirectoryNotFound,
            ),
            (
                ErrorKind::PermissionDenied,
                ValidationErrorCode::WatcherDirectoryInaccessible,
            ),
            (
                ErrorKind::InvalidInput,
                ValidationErrorCode::WatcherDirectoryInaccessible,
            ),
            (
                ErrorKind::Other,
                ValidationErrorCode::WatcherDirectoryInaccessible,
            ),
        ];

        for (kind, code) in cases {
            let fs = MockFileSystem::new().with_canonicalize_error(WATCHER_CONFIG_DIR, kind);
            let err =
                validate_watcher_directory(&fs, "test", Path::new(WATCHER_CONFIG_DIR)).unwrap_err();
            assert_eq!(err.code, code, "kind {:?}: {:?}", kind, err);
            let guidance = err.guidance.unwrap_or_default();
            assert!(guidance.contains(WATCHER_CONFIG_DIR), "{}", guidance);
            if kind == ErrorKind::NotFound {
                assert_eq!(err.message, WATCHER_DIRECTORY_NOT_FOUND_ERR_MSG);
                assert!(guidance.contains("does not exist"), "{}", guidance);
            } else {
                assert_eq!(err.message, WATCHER_DIRECTORY_INACCESSIBLE_ERR_MSG);
                assert!(
                    guidance.contains("mock: canonicalize failed"),
                    "kind {:?}: {}",
                    kind,
                    guidance
                );
                assert!(!guidance.contains("does not exist"), "{}", guidance);
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_validate_watcher_directory_absolute_missing_real_fs() {
        use crate::filesystem::RealFileSystem;

        let tmp = tempfile::TempDir::new().unwrap();
        let missing = std::fs::canonicalize(tmp.path()).unwrap().join("missing");
        let io_err = std::fs::canonicalize(&missing).unwrap_err();
        assert_eq!(io_err.kind(), std::io::ErrorKind::NotFound);

        let err = validate_watcher_directory(&RealFileSystem, "test", &missing).unwrap_err();
        assert_eq!(
            err.code,
            ValidationErrorCode::WatcherDirectoryNotFound,
            "{:?}",
            err
        );
        let guidance = err.guidance.unwrap_or_default();
        assert!(guidance.contains("does not exist"), "{}", guidance);
    }

    #[cfg(unix)]
    #[test]
    fn test_validate_watcher_directory_permission_denied_real_fs() {
        use crate::filesystem::RealFileSystem;
        use std::fs::Permissions;
        use std::os::unix::fs::PermissionsExt;

        // Root bypasses directory search permissions, so EACCES can't be
        // produced.
        if rustix::process::geteuid().is_root() {
            eprintln!("skipping: running as root, permission checks are bypassed");
            return;
        }

        /// Restores search permission on drop so TempDir cleanup succeeds
        /// even if an assertion panics.
        struct RestorePermissions(PathBuf);
        impl Drop for RestorePermissions {
            fn drop(&mut self) {
                let _ = std::fs::set_permissions(&self.0, Permissions::from_mode(0o700));
            }
        }

        let tmp = tempfile::TempDir::new().unwrap();
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let locked = base.join("locked");
        let child = locked.join("requests");
        std::fs::create_dir_all(&child).unwrap();
        std::fs::set_permissions(&locked, Permissions::from_mode(0o000)).unwrap();
        let _restore = RestorePermissions(locked.clone());

        let io_err = std::fs::canonicalize(&child).unwrap_err();
        assert_eq!(io_err.kind(), std::io::ErrorKind::PermissionDenied);

        let err = validate_watcher_directory(&RealFileSystem, "test", &child).unwrap_err();
        assert_eq!(
            err.code,
            ValidationErrorCode::WatcherDirectoryInaccessible,
            "{:?}",
            err
        );
        let guidance = err.guidance.unwrap_or_default();
        assert!(
            guidance.contains(&child.display().to_string()),
            "{}",
            guidance
        );
        assert!(guidance.contains(&io_err.to_string()), "{}", guidance);
        assert!(!guidance.contains("does not exist"), "{}", guidance);
    }

    #[test]
    fn test_validate_watcher_directory_traversal_missing() {
        assert_watcher_directory_err(
            &MockFileSystem::new(),
            TRAVERSAL_DIR,
            ValidationErrorCode::WatcherDirectoryNotFound,
        );
    }

    #[test]
    fn test_validate_watcher_directory_relative_rejected_even_if_resolvable() {
        // The relative path would resolve to a valid directory, but is
        // rejected before canonicalizing.
        let fs = MockFileSystem::new()
            .with_dir(WATCHER_CONFIG_DIR)
            .with_canonical_alias(RELATIVE_DIR, WATCHER_CONFIG_DIR);
        assert_watcher_directory_err(&fs, RELATIVE_DIR, ValidationErrorCode::RelativePath);
    }

    #[test]
    fn test_validate_watcher_directory_traversal_non_canonical() {
        let fs = MockFileSystem::new()
            .with_dir(WATCHER_CONFIG_DIR)
            .with_canonical_alias(TRAVERSAL_DIR, WATCHER_CONFIG_DIR);
        assert_watcher_directory_err(&fs, TRAVERSAL_DIR, ValidationErrorCode::UnsafePath);
    }

    #[test]
    fn test_validate_watcher_directory_symlink_non_canonical() {
        let fs = MockFileSystem::new()
            .with_dir(WATCHER_CONFIG_DIR)
            .with_canonical_alias(SYMLINK_DIR, WATCHER_CONFIG_DIR);
        assert_watcher_directory_err(&fs, SYMLINK_DIR, ValidationErrorCode::UnsafePath);
    }

    #[test]
    fn test_validate_watcher_directory_is_file() {
        let fs = MockFileSystem::new().with_file(WATCHER_CONFIG_DIR);
        assert_watcher_directory_err(
            &fs,
            WATCHER_CONFIG_DIR,
            ValidationErrorCode::WatcherDirectoryNotFound,
        );
    }

    // ========================================================================
    // Two-directory watcher validation (existence / distinctness / mounts)
    // ========================================================================

    #[cfg(unix)]
    const WATCHER_CONFIG_DIR: &str = "/shared/wcp-watchers/config";
    #[cfg(unix)]
    const WATCHER_REQUESTS_DIR: &str = "/shared/wcp-watchers/requests";
    #[cfg(windows)]
    const WATCHER_CONFIG_DIR: &str = r"C:\shared\wcp-watchers\config";
    #[cfg(windows)]
    const WATCHER_REQUESTS_DIR: &str = r"C:\shared\wcp-watchers\requests";

    #[cfg(unix)]
    const OVERRIDE_CONFIG_DIR: &str = "/mnt/wcp/config";
    #[cfg(unix)]
    const OVERRIDE_REQUESTS_DIR: &str = "/mnt/wcp/requests";
    #[cfg(windows)]
    const OVERRIDE_CONFIG_DIR: &str = r"C:\mnt\wcp\config";
    #[cfg(windows)]
    const OVERRIDE_REQUESTS_DIR: &str = r"C:\mnt\wcp\requests";

    #[cfg(unix)]
    const TRAVERSAL_DIR: &str = "/shared/../etc";
    #[cfg(windows)]
    const TRAVERSAL_DIR: &str = r"C:\shared\..\etc";

    const RELATIVE_DIR: &str = "relative/dir";

    /// A symlink-like spelling, registered in tests as an alias of
    /// [`WATCHER_CONFIG_DIR`] via [`MockFileSystem::with_canonical_alias`].
    #[cfg(unix)]
    const SYMLINK_DIR: &str = "/mnt/link-to-config";
    #[cfg(windows)]
    const SYMLINK_DIR: &str = r"C:\mnt\link-to-config";

    /// A mock filesystem with both default watcher directories on read-write
    /// mounts, as the provider requires.
    fn defaults_fs() -> MockFileSystem {
        MockFileSystem::new()
            .with_dir(DEFAULT_WATCHER_CONFIG_DIR)
            .with_dir(DEFAULT_WATCHER_REQUESTS_DIR)
    }

    /// A mock filesystem with the default config dir on a read-only mount and
    /// the default requests dir on a read-write mount, as the watcher requires.
    fn watcher_defaults_fs() -> MockFileSystem {
        MockFileSystem::new()
            .with_read_only_dir(DEFAULT_WATCHER_CONFIG_DIR)
            .with_dir(DEFAULT_WATCHER_REQUESTS_DIR)
    }

    /// Validates the two non-default test directories. `false` is the provider's
    /// side (config read-write), `true` the watcher's (config read-only).
    fn validate_test_dirs(
        fs: &MockFileSystem,
        validate_config_read_only: bool,
    ) -> Result<WatcherDirectories, Vec<ValidationError>> {
        validate_watcher_directories(
            fs,
            validate_config_read_only,
            "config_field",
            Some(WATCHER_CONFIG_DIR),
            "requests_field",
            Some(WATCHER_REQUESTS_DIR),
        )
    }

    #[test]
    fn test_validate_watcher_directories_defaults_when_none() {
        let dirs = validate_watcher_directories(
            &defaults_fs(),
            false,
            "config_field",
            None,
            "requests_field",
            None,
        )
        .unwrap();
        assert_eq!(
            dirs,
            WatcherDirectories {
                config_dir: PathBuf::from(DEFAULT_WATCHER_CONFIG_DIR),
                requests_dir: PathBuf::from(DEFAULT_WATCHER_REQUESTS_DIR),
                warnings: Vec::new(),
            }
        );
    }

    #[test]
    fn test_validate_watcher_directories_overrides_used() {
        // Only the override dirs exist; the defaults are not registered.
        let fs = MockFileSystem::new()
            .with_dir(OVERRIDE_CONFIG_DIR)
            .with_dir(OVERRIDE_REQUESTS_DIR);
        let dirs = validate_watcher_directories(
            &fs,
            false,
            "config_field",
            Some(OVERRIDE_CONFIG_DIR),
            "requests_field",
            Some(OVERRIDE_REQUESTS_DIR),
        )
        .unwrap();
        assert_eq!(
            dirs,
            WatcherDirectories {
                config_dir: PathBuf::from(OVERRIDE_CONFIG_DIR),
                requests_dir: PathBuf::from(OVERRIDE_REQUESTS_DIR),
                warnings: Vec::new(),
            }
        );
    }

    #[test]
    fn test_validate_watcher_directories_override_one_side() {
        let fs = MockFileSystem::new()
            .with_dir(OVERRIDE_CONFIG_DIR)
            .with_dir(DEFAULT_WATCHER_REQUESTS_DIR);
        let dirs = validate_watcher_directories(
            &fs,
            false,
            "config_field",
            Some(OVERRIDE_CONFIG_DIR),
            "requests_field",
            None,
        )
        .unwrap();
        assert_eq!(
            dirs,
            WatcherDirectories {
                config_dir: PathBuf::from(OVERRIDE_CONFIG_DIR),
                requests_dir: PathBuf::from(DEFAULT_WATCHER_REQUESTS_DIR),
                warnings: Vec::new(),
            }
        );
    }

    #[test]
    fn test_validate_watcher_directories_invalid_override_each_field() {
        let cases = [
            ("", ValidationErrorCode::InvalidValue),
            (RELATIVE_DIR, ValidationErrorCode::RelativePath),
            // Unregistered, so the mock can't canonicalize it.
            (TRAVERSAL_DIR, ValidationErrorCode::WatcherDirectoryNotFound),
            (SYMLINK_DIR, ValidationErrorCode::UnsafePath),
        ];
        // The defaults exist, so the only failure is the bad override.
        let fs = defaults_fs()
            .with_dir(WATCHER_CONFIG_DIR)
            .with_canonical_alias(SYMLINK_DIR, WATCHER_CONFIG_DIR);
        for (bad, code) in cases {
            let errors = validate_watcher_directories(
                &fs,
                false,
                "config_field",
                Some(bad),
                "requests_field",
                None,
            )
            .unwrap_err();
            assert_eq!(errors.len(), 1, "config '{}': {:?}", bad, errors);
            assert_eq!(errors[0].code, code, "config '{}'", bad);
            assert_eq!(errors[0].field, "config_field");

            let errors = validate_watcher_directories(
                &fs,
                false,
                "config_field",
                None,
                "requests_field",
                Some(bad),
            )
            .unwrap_err();
            assert_eq!(errors.len(), 1, "requests '{}': {:?}", bad, errors);
            assert_eq!(errors[0].code, code, "requests '{}'", bad);
            assert_eq!(errors[0].field, "requests_field");
        }
    }

    #[test]
    fn test_validate_watcher_directories_both_invalid_collected() {
        let fs = MockFileSystem::new()
            .with_dir(WATCHER_CONFIG_DIR)
            .with_canonical_alias(SYMLINK_DIR, WATCHER_CONFIG_DIR);
        let errors = validate_watcher_directories(
            &fs,
            false,
            "config_field",
            Some(SYMLINK_DIR),
            "requests_field",
            Some(""),
        )
        .unwrap_err();
        assert_eq!(errors.len(), 2, "{:?}", errors);
        assert_eq!(errors[0].code, ValidationErrorCode::UnsafePath);
        assert_eq!(errors[0].field, "config_field");
        assert_eq!(errors[1].code, ValidationErrorCode::InvalidValue);
        assert_eq!(errors[1].field, "requests_field");
    }

    #[test]
    fn test_validate_watcher_directories_symlink_alias_of_other_dir() {
        // The requests override is a non-canonical alias of the config dir.
        // It is rejected as non-canonical before the pair is compared.
        let fs = MockFileSystem::new()
            .with_dir(WATCHER_CONFIG_DIR)
            .with_canonical_alias(SYMLINK_DIR, WATCHER_CONFIG_DIR);
        let errors = validate_watcher_directories(
            &fs,
            false,
            "config_field",
            Some(WATCHER_CONFIG_DIR),
            "requests_field",
            Some(SYMLINK_DIR),
        )
        .unwrap_err();
        assert_eq!(errors.len(), 1, "{:?}", errors);
        assert_eq!(errors[0].code, ValidationErrorCode::UnsafePath);
        assert_eq!(errors[0].field, "requests_field");
    }

    #[test]
    fn test_validate_watcher_directories_both_missing() {
        let errors = validate_watcher_directories(
            &MockFileSystem::new(),
            false,
            "config_field",
            None,
            "requests_field",
            None,
        )
        .unwrap_err();
        assert_eq!(errors.len(), 2, "{:?}", errors);
        assert!(errors
            .iter()
            .all(|e| e.code == ValidationErrorCode::WatcherDirectoryNotFound));
        assert_eq!(errors[0].field, "config_field");
        assert_eq!(errors[1].field, "requests_field");
    }

    #[test]
    fn test_validate_watcher_directories_config_missing() {
        // Config dir is not registered; requests dir exists.
        let fs = MockFileSystem::new().with_dir(WATCHER_REQUESTS_DIR);
        let errors = validate_watcher_directories(
            &fs,
            false,
            "config_field",
            Some(WATCHER_CONFIG_DIR),
            "requests_field",
            Some(WATCHER_REQUESTS_DIR),
        )
        .unwrap_err();
        assert_eq!(errors.len(), 1);
        assert_eq!(
            errors[0].code,
            ValidationErrorCode::WatcherDirectoryNotFound
        );
        assert_eq!(errors[0].field, "config_field");
    }

    #[test]
    fn test_validate_watcher_directories_requests_missing() {
        // Requests dir is not registered; config dir exists.
        let fs = MockFileSystem::new().with_dir(WATCHER_CONFIG_DIR);
        let errors = validate_watcher_directories(
            &fs,
            false,
            "config_field",
            Some(WATCHER_CONFIG_DIR),
            "requests_field",
            Some(WATCHER_REQUESTS_DIR),
        )
        .unwrap_err();
        assert_eq!(errors.len(), 1);
        assert_eq!(
            errors[0].code,
            ValidationErrorCode::WatcherDirectoryNotFound
        );
        assert_eq!(errors[0].field, "requests_field");
    }

    #[test]
    fn test_validate_watcher_directories_path_is_file() {
        // Config path exists but is a file, not a directory.
        let fs = MockFileSystem::new()
            .with_file(WATCHER_CONFIG_DIR)
            .with_dir(WATCHER_REQUESTS_DIR);
        let errors = validate_watcher_directories(
            &fs,
            false,
            "config_field",
            Some(WATCHER_CONFIG_DIR),
            "requests_field",
            Some(WATCHER_REQUESTS_DIR),
        )
        .unwrap_err();
        assert_eq!(errors.len(), 1);
        assert_eq!(
            errors[0].code,
            ValidationErrorCode::WatcherDirectoryNotFound
        );
        assert_eq!(errors[0].field, "config_field");
    }

    #[test]
    fn test_validate_watcher_directories_same_path() {
        // Both arguments are the same existing directory: a single
        // distinctness error and no mount-mode error.
        let fs = MockFileSystem::new().with_dir(WATCHER_CONFIG_DIR);
        let errors = validate_watcher_directories(
            &fs,
            false,
            "config_field",
            Some(WATCHER_CONFIG_DIR),
            "requests_field",
            Some(WATCHER_CONFIG_DIR),
        )
        .unwrap_err();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].code, ValidationErrorCode::ConflictingPaths);
        assert_eq!(errors[0].field, "requests_field");
    }

    /// Asserts `error` is a wrong-mount-mode error on `field` whose guidance
    /// names `dir`, the observed and expected modes, and the fix.
    fn assert_wrong_mount_mode(
        error: &ValidationError,
        field: &str,
        dir: &str,
        observed: &str,
        expected: &str,
    ) {
        assert_eq!(
            error.code,
            ValidationErrorCode::WatcherDirectoryWrongMountMode,
            "{:?}",
            error
        );
        assert_eq!(error.field, field);
        let guidance = error.guidance.clone().unwrap_or_default();
        assert!(
            guidance.contains(&format!(
                "'{}' is on a {} mount, but this process requires a {} mount.",
                dir, observed, expected
            )),
            "{}",
            guidance
        );
        assert!(
            guidance.contains(&format!("Mount it {}", expected)),
            "{}",
            guidance
        );
    }

    #[test]
    fn test_validate_watcher_directories_provider_rejects_read_only_config() {
        let fs = MockFileSystem::new()
            .with_read_only_dir(WATCHER_CONFIG_DIR)
            .with_dir(WATCHER_REQUESTS_DIR);
        let errors = validate_test_dirs(&fs, false).unwrap_err();
        assert_eq!(errors.len(), 1, "{:?}", errors);
        assert_wrong_mount_mode(
            &errors[0],
            "config_field",
            WATCHER_CONFIG_DIR,
            "read-only",
            "read-write",
        );
    }

    #[test]
    fn test_validate_watcher_directories_provider_rejects_read_only_requests() {
        let fs = MockFileSystem::new()
            .with_dir(WATCHER_CONFIG_DIR)
            .with_read_only_dir(WATCHER_REQUESTS_DIR);
        let errors = validate_test_dirs(&fs, false).unwrap_err();
        assert_eq!(errors.len(), 1, "{:?}", errors);
        assert_wrong_mount_mode(
            &errors[0],
            "requests_field",
            WATCHER_REQUESTS_DIR,
            "read-only",
            "read-write",
        );
    }

    #[test]
    fn test_validate_watcher_directories_provider_both_read_only_collected() {
        let fs = MockFileSystem::new()
            .with_read_only_dir(WATCHER_CONFIG_DIR)
            .with_read_only_dir(WATCHER_REQUESTS_DIR);
        let errors = validate_test_dirs(&fs, false).unwrap_err();
        assert_eq!(errors.len(), 2, "{:?}", errors);
        assert!(errors
            .iter()
            .all(|e| e.code == ValidationErrorCode::WatcherDirectoryWrongMountMode));
        assert_eq!(errors[0].field, "config_field");
        assert_eq!(errors[1].field, "requests_field");
    }

    #[test]
    fn test_validate_watcher_directories_watcher_accepts_read_only_config() {
        let dirs = validate_watcher_directories(
            &watcher_defaults_fs(),
            true,
            "config_field",
            None,
            "requests_field",
            None,
        )
        .unwrap();
        assert_eq!(
            dirs,
            WatcherDirectories {
                config_dir: PathBuf::from(DEFAULT_WATCHER_CONFIG_DIR),
                requests_dir: PathBuf::from(DEFAULT_WATCHER_REQUESTS_DIR),
                warnings: Vec::new(),
            }
        );
    }

    #[test]
    fn test_validate_watcher_directories_watcher_rejects_writable_config() {
        let fs = MockFileSystem::new()
            .with_dir(WATCHER_CONFIG_DIR)
            .with_dir(WATCHER_REQUESTS_DIR);
        let errors = validate_test_dirs(&fs, true).unwrap_err();
        assert_eq!(errors.len(), 1, "{:?}", errors);
        assert_wrong_mount_mode(
            &errors[0],
            "config_field",
            WATCHER_CONFIG_DIR,
            "read-write",
            "read-only",
        );
    }

    #[test]
    fn test_validate_watcher_directories_watcher_rejects_read_only_requests() {
        let fs = MockFileSystem::new()
            .with_read_only_dir(WATCHER_CONFIG_DIR)
            .with_read_only_dir(WATCHER_REQUESTS_DIR);
        let errors = validate_test_dirs(&fs, true).unwrap_err();
        assert_eq!(errors.len(), 1, "{:?}", errors);
        assert_wrong_mount_mode(
            &errors[0],
            "requests_field",
            WATCHER_REQUESTS_DIR,
            "read-only",
            "read-write",
        );
    }

    #[test]
    fn test_validate_watcher_directories_mount_mode_unknown_each_field() {
        // An existing directory whose mount mode can't be read fails
        // validation on its own field instead of passing the mode check.
        let fs = MockFileSystem::new()
            .with_dir_mount_mode_unknown(WATCHER_CONFIG_DIR)
            .with_dir(WATCHER_REQUESTS_DIR);
        let errors = validate_test_dirs(&fs, false).unwrap_err();
        assert_eq!(errors.len(), 1, "{:?}", errors);
        assert_eq!(
            errors[0].code,
            ValidationErrorCode::WatcherDirectoryMountUnknown
        );
        assert_eq!(errors[0].field, "config_field");
        let guidance = errors[0].guidance.clone().unwrap_or_default();
        assert!(guidance.contains(WATCHER_CONFIG_DIR), "{}", guidance);

        let fs = MockFileSystem::new()
            .with_dir(WATCHER_CONFIG_DIR)
            .with_dir_mount_mode_unknown(WATCHER_REQUESTS_DIR);
        let errors = validate_test_dirs(&fs, false).unwrap_err();
        assert_eq!(errors.len(), 1, "{:?}", errors);
        assert_eq!(
            errors[0].code,
            ValidationErrorCode::WatcherDirectoryMountUnknown
        );
        assert_eq!(errors[0].field, "requests_field");
    }

    #[test]
    fn test_validate_watcher_directories_mount_mode_unknown_both_collected() {
        let fs = MockFileSystem::new()
            .with_dir_mount_mode_unknown(WATCHER_CONFIG_DIR)
            .with_dir_mount_mode_unknown(WATCHER_REQUESTS_DIR);
        let errors = validate_test_dirs(&fs, false).unwrap_err();
        assert_eq!(errors.len(), 2, "{:?}", errors);
        assert!(errors
            .iter()
            .all(|e| e.code == ValidationErrorCode::WatcherDirectoryMountUnknown));
        assert_eq!(errors[0].field, "config_field");
        assert_eq!(errors[1].field, "requests_field");
    }

    #[test]
    fn test_is_unverifiable_windows_mount_mode_decision() {
        use std::io::{Error, ErrorKind};

        // Exactly one case passes: `Unsupported` on Windows.
        assert!(is_unverifiable_windows_mount_mode(
            &Error::from(ErrorKind::Unsupported),
            true
        ));
        // `Unsupported` anywhere else fails closed.
        assert!(!is_unverifiable_windows_mount_mode(
            &Error::from(ErrorKind::Unsupported),
            false
        ));
        // Every other error kind fails closed on both platforms.
        for kind in [
            ErrorKind::NotFound,
            ErrorKind::PermissionDenied,
            ErrorKind::InvalidInput,
            ErrorKind::Other,
        ] {
            for on_windows in [true, false] {
                assert!(
                    !is_unverifiable_windows_mount_mode(&Error::from(kind), on_windows),
                    "{kind:?} on_windows={on_windows} must fail closed"
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_validate_watcher_directories_unsupported_still_rejected_on_unix() {
        // The Windows warn-and-pass gap never applies on Unix: an
        // `Unsupported` lookup is a mount-unknown error for both dirs, on
        // both sides.
        let fs = MockFileSystem::new()
            .with_dir_mount_mode_error(WATCHER_CONFIG_DIR, std::io::ErrorKind::Unsupported)
            .with_dir_mount_mode_error(WATCHER_REQUESTS_DIR, std::io::ErrorKind::Unsupported);
        for validate_config_read_only in [false, true] {
            let errors = validate_test_dirs(&fs, validate_config_read_only).unwrap_err();
            assert_eq!(errors.len(), 2, "{:?}", errors);
            assert!(errors
                .iter()
                .all(|e| e.code == ValidationErrorCode::WatcherDirectoryMountUnknown));
            assert_eq!(errors[0].field, "config_field");
            assert_eq!(errors[1].field, "requests_field");
        }
    }

    #[cfg(windows)]
    #[test]
    fn test_validate_watcher_directories_unsupported_passes_on_windows() {
        // Windows gap: `Unsupported` warns and passes for both dirs, on both
        // sides.
        let fs = MockFileSystem::new()
            .with_dir_mount_mode_error(WATCHER_CONFIG_DIR, std::io::ErrorKind::Unsupported)
            .with_dir_mount_mode_error(WATCHER_REQUESTS_DIR, std::io::ErrorKind::Unsupported);
        for validate_config_read_only in [false, true] {
            let dirs = validate_test_dirs(&fs, validate_config_read_only).unwrap();
            assert_eq!(dirs.config_dir, PathBuf::from(WATCHER_CONFIG_DIR));
            assert_eq!(dirs.requests_dir, PathBuf::from(WATCHER_REQUESTS_DIR));
            // The skipped checks are returned for logging once the logger is
            // up, one per directory, naming the directory.
            assert_eq!(dirs.warnings.len(), 2, "{:?}", dirs.warnings);
            assert!(dirs.warnings[0].contains(WATCHER_CONFIG_DIR));
            assert!(dirs.warnings[1].contains(WATCHER_REQUESTS_DIR));
        }
    }

    #[cfg(windows)]
    #[test]
    fn test_validate_watcher_directories_other_errors_still_rejected_on_windows() {
        // Only `Unsupported` is accepted on Windows; any other lookup error
        // still fails on its own field.
        let fs = MockFileSystem::new()
            .with_dir_mount_mode_error(WATCHER_CONFIG_DIR, std::io::ErrorKind::Unsupported)
            .with_dir_mount_mode_unknown(WATCHER_REQUESTS_DIR);
        for validate_config_read_only in [false, true] {
            let errors = validate_test_dirs(&fs, validate_config_read_only).unwrap_err();
            assert_eq!(errors.len(), 1, "{:?}", errors);
            assert_eq!(
                errors[0].code,
                ValidationErrorCode::WatcherDirectoryMountUnknown
            );
            assert_eq!(errors[0].field, "requests_field");
        }
    }

    /// Two canonical subdirectories of one fresh TempDir: one real read-write
    /// mount, one device id.
    #[cfg(unix)]
    fn real_same_filesystem_dirs() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let tmp = tempfile::TempDir::new().unwrap();
        // Canonical base so the paths are absolute and free of `.`/`..`.
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let config_dir = base.join("config");
        let requests_dir = base.join("requests");
        std::fs::create_dir(&config_dir).unwrap();
        std::fs::create_dir(&requests_dir).unwrap();
        (tmp, config_dir, requests_dir)
    }

    #[cfg(unix)]
    #[test]
    fn test_validate_watcher_directories_real_same_filesystem_accepted_for_provider() {
        use crate::filesystem::RealFileSystem;

        // Both dirs share one filesystem (same st_dev) and are read-write.
        // The provider accepts them: bind mounts and subPath volumes of one
        // volume look exactly like this, so "same device" is not a refusal.
        let (_tmp, config_dir, requests_dir) = real_same_filesystem_dirs();
        let dirs = validate_watcher_directories(
            &RealFileSystem,
            false,
            "config_field",
            Some(config_dir.to_str().unwrap()),
            "requests_field",
            Some(requests_dir.to_str().unwrap()),
        )
        .unwrap();
        assert_eq!(
            dirs,
            WatcherDirectories {
                config_dir,
                requests_dir,
                warnings: Vec::new(),
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_validate_watcher_directories_real_writable_config_rejected_for_watcher() {
        use crate::filesystem::RealFileSystem;

        // A TempDir is read-write, so the real statvfs check refuses it as
        // the watcher's config dir. (The read-only case needs a real ro
        // mount; the e2e reload tests create one in a private namespace.)
        let (_tmp, config_dir, requests_dir) = real_same_filesystem_dirs();
        let errors = validate_watcher_directories(
            &RealFileSystem,
            true,
            "config_field",
            Some(config_dir.to_str().unwrap()),
            "requests_field",
            Some(requests_dir.to_str().unwrap()),
        )
        .unwrap_err();
        assert_eq!(errors.len(), 1, "{:?}", errors);
        assert_eq!(
            errors[0].code,
            ValidationErrorCode::WatcherDirectoryWrongMountMode
        );
        assert_eq!(errors[0].field, "config_field");
    }

    #[cfg(unix)]
    #[test]
    fn test_validate_watcher_directories_real_symlink_rejected() {
        use crate::filesystem::RealFileSystem;
        use tempfile::TempDir;

        // A symlink to an existing directory is not canonical, so the real
        // filesystem rejects it before the distinctness and mount checks.
        let tmp = TempDir::new().unwrap();
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let config_dir = base.join("config");
        let requests_dir = base.join("requests");
        let link = base.join("link");
        std::fs::create_dir(&config_dir).unwrap();
        std::fs::create_dir(&requests_dir).unwrap();
        std::os::unix::fs::symlink(&config_dir, &link).unwrap();

        let errors = validate_watcher_directories(
            &RealFileSystem,
            false,
            "config_field",
            Some(link.to_str().unwrap()),
            "requests_field",
            Some(requests_dir.to_str().unwrap()),
        )
        .unwrap_err();
        assert_eq!(errors.len(), 1, "{:?}", errors);
        assert_eq!(errors[0].code, ValidationErrorCode::UnsafePath);
        assert_eq!(errors[0].field, "config_field");
    }

    #[test]
    fn test_validate_paths_unique_valid() {
        let paths = vec![
            CertificateBlockPaths {
                certificate_path: Path::new("/etc/cert1.pem"),
                private_key_path: Path::new("/etc/key1.pem"),
                chain_path: None,
            },
            CertificateBlockPaths {
                certificate_path: Path::new("/etc/cert2.pem"),
                private_key_path: Path::new("/etc/key2.pem"),
                chain_path: None,
            },
        ];
        assert!(CrossFieldValidator::validate_paths_unique(&paths).is_empty());
    }

    #[test]
    fn test_validate_paths_unique_duplicate() {
        let paths = vec![
            CertificateBlockPaths {
                certificate_path: Path::new("/etc/cert.pem"),
                private_key_path: Path::new("/etc/key1.pem"),
                chain_path: None,
            },
            CertificateBlockPaths {
                certificate_path: Path::new("/etc/cert.pem"),
                private_key_path: Path::new("/etc/key2.pem"),
                chain_path: None,
            },
        ];
        let errors = CrossFieldValidator::validate_paths_unique(&paths);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].field.ends_with("certificate_path"));
    }

    #[test]
    fn test_validate_paths_unique_duplicate_chain_path() {
        let paths = vec![
            CertificateBlockPaths {
                certificate_path: Path::new("/etc/cert1.pem"),
                private_key_path: Path::new("/etc/key1.pem"),
                chain_path: Some(Path::new("/etc/chain.pem")),
            },
            CertificateBlockPaths {
                certificate_path: Path::new("/etc/cert2.pem"),
                private_key_path: Path::new("/etc/key2.pem"),
                chain_path: Some(Path::new("/etc/chain.pem")),
            },
        ];
        let errors = CrossFieldValidator::validate_paths_unique(&paths);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].field.ends_with("chain_path"));
    }

    #[test]
    fn test_validate_paths_unique_within_single_block() {
        let paths = vec![CertificateBlockPaths {
            certificate_path: Path::new("/etc/cert.pem"),
            private_key_path: Path::new("/etc/cert.pem"),
            chain_path: None,
        }];
        let errors = CrossFieldValidator::validate_paths_unique(&paths);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].field.ends_with("private_key_path"));
    }

    // ========================================================================
    // Unix permission config tests
    // ========================================================================

    #[cfg(unix)]
    #[test]
    fn test_validate_permission_config_unix_mode_777() {
        let config = PermissionConfig {
            mode: "777".to_string(),
        };
        let perm = validate_permission_config("test", &config).unwrap();
        assert_eq!(perm.mode, 0o777);
    }

    #[cfg(unix)]
    #[test]
    fn test_validate_permission_config_unix_mode_000() {
        let config = PermissionConfig {
            mode: "000".to_string(),
        };
        let perm = validate_permission_config("test", &config).unwrap();
        assert_eq!(perm.mode, 0);
    }

    #[cfg(unix)]
    #[test]
    fn test_validate_permission_config_unix_invalid_mode_non_octal() {
        let config = PermissionConfig {
            mode: "999".to_string(),
        };
        let err = validate_permission_config("test", &config).unwrap_err();
        assert_eq!(err.code, ValidationErrorCode::InvalidValue);
    }

    #[cfg(unix)]
    #[test]
    fn test_validate_permission_config_unix_invalid_mode_text() {
        let config = PermissionConfig {
            mode: "abc".to_string(),
        };
        let err = validate_permission_config("test", &config).unwrap_err();
        assert_eq!(err.code, ValidationErrorCode::InvalidValue);
    }

    #[cfg(unix)]
    #[test]
    fn test_validate_permission_config_unix_mode_out_of_range() {
        let config = PermissionConfig {
            mode: "1000".to_string(),
        };
        let err = validate_permission_config("test", &config).unwrap_err();
        assert_eq!(err.code, ValidationErrorCode::ValueOutOfRange);
    }

    // ========================================================================
    // Windows permission config tests
    // ========================================================================

    #[cfg(windows)]
    #[test]
    fn test_validate_permission_config_windows_valid_user() {
        let config = PermissionConfig {
            trustee_name: "Administrator".to_string(),
            trustee_type: TrusteeType::User,
            rights: Rights::Read,
        };
        let result = validate_permission_config("test", &config);
        assert!(result.is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn test_validate_permission_config_windows_valid_group() {
        let config = PermissionConfig {
            trustee_name: "Users".to_string(),
            trustee_type: TrusteeType::Group,
            rights: Rights::Read,
        };
        let result = validate_permission_config("test", &config);
        assert!(result.is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn test_validate_permission_config_windows_empty_trustee() {
        let config = PermissionConfig {
            trustee_name: "".to_string(),
            trustee_type: TrusteeType::User,
            rights: Rights::Read,
        };
        let err = validate_permission_config("test", &config).unwrap_err();
        assert_eq!(err.code, ValidationErrorCode::InvalidValue);
        assert!(err.message.contains("trustee"));
    }

    #[cfg(windows)]
    #[test]
    fn test_validate_permission_config_windows_whitespace_trustee() {
        let config = PermissionConfig {
            trustee_name: "   ".to_string(),
            trustee_type: TrusteeType::User,
            rights: Rights::Read,
        };
        let err = validate_permission_config("test", &config).unwrap_err();
        assert_eq!(err.code, ValidationErrorCode::InvalidValue);
    }
}
