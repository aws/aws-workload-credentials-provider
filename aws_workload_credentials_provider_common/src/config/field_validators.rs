//! Field-level validators for configuration values.
//!
//! This module contains validators for:
//! - Range validation (generic numeric range checking)
//! - ARN validation (certificate and IAM role ARNs)
//! - File path validation (absolute paths, parent directory existence)
//! - Refresh command validation (non-empty check)
//! - Cross-field validation (path uniqueness within and across certificate blocks)

use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, LazyLock};

use regex::Regex;

use super::error::{ValidationError, ValidationErrorCode};
use super::error_messages::{
    DUPLICATE_CERTIFICATE_PATH_ERR_MSG, EMPTY_REFRESH_COMMAND_ERR_MSG, EMPTY_TRUSTEE_NAME_ERR_MSG,
    INVALID_CERTIFICATE_ARN_ERR_MSG, INVALID_FILE_PATH_ERR_MSG, INVALID_IAM_ROLE_ARN_ERR_MSG,
    INVALID_REFRESH_COMMAND_ERR_MSG,
};
use super::types::PermissionConfig;
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
    Regex::new(r"^arn:[\w-]+:acm:[^:]+:\d{12}:certificate/[\w+=,.@/-]+$").unwrap()
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
    /// - Absolute
    /// - Parent directory exists
    /// - Parent directory resolves to itself (no symlinks or `..` indirection)
    ///
    /// Note: Does not check if the file itself exists (it will be created).
    pub fn validate(&self, field_name: &str, path: &Path) -> Result<(), ValidationError> {
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
