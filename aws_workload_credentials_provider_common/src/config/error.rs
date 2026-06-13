//! Validation error types for config validation.
//!
//! This module defines structured error types that provide detailed information
//! about config validation failures, including field paths, error codes, and guidance.

use serde::Serialize;
use std::fmt;

/// Error codes for config validation failures.
///
/// Each code represents a specific category of config validation error,
/// enabling programmatic handling of different error types.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum ValidationErrorCode {
    // Syntax/file errors
    /// Error reading file
    FileReadError,
    /// Invalid TOML syntax
    TomlSyntaxError,
    /// Duplicate key in TOML table
    DuplicateKey,
    /// Flat keys alongside nested sections
    FormatConflict,

    // Required field errors
    /// A required field is missing
    MissingRequiredField,

    // Type errors
    /// Field value has incorrect type
    InvalidType,

    // Range errors
    /// Field value is outside acceptable range
    ValueOutOfRange,
    /// Invalid log level value
    InvalidLogLevel,

    // ARN errors
    /// Invalid ACM certificate ARN format
    InvalidCertificateArn,
    /// Duplicate certificate ARN
    DuplicateCertificateArn,
    /// Invalid IAM role ARN format
    InvalidRoleArn,

    // File path errors
    /// Path is not absolute
    RelativePath,
    /// Parent directory does not exist
    ParentDirectoryNotFound,
    /// Parent directory is not writable
    ParentDirectoryNotWritable,
    /// Path contains traversal components (e.g., `..`) or symlinks that resolve outside expected directory
    UnsafePath,

    // Refresh command errors
    /// Command string is empty
    EmptyCommand,
    /// Command contains invalid characters or format
    InvalidCommand,

    // Value errors
    /// Field value is syntactically valid but semantically invalid
    InvalidValue,

    // Cross-field errors
    /// Same path used across multiple certificate blocks
    ConflictingPaths,
}

/// A single config validation error with detailed information.
///
/// Each error includes the field path where the error occurred,
/// an error code for programmatic handling, a human-readable message,
/// and optional guidance on how to fix the issue.
#[derive(Debug, Clone, Serialize)]
pub struct ValidationError {
    /// The field path where the error occurred.
    ///
    /// Examples: "http_port", "capabilities.acm.certificates\[0\].certificate_arn"
    pub field: String,

    /// Error code for programmatic handling.
    pub code: ValidationErrorCode,

    /// Human-readable error message.
    pub message: String,

    /// Optional guidance on how to fix the issue.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guidance: Option<String>,
}

impl ValidationError {
    /// Creates a new config validation error.
    pub fn new(
        field: impl Into<String>,
        code: ValidationErrorCode,
        message: impl Into<String>,
    ) -> Self {
        Self {
            field: field.into(),
            code,
            message: message.into(),
            guidance: None,
        }
    }

    /// Creates a new config validation error with guidance.
    pub fn with_guidance(
        field: impl Into<String>,
        code: ValidationErrorCode,
        message: impl Into<String>,
        guidance: impl Into<String>,
    ) -> Self {
        Self {
            field: field.into(),
            code,
            message: message.into(),
            guidance: Some(guidance.into()),
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.field, self.message)?;
        if let Some(ref guidance) = self.guidance {
            write!(f, " ({})", guidance)?;
        }
        Ok(())
    }
}

impl std::error::Error for ValidationError {}

/// A collection of config validation errors.
///
/// This type collects all config validation errors rather than stopping at the first,
/// providing comprehensive feedback to the user.
#[derive(Debug, Clone, Serialize)]
pub struct ValidationErrors {
    /// The list of config validation errors.
    pub errors: Vec<ValidationError>,
}

impl ValidationErrors {
    /// Creates a new empty error collection.
    pub fn new() -> Self {
        Self { errors: Vec::new() }
    }

    /// Creates an error collection from a single error.
    pub fn from_error(error: ValidationError) -> Self {
        Self {
            errors: vec![error],
        }
    }

    /// Creates an error collection from a vector of errors.
    pub fn from_vec(errors: Vec<ValidationError>) -> Self {
        Self { errors }
    }

    /// Returns true if there are no errors.
    pub fn is_empty(&self) -> bool {
        self.errors.is_empty()
    }

    /// Returns the number of errors.
    pub fn len(&self) -> usize {
        self.errors.len()
    }

    /// Converts the errors to JSON format for structured logging.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Converts the errors to pretty-printed JSON format.
    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }
}

impl Default for ValidationErrors {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ValidationErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Configuration validation failed with {} error(s):",
            self.errors.len()
        )?;
        for (i, error) in self.errors.iter().enumerate() {
            writeln!(f, "  {}. {}", i + 1, error)?;
        }
        Ok(())
    }
}

impl std::error::Error for ValidationErrors {}

/// Collects config validation errors during the config validation process.
///
/// ErrorCollector implements the collect-all-errors strategy, allowing
/// config validation to continue past the first error and report all issues
/// to the user at once.
#[derive(Debug, Default)]
pub struct ErrorCollector {
    errors: Vec<ValidationError>,
}

impl ErrorCollector {
    /// Creates a new empty error collector.
    pub fn new() -> Self {
        Self { errors: Vec::new() }
    }

    /// Adds a single config validation error.
    pub fn add(&mut self, error: ValidationError) {
        self.errors.push(error);
    }

    /// Adds multiple config validation errors.
    pub fn add_all(&mut self, errors: impl IntoIterator<Item = ValidationError>) {
        self.errors.extend(errors);
    }

    /// Returns the number of collected errors.
    pub fn len(&self) -> usize {
        self.errors.len()
    }

    /// Returns true if no errors have been collected.
    pub fn is_empty(&self) -> bool {
        self.errors.is_empty()
    }

    /// Converts the collector into a Result.
    ///
    /// Returns `Ok(())` if no errors were collected, or `Err(ValidationErrors)`
    /// containing all collected errors.
    pub fn into_result(self) -> Result<(), ValidationErrors> {
        if self.errors.is_empty() {
            Ok(())
        } else {
            Err(ValidationErrors::from_vec(self.errors))
        }
    }

    /// Returns a reference to the collected errors.
    pub fn errors(&self) -> &[ValidationError] {
        &self.errors
    }
}

impl From<ValidationError> for ValidationErrors {
    fn from(error: ValidationError) -> Self {
        Self::from_error(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_error_new() {
        let error = ValidationError::new(
            "http_port",
            ValidationErrorCode::ValueOutOfRange,
            "Port 80 is outside the valid range [1024, 65535]",
        );

        assert_eq!(error.field, "http_port");
        assert_eq!(error.code, ValidationErrorCode::ValueOutOfRange);
        assert_eq!(
            error.message,
            "Port 80 is outside the valid range [1024, 65535]"
        );
        assert_eq!(error.guidance, None);
        assert_eq!(
            format!("{}", error),
            "http_port: Port 80 is outside the valid range [1024, 65535]"
        );
    }

    #[test]
    fn test_validation_error_with_guidance() {
        let error = ValidationError::with_guidance(
            "capabilities.acm.certificates[0].certificate_arn",
            ValidationErrorCode::InvalidCertificateArn,
            "Invalid certificate ARN format",
            "Use format: arn:{partition}:acm:{region}:{account-id}:certificate/{certificate-id}",
        );

        assert_eq!(
            error.field,
            "capabilities.acm.certificates[0].certificate_arn"
        );
        assert_eq!(error.code, ValidationErrorCode::InvalidCertificateArn);
        assert_eq!(error.message, "Invalid certificate ARN format");
        assert_eq!(
            error.guidance,
            Some("Use format: arn:{partition}:acm:{region}:{account-id}:certificate/{certificate-id}".to_string())
        );
        assert_eq!(
            format!("{}", error),
            "capabilities.acm.certificates[0].certificate_arn: Invalid certificate ARN format (Use format: arn:{partition}:acm:{region}:{account-id}:certificate/{certificate-id})"
        );
    }

    #[test]
    fn test_validation_errors_empty() {
        let errors = ValidationErrors::new();
        assert!(errors.is_empty());
        assert_eq!(errors.len(), 0);
    }

    #[test]
    fn test_validation_errors_from_error() {
        let error = ValidationError::new(
            "field",
            ValidationErrorCode::MissingRequiredField,
            "Field is required",
        );
        let errors = ValidationErrors::from_error(error);

        assert!(!errors.is_empty());
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn test_validation_errors_to_json() {
        let error = ValidationError::new(
            "http_port",
            ValidationErrorCode::ValueOutOfRange,
            "Invalid port",
        );
        let errors = ValidationErrors::from_error(error);

        let json = errors.to_json();
        assert!(json.contains("http_port"));
        assert!(json.contains("ValueOutOfRange"));
        assert!(json.contains("Invalid port"));
    }

    #[test]
    fn test_validation_errors_display() {
        let errors = ValidationErrors::from_vec(vec![
            ValidationError::new(
                "field1",
                ValidationErrorCode::MissingRequiredField,
                "Missing",
            ),
            ValidationError::new("field2", ValidationErrorCode::InvalidType, "Wrong type"),
        ]);

        let display = format!("{}", errors);
        assert_eq!(
            display,
            "Configuration validation failed with 2 error(s):\n  1. field1: Missing\n  2. field2: Wrong type\n"
        );
    }

    #[test]
    fn test_error_collector_new() {
        let collector = ErrorCollector::new();
        assert!(collector.is_empty());
        assert_eq!(collector.len(), 0);
    }

    #[test]
    fn test_error_collector_add() {
        let mut collector = ErrorCollector::new();
        collector.add(ValidationError::new(
            "field1",
            ValidationErrorCode::MissingRequiredField,
            "Field is required",
        ));

        assert!(!collector.is_empty());
        assert_eq!(collector.len(), 1);
    }

    #[test]
    fn test_error_collector_into_result() {
        let collector = ErrorCollector::new();
        assert!(collector.into_result().is_ok());

        let mut collector = ErrorCollector::new();
        collector.add(ValidationError::new(
            "field",
            ValidationErrorCode::InvalidType,
            "Invalid",
        ));
        assert!(collector.into_result().is_err());
    }

    #[test]
    fn test_validation_errors_to_json_pretty() {
        let error = ValidationError::new(
            "http_port",
            ValidationErrorCode::ValueOutOfRange,
            "Invalid port",
        );
        let errors = ValidationErrors::from_error(error);

        let json = errors.to_json_pretty();
        let expected = r#"{
  "errors": [
    {
      "field": "http_port",
      "code": "ValueOutOfRange",
      "message": "Invalid port"
    }
  ]
}"#;
        assert_eq!(json, expected);
    }

    #[test]
    fn test_validation_errors_default() {
        let errors = ValidationErrors::default();
        assert!(errors.is_empty());
        assert_eq!(errors.len(), 0);
    }

    #[test]
    fn test_error_collector_add_all() {
        let mut collector = ErrorCollector::new();
        let errors = vec![
            ValidationError::new(
                "field1",
                ValidationErrorCode::MissingRequiredField,
                "Missing",
            ),
            ValidationError::new("field2", ValidationErrorCode::InvalidType, "Wrong type"),
        ];

        collector.add_all(errors);
        assert_eq!(collector.len(), 2);
        assert!(!collector.is_empty());
    }

    #[test]
    fn test_error_collector_errors() {
        let mut collector = ErrorCollector::new();
        collector.add(ValidationError::new(
            "field1",
            ValidationErrorCode::MissingRequiredField,
            "Missing",
        ));

        let errors = collector.errors();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].field, "field1");
    }

    #[test]
    fn test_validation_error_from_trait() {
        let error = ValidationError::new("field", ValidationErrorCode::InvalidType, "Invalid");
        let errors: ValidationErrors = error.into();

        assert_eq!(errors.len(), 1);
        assert_eq!(errors.errors[0].field, "field");
    }
}
