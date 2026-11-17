//! `watcher.config.toml`: the reload commands a watcher may run, grouped by
//! command. The provider writes it and the watcher reads it, so both use this
//! schema and validation.

use std::collections::HashSet;
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

use super::error::{ValidationError, ValidationErrorCode};
use super::error_messages::{
    EMPTY_REFRESH_COMMAND_ERR_MSG, INVALID_RELOAD_COMMAND_ERR_MSG, MISSING_RELOAD_ENTRY_ERR_MSG,
    RELOAD_WITHOUT_CERTIFICATES_ERR_MSG, UNSUPPORTED_WATCHER_SCHEMA_VERSION_ERR_MSG,
    WATCHER_ID_MISMATCH_ERR_MSG,
};
use super::field_validators::{validate_watcher_id, ArnValidator};

/// The schema version this build writes and reads.
pub const WATCHER_CONFIG_SCHEMA_VERSION: u32 = 1;

/// File name of a watcher's config inside its config directory.
pub const WATCHER_CONFIG_FILE_NAME: &str = "watcher.config.toml";

/// Largest config a watcher reads. Validation doesn't bound command or ARN
/// length, so the provider checks each whole file against this before writing.
pub const MAX_WATCHER_CONFIG_BYTES: u64 = 256 * 1024;

/// Characters allowed in one command element: the `refresh_command` class
/// without its leading-`/` anchor, which only element 0 needs.
#[cfg(unix)]
static COMMAND_ELEMENT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9/_\-\. =+@]+$").unwrap());

#[cfg(windows)]
static COMMAND_ELEMENT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^[a-zA-Z0-9 \-_.\\/:"=+@~]+$"#).unwrap());

/// One watcher's config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatcherConfig {
    pub schema_version: u32,
    pub watcher_id: String,
    #[serde(rename = "reload", default)]
    pub reloads: Vec<ReloadEntry>,
}

/// A reload command, run as an argument list with no shell, and every
/// certificate it reloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReloadEntry {
    pub command: Vec<String>,
    pub certificate_arns: Vec<String>,
}

impl WatcherConfig {
    /// Reads the schema version first, so a config from a newer provider gets the
    /// version error rather than an unknown-field error.
    pub fn from_toml(toml_str: &str) -> Result<Self, ValidationError> {
        #[derive(Deserialize)]
        struct VersionOnly {
            schema_version: u32,
        }
        let syntax_error = |e: toml::de::Error| {
            ValidationError::new(
                "watcher.config.toml",
                ValidationErrorCode::TomlSyntaxError,
                e.to_string(),
            )
        };
        let version: VersionOnly = toml::from_str(toml_str).map_err(syntax_error)?;
        if version.schema_version != WATCHER_CONFIG_SCHEMA_VERSION {
            return Err(unsupported_version(version.schema_version));
        }
        toml::from_str(toml_str).map_err(syntax_error)
    }

    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string(self)
    }

    /// Checks the config for the watcher `expected_watcher_id`, collecting
    /// every error.
    pub fn validate(&self, expected_watcher_id: &str) -> Result<(), Vec<ValidationError>> {
        let mut errors = Vec::new();
        if self.schema_version != WATCHER_CONFIG_SCHEMA_VERSION {
            errors.push(unsupported_version(self.schema_version));
        }
        if self.watcher_id != expected_watcher_id {
            errors.push(ValidationError::with_guidance(
                "watcher_id",
                ValidationErrorCode::InvalidWatcherId,
                WATCHER_ID_MISMATCH_ERR_MSG,
                format!(
                    "Got '{}', expected '{}'",
                    self.watcher_id, expected_watcher_id
                ),
            ));
        }

        // A watcher must not start with no mappings.
        if self.reloads.is_empty() {
            errors.push(ValidationError::new(
                "reload",
                ValidationErrorCode::MissingRequiredField,
                MISSING_RELOAD_ENTRY_ERR_MSG,
            ));
        }
        let mut seen = HashSet::new();
        for (i, reload) in self.reloads.iter().enumerate() {
            validate_command(
                &format!("reload[{i}].command"),
                &reload.command,
                &mut errors,
            );
            if reload.certificate_arns.is_empty() {
                errors.push(ValidationError::new(
                    format!("reload[{i}].certificate_arns"),
                    ValidationErrorCode::MissingRequiredField,
                    RELOAD_WITHOUT_CERTIFICATES_ERR_MSG,
                ));
            }
            for (j, arn) in reload.certificate_arns.iter().enumerate() {
                let field = format!("reload[{i}].certificate_arns[{j}]");
                if let Err(e) = ArnValidator::validate_certificate_arn(&field, arn) {
                    errors.push(e);
                } else if !seen.insert(arn.as_str()) {
                    errors.push(ValidationError::new(
                        field,
                        ValidationErrorCode::DuplicateCertificateArn,
                        format!("Certificate ARN '{arn}' appears in more than one reload entry."),
                    ));
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

fn unsupported_version(version: u32) -> ValidationError {
    ValidationError::with_guidance(
        "schema_version",
        ValidationErrorCode::ValueOutOfRange,
        UNSUPPORTED_WATCHER_SCHEMA_VERSION_ERR_MSG,
        format!("Got {version}, supported: {WATCHER_CONFIG_SCHEMA_VERSION}"),
    )
}

/// Splits a `refresh_command` into the argument list a watcher runs. Splits on
/// whitespace outside double quotes and drops the quotes, so a quoted Windows
/// path with spaces becomes one unquoted element. An unclosed quote is kept, so
/// validation rejects it.
pub fn split_command(command: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_arg = false;
    let mut quoted = false;
    for c in command.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                in_arg = true;
            }
            c if c.is_whitespace() && !quoted => {
                if in_arg {
                    args.push(std::mem::take(&mut current));
                    in_arg = false;
                }
            }
            c => {
                current.push(c);
                in_arg = true;
            }
        }
    }
    if quoted {
        return command.split_whitespace().map(str::to_string).collect();
    }
    if in_arg {
        args.push(current);
    }
    args
}

/// Whether `id` is a valid `watcher_id`, and so safe to use as a directory name.
pub fn is_valid_watcher_id(id: &str) -> bool {
    validate_watcher_id("watcher_id", id).is_ok()
}

/// Checks one reload command against the watcher's rules.
pub fn validate_command(field: &str, command: &[String], errors: &mut Vec<ValidationError>) {
    if command.is_empty() {
        errors.push(ValidationError::new(
            field,
            ValidationErrorCode::EmptyCommand,
            EMPTY_REFRESH_COMMAND_ERR_MSG,
        ));
        return;
    }
    for (j, element) in command.iter().enumerate() {
        // `split_command` removes quotes, so one here came from a hand-written config.
        // Windows takes any program a Windows install accepts, absolute or not.
        let valid = COMMAND_ELEMENT_RE.is_match(element)
            && !element.contains('"')
            && (j > 0 || cfg!(windows) || Path::new(element).is_absolute());
        if !valid {
            errors.push(ValidationError::with_guidance(
                format!("{field}[{j}]"),
                ValidationErrorCode::InvalidCommand,
                INVALID_RELOAD_COMMAND_ERR_MSG,
                format!("Got: '{element}'"),
            ));
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    const ARN_A: &str =
        "arn:aws:acm:us-west-2:123456789012:certificate/abc12345-1234-1234-1234-123456789012";
    const ARN_B: &str =
        "arn:aws:acm:us-west-2:123456789012:certificate/def67890-5678-5678-5678-567890123456";

    fn reload(command: &[&str], arns: &[&str]) -> ReloadEntry {
        ReloadEntry {
            command: command.iter().map(|s| s.to_string()).collect(),
            certificate_arns: arns.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn config(reloads: Vec<ReloadEntry>) -> WatcherConfig {
        WatcherConfig {
            schema_version: WATCHER_CONFIG_SCHEMA_VERSION,
            watcher_id: "nginx".into(),
            reloads,
        }
    }

    fn codes(result: Result<(), Vec<ValidationError>>) -> Vec<ValidationErrorCode> {
        result.unwrap_err().into_iter().map(|e| e.code).collect()
    }

    #[test]
    fn task_example_parses_and_validates() {
        let toml = r#"
schema_version = 1
watcher_id = "nginx"

[[reload]]
command = ["/usr/sbin/nginx", "-s", "reload"]
certificate_arns = [
  "arn:aws:acm:us-west-2:123456789012:certificate/abc12345-1234-1234-1234-123456789012",
  "arn:aws:acm:us-west-2:123456789012:certificate/def67890-5678-5678-5678-567890123456",
]

[[reload]]
command = ["/usr/sbin/apachectl", "-k", "graceful"]
certificate_arns = [
  "arn:aws:acm:us-west-2:123456789012:certificate/0a1b2c3d-9999-9999-9999-999999999999",
]
"#;
        let parsed = WatcherConfig::from_toml(toml).unwrap();
        assert_eq!(parsed.reloads.len(), 2);
        assert_eq!(
            parsed.reloads[0].command,
            ["/usr/sbin/nginx", "-s", "reload"]
        );
        assert!(parsed.validate("nginx").is_ok());
    }

    #[test]
    fn written_toml_reads_back_the_same() {
        let written = config(vec![reload(&["/usr/sbin/nginx", "-s", "reload"], &[ARN_A])]);
        let toml = written.to_toml().unwrap();
        assert!(toml.contains("[[reload]]"), "{toml}");
        assert_eq!(WatcherConfig::from_toml(&toml).unwrap(), written);
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let toml = "schema_version = 1\nwatcher_id = \"nginx\"\nextra = 1\n";
        let err = WatcherConfig::from_toml(toml).unwrap_err();
        assert_eq!(err.code, ValidationErrorCode::TomlSyntaxError);
    }

    #[test]
    fn newer_schema_gets_the_version_error_not_an_unknown_field_error() {
        let toml = "schema_version = 2\nwatcher_id = \"nginx\"\nnew_field = true\n";
        let err = WatcherConfig::from_toml(toml).unwrap_err();
        assert_eq!(err.code, ValidationErrorCode::ValueOutOfRange);
        assert_eq!(err.message, UNSUPPORTED_WATCHER_SCHEMA_VERSION_ERR_MSG);
    }

    #[test]
    fn version_and_watcher_id_must_match() {
        let mut c = config(vec![reload(&["/usr/sbin/nginx"], &[ARN_A])]);
        c.schema_version = 2;
        assert_eq!(
            codes(c.validate("haproxy")),
            [
                ValidationErrorCode::ValueOutOfRange,
                ValidationErrorCode::InvalidWatcherId
            ]
        );
    }

    #[test]
    fn flags_pass_but_element_zero_must_be_absolute() {
        assert!(
            config(vec![reload(&["/usr/sbin/nginx", "-s", "reload"], &[ARN_A])])
                .validate("nginx")
                .is_ok()
        );
        assert_eq!(
            codes(config(vec![reload(&["nginx", "-s", "reload"], &[ARN_A])]).validate("nginx")),
            [ValidationErrorCode::InvalidCommand]
        );
    }

    #[test]
    fn quoted_or_shell_elements_are_rejected() {
        for bad in ["\"/usr/sbin/nginx\"", "/bin/sh;reboot", "$(id)"] {
            let c = config(vec![reload(&[bad], &[ARN_A])]);
            assert_eq!(
                codes(c.validate("nginx")),
                [ValidationErrorCode::InvalidCommand],
                "{bad}"
            );
        }
    }

    #[test]
    fn config_without_reload_entries_is_rejected() {
        let c = WatcherConfig::from_toml("schema_version = 1\nwatcher_id = \"nginx\"\n").unwrap();
        assert_eq!(
            codes(c.validate("nginx")),
            [ValidationErrorCode::MissingRequiredField]
        );
    }

    #[test]
    fn split_command_ignores_extra_whitespace() {
        assert_eq!(
            split_command("  /usr/sbin/nginx   -s reload "),
            ["/usr/sbin/nginx", "-s", "reload"]
        );
    }

    #[test]
    fn split_command_keeps_a_quoted_path_as_one_unquoted_element() {
        assert_eq!(
            split_command(r#""C:\Program Files\nginx\nginx.exe" -s reload"#),
            [r"C:\Program Files\nginx\nginx.exe", "-s", "reload"]
        );
    }

    #[test]
    fn split_command_leaves_an_unclosed_quote_for_validation_to_reject() {
        let args = split_command(r#""/usr/sbin/nginx -s reload"#);
        assert_eq!(args[0], "\"/usr/sbin/nginx");
        let mut errors = Vec::new();
        validate_command("command", &args, &mut errors);
        assert!(!errors.is_empty());
    }

    #[test]
    fn empty_command_and_empty_arn_list_are_rejected() {
        assert_eq!(
            codes(config(vec![reload(&[], &[])]).validate("nginx")),
            [
                ValidationErrorCode::EmptyCommand,
                ValidationErrorCode::MissingRequiredField
            ]
        );
    }

    #[test]
    fn arns_must_be_valid_and_appear_once() {
        let c = config(vec![
            reload(&["/usr/sbin/nginx"], &[ARN_A, "not-an-arn"]),
            reload(&["/usr/sbin/apachectl"], &[ARN_B, ARN_A]),
        ]);
        assert_eq!(
            codes(c.validate("nginx")),
            [
                ValidationErrorCode::InvalidCertificateArn,
                ValidationErrorCode::DuplicateCertificateArn
            ]
        );
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    fn errors(command: &[&str]) -> usize {
        let command: Vec<String> = command.iter().map(|s| s.to_string()).collect();
        let mut errors = Vec::new();
        validate_command("command", &command, &mut errors);
        errors.len()
    }

    #[test]
    fn a_program_is_accepted_as_a_windows_install_accepts_it() {
        for program in [
            r"C:\nginx\nginx.exe",
            "C:/nginx/nginx.exe",
            r"\nginx\nginx.exe",
            "C:nginx.exe",
            "nginx",
        ] {
            assert_eq!(errors(&[program, "-s", "reload"]), 0, "{program}");
        }
    }

    #[test]
    fn a_quoted_path_with_spaces_validates_once_split() {
        let args = split_command(r#""C:\Program Files\nginx\nginx.exe" -s reload"#);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        assert_eq!(errors(&args), 0);
    }

    #[test]
    fn shell_characters_and_quotes_are_rejected() {
        for bad in [
            r"C:\nginx\nginx.exe&calc",
            r"C:\nginx\nginx.exe|calc",
            r"C:\%WINDIR%\x.exe",
            r#""C:\nginx\nginx.exe""#,
        ] {
            assert_eq!(errors(&[bad]), 1, "{bad}");
        }
    }
}
