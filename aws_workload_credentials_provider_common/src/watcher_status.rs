//! Shared protocol types for statuses published by the WCP watcher.
//!
//! The watcher writes these records and the ACM provider reads them. Keeping
//! the protocol here avoids making either side depend on the other's crate.

use std::ffi::OsStr;

use chrono::DateTime;
use serde::{Deserialize, Serialize};

use crate::config::field_validators::ArnValidator;
use crate::watcher_request::is_valid_command_id;

/// Maximum number of bytes retained from a command's stderr, measured as
/// JSON-escaped text so a capped record always fits [`MAX_STATUS_BYTES`].
pub const MAX_ERROR_DETAIL_BYTES: usize = 4096;

/// Maximum serialized size of one status record, as the protocol sets it.
pub const MAX_STATUS_BYTES: usize = 8 * 1024;

/// File extension used for published status records.
pub const STATUS_EXTENSION: &str = "status";

/// The result that the watcher reports for one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusOutcome {
    Success,
    Failure,
    Timeout,
    NotFound,
    /// Reserved for protocol compatibility. The current watcher does not emit it.
    Superseded,
}

/// The WCP watcher status-file protocol record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusRecord {
    pub command_id: String,
    pub cert_arn: String,
    pub request_created_at: String,
    pub outcome: StatusOutcome,
    pub exit_code: Option<i32>,
    /// `None` when no command ran (`not_found`, `superseded`).
    pub started_at: Option<String>,
    /// `None` when no command ran (`not_found`, `superseded`).
    pub completed_at: Option<String>,
    pub error_detail: Option<String>,
}

/// A field-level validation failure for an untrusted status record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusValidationError {
    InvalidField(&'static str),
    /// The fields contradict the outcome, such as `success` with a nonzero
    /// exit code or a completion before the start.
    Inconsistent(&'static str),
    ErrorDetailTooLong,
    RecordTooLarge,
}

impl StatusRecord {
    /// Validates fields that are used as identifiers, log values, or times.
    ///
    /// This is deliberately separate from deserialization. A JSON record can
    /// have the right shape while still containing an unsafe identifier or an
    /// unparseable timestamp.
    pub fn validate(&self) -> Result<(), StatusValidationError> {
        if !is_valid_command_id(&self.command_id) {
            return Err(StatusValidationError::InvalidField("command_id"));
        }
        if ArnValidator::validate_certificate_arn("cert_arn", &self.cert_arn).is_err() {
            return Err(StatusValidationError::InvalidField("cert_arn"));
        }
        if !is_valid_timestamp(&self.request_created_at) {
            return Err(StatusValidationError::InvalidField("request_created_at"));
        }
        for (name, value) in [
            ("started_at", &self.started_at),
            ("completed_at", &self.completed_at),
        ] {
            if value
                .as_deref()
                .is_some_and(|value| !is_valid_timestamp(value))
            {
                return Err(StatusValidationError::InvalidField(name));
            }
        }
        self.check_consistency()?;
        if self
            .error_detail
            .as_ref()
            .is_some_and(|detail| detail.len() > MAX_ERROR_DETAIL_BYTES)
        {
            return Err(StatusValidationError::ErrorDetailTooLong);
        }
        let encoded =
            serde_json::to_vec(self).map_err(|_| StatusValidationError::RecordTooLarge)?;
        if encoded.len() > MAX_STATUS_BYTES {
            return Err(StatusValidationError::RecordTooLarge);
        }
        Ok(())
    }

    fn check_consistency(&self) -> Result<(), StatusValidationError> {
        use StatusValidationError::Inconsistent;
        let ran = !matches!(
            self.outcome,
            StatusOutcome::NotFound | StatusOutcome::Superseded
        );
        // The two times aren't compared: both come from the wall clock, which
        // can step back during a reload, and they are only logged.
        match (ran, &self.started_at, &self.completed_at) {
            (true, Some(_), Some(_)) => {}
            (true, _, _) => return Err(Inconsistent("a command ran but has no times")),
            (false, None, None) => {}
            (false, _, _) => return Err(Inconsistent("no command ran but times are set")),
        }
        match (self.outcome, self.exit_code) {
            (StatusOutcome::Success, Some(0)) => {}
            (StatusOutcome::Success, _) => return Err(Inconsistent("success needs exit code 0")),
            (StatusOutcome::Failure, Some(0)) => {
                return Err(Inconsistent("failure has exit code 0"))
            }
            (StatusOutcome::Failure, _) => {}
            (_, Some(_)) => return Err(Inconsistent("exit code without a finished command")),
            (_, None) => {}
        }
        if !ran && self.error_detail.is_some() {
            return Err(Inconsistent("error detail without a command"));
        }
        Ok(())
    }
}

/// An RFC 3339 timestamp of bounded length.
pub fn is_valid_timestamp(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && DateTime::parse_from_rfc3339(value).is_ok()
}

/// Bytes `character` takes once JSON-escaped, as `serde_json` writes it.
fn escaped_len(character: char) -> usize {
    match character {
        '"' | '\\' | '\u{08}' | '\u{0c}' | '\n' | '\r' | '\t' => 2,
        c if (c as u32) < 0x20 => 6,
        c => c.len_utf8(),
    }
}

/// Keeps stderr-only detail within [`MAX_ERROR_DETAIL_BYTES`] once JSON-escaped.
pub fn cap_error_detail(stderr: &[u8]) -> Option<String> {
    if stderr.is_empty() {
        return None;
    }
    let mut detail = String::from_utf8_lossy(stderr).into_owned();
    let mut escaped = 0;
    let end = detail
        .char_indices()
        .find_map(|(index, character)| {
            escaped += escaped_len(character);
            (escaped > MAX_ERROR_DETAIL_BYTES).then_some(index)
        })
        .unwrap_or(detail.len());
    detail.truncate(end);
    Some(detail)
}

/// Returns the exact publication name for a command ID.
pub fn status_filename(command_id: &str) -> String {
    format!("{command_id}.{STATUS_EXTENSION}")
}

/// Returns whether a UTF-8 filename is an accepted status candidate.
pub fn is_status_filename(name: &str) -> bool {
    let Some(command_id) = name.strip_suffix(".status") else {
        return false;
    };
    is_valid_command_id(command_id) && status_filename(command_id) == name
}

/// Returns whether an OS filename is an accepted status candidate.
pub fn is_status_candidate(name: &OsStr) -> bool {
    name.to_str().is_some_and(is_status_filename)
}

/// Extracts the command ID from an accepted status filename.
pub fn command_id_from_status_filename(name: &OsStr) -> Option<&str> {
    let name = name.to_str()?;
    if !is_status_filename(name) {
        return None;
    }
    name.strip_suffix(".status")
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMAND_ID: &str = "3f2b8c1e-7a4d-4e9b-8c2f-1d6e5a9b0c7d";
    const CERT_ARN: &str = "arn:aws:acm:us-west-2:123456789012:certificate/test";

    fn record(outcome: StatusOutcome) -> StatusRecord {
        StatusRecord {
            command_id: COMMAND_ID.to_string(),
            cert_arn: CERT_ARN.to_string(),
            request_created_at: "2025-10-20T17:06:40Z".to_string(),
            outcome,
            exit_code: Some(0),
            started_at: Some("2025-10-20T17:06:41.123Z".to_string()),
            completed_at: Some("2025-10-20T17:06:41.456Z".to_string()),
            error_detail: None,
        }
    }

    fn not_run(outcome: StatusOutcome) -> StatusRecord {
        StatusRecord {
            exit_code: None,
            started_at: None,
            completed_at: None,
            ..record(outcome)
        }
    }

    #[test]
    fn serializes_every_outcome_using_protocol_names() {
        let outcomes = [
            (StatusOutcome::Success, "success"),
            (StatusOutcome::Failure, "failure"),
            (StatusOutcome::Timeout, "timeout"),
            (StatusOutcome::NotFound, "not_found"),
            (StatusOutcome::Superseded, "superseded"),
        ];
        for (outcome, expected) in outcomes {
            assert_eq!(
                serde_json::to_value(record(outcome)).unwrap()["outcome"],
                expected
            );
        }
    }

    #[test]
    fn accepts_valid_record_and_rejects_invalid_fields() {
        assert!(record(StatusOutcome::Success).validate().is_ok());

        let mut invalid = record(StatusOutcome::Success);
        invalid.command_id = "not-a-command".to_string();
        assert_eq!(
            invalid.validate(),
            Err(StatusValidationError::InvalidField("command_id"))
        );

        let mut invalid = record(StatusOutcome::Success);
        invalid.started_at = Some("not-a-time".to_string());
        assert_eq!(
            invalid.validate(),
            Err(StatusValidationError::InvalidField("started_at"))
        );
    }

    #[test]
    fn rejects_fields_that_contradict_the_outcome() {
        let mut failure = record(StatusOutcome::Failure);
        failure.exit_code = Some(1);
        let mut timeout = record(StatusOutcome::Timeout);
        timeout.exit_code = None;
        for valid in [
            record(StatusOutcome::Success),
            failure.clone(),
            StatusRecord {
                exit_code: None,
                ..failure.clone()
            },
            timeout.clone(),
            not_run(StatusOutcome::NotFound),
            not_run(StatusOutcome::Superseded),
        ] {
            assert_eq!(valid.validate(), Ok(()), "{valid:?}");
        }

        let mut success_nonzero = record(StatusOutcome::Success);
        success_nonzero.exit_code = Some(1);
        let mut success_no_code = record(StatusOutcome::Success);
        success_no_code.exit_code = None;
        let mut failure_zero = record(StatusOutcome::Failure);
        failure_zero.exit_code = Some(0);
        let mut timeout_zero = timeout.clone();
        timeout_zero.exit_code = Some(0);
        // The wall clock can step back during a reload, so this stays valid.
        let mut backwards = record(StatusOutcome::Success);
        backwards.completed_at = Some("2025-10-20T17:06:40Z".to_string());
        assert_eq!(backwards.validate(), Ok(()));
        let mut ran_without_times = record(StatusOutcome::Success);
        ran_without_times.completed_at = None;
        let mut not_found_with_times = not_run(StatusOutcome::NotFound);
        not_found_with_times.started_at = record(StatusOutcome::Success).started_at;
        let mut not_found_with_code = not_run(StatusOutcome::NotFound);
        not_found_with_code.exit_code = Some(0);
        let mut not_found_with_detail = not_run(StatusOutcome::NotFound);
        not_found_with_detail.error_detail = Some("stderr".to_string());
        for invalid in [
            success_nonzero,
            success_no_code,
            failure_zero,
            timeout_zero,
            ran_without_times,
            not_found_with_times,
            not_found_with_code,
            not_found_with_detail,
        ] {
            assert!(
                matches!(
                    invalid.validate(),
                    Err(StatusValidationError::Inconsistent(_))
                ),
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn capped_control_character_stderr_still_fits_the_record_limit() {
        let stderr = vec![0x01u8; MAX_ERROR_DETAIL_BYTES];
        let mut status = record(StatusOutcome::Failure);
        status.exit_code = Some(1);
        status.error_detail = cap_error_detail(&stderr);
        assert_eq!(status.validate(), Ok(()));
        assert!(serde_json::to_vec(&status).unwrap().len() <= MAX_STATUS_BYTES);
    }

    #[test]
    fn caps_error_detail_by_utf8_bytes() {
        let stderr = format!("{}é", "x".repeat(MAX_ERROR_DETAIL_BYTES));
        let detail = cap_error_detail(stderr.as_bytes()).unwrap();
        assert!(detail.len() <= MAX_ERROR_DETAIL_BYTES);
        assert!(detail.is_char_boundary(detail.len()));

        let mut status = record(StatusOutcome::Failure);
        status.exit_code = Some(1);
        status.error_detail = Some("x".repeat(MAX_ERROR_DETAIL_BYTES + 1));
        assert_eq!(
            status.validate(),
            Err(StatusValidationError::ErrorDetailTooLong)
        );
    }

    #[test]
    fn filters_status_filenames_and_extracts_command_id() {
        let name = status_filename(COMMAND_ID);
        assert!(is_status_filename(&name));
        assert!(is_status_candidate(OsStr::new(&name)));
        assert_eq!(
            command_id_from_status_filename(OsStr::new(&name)),
            Some(COMMAND_ID)
        );
        assert!(!is_status_filename(".status"));
        assert!(!is_status_filename("other.status.tmp"));
        assert!(!is_status_filename("not-a-command.status"));
        assert!(!is_status_filename("inbox/file.status"));
    }
}
