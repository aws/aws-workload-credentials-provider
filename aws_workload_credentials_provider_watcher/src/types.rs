//! The argv executor `aws_workload_credentials_provider_common` doesn't
//! provide yet, and test fixtures for the request protocol.
//!
//! The request type, the inbox layout and the ACM provider's writer are
//! `common::watcher_request`; the watcher configuration file is
//! `common::config::watcher_config`.
//!
//! TODO: delete this module once `common` has `execute_argv`.

use std::future::Future;
use std::io;

use tokio::process::Command;

use aws_workload_credentials_provider_common::refresh_executor::{
    execute_child_cmd, DirectRefreshExecutor,
};

/// Suffix of the ACM provider's mid-write request files in `inbox/`.
///
/// `common::watcher_request::enqueue` names its temp files `.{32 hex}.tmp`,
/// which ends in this suffix; `common` has no constant for it.
///
/// Test-only: the watcher no longer looks for this suffix, because only
/// `.cmd` files are accepted. It is kept so the tests can prove such files
/// are ignored.
#[cfg(test)]
pub const REQUEST_TEMP_SUFFIX: &str = ".tmp";

/// Runs an already-split argv array in this container.
///
/// Used on non-Windows targets only; the Windows path is in
/// `reload::DirectReloadSink`.
///
/// TODO: delete once `common`'s `DirectRefreshExecutor::execute_argv` lands;
/// the inherent method then takes precedence over this trait at every call
/// site.
#[cfg_attr(windows, allow(dead_code))]
pub trait DirectRefreshExecutorArgv {
    fn execute_argv(
        &self,
        command: &[String],
        certificate_arn: &str,
    ) -> impl Future<Output = Result<(), io::Error>> + Send;
}

impl DirectRefreshExecutorArgv for DirectRefreshExecutor {
    async fn execute_argv(&self, command: &[String], _certificate_arn: &str) -> io::Result<()> {
        let (program, args) = command.split_first().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "refresh command is empty")
        })?;
        let mut cmd = Command::new(program);
        cmd.args(args);
        // Bounded by `REFRESH_COMMAND_TIMEOUT` inside `execute_child_cmd`.
        execute_child_cmd(cmd).await
    }
}

/// Fixed examples of what the ACM provider writes, for tests. Tests that need
/// a real write call `common::watcher_request::enqueue` itself.
///
/// The names and the request constructor are here because `common` keeps its
/// own (`request_name`, `uuid_v4`) private.
#[cfg(test)]
pub mod acm_provider_writer {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use aws_workload_credentials_provider_common::watcher_request::{
        RefreshRequest, REQUEST_EXTENSION,
    };

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    /// A `command_id` as the WCP writer makes one: a lowercase UUIDv4
    /// (`watcher_request.rs`'s `uuid_v4`).
    pub const WCP_COMMAND_ID: &str = "3f2b8c1e-7a4d-4e9b-8c2f-1d6e5a9b0c7d";

    /// A `created_at` as the WCP writer makes one: RFC 3339, UTC, seconds,
    /// `Z` (`to_rfc3339_opts(SecondsFormat::Secs, true)`).
    pub const WCP_CREATED_AT: &str = "2025-10-20T17:06:40Z";

    /// The WCP writer's final name for [`WCP_COMMAND_ID`]:
    /// `{epoch_millis}-{sequence:03}-{command_id}.cmd` (`request_name`).
    pub const WCP_REQUEST_NAME: &str = "1760980000123-000-3f2b8c1e-7a4d-4e9b-8c2f-1d6e5a9b0c7d.cmd";

    /// The WCP writer's temp name: `.{32 hex}.tmp`, in `inbox/`.
    pub const WCP_TEMP_NAME: &str = ".0123456789abcdef0123456789abcdef.tmp";

    /// The body the WCP writer produces for `certificate_arn`, byte for byte:
    /// `serde_json::to_vec` of `common::watcher_request::RefreshRequest`,
    /// fields in declaration order and no whitespace.
    pub fn wcp_request_body(certificate_arn: &str) -> String {
        format!(
            r#"{{"command_id":"{WCP_COMMAND_ID}","certificate_arn":"{certificate_arn}","created_at":"{WCP_CREATED_AT}"}}"#
        )
    }

    /// A request for `certificate_arn` with a fresh `command_id`, created
    /// now. The `command_id` is a version 4 UUID with a counter in its last
    /// group, so it passes the watcher's check and stays distinct.
    pub fn new_request(certificate_arn: &str) -> RefreshRequest {
        RefreshRequest {
            command_id: format!(
                "00000000-0000-4000-8000-{:012x}",
                NEXT_ID.fetch_add(1, Ordering::Relaxed)
            ),
            certificate_arn: certificate_arn.to_string(),
            created_at: rfc3339_utc(SystemTime::now()),
        }
    }

    /// `{epoch_millis}-{sequence:03}-{command_id}.cmd`, the WCP writer's
    /// `request_name` format.
    pub fn request_file_name(epoch_millis: u64, sequence: u64, command_id: &str) -> String {
        format!("{epoch_millis}-{sequence:03}-{command_id}.{REQUEST_EXTENSION}")
    }

    /// True when `name` has the shape [`request_file_name`] produces.
    pub fn is_request_file_name(name: &str) -> bool {
        let Some(stem) = name
            .strip_suffix(REQUEST_EXTENSION)
            .and_then(|name| name.strip_suffix('.'))
        else {
            return false;
        };
        let mut parts = stem.splitn(3, '-');
        let is_number = |s: Option<&str>| {
            s.is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        };
        is_number(parts.next())
            && is_number(parts.next())
            && parts.next().is_some_and(|id| !id.is_empty())
    }

    /// `YYYY-MM-DDTHH:MM:SSZ` for `time`, which must not precede the epoch.
    fn rfc3339_utc(time: SystemTime) -> String {
        let secs = time.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));

        // Days since the epoch to a civil date (Howard Hinnant's algorithm).
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = yoe + era * 400 + i64::from(month <= 2);

        format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
            rem / 3_600,
            rem % 3_600 / 60,
            rem % 60
        )
    }
}
