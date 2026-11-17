//! Startup, run and per-request failures.
//!
//! Every variant that has a path prints the path, following
//! `config::watcher_config::WatcherConfigError`: the likely cause of any of
//! these is a deployment problem — an unmounted volume, a mis-mounted
//! configuration file, a uid mismatch — and the path is what the operator needs
//! in order to find it.

use std::fmt;
use std::io;
use std::path::PathBuf;

use aws_workload_credentials_provider_common::config::{ValidationError, ValidationErrors};

/// A failure that prevents the watcher from starting.
///
/// Every one of these is fatal: the process logs it and exits non-zero so that
/// a container liveness check restarts it rather than leaving a watcher running
/// that silently never reloads anything.
#[derive(Debug)]
pub enum StartupError {
    /// The watcher's identity was not supplied.
    MissingWatcherId { var: &'static str },

    /// An environment variable held a value the ACM provider's own validators
    /// reject.
    InvalidEnvValue {
        var: &'static str,
        source: ValidationError,
    },

    /// The configuration file could not be read.
    ConfigRead { path: PathBuf, source: io::Error },

    /// The configuration file is larger than [`crate::plan::MAX_CONFIG_BYTES`].
    ConfigTooLarge {
        path: PathBuf,
        size: u64,
        limit: u64,
    },

    /// The configuration file is not valid TOML or doesn't match the schema
    /// shape: `WatcherConfig::from_toml`'s `TomlSyntaxError`
    ConfigParse {
        path: PathBuf,
        source: ValidationError,
    },

    /// The configuration file has an unsupported `schema_version`, or parsed
    /// but failed `WatcherConfig::validate`. Holds every error found.
    ConfigInvalid {
        path: PathBuf,
        source: ValidationErrors,
    },

    /// Watcher config and/or requests directories are invalid.
    DirectoriesInvalid { source: ValidationErrors },

    /// `<watcher_id>/`, the inbox or the pending directory failed its leaf
    /// check.
    RequestDirInvalid { source: InboxCheckError },

    /// `<watcher_id>/` or the inbox directory could not be created.
    RequestDirUncreatable { path: PathBuf, source: io::Error },

    /// The pending directory could not be created or listed.
    PendingDirUnusable { path: PathBuf, source: io::Error },

    /// A filesystem watch could not be established on the inbox directory.
    Watch {
        path: PathBuf,
        source: notify::Error,
    },
}

impl fmt::Display for StartupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingWatcherId { var } => write!(
                f,
                "The watcher's identity isn't set. Set {} to the watcher ID this container \
                 handles; it selects both the configuration file and the request directory, \
                 so it can't be guessed.",
                var
            ),
            Self::InvalidEnvValue { var, source } => {
                write!(f, "The value of {} isn't valid: {}", var, source)
            }
            Self::ConfigRead { path, source } => write!(
                f,
                "Failed to read the watcher configuration file '{}': {}. Check that the \
                 configuration volume is mounted and readable by this container.",
                path.display(),
                source
            ),
            Self::ConfigTooLarge { path, size, limit } => write!(
                f,
                "The watcher configuration file '{}' is {} bytes, over the {} byte limit.",
                path.display(),
                size,
                limit
            ),
            Self::ConfigParse { path, source } => write!(
                f,
                "The watcher configuration file '{}' isn't valid TOML: {}",
                path.display(),
                source
            ),
            Self::ConfigInvalid { path, source } => write!(
                f,
                "The watcher configuration file '{}' isn't valid: {}",
                path.display(),
                source
            ),
            Self::RequestDirInvalid { source } => write!(f, "{}", source),
            Self::RequestDirUncreatable { path, source } => write!(
                f,
                "Failed to create the request directory '{}': {}. Check that the \
                 request volume is mounted and writable by this container.",
                path.display(),
                source
            ),
            Self::PendingDirUnusable { path, source } => write!(
                f,
                "Failed to create or list the pending request directory '{}': {}. Check that \
                 the request volume is mounted and writable by this container.",
                path.display(),
                source
            ),
            Self::Watch { path, source } => write!(
                f,
                "Failed to watch the inbox request directory '{}': {}",
                path.display(),
                source
            ),
            Self::DirectoriesInvalid { source } => write!(
                f,
                "The watcher config and/or request directories are invalid: {}",
                source
            ),
        }
    }
}

impl std::error::Error for StartupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MissingWatcherId { .. } => None,
            Self::InvalidEnvValue { source, .. } => Some(source),
            Self::ConfigRead { source, .. } => Some(source),
            Self::ConfigTooLarge { .. } => None,
            Self::ConfigParse { source, .. } => Some(source),
            Self::ConfigInvalid { source, .. } => Some(source),
            Self::RequestDirInvalid { source } => Some(source),
            Self::RequestDirUncreatable { source, .. } => Some(source),
            Self::PendingDirUnusable { source, .. } => Some(source),
            Self::Watch { source, .. } => Some(source),
            Self::DirectoriesInvalid { source } => Some(source),
        }
    }
}

/// Why the inbox or pending directory failed the check that runs before
/// every scan, and at startup.
///
/// Never fatal during the run: the scan is skipped and retried. Only a run of
/// these lasting [`crate::run::SCAN_FAILURE_EXIT_WINDOW`] stops the loop, as
/// [`RunError::InboxUnavailable`]. At startup it is
/// [`StartupError::RequestDirInvalid`].
#[derive(Debug)]
pub enum InboxCheckError {
    /// The config and/or requests roots failed the shared directory check,
    /// the same one startup runs.
    Roots { source: ValidationErrors },

    /// The directory could not be resolved, usually because it is missing.
    Unresolvable { path: PathBuf, source: io::Error },

    /// The directory resolves somewhere else: a component of
    /// `<watcher_id>/<subdir>` is a symlink.
    NotCanonical { path: PathBuf, resolved: PathBuf },

    /// The path exists but is not a directory.
    NotADirectory { path: PathBuf },
}

impl fmt::Display for InboxCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Roots { source } => write!(
                f,
                "The watcher config and/or request directories are invalid: {}",
                source
            ),
            Self::Unresolvable { path, source } => write!(
                f,
                "The request directory '{}' can't be resolved: {}",
                path.display(),
                source
            ),
            Self::NotCanonical { path, resolved } => write!(
                f,
                "The request directory '{}' resolves to '{}'. It must not be or contain \
                 a symlink.",
                path.display(),
                resolved.display()
            ),
            Self::NotADirectory { path } => write!(
                f,
                "The request directory '{}' isn't a directory.",
                path.display()
            ),
        }
    }
}

impl std::error::Error for InboxCheckError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Roots { source } => Some(source),
            Self::Unresolvable { source, .. } => Some(source),
            Self::NotCanonical { .. } => None,
            Self::NotADirectory { .. } => None,
        }
    }
}

/// A failure that stops the event loop.
#[derive(Debug)]
pub enum RunError {
    /// The channel fed by the `notify` callback closed, which can only mean
    /// the backend's own thread is gone.
    ///
    /// Unrecoverable on purpose, and never answered with a rebind: a watcher
    /// that is not watching would keep running and reload nothing, so it exits
    /// non-zero instead and lets the container be restarted.
    WatchChannelClosed { path: PathBuf },

    /// No scan of the inbox directory has succeeded for
    /// [`crate::run::SCAN_FAILURE_EXIT_WINDOW`]: every one in that time either
    /// failed validation or could not list the directory.
    ///
    /// A failed rebind does not count here. While scans succeed, the periodic
    /// scan still finds every request, so a watcher whose watch cannot be
    /// re-established keeps running.
    InboxUnavailable {
        path: PathBuf,
        since: std::time::Duration,
        last_error: String,
    },
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WatchChannelClosed { path } => write!(
                f,
                "The filesystem watch on '{}' stopped delivering events. Exiting so the \
                 container is restarted rather than running without a watch.",
                path.display()
            ),
            Self::InboxUnavailable {
                path,
                since,
                last_error,
            } => write!(
                f,
                "The inbox request directory '{}' hasn't been scanned successfully for {:?} \
                 (last error: {}). Exiting so the watcher is restarted.",
                path.display(),
                since,
                last_error
            ),
        }
    }
}

impl std::error::Error for RunError {}

/// A failure reading one request file.
///
/// Separate from [`StartupError`] because it is per-file and never fatal: a
/// malformed request is logged and deleted from the pending directory, and
/// the watcher keeps serving every other certificate.
#[derive(Debug)]
pub enum RequestError {
    /// The file is larger than [`crate::inbox::MAX_REQUEST_BYTES`].
    TooLarge {
        path: PathBuf,
        size: u64,
        limit: u64,
    },

    /// The name is a symlink, FIFO, device or other non-regular file. Never
    /// read.
    NotAFile { path: PathBuf, kind: &'static str },

    /// The file could not be read.
    Read { path: PathBuf, source: io::Error },

    /// The file is not a valid refresh request.
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },

    /// The file parses, but a field the watcher logs is malformed
    /// (`RefreshRequest::invalid_field`). Only the field's name is kept: its
    /// value came from an untrusted file and is never logged.
    Invalid { path: PathBuf, field: &'static str },
}

impl RequestError {
    /// True when the file was not there.
    ///
    /// Not an error to report: a claimed request that is gone from the
    /// pending directory was removed by something else, and there is nothing
    /// left to read.
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::Read { source, .. } if source.kind() == io::ErrorKind::NotFound)
    }

    /// True when the file is not a request: not a regular file, too large,
    /// it does not parse, or a field is malformed. Reading it again cannot
    /// change that.
    pub fn is_unusable(&self) -> bool {
        matches!(
            self,
            Self::NotAFile { .. }
                | Self::TooLarge { .. }
                | Self::Parse { .. }
                | Self::Invalid { .. }
        )
    }
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { path, size, limit } => write!(
                f,
                "The request file {:?} is at least {} bytes, over the {} byte limit.",
                path, size, limit
            ),
            Self::NotAFile { path, kind } => write!(
                f,
                "The request file {:?} is a {}, not a regular file.",
                path, kind
            ),
            Self::Read { path, source } => {
                write!(f, "Failed to read the request file {:?}: {}", path, source)
            }
            Self::Parse { path, source } => write!(
                f,
                "The request file {:?} isn't a valid refresh request: {}",
                path, source
            ),
            Self::Invalid { path, field } => write!(
                f,
                "The request file {:?} isn't a valid refresh request: its '{}' is malformed.",
                path, field
            ),
        }
    }
}

impl std::error::Error for RequestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::TooLarge { .. } => None,
            Self::NotAFile { .. } => None,
            Self::Read { source, .. } => Some(source),
            Self::Parse { source, .. } => Some(source),
            Self::Invalid { .. } => None,
        }
    }
}
