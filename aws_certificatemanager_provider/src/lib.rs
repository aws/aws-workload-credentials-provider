//! AWS ACM certificate management for the AWS Workload Credentials Provider.

mod acm_manager;
mod certificate_file_store;
mod certificate_task;
pub mod discovery;
pub mod error;
mod refresh_executor;
mod run;
mod scheduler;
pub mod telemetry;
mod traits;
mod utils;
mod watcher_configs;
mod watcher_status;

#[cfg(test)]
pub(crate) mod test_dirs {
    /// A temp directory whose path has no symlinks in it.
    ///
    /// The requests directory must be canonical: the status scanner opens it
    /// one component at a time without following symlinks. macOS's temp
    /// directory is under `/var`, a symlink to `/private/var`, so a plain
    /// `tempfile::tempdir()` there can't be opened. On Windows the plain temp
    /// directory is used, since `canonicalize` would add a `\\?\` prefix.
    pub(crate) fn tempdir() -> tempfile::TempDir {
        #[cfg(unix)]
        {
            let base = std::fs::canonicalize(std::env::temp_dir()).unwrap();
            tempfile::tempdir_in(base).unwrap()
        }
        #[cfg(not(unix))]
        {
            tempfile::tempdir().unwrap()
        }
    }
}

#[cfg(windows)]
pub use refresh_executor::scheduled_task_name;
pub use run::acm_workload;
#[cfg(unix)]
pub use run::run_acm;
