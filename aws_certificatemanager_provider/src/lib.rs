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

#[cfg(windows)]
pub use refresh_executor::scheduled_task_name;
pub use run::acm_workload;
#[cfg(unix)]
pub use run::run_acm;
