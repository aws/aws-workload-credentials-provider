use crate::config::types::LogLevel;
use log::{info, LevelFilter, SetLoggerError};
use log4rs::append::console::ConsoleAppender;
use log4rs::append::rolling_file::policy::compound::roll::fixed_window::FixedWindowRoller;
use log4rs::append::rolling_file::policy::compound::trigger::size::SizeTrigger;
use log4rs::append::rolling_file::policy::compound::CompoundPolicy;
use log4rs::append::rolling_file::RollingFileAppender;
use log4rs::config::{Appender, Root};
use log4rs::Config;
use std::path::{Path, PathBuf};
use std::sync::Once;

impl From<LogLevel> for LevelFilter {
    fn from(log_level: LogLevel) -> LevelFilter {
        match log_level {
            LogLevel::Debug => LevelFilter::Debug,
            LogLevel::Info => LevelFilter::Info,
            LogLevel::Warn => LevelFilter::Warn,
            LogLevel::Error => LevelFilter::Error,
            LogLevel::None => LevelFilter::Off,
        }
    }
}

/// Resolves the base provider directory on Windows: `%PROGRAMDATA%\AWS\WorkloadCredentialsProvider\`.
#[cfg(windows)]
pub fn provider_base_dir() -> Result<PathBuf, std::env::VarError> {
    let program_data = std::env::var("PROGRAMDATA")?;
    Ok(PathBuf::from(program_data)
        .join("AWS")
        .join("WorkloadCredentialsProvider"))
}

/// Default configuration file path (Windows).
#[cfg(windows)]
pub fn default_config_path() -> Result<PathBuf, std::env::VarError> {
    Ok(provider_base_dir()?.join("config.toml"))
}

pub fn log_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(std::env::current_dir()?.join("logs"))
}

const MAX_LOG_ARCHIVE_FILES: u32 = 5;
const BYTES_PER_MB: u64 = 1024 * 1024;
const MAX_ALLOWED_LOG_SIZE_IN_MB: u64 = 10;

#[doc(hidden)]
static STARTUP: Once = Once::new();

/// Initializes file based logging for the daemon.
///
/// # Arguments
///
/// * `log_level` - The log level to report.
/// * `log_to_file` - Whether to log to a file or stdout/stderr.
/// * `log_file_name` - The base name for log files (e.g. "secrets_manager_provider").
///
/// # Returns
///
/// * `Ok(())` - If no errors are encountered.
/// * `Err(Error)` - For errors initializing the log.
pub fn init_logger(
    log_level: LogLevel,
    log_to_file: bool,
    log_file_name: &str,
    log_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let log_file_path = log_dir.join(format!("{}.log", log_file_name));
    let log_archive_pattern = log_dir
        .join("archive")
        .join(format!("{}_{{}}.gz", log_file_name));

    let (log_config, logger_type) = match log_to_file {
        true => {
            let file_appender = "FILE_APPENDER";

            let fixed_window_roller = FixedWindowRoller::builder()
                .build(log_archive_pattern.to_str().unwrap(), MAX_LOG_ARCHIVE_FILES)?;
            let fixed_window_roller = Box::new(fixed_window_roller);

            let file_size_trigger =
                Box::new(SizeTrigger::new(MAX_ALLOWED_LOG_SIZE_IN_MB * BYTES_PER_MB));
            let compound_policy =
                Box::new(CompoundPolicy::new(file_size_trigger, fixed_window_roller));

            let rolling_file_appender =
                RollingFileAppender::builder().build(log_file_path, compound_policy)?;

            (
                Config::builder()
                    .appender(
                        Appender::builder().build(file_appender, Box::new(rolling_file_appender)),
                    )
                    .build(
                        Root::builder()
                            .appender(file_appender)
                            .build(LevelFilter::from(log_level)),
                    )?,
                "File",
            )
        }
        false => {
            let console_appender = "CONSOLE_APPENDER";

            (
                Config::builder()
                    .appender(Appender::builder().build(
                        console_appender,
                        Box::new(ConsoleAppender::builder().build()),
                    ))
                    .build(
                        Root::builder()
                            .appender(console_appender)
                            .build(LevelFilter::from(log_level)),
                    )?,
                "Console",
            )
        }
    };

    // Don't initialize logging more than once in unit tests.
    let mut res: Option<SetLoggerError> = None;
    STARTUP.call_once(|| {
        if let Err(err) = log4rs::init_config(log_config) {
            res = Some(err);
        }
    });
    if let Some(err) = res {
        return Err(Box::new(err));
    }

    info!(
        "{} logger initialized with `{:?}` log level.",
        logger_type, log_level
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::config::types::LogLevel;
    use crate::logging::init_logger;
    use log::{debug, error, info, warn, LevelFilter};

    #[test]
    fn test_init_file_logger() {
        let tmp = std::env::temp_dir().join("workload_credentials_provider_test_logs");
        init_logger(LogLevel::Info, true, "test_provider", &tmp).unwrap();
        debug!("{:?}", "Debug log");
        error!("{:?}", "Error log");
        info!("{:?}", "Info log");
        warn!("{:?}", "Warn log");
    }

    #[test]
    fn test_init_console_logger() {
        let tmp = std::env::temp_dir().join("workload_credentials_provider_test_logs");
        init_logger(LogLevel::Info, false, "test_provider", &tmp).unwrap();
        debug!("{:?}", "Debug log");
        error!("{:?}", "Error log");
        info!("{:?}", "Info log");
        warn!("{:?}", "Warn log");
    }

    /// Tests that From<LogLevel> correctly converts LogLevel to LevelFilter
    #[test]
    fn test_log_level_to_level_filter() {
        assert_eq!(LevelFilter::from(LogLevel::Debug), LevelFilter::Debug);
        assert_eq!(LevelFilter::from(LogLevel::Info), LevelFilter::Info);
        assert_eq!(LevelFilter::from(LogLevel::Warn), LevelFilter::Warn);
        assert_eq!(LevelFilter::from(LogLevel::Error), LevelFilter::Error);
        assert_eq!(LevelFilter::from(LogLevel::None), LevelFilter::Off);
    }
}
