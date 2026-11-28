use crate::config::types::{LogLevel, LoggingConfig};
use crate::telemetry::sender::DRY_RUN_LOG_TARGET;
use log::{info, LevelFilter, SetLoggerError};
use log4rs::append::console::ConsoleAppender;
use log4rs::append::rolling_file::policy::compound::roll::fixed_window::FixedWindowRoller;
use log4rs::append::rolling_file::policy::compound::trigger::size::SizeTrigger;
use log4rs::append::rolling_file::policy::compound::CompoundPolicy;
use log4rs::append::rolling_file::RollingFileAppender;
use log4rs::config::{Appender, Logger, Root};
use log4rs::encode::pattern::PatternEncoder;
use log4rs::encode::Encode;
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
/// * `logging` - The log level, whether to log to a file or stdout/stderr, and
///   whether telemetry is a dry run. Dry-run records are logged at any log
///   level. With `log_to_file` they go to `<log_file_name>_telemetry_dryrun.log`,
///   one JSON request per line, so they don't push the provider's own logs out.
/// * `log_file_name` - The base name for log files (e.g. "secrets_manager_provider").
/// * `log_dir` - The directory the log files go in.
///
/// # Returns
///
/// * `Ok(())` - If no errors are encountered.
/// * `Err(Error)` - For errors initializing the log.
pub fn init_logger(
    logging: &LoggingConfig,
    log_file_name: &str,
    log_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut config, appender, logger_type) = match logging.log_to_file {
        true => {
            let file_appender = "FILE_APPENDER";
            let rolling_file_appender =
                rolling_file_appender(log_dir, log_file_name, Box::new(PatternEncoder::default()))?;
            (
                Config::builder().appender(
                    Appender::builder().build(file_appender, Box::new(rolling_file_appender)),
                ),
                file_appender,
                "File",
            )
        }
        false => {
            let console_appender = "CONSOLE_APPENDER";
            (
                Config::builder().appender(Appender::builder().build(
                    console_appender,
                    Box::new(ConsoleAppender::builder().build()),
                )),
                console_appender,
                "Console",
            )
        }
    };

    if logging.telemetry_dry_run {
        let mut dry_run_logger = Logger::builder();
        if logging.log_to_file {
            let dry_run_appender = "TELEMETRY_DRY_RUN_APPENDER";
            let rolling_file_appender = rolling_file_appender(
                log_dir,
                &format!("{log_file_name}_telemetry_dryrun"),
                Box::new(PatternEncoder::new("{m}{n}")),
            )?;
            config = config.appender(
                Appender::builder().build(dry_run_appender, Box::new(rolling_file_appender)),
            );
            dry_run_logger = dry_run_logger.appender(dry_run_appender).additive(false);
        }
        config = config.logger(dry_run_logger.build(DRY_RUN_LOG_TARGET, LevelFilter::Info));
    }

    let log_config = config.build(
        Root::builder()
            .appender(appender)
            .build(LevelFilter::from(logging.log_level)),
    )?;

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
        logger_type, logging.log_level
    );

    Ok(())
}

/// `<log_dir>/<name>.log`, rolled over at [`MAX_ALLOWED_LOG_SIZE_IN_MB`] into
/// `<log_dir>/archive/<name>_<n>.gz`, keeping [`MAX_LOG_ARCHIVE_FILES`].
fn rolling_file_appender(
    log_dir: &Path,
    name: &str,
    encoder: Box<dyn Encode>,
) -> Result<RollingFileAppender, Box<dyn std::error::Error>> {
    let log_file_path = log_dir.join(format!("{}.log", name));
    let log_archive_pattern = log_dir.join("archive").join(format!("{}_{{}}.gz", name));
    let log_archive_pattern = log_archive_pattern
        .to_str()
        .ok_or_else(|| format!("log directory {} is not valid UTF-8", log_dir.display()))?;

    let fixed_window_roller =
        FixedWindowRoller::builder().build(log_archive_pattern, MAX_LOG_ARCHIVE_FILES)?;
    let fixed_window_roller = Box::new(fixed_window_roller);

    let file_size_trigger = Box::new(SizeTrigger::new(MAX_ALLOWED_LOG_SIZE_IN_MB * BYTES_PER_MB));
    let compound_policy = Box::new(CompoundPolicy::new(file_size_trigger, fixed_window_roller));

    Ok(RollingFileAppender::builder()
        .encoder(encoder)
        .build(log_file_path, compound_policy)?)
}

#[cfg(test)]
mod tests {
    use crate::config::types::{LogLevel, LoggingConfig};
    use crate::logging::init_logger;
    use log::{debug, error, info, warn, LevelFilter};

    #[test]
    fn test_init_file_logger() {
        let tmp = std::env::temp_dir().join("workload_credentials_provider_test_logs");
        let logging = LoggingConfig {
            log_level: LogLevel::Info,
            log_to_file: true,
            telemetry_dry_run: false,
        };
        init_logger(&logging, "test_provider", &tmp).unwrap();
        debug!("{:?}", "Debug log");
        error!("{:?}", "Error log");
        info!("{:?}", "Info log");
        warn!("{:?}", "Warn log");
    }

    #[test]
    fn test_init_console_logger() {
        let tmp = std::env::temp_dir().join("workload_credentials_provider_test_logs");
        let logging = LoggingConfig {
            log_level: LogLevel::Info,
            log_to_file: false,
            telemetry_dry_run: false,
        };
        init_logger(&logging, "test_provider", &tmp).unwrap();
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
