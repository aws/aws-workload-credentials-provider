use crate::constants::EMPTY_ENV_LIST_MSG;
use crate::constants::{BAD_MAX_CONN_MSG, BAD_PREFIX_MSG, EMPTY_SSRF_LIST_MSG};
use crate::constants::{DEFAULT_MAX_CONNECTIONS, GENERIC_CONFIG_ERR_MSG};
use crate::constants::{INVALID_CACHE_SIZE_ERR_MSG, INVALID_HTTP_PORT_ERR_MSG};
use crate::constants::{INVALID_LOG_LEVEL_ERR_MSG, INVALID_TTL_SECONDS_ERR_MSG};
use config::Config as ConfigLib;
use config::File;
use serde_derive::Deserialize;
use std::num::NonZeroUsize;
use std::ops::Range;
use std::str::FromStr;
use std::time::Duration;

const DEFAULT_LOG_LEVEL: &str = "info";
const DEFAULT_LOG_TO_FILE: bool = true;
const DEFAULT_HTTP_PORT: &str = "2773";
const DEFAULT_TTL_SECONDS: &str = "300";
const DEFAULT_CACHE_SIZE: &str = "1000";
const DEFAULT_SSRF_HEADERS: [&str; 2] = ["X-Aws-Parameters-Secrets-Token", "X-Vault-Token"];
const DEFAULT_SSRF_ENV_VARIABLES: [&str; 3] = [
    "AWS_TOKEN",
    "AWS_SESSION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
];
const DEFAULT_PATH_PREFIX: &str = "/v1/";
const DEFAULT_IGNORE_TRANSIENT_ERRORS: bool = true;
const DEFAULT_STS_CHECK: bool = true;

const DEFAULT_REGION: Option<String> = None;

/// Private struct used to deserialize configurations from the file.
#[doc(hidden)]
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)] // We want to error out when file has misspelled or unknown configurations.
struct ConfigFile {
    log_level: String,
    log_to_file: bool,
    http_port: String,
    ttl_seconds: String,
    cache_size: String,
    ssrf_headers: Vec<String>,
    ssrf_env_variables: Vec<String>,
    path_prefix: String,
    max_conn: String,
    region: Option<String>,
    ignore_transient_errors: bool,
    validate_credentials: bool,
}

/// The log levels supported by the daemon.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq, Copy)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
    None,
}

/// Returns the log level if the provided `log_level` string is valid.
/// Returns Err if it's invalid.
impl FromStr for LogLevel {
    type Err = String;
    fn from_str(log_level: &str) -> Result<Self, String> {
        match log_level.to_lowercase().as_str() {
            "debug" => Ok(LogLevel::Debug),
            "info" => Ok(LogLevel::Info),
            "warn" => Ok(LogLevel::Warn),
            "error" => Ok(LogLevel::Error),
            "none" => Ok(LogLevel::None),
            _ => Err(String::from(INVALID_LOG_LEVEL_ERR_MSG)),
        }
    }
}

/// The contains the configurations that are used by the daemon.
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    /// The level of logging the agent provides ie. debug, info, warn, error or none.
    log_level: LogLevel,

    // Whether to write logs to a file (default) or to stdout/stderr
    log_to_file: bool,

    /// The port for the local HTTP server.
    http_port: u16,

    /// The `time to live` of a secret
    ttl: Duration,

    /// Maximum number secrets that can be stored in the cache.
    cache_size: NonZeroUsize,

    /// A list of request headers which will be checked in order for the SSRF
    /// token. Contains at least one request header.
    ssrf_headers: Vec<String>,

    /// The list of the environment variable names to search through for the SSRF token.
    ssrf_env_variables: Vec<String>,

    /// The prefix for path based requests.
    path_prefix: String,

    /// The maximum number of simultaneous connections.
    max_conn: usize,

    /// The AWS Region that will be used to send the Secrets Manager request to.
    region: Option<String>,

    /// Whether the agent should serve cached data on transient refresh errors
    ignore_transient_errors: bool,

    /// Whether the agent should validate AWS credentials at startup
    validate_credentials: bool,
}

/// The default configuration options.
impl Default for Config {
    fn default() -> Self {
        Config::new(None).expect(GENERIC_CONFIG_ERR_MSG)
    }
}

/// The contains the configurations that are used by the daemon.
impl Config {
    /// Initialize the configuation using the optional configuration file.
    ///
    /// If and override file is not provided, default configurations will be
    /// used.
    ///
    /// # Arguments
    ///
    /// * `file_pth` - The configuration file (in toml format) used to override the default, or None to use the defaults.
    ///
    /// # Returns
    ///
    /// * `Ok(Config)` - The config struct.
    /// * `Err((Error)` - The error encountered when trying to read or parse the config overrides.
    pub fn new(file_path: Option<&str>) -> Result<Config, Box<dyn std::error::Error>> {
        // Setting default configurations
        let mut config = ConfigLib::builder()
            .set_default("log_level", DEFAULT_LOG_LEVEL)?
            .set_default("log_to_file", DEFAULT_LOG_TO_FILE)?
            .set_default("http_port", DEFAULT_HTTP_PORT)?
            .set_default("ttl_seconds", DEFAULT_TTL_SECONDS)?
            .set_default("cache_size", DEFAULT_CACHE_SIZE)?
            .set_default::<&str, Vec<String>>(
                "ssrf_headers",
                DEFAULT_SSRF_HEADERS.map(String::from).to_vec(),
            )?
            .set_default::<&str, Vec<String>>(
                "ssrf_env_variables",
                DEFAULT_SSRF_ENV_VARIABLES.map(String::from).to_vec(),
            )?
            .set_default("path_prefix", DEFAULT_PATH_PREFIX)?
            .set_default("max_conn", DEFAULT_MAX_CONNECTIONS)?
            .set_default("region", DEFAULT_REGION)?
            .set_default("ignore_transient_errors", DEFAULT_IGNORE_TRANSIENT_ERRORS)?
            .set_default("validate_credentials", DEFAULT_STS_CHECK)?;

        // Merge the config overrides onto the default configurations, if provided.
        config = match file_path {
            Some(file_path_str) => config.add_source(File::with_name(file_path_str)),
            None => config,
        };

        Config::build(config.build()?.try_deserialize()?)
    }

    /// The level of logging the agent provides ie. debug, info, warn, error or none
    ///
    /// # Returns
    ///
    /// * `LogLevel` - The log level to use. Defaults to Info.
    pub fn log_level(&self) -> LogLevel {
        self.log_level
    }

    /// Whether to write logs to a file (default) or to stdout/stderr
    ///
    /// # Returns
    ///
    /// * `log_to_file` - `true` if writing logs to a file (default), `false` if writing logs to
    /// stdout/stderr
    pub fn log_to_file(&self) -> bool {
        self.log_to_file
    }

    /// The port for the local HTTP server to listen for incomming requests.
    ///
    /// # Returns
    ///
    /// * `port` - The TCP port number. Defaults to 2773.
    pub fn http_port(&self) -> u16 {
        self.http_port
    }

    /// The `time to live` of a secret in the cache in seconds.
    ///
    /// # Returns
    ///
    /// * `ttl` - The number of seconds to retain a secret in the cache. Defaults to 300.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Maximum number secrets that can be stored in the cache
    ///
    /// # Returns
    ///
    /// * `cache_size` - The maximum number of secrets to cache. Defaults to 1000.
    pub fn cache_size(&self) -> NonZeroUsize {
        self.cache_size
    }

    /// A list of request headers which will be checked for the SSRF token (can not be empty).
    ///
    /// # Returns
    ///
    /// * `ssrf_headers` - List of headers to check for SSRF token. Defaults to ["X-Aws-Parameters-Secrets-Token", "X-Vault-Token"].
    pub fn ssrf_headers(&self) -> Vec<String> {
        self.ssrf_headers.clone()
    }

    /// The name of the environment variable containing the SSRF token.
    ///
    /// # Returns
    ///
    /// * `ssrf_env_variables` - The name of the env variable containing the SSRF token value. Defaults to ["AWS_TOKEN", "AWS_SESSION_TOKEN", "AWS_CONTAINER_AUTHORIZATION_TOKEN"].
    pub fn ssrf_env_variables(&self) -> Vec<String> {
        self.ssrf_env_variables.clone()
    }

    /// The prefix for path based requests (must begin with /).
    ///
    /// # Returns
    ///
    /// * `path_prefix` - The path name prefix. Defaults to /v1/.
    pub fn path_prefix(&self) -> String {
        self.path_prefix.clone()
    }

    /// The maximum number of simultaneous connections (1000 max).
    ///
    /// # Returns
    ///
    /// * `max_conn` - The maximum allowed simultaneious connections. Defaults to 800.
    pub fn max_conn(&self) -> usize {
        self.max_conn
    }

    /// The AWS Region that will be used to send the Secrets Manager request to.
    /// The default region is automatically determined through SDK defaults.
    /// For a list of all of the Regions that you can specify, see https://docs.aws.amazon.com/general/latest/gr/asm.html
    ///
    /// # Returns
    ///
    /// * `region` - The AWS Region that will be used to send the Secrets Manager request to.
    pub fn region(&self) -> Option<&String> {
        self.region.as_ref()
    }

    /// Whether the client should serve cached data on transient refresh errors
    ///
    /// # Returns
    ///
    /// * `ignore_transient_errors` - Whether the client should serve cached data on transient refresh errors. Defaults to "true"
    pub fn ignore_transient_errors(&self) -> bool {
        self.ignore_transient_errors
    }

    /// Whether to validate AWS credentials on startup using STS GetCallerIdentity
    ///
    /// # Returns
    ///
    /// * `validate_credentials` - Whether the agent should validate AWS credentials at startup. Defaults to "true"
    pub fn validate_credentials(&self) -> bool {
        self.validate_credentials
    }

    /// Private helper that fills in the Config instance from the specified
    /// config overrides (or defaults).
    ///
    /// # Arguments
    ///
    /// * `config_file` - The parsed config overrides and defaults.
    ///
    /// # Returns
    ///
    /// * `Ok(Config)` - If no errors were found in the overrides.
    /// * `Err(Error)` - An error message with the configuration error.
    #[doc(hidden)]
    fn build(config_file: ConfigFile) -> Result<Config, Box<dyn std::error::Error>> {
        let config = Config {
            // Configurations that are allowed to be overridden.
            log_level: LogLevel::from_str(config_file.log_level.as_str())?,
            log_to_file: config_file.log_to_file,
            http_port: parse_num::<u16>(
                &config_file.http_port,
                INVALID_HTTP_PORT_ERR_MSG,
                None,
                Some(1..1024),
            )?,
            ttl: Duration::from_secs(parse_num::<u64>(
                &config_file.ttl_seconds,
                INVALID_TTL_SECONDS_ERR_MSG,
                Some(0..3601),
                None,
            )?),
            cache_size: match NonZeroUsize::new(parse_num::<usize>(
                &config_file.cache_size,
                INVALID_CACHE_SIZE_ERR_MSG,
                Some(0..1001),
                None,
            )?) {
                Some(x) => x,
                None => Err(INVALID_CACHE_SIZE_ERR_MSG)?,
            },
            ssrf_headers: config_file.ssrf_headers,
            ssrf_env_variables: config_file.ssrf_env_variables,
            path_prefix: config_file.path_prefix,
            max_conn: parse_num::<usize>(
                &config_file.max_conn,
                BAD_MAX_CONN_MSG,
                Some(1..1001),
                None,
            )?,
            region: config_file.region,
            ignore_transient_errors: config_file.ignore_transient_errors,
            validate_credentials: config_file.validate_credentials,
        };

        // Additional validations.
        if config.ssrf_headers.is_empty() {
            Err(EMPTY_SSRF_LIST_MSG)?;
        }
        if config.ssrf_env_variables.is_empty() {
            Err(EMPTY_ENV_LIST_MSG)?;
        }
        if !config.path_prefix.starts_with('/') {
            Err(BAD_PREFIX_MSG)?;
        }

        Ok(config)
    }
}

/// Private helper to convert a string to number and perform range checks, returning a custom error on failure.
///
/// # Arguments
///
/// * `str_val` - The sring to convert.
/// * `msg` - The custom error message.
/// * `pos_range` - An optional positive range constraint. The number must be within this range.
/// * `neg_range` - An optional negitive range constraint. The number must not be within this range.
///
/// # Returns
///
/// * `Ok(num)` - When the string can be parsed and the number satisfies the range checks.
/// * `Err(Error)` - The custom error message on failure.
///
/// # Example
///
/// ```
/// use std::ops::Range;
/// assert_eq!(parse_num::<u32>(&String::from("42"), "What is the qustion?", Some(1..100), None).unwrap(), 42);
/// ```
#[doc(hidden)]
fn parse_num<T>(
    str_val: &str,
    msg: &str,
    pos_range: Option<Range<T>>,
    neg_range: Option<Range<T>>,
) -> Result<T, Box<dyn std::error::Error>>
where
    T: PartialOrd + Sized + std::str::FromStr,
{
    let val = match str_val.parse::<T>() {
        Ok(x) => x,
        _ => Err(msg)?,
    };
    if let Some(rng) = pos_range {
        if !rng.contains(&val) {
            Err(msg)?;
        }
    }
    if let Some(rng) = neg_range {
        if rng.contains(&val) {
            Err(msg)?;
        }
    }

    Ok(val)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Test helper function that returns a ConfigFile with default values.
    fn get_default_config_file() -> ConfigFile {
        ConfigFile {
            log_level: String::from(DEFAULT_LOG_LEVEL),
            log_to_file: DEFAULT_LOG_TO_FILE,
            http_port: String::from(DEFAULT_HTTP_PORT),
            ttl_seconds: String::from(DEFAULT_TTL_SECONDS),
            cache_size: String::from(DEFAULT_CACHE_SIZE),
            ssrf_headers: DEFAULT_SSRF_HEADERS.map(String::from).to_vec(),
            ssrf_env_variables: DEFAULT_SSRF_ENV_VARIABLES.map(String::from).to_vec(),
            path_prefix: String::from(DEFAULT_PATH_PREFIX),
            max_conn: String::from(DEFAULT_MAX_CONNECTIONS),
            region: None,
            ignore_transient_errors: DEFAULT_IGNORE_TRANSIENT_ERRORS,
            validate_credentials: DEFAULT_STS_CHECK,
        }
    }

    /// Tests that the default configurations are correct.
    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.clone().log_level(), LogLevel::Info);
        assert_eq!(config.clone().http_port(), 2773);
        assert_eq!(config.clone().ttl(), Duration::from_secs(300));
        assert_eq!(
            config.clone().cache_size(),
            NonZeroUsize::new(1000).unwrap()
        );
        assert_eq!(
            config.clone().ssrf_headers(),
            DEFAULT_SSRF_HEADERS.map(String::from).to_vec()
        );
        assert_eq!(
            config.clone().ssrf_env_variables(),
            DEFAULT_SSRF_ENV_VARIABLES.map(String::from).to_vec()
        );
        assert_eq!(config.clone().path_prefix(), DEFAULT_PATH_PREFIX);
        assert_eq!(config.clone().max_conn(), 800);
        assert_eq!(config.clone().region(), None);
        assert!(config.ignore_transient_errors());
        assert!(config.validate_credentials());
    }

    /// Tests the config overrides are applied correctly from the provided config file.
    #[test]
    fn test_config_overrides() {
        let config = Config::new(Some("tests/resources/configs/config_file_valid.toml")).unwrap();
        assert_eq!(config.clone().log_level(), LogLevel::Debug);
        assert_eq!(config.clone().http_port(), 65535);
        assert_eq!(config.clone().ttl(), Duration::from_secs(300));
        assert_eq!(
            config.clone().cache_size(),
            NonZeroUsize::new(1000).unwrap()
        );
        assert_eq!(
            config.clone().ssrf_headers(),
            vec!("X-Aws-Parameters-Secrets-Token".to_string())
        );
        assert_eq!(
            config.clone().ssrf_env_variables(),
            vec!("MY_TOKEN".to_string())
        );
        assert_eq!(config.clone().path_prefix(), "/other");
        assert_eq!(config.clone().max_conn(), 10);
        assert_eq!(config.clone().region(), Some(&"us-west-2".to_string()));
        assert!(!config.ignore_transient_errors());
        assert!(!config.validate_credentials());
    }

    /// Tests that an Err is returned when an invalid value is provided in one of the configurations.
    #[test]
    fn test_config_overrides_invalid_value() {
        match Config::new(Some(
            "tests/resources/configs/config_file_with_invalid_config.toml",
        )) {
            Ok(_) => panic!(),
            Err(e) => assert_eq!(e.to_string(), INVALID_LOG_LEVEL_ERR_MSG),
        };
    }

    /// Tests that an valid log level values don't return an Err.
    #[test]
    fn test_validate_config_valid_log_level_values() {
        let mut input_output_map = HashMap::new();
        input_output_map.insert("info".to_string(), LogLevel::Info);
        input_output_map.insert("Info".to_string(), LogLevel::Info);
        input_output_map.insert("INFO".to_string(), LogLevel::Info);
        input_output_map.insert("debug".to_string(), LogLevel::Debug);
        input_output_map.insert("Debug".to_string(), LogLevel::Debug);
        input_output_map.insert("DEBUG".to_string(), LogLevel::Debug);
        input_output_map.insert("warn".to_string(), LogLevel::Warn);
        input_output_map.insert("Warn".to_string(), LogLevel::Warn);
        input_output_map.insert("WARN".to_string(), LogLevel::Warn);
        input_output_map.insert("error".to_string(), LogLevel::Error);
        input_output_map.insert("Error".to_string(), LogLevel::Error);
        input_output_map.insert("ERROR".to_string(), LogLevel::Error);
        input_output_map.insert("none".to_string(), LogLevel::None);
        input_output_map.insert("None".to_string(), LogLevel::None);
        input_output_map.insert("NONE".to_string(), LogLevel::None);

        for (input, output) in input_output_map.iter() {
            let invalid_config = ConfigFile {
                log_level: input.clone(),
                ..get_default_config_file()
            };
            match Config::build(invalid_config) {
                Ok(actual) => assert_eq!(actual.log_level(), output.clone()),
                Err(_) => panic!(),
            };
        }
    }

    /// Tests that an invalid log level returns an Err
    #[test]
    fn test_validate_config_invalid_log_level() {
        let invalid_config = ConfigFile {
            log_level: String::from("information"),
            ..get_default_config_file()
        };
        match Config::build(invalid_config) {
            Ok(_) => panic!(),
            Err(e) => assert_eq!(e.to_string(), INVALID_LOG_LEVEL_ERR_MSG),
        };
    }

    /// Tests that an invalid http port value returns an Err
    #[test]
    fn test_validate_config_http_port_invalid_values() {
        for value in ["1023", "-1", "65536", "not a number"] {
            let invalid_config = ConfigFile {
                http_port: String::from(value),
                ..get_default_config_file()
            };
            match Config::build(invalid_config) {
                Ok(_) => panic!(),
                Err(e) => assert_eq!(e.to_string(), INVALID_HTTP_PORT_ERR_MSG),
            };
        }
    }

    /// Tests that an invalid max conn value returns an Err
    #[test]
    fn test_validate_config_max_conn_invalid_values() {
        for value in ["1001", "-1", "0", "not a number"] {
            let invalid_config = ConfigFile {
                max_conn: String::from(value),
                ..get_default_config_file()
            };
            match Config::build(invalid_config) {
                Ok(_) => panic!(),
                Err(e) => assert_eq!(e.to_string(), BAD_MAX_CONN_MSG),
            };
        }
    }

    /// Tests that an invalid ttl_seconds value returns an Err
    #[test]
    fn test_validate_ttl_seconds_invalid_values() {
        for value in ["-1", "3601", "not a number"] {
            let invalid_config = ConfigFile {
                ttl_seconds: String::from(value),
                ..get_default_config_file()
            };
            match Config::build(invalid_config) {
                Ok(_) => panic!(),
                Err(e) => assert_eq!(e.to_string(), INVALID_TTL_SECONDS_ERR_MSG),
            };
        }
    }

    /// Tests that an invalid cache_size value returns an Err
    #[test]
    fn test_validate_cache_size_invalid_values() {
        for value in ["-1", "0", "1001", "not a number"] {
            let invalid_config = ConfigFile {
                cache_size: String::from(value),
                ..get_default_config_file()
            };
            match Config::build(invalid_config) {
                Ok(_) => panic!(),
                Err(e) => assert_eq!(e.to_string(), INVALID_CACHE_SIZE_ERR_MSG),
            };
        }
    }

    /// Tests that an invalid ssrf header list returns an Err
    #[test]
    fn test_validate_ssrf_headers() {
        let invalid_config = ConfigFile {
            ssrf_headers: Vec::new(),
            ..get_default_config_file()
        };
        match Config::build(invalid_config) {
            Ok(_) => panic!(),
            Err(e) => assert_eq!(e.to_string(), EMPTY_SSRF_LIST_MSG),
        };
    }

    /// Tests that an invalid env variable list returns an Err
    #[test]
    fn test_validate_ssrf_env_variables() {
        let invalid_config = ConfigFile {
            ssrf_env_variables: Vec::new(),
            ..get_default_config_file()
        };
        match Config::build(invalid_config) {
            Ok(_) => panic!(),
            Err(e) => assert_eq!(e.to_string(), EMPTY_ENV_LIST_MSG),
        };
    }

    /// Tests that an invalid path prefix returns an Err
    #[test]
    fn test_validate_path_prefix() {
        let invalid_config = ConfigFile {
            path_prefix: String::from("v1"),
            ..get_default_config_file()
        };
        match Config::build(invalid_config) {
            Ok(_) => panic!(),
            Err(e) => assert_eq!(e.to_string(), BAD_PREFIX_MSG),
        };
    }

    /// Tests that an empty config file does not return an error and the default configuration are used.
    #[test]
    fn test_config_empty_config_file() {
        let config = Config::new(Some("tests/resources/configs/config_file_empty.toml")).unwrap();
        assert_eq!(config.clone().log_level(), LogLevel::Info);
        assert_eq!(config.clone().http_port(), 2773);
        assert_eq!(config.clone().ttl(), Duration::from_secs(300));
        assert!(config.validate_credentials());
        assert_eq!(
            config.clone().cache_size(),
            NonZeroUsize::new(1000).unwrap()
        );
    }

    /// Tests that a wrong file path returns an Err with appropriate message
    #[test]
    fn test_config_wrong_config_file_path() {
        match Config::new(Some("file_does_not_exist")) {
            Ok(_) => panic!(),
            Err(e) => assert_eq!(
                e.to_string(),
                "configuration file \"file_does_not_exist\" not found"
            ),
        };
    }

    /// Tests that a config file with invalid content returns an Err with appropriate message.
    #[test]
    #[should_panic(expected = "TOML parse error")]
    fn test_config_invalid_file_contents() {
        Config::new(Some(
            "tests/resources/configs/config_file_with_invalid_contents.toml",
        ))
        .unwrap();
    }
}
