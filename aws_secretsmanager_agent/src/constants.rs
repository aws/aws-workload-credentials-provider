/// User visible error messages.
pub const INVALID_LOG_LEVEL_ERR_MSG: &str = "The log level specified in the configuration file isn't valid. The log level must be DEBUG, INFO, WARN, ERROR, or NONE.";
pub const INVALID_HTTP_PORT_ERR_MSG: &str = "The HTTP port specified in the configuration file isn't valid. The HTTP port must be in the range 1024 to 65535.";
pub const INVALID_TTL_SECONDS_ERR_MSG: &str = "The TTL in seconds specified in the configuration file isn't valid. The TTL in seconds must be in the range 0 to 3600.";
pub const INVALID_CACHE_SIZE_ERR_MSG: &str = "The cache size specified in the configuration file isn't valid. The cache size must be in the range 1 to 1000.";
pub const GENERIC_CONFIG_ERR_MSG: &str =
    "There was an unexpected error in loading the configuration file.";
pub const BAD_MAX_CONN_MSG: &str = "The maximum number of connections specified in the configuration file isn't valid. The maximum number of connections must be in the range 1 to 1000.";
pub const EMPTY_SSRF_LIST_MSG: &str =
    "The list of SSRF headers in the configuration file can't be empty.";
pub const EMPTY_ENV_LIST_MSG: &str =
    "The list of SSRF environment variables in the configuration file can't be empty.";
pub const BAD_PREFIX_MSG: &str =
    "The path prefix specified in the configuration file must begin with /.";

/// Other constants that are used across the code base.

// The application name.
pub const APPNAME: &str = "aws-secrets-manager-agent";
// The build version of the agent
pub const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");
// The maximum for incoming connections need to be relatively high, since during periods of high latency, we can easily have many outstanding connections on a very busy box.
pub const DEFAULT_MAX_CONNECTIONS: &str = "800";
// The max request time
pub const MAX_REQ_TIME_SEC: u64 = 61;
// The max buffer size
pub const MAX_BUF_BYTES: usize = (65 + 256) * 1024; // 321 KB
