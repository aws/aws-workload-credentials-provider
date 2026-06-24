// Constants that are used across the code base.

// The build version of the provider
pub const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");
// The max request time
pub const MAX_REQ_TIME_SEC: u64 = 61;
// The max buffer size
pub const MAX_BUF_BYTES: usize = (65 + 256) * 1024; // 321 KB
