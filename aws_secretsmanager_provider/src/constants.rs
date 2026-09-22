// Constants that are used across the code base.

use std::time::Duration;

// The build version of the provider
pub const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");
// The max request time
pub const MAX_REQ_TIME_SEC: u64 = 61;
// The max buffer size
pub const MAX_BUF_BYTES: usize = (65 + 256) * 1024; // 321 KB

// Per-attempt SDK operation timeout for Secrets Manager / STS AssumeRole calls.
// Fast tier. Sized off cross-region latency: the worst legitimate case is a cold
// connection to a distant region (GetSecretValue cold p99 ~757ms / max ~800ms,
// dominated by TLS setup); warm is <~280ms everywhere. 2s gives ~2.5x over the
// cold max, with room for farther regions.
// Overridable at startup via the SMA_SM_OP_TIMEOUT env var (seconds).
pub const SDK_OP_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(2);
