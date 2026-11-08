// Constants that are used across the code base.

use std::time::Duration;

// The build version of the provider
pub const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");
// The max request time
pub const MAX_REQ_TIME_SEC: u64 = 61;
// The max buffer size
pub const MAX_BUF_BYTES: usize = (65 + 256) * 1024; // 321 KB

// Per-attempt SDK operation timeout for Secrets Manager / STS AssumeRole calls.
// Fast tier: covers a new connection to a distant region, even for a max-size
// secret. Prefetch batches use PREFETCH_BATCH_ATTEMPT_TIMEOUT instead.
pub const SDK_OP_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(2);
// Per-attempt timeout for prefetch BatchGetSecretValue calls only. A batch of
// large secrets fetched from a distant region on a new connection can take
// longer than SDK_OP_ATTEMPT_TIMEOUT. Prefetch runs in the background, so a
// longer bound here doesn't delay requests.
pub const PREFETCH_BATCH_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);
