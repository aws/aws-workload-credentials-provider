//! Shared helper for building a per-attempt SDK operation timeout.
//!
//! Neither provider binary bounds its AWS calls today, so a hung service
//! response can stall a certificate refresh (→ cert expiry) or a secret fetch.
//! This helper builds a [`TimeoutConfig`] carrying an `operation_attempt_timeout`
//! that both providers attach to their SDK clients.

use std::time::Duration;

use aws_smithy_types::timeout::TimeoutConfig;

/// Builds a [`TimeoutConfig`] carrying a per-attempt operation timeout.
///
/// The timeout defaults to `default`, but can be overridden at process start by
/// setting the `env_key` environment variable to a positive whole number of
/// seconds. Unset, non-numeric, or non-positive values fall back to `default`
/// (a 0s timeout would fail every call).
///
/// A per-*attempt* timeout (not the overall `operation_timeout`) is intentional:
/// in the AWS Rust SDK a per-attempt timeout is retryable, so the configured
/// retry policy still applies across attempts.
///
/// # Arguments
///
/// * `env_key` - Environment variable name checked for a seconds override.
/// * `default` - Fallback per-attempt timeout when the override is absent/invalid.
pub fn op_timeout_config(env_key: &str, default: Duration) -> TimeoutConfig {
    // Fully-qualified `std::env::var` on purpose: callers in the SM provider
    // alias `var` to a test shim, and this helper must read the real process env.
    let timeout = std::env::var(env_key)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .map(Duration::from_secs)
        .unwrap_or(default);

    TimeoutConfig::builder()
        .operation_attempt_timeout(timeout)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_env_uses_default() {
        let cfg = op_timeout_config("WCP_TEST_UNSET_OP_TIMEOUT", Duration::from_secs(1));
        assert_eq!(
            cfg.operation_attempt_timeout(),
            Some(Duration::from_secs(1))
        );
    }

    #[test]
    fn positive_env_overrides_default() {
        // Unique key so this doesn't race other tests reading the same var.
        let key = "WCP_TEST_POSITIVE_OP_TIMEOUT";
        std::env::set_var(key, "7");
        let cfg = op_timeout_config(key, Duration::from_secs(3));
        std::env::remove_var(key);
        assert_eq!(
            cfg.operation_attempt_timeout(),
            Some(Duration::from_secs(7))
        );
    }

    #[test]
    fn zero_and_invalid_env_fall_back_to_default() {
        let default = Duration::from_secs(3);
        for bad in ["0", "-1", "abc", ""] {
            let key = "WCP_TEST_BAD_OP_TIMEOUT";
            std::env::set_var(key, bad);
            let cfg = op_timeout_config(key, default);
            std::env::remove_var(key);
            assert_eq!(
                cfg.operation_attempt_timeout(),
                Some(default),
                "value {bad:?} should fall back to default"
            );
        }
    }
}
