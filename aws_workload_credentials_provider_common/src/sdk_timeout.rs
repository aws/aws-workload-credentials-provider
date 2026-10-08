//! Shared helper for applying a per-attempt SDK operation timeout.
//!
//! Without a bound on AWS calls, a hung service response can stall a
//! certificate refresh (→ cert expiry) or a secret fetch. This helper folds a
//! default per-attempt operation timeout into the SDK-resolved [`TimeoutConfig`]
//! that both providers attach to their SDK clients.

use std::time::Duration;

use aws_smithy_types::timeout::TimeoutConfig;
use aws_types::SdkConfig;

/// Returns `sdk_config` with `default` merged in as its per-attempt operation
/// timeout. The loaded config's other timeout settings are kept as they are.
///
/// # Arguments
///
/// * `sdk_config` - The config returned by `aws_config::load_defaults`.
/// * `default` - Per-attempt timeout applied when the loaded config left it unset.
pub fn with_op_timeout(sdk_config: SdkConfig, default: Duration) -> SdkConfig {
    let timeout_config = op_timeout_config(default, sdk_config.timeout_config());
    sdk_config
        .into_builder()
        .timeout_config(timeout_config)
        .build()
}

/// Builds a [`TimeoutConfig`] that adds `default` as the per-attempt operation
/// timeout on top of the config the SDK already resolved. Merging (rather than
/// replacing) keeps the resolved connect/read settings, and a slot the resolved
/// config already set wins over `default`.
///
/// There is no runtime override: the Rust SDK does not read
/// `AWS_API_CALL_ATTEMPT_TIMEOUT` or the `api_call_attempt_timeout` profile setting.
///
/// A per-*attempt* timeout (not the overall `operation_timeout`) is used so the
/// SDK's retry policy still applies across attempts.
///
/// # Arguments
///
/// * `default` - Per-attempt timeout applied when the loaded config left it unset.
/// * `resolved` - The `TimeoutConfig` the SDK already resolved, if any.
fn op_timeout_config(default: Duration, resolved: Option<&TimeoutConfig>) -> TimeoutConfig {
    // Our contribution: only the per-attempt slot is set.
    let ours = TimeoutConfig::builder().operation_attempt_timeout(default);

    match resolved {
        // Resolved fields win; ours fills only the slots it left unset.
        Some(resolved) => resolved.to_builder().take_unset_from(ours).build(),
        None => ours.build(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_resolved_sets_only_attempt_timeout() {
        let cfg = op_timeout_config(Duration::from_secs(2), None);
        assert_eq!(
            cfg.operation_attempt_timeout(),
            Some(Duration::from_secs(2))
        );
        // Nothing else is invented.
        assert_eq!(cfg.connect_timeout(), None);
    }

    #[test]
    fn resolved_connect_timeout_survives_merge() {
        // Simulates the SDK-resolved config: a connect timeout but no attempt timeout.
        let resolved = TimeoutConfig::builder()
            .connect_timeout(Duration::from_millis(3100))
            .build();
        let cfg = op_timeout_config(Duration::from_secs(2), Some(&resolved));
        // Our attempt timeout is applied...
        assert_eq!(
            cfg.operation_attempt_timeout(),
            Some(Duration::from_secs(2))
        );
        // ...and the resolved connect timeout is preserved, not discarded.
        assert_eq!(cfg.connect_timeout(), Some(Duration::from_millis(3100)));
    }

    #[test]
    fn preset_attempt_timeout_wins_over_our_default() {
        // A loaded config that already carries an attempt timeout: our default
        // must not override it.
        let resolved = TimeoutConfig::builder()
            .connect_timeout(Duration::from_millis(3100))
            .operation_attempt_timeout(Duration::from_secs(10))
            .build();
        let cfg = op_timeout_config(Duration::from_secs(2), Some(&resolved));
        assert_eq!(
            cfg.operation_attempt_timeout(),
            Some(Duration::from_secs(10)),
            "an already-set attempt timeout should win over our default"
        );
    }

    #[test]
    fn with_op_timeout_merges_into_sdk_config() {
        let sdk_config = SdkConfig::builder()
            .timeout_config(
                TimeoutConfig::builder()
                    .connect_timeout(Duration::from_millis(3100))
                    .build(),
            )
            .build();
        let cfg = with_op_timeout(sdk_config, Duration::from_secs(5));
        let timeouts = cfg.timeout_config().expect("timeout config should be set");
        assert_eq!(
            timeouts.operation_attempt_timeout(),
            Some(Duration::from_secs(5))
        );
        assert_eq!(
            timeouts.connect_timeout(),
            Some(Duration::from_millis(3100))
        );
    }

    #[test]
    fn with_op_timeout_without_resolved_timeouts() {
        let cfg = with_op_timeout(SdkConfig::builder().build(), Duration::from_secs(2));
        assert_eq!(
            cfg.timeout_config()
                .and_then(TimeoutConfig::operation_attempt_timeout),
            Some(Duration::from_secs(2))
        );
    }
}
