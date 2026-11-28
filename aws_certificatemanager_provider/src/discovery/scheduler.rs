//! Discovery cycle scheduler.
//!
//! Runs a periodic discovery loop that invokes a probe callback, assembles
//! `cert.discovery` telemetry records, and submits them via the
//! `TelemetrySubmitter` trait.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aws_smithy_types::DateTime;
use aws_workload_credentials_provider_common::telemetry::{
    AgentIdentity, Capability, PayloadEnvelope, PayloadType,
};
use log::{debug, error, info, warn};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::discovery::config::DiscoveryConfig;
use crate::discovery::engine::ProbeStats;
use crate::discovery::payload::{
    batch_observations, generate_cycle_id, BatchInfo, CertDiscoveryRecord, Observation,
};
use crate::discovery::telemetry::TelemetrySubmitter;

const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

const DISCOVERY_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/// Upper bound of the random delay before the first cycle.
pub(crate) const MAX_STARTUP_JITTER: Duration = Duration::from_secs(5 * 60);
/// Upper bound of the random delay added to each later cycle's 24h interval.
const MAX_CYCLE_JITTER: Duration = Duration::from_secs(5 * 60);

/// Runs the discovery loop. Runs the first discovery cycle up to
/// `MAX_STARTUP_JITTER` after startup and each later one 24h plus up to
/// `MAX_CYCLE_JITTER` after the previous, so hosts that start together do not
/// send their requests together.
///
/// `probe_fn` is called each cycle to probe the configured targets.
/// It receives the config and an observation sender, then sends observations
/// as probes complete. The scheduler filters to success-only before submitting
/// telemetry.
///
/// Cancellation is checked at every blocking point: startup delay, probing,
/// submission, and inter-cycle sleep.
pub async fn run_discovery_loop<F, Fut>(
    config: DiscoveryConfig,
    submitter: Arc<dyn TelemetrySubmitter>,
    identity: AgentIdentity,
    cancel_token: CancellationToken,
    configured_cert_count: Option<u32>,
    probe_fn: F,
) where
    F: Fn(&DiscoveryConfig, mpsc::UnboundedSender<Observation>) -> Fut,
    Fut: std::future::Future<Output = ProbeStats>,
{
    if !config.enabled {
        info!("Certificate discovery is disabled");
        return;
    }

    if let Err(error) = PayloadEnvelope::new(
        Capability::Acm,
        PayloadType::CertDiscovery,
        0,
        0,
        &identity.host_id,
        &identity.boot_nonce,
        AGENT_VERSION,
        &identity.region,
        identity.deployment_type,
    ) {
        error!(
            "Certificate discovery startup aborted: invalid telemetry envelope: {}",
            error
        );
        return;
    }

    info!(
        "Certificate discovery starting: {} ports, timeout {}s",
        config.discovery_targets.len(),
        config.timeout_secs
    );

    let startup_delay = random_duration(MAX_STARTUP_JITTER);
    tokio::select! {
        _ = cancel_token.cancelled() => {
            info!("Discovery cancelled during startup delay");
            return;
        }
        _ = tokio::time::sleep(startup_delay) => {}
    }

    let mut batch_sequence = 0;
    loop {
        run_single_cycle(
            &config,
            &submitter,
            &identity,
            &mut batch_sequence,
            &cancel_token,
            configured_cert_count,
            &probe_fn,
        )
        .await;

        let jitter = random_duration(MAX_CYCLE_JITTER);
        let sleep_duration = DISCOVERY_INTERVAL + jitter;

        tokio::select! {
            _ = cancel_token.cancelled() => {
                info!("Discovery shutting down");
                return;
            }
            _ = tokio::time::sleep(sleep_duration) => {}
        }
    }
}

async fn run_single_cycle<F, Fut>(
    config: &DiscoveryConfig,
    submitter: &Arc<dyn TelemetrySubmitter>,
    identity: &AgentIdentity,
    batch_sequence: &mut u64,
    cancel_token: &CancellationToken,
    configured_cert_count: Option<u32>,
    probe_fn: &F,
) where
    F: Fn(&DiscoveryConfig, mpsc::UnboundedSender<Observation>) -> Fut,
    Fut: std::future::Future<Output = ProbeStats>,
{
    let cycle_start = Instant::now();
    let cycle_start_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let cycle_start_epoch = cycle_start_ms / 1000;

    info!("Discovery cycle starting");

    let timeout = Duration::from_secs(config.timeout_secs);
    let (sender, mut receiver) = mpsc::unbounded_channel();
    let (timed_out, probe_stats) = tokio::select! {
        biased;
        _ = cancel_token.cancelled() => {
            info!("Discovery cancelled during cycle");
            return;
        }
        result = tokio::time::timeout(timeout, probe_fn(config, sender)) => {
            match result {
                Ok(stats) => (false, stats),
                Err(_) => (true, ProbeStats::default()),
            }
        },
    };

    receiver.close();
    let mut observations = Vec::new();
    while let Some(observation) = receiver.recv().await {
        observations.push(observation);
    }
    if timed_out {
        warn!(
            "Discovery cycle timed out after {}s, preserving {} partial observations",
            config.timeout_secs,
            observations.len()
        );
    }

    let cycle_duration_ms = cycle_start.elapsed().as_millis() as u64;
    info!(
        "Discovery cycle completed: {} observations in {}ms ({} targets, {} failed)",
        observations.len(),
        cycle_duration_ms,
        probe_stats.total_targets_probed,
        probe_stats.failed_probes
    );

    let (batches, dropped) = batch_observations(observations);
    if dropped > 0 {
        warn!("Discovery: dropped {} oversized observations", dropped);
    }
    if batches.is_empty() {
        debug!("Discovery: no successful observations to report");
        return;
    }

    let cycle_id = generate_cycle_id(&identity.host_id, cycle_start_epoch);
    let total_batches = batches.len();
    let current_batch_sequence = *batch_sequence;
    // ACM discovery increments batch_sequence once per discovery cycle (24h).
    // All batches within a single cycle share the same sequence number
    // and are disambiguated by batch_index in the envelope.
    *batch_sequence = (*batch_sequence).wrapping_add(1);
    let mut failed_count = 0;
    for (idx, batch) in batches.into_iter().enumerate() {
        if cancel_token.is_cancelled() {
            return;
        }
        let envelope = match PayloadEnvelope::new(
            Capability::Acm,
            PayloadType::CertDiscovery,
            current_batch_sequence,
            idx as u32,
            &identity.host_id,
            &identity.boot_nonce,
            AGENT_VERSION,
            &identity.region,
            identity.deployment_type,
        ) {
            Ok(envelope) => envelope,
            Err(error) => {
                warn!("Discovery: invalid telemetry envelope: {}", error);
                return;
            }
        };
        let record = CertDiscoveryRecord {
            envelope,
            cycle_id: cycle_id.clone(),
            cycle_start_ms,
            cycle_timestamp: format_iso8601(cycle_start_epoch),
            cycle_duration_ms,
            batch_info: BatchInfo { total_batches },
            scan_complete: Some(!timed_out),
            // On timeout the probe future is cancelled mid-scan, so ProbeStats
            // is default(all zeros) while the channel may hold partial
            // observations. Emit None to avoid a contradictory payload;
            // scan_complete: false already signals the partial case.
            total_targets_probed: (!timed_out).then_some(probe_stats.total_targets_probed),
            successful_probes: (!timed_out).then_some(probe_stats.successful_probes),
            failed_probes: (!timed_out).then_some(probe_stats.failed_probes),
            // A completed scan reports its count, including 0, so persistence
            // can treat the scan as complete. A timed-out scan didn't see
            // every target, so its count is omitted as unknown.
            dropped_observations: (!timed_out).then_some(dropped as u32),
            configured_cert_count,
            observations: batch,
        };
        let result = tokio::select! {
            biased;
            _ = cancel_token.cancelled() => return,
            result = submitter.submit(&record) => result,
        };
        match result {
            Ok(()) => {}
            Err(error) => {
                failed_count += 1;
                warn!(
                    "Discovery: failed to submit batch {}/{} for cycle {}: {}",
                    idx + 1,
                    total_batches,
                    cycle_id,
                    error
                );
            }
        }
    }

    if failed_count > 0 {
        warn!(
            "Discovery: {} of {} batch(es) failed for cycle {}",
            failed_count, total_batches, cycle_id
        );
    } else {
        info!(
            "Discovery: submitted {} batch(es) for cycle {}",
            total_batches, cycle_id
        );
    }
}

/// Hash-based pseudo-random duration, not cryptographic. Used only for discovery
/// jitter to avoid fleet-wide synchronization. Avoids pulling in a `rand`
/// dependency for a non-security-sensitive delay.
fn random_duration(max: Duration) -> Duration {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .hash(&mut hasher);
    std::thread::current().id().hash(&mut hasher);
    let fraction = (hasher.finish() % 1000) as f64 / 1000.0;
    Duration::from_secs_f64(max.as_secs_f64() * fraction)
}

/// Formats a Unix epoch timestamp as ISO 8601 UTC (e.g. "2024-07-30T00:00:00Z").
fn format_iso8601(epoch_secs: u64) -> String {
    DateTime::from_secs(epoch_secs as i64)
        .fmt(aws_smithy_types::date_time::Format::DateTime)
        .expect("valid epoch")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::payload::{
        CertDiscoveryRecord, Observation, ProbeOutcome, MAX_OBSERVATIONS_PER_BATCH,
    };
    use crate::discovery::telemetry::testing::{
        MockSubmitter, PendingSubmitter, ScriptedSubmitter,
    };
    use crate::discovery::telemetry::SubmitError;
    use crate::discovery::test_support::{capture_logs, logged_on_this_thread};
    use aws_workload_credentials_provider_common::telemetry::DeploymentType;
    use std::collections::{HashMap, HashSet};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tempfile::TempDir;

    fn test_config() -> DiscoveryConfig {
        DiscoveryConfig {
            enabled: true,
            timeout_secs: 5,
            discovery_targets: HashMap::from([(443, vec![])]),
        }
    }

    fn send_observations(
        observations: Vec<Observation>,
    ) -> impl Fn(
        &DiscoveryConfig,
        mpsc::UnboundedSender<Observation>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ProbeStats> + Send>> {
        move |_, sender| {
            let observations = observations.clone();
            Box::pin(async move {
                let total = observations.len() as u32;
                let mut successful = 0u32;
                for observation in &observations {
                    if observation.outcome == ProbeOutcome::Success {
                        successful += 1;
                    }
                }
                for observation in observations {
                    let _ = sender.send(observation);
                }
                ProbeStats {
                    total_targets_probed: total,
                    successful_probes: successful,
                    failed_probes: total - successful,
                }
            })
        }
    }

    fn test_identity() -> AgentIdentity {
        AgentIdentity {
            host_id: "i-test".to_string(),
            boot_nonce: "boot-test".to_string(),
            region: "us-west-2".to_string(),
            deployment_type: DeploymentType::Ec2,
            ecs_network_mode: None,
        }
    }

    fn successful_observation(port: u16) -> Observation {
        Observation {
            port,
            sni: None,
            outcome: ProbeOutcome::Success,
            certificate_der: Some("cert".to_string()),
            chain_der: None,
            mtls_detected: None,
            tls_version: None,
            cipher_suite: None,
            handshake_signature_scheme: None,
            key_algorithm: None,
        }
    }

    fn sample_record() -> CertDiscoveryRecord {
        let envelope = PayloadEnvelope::new(
            Capability::Acm,
            PayloadType::CertDiscovery,
            7,
            0,
            "i-test",
            "boot-test",
            AGENT_VERSION,
            "us-west-2",
            DeploymentType::Ec2,
        )
        .expect("valid telemetry envelope");
        CertDiscoveryRecord {
            envelope,
            cycle_id: "i-test:1722297600".to_string(),
            cycle_start_ms: 1_722_297_600_000,
            cycle_timestamp: "2024-07-30T00:00:00Z".to_string(),
            cycle_duration_ms: 100,
            batch_info: BatchInfo { total_batches: 1 },
            scan_complete: Some(true),
            total_targets_probed: Some(3),
            successful_probes: Some(1),
            failed_probes: Some(2),
            dropped_observations: None,
            configured_cert_count: None,
            observations: vec![successful_observation(443)],
        }
    }

    async fn advance_time(duration: Duration) {
        tokio::time::advance(duration).await;
        for _ in 0..3 {
            tokio::task::yield_now().await;
        }
    }

    #[test]
    fn random_duration_within_bounds() {
        let mut seen = HashSet::new();
        for _ in 0..100 {
            let duration = random_duration(Duration::from_secs(60));
            assert!(duration <= Duration::from_secs(60));
            seen.insert(duration.as_millis());
        }
        assert!(seen.len() > 5, "jitter must produce a meaningful spread");
    }

    #[test]
    fn iso8601_known_epoch() {
        assert_eq!(format_iso8601(1722297600), "2024-07-30T00:00:00Z");
    }

    #[test]
    fn iso8601_unix_epoch() {
        assert_eq!(format_iso8601(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn iso8601_leap_year() {
        // 2024-02-29 is a leap day
        assert_eq!(format_iso8601(1709164800), "2024-02-29T00:00:00Z");
    }

    #[tokio::test]
    async fn disabled_returns_immediately() {
        let config = DiscoveryConfig {
            enabled: false,
            ..DiscoveryConfig::default()
        };
        let submitter = Arc::new(MockSubmitter::log_only());
        let cancel = CancellationToken::new();
        let submitter_clone = submitter.clone();
        run_discovery_loop(
            config,
            submitter_clone,
            test_identity(),
            cancel,
            None,
            send_observations(vec![]),
        )
        .await;
        assert_eq!(
            submitter.submit_count(),
            0,
            "disabled config must not submit"
        );
    }

    #[tokio::test]
    async fn cancellation_exits() {
        let config = test_config();
        let submitter = Arc::new(MockSubmitter::log_only());
        let cancel = CancellationToken::new();
        cancel.cancel();
        let submitter_clone = submitter.clone();
        run_discovery_loop(
            config,
            submitter_clone,
            test_identity(),
            cancel,
            None,
            send_observations(vec![]),
        )
        .await;
        assert_eq!(
            submitter.submit_count(),
            0,
            "cancelled loop must not submit"
        );
    }

    #[tokio::test]
    async fn invalid_boot_nonce_exits_before_probe() {
        tokio::time::pause();
        let config = test_config();
        let submitter = Arc::new(MockSubmitter::log_only());
        let cancel = CancellationToken::new();
        let cancel_from_probe = cancel.clone();
        let probe_count = AtomicUsize::new(0);
        let identity = AgentIdentity {
            boot_nonce: "invalid:nonce".to_string(),
            ..test_identity()
        };

        run_discovery_loop(
            config,
            submitter.clone(),
            identity,
            cancel,
            None,
            |_, sender| {
                probe_count.fetch_add(1, Ordering::Relaxed);
                cancel_from_probe.cancel();
                async move {
                    let _ = sender.send(successful_observation(443));
                    ProbeStats {
                        total_targets_probed: 1,
                        successful_probes: 1,
                        failed_probes: 0,
                    }
                }
            },
        )
        .await;

        assert_eq!(probe_count.load(Ordering::Relaxed), 0);
        assert_eq!(submitter.submit_count(), 0);
    }

    #[tokio::test]
    async fn probe_timeout_submits_nothing() {
        let config = DiscoveryConfig {
            timeout_secs: 0,
            ..test_config()
        };
        let submitter = Arc::new(MockSubmitter::log_only());
        let submitter_trait: Arc<dyn TelemetrySubmitter> = submitter.clone();
        let cancel = CancellationToken::new();

        run_single_cycle(
            &config,
            &submitter_trait,
            &test_identity(),
            &mut 0,
            &cancel,
            None,
            &|_: &DiscoveryConfig, sender: mpsc::UnboundedSender<Observation>| async move {
                tokio::time::sleep(Duration::from_secs(10)).await;
                let _ = sender.send(successful_observation(443));
                ProbeStats {
                    total_targets_probed: 1,
                    successful_probes: 1,
                    failed_probes: 0,
                }
            },
        )
        .await;

        assert_eq!(submitter.submit_count(), 0);
    }

    #[tokio::test]
    async fn probe_timeout_preserves_partial_observations() {
        tokio::time::pause();
        let tmp = TempDir::new().unwrap();
        let config = DiscoveryConfig {
            timeout_secs: 1,
            ..test_config()
        };
        let submitter: Arc<dyn TelemetrySubmitter> =
            Arc::new(MockSubmitter::with_directory(tmp.path().to_path_buf()));
        let cancel = CancellationToken::new();
        let identity = test_identity();
        let mut batch_sequence = 0;
        let first = successful_observation(443);
        let probe = |_: &DiscoveryConfig, sender: mpsc::UnboundedSender<Observation>| {
            let first = first.clone();
            async move {
                sender.send(first).unwrap();
                std::future::pending::<ProbeStats>().await
            }
        };

        tokio::join!(
            run_single_cycle(
                &config,
                &submitter,
                &identity,
                &mut batch_sequence,
                &cancel,
                None,
                &probe,
            ),
            async {
                tokio::task::yield_now().await;
                tokio::time::advance(Duration::from_secs(1)).await;
            }
        );

        let entries: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .collect();
        assert_eq!(entries.len(), 1, "one batch should be submitted");
        let content = std::fs::read_to_string(entries[0].path()).unwrap();
        let record: CertDiscoveryRecord = serde_json::from_str(&content).unwrap();
        assert_eq!(record.observations.len(), 1);
        assert_eq!(record.observations[0].port, 443);
        // Timeout metadata: scan_complete is false, probe stats are None
        // because ProbeStats lives inside the cancelled future.
        assert_eq!(record.scan_complete, Some(false));
        assert_eq!(record.total_targets_probed, None);
        assert_eq!(record.successful_probes, None);
        assert_eq!(record.failed_probes, None);
        assert!(
            !content.contains("dropped_observations"),
            "a timed-out scan must omit dropped_observations: {content}"
        );
    }

    /// Runs one completed cycle with `observations` and returns the one
    /// submitted record, as written.
    async fn completed_cycle_record(observations: Vec<Observation>) -> String {
        let tmp = TempDir::new().unwrap();
        let submitter: Arc<dyn TelemetrySubmitter> =
            Arc::new(MockSubmitter::with_directory(tmp.path().to_path_buf()));
        run_single_cycle(
            &test_config(),
            &submitter,
            &test_identity(),
            &mut 0,
            &CancellationToken::new(),
            None,
            &send_observations(observations),
        )
        .await;
        let entries: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(entries.len(), 1, "one batch should be submitted");
        std::fs::read_to_string(entries[0].path()).unwrap()
    }

    /// A completed scan that drops nothing reports `dropped_observations: 0`,
    /// not an absent count, which persistence reads as unknown.
    #[tokio::test]
    async fn completed_scan_reports_zero_dropped_observations() {
        let content = completed_cycle_record(vec![successful_observation(443)]).await;
        let record: CertDiscoveryRecord = serde_json::from_str(&content).unwrap();
        assert_eq!(record.scan_complete, Some(true));
        assert_eq!(record.dropped_observations, Some(0));
        let json: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(json["dropped_observations"], 0, "{content}");
    }

    /// A completed scan reports how many observations it dropped: here a
    /// SUCCESS observation with no leaf certificate, which the model rejects.
    #[tokio::test]
    async fn completed_scan_reports_dropped_observation_count() {
        let mut no_leaf = successful_observation(8443);
        no_leaf.certificate_der = None;
        let content = completed_cycle_record(vec![successful_observation(443), no_leaf]).await;
        let record: CertDiscoveryRecord = serde_json::from_str(&content).unwrap();
        assert_eq!(record.scan_complete, Some(true));
        assert_eq!(record.dropped_observations, Some(1));
        assert_eq!(record.observations.len(), 1);
    }

    #[tokio::test]
    async fn failed_batch_does_not_abort_remaining_batches() {
        let config = test_config();
        let scripted = Arc::new(ScriptedSubmitter::new(vec![
            Err(SubmitError::Rejected("first batch".to_string())),
            Ok(()),
        ]));
        let submitter: Arc<dyn TelemetrySubmitter> = scripted.clone();
        let cancel = CancellationToken::new();

        run_single_cycle(
            &config,
            &submitter,
            &test_identity(),
            &mut 0,
            &cancel,
            None,
            &send_observations(
                (0..=MAX_OBSERVATIONS_PER_BATCH)
                    .map(|port| successful_observation(port as u16))
                    .collect(),
            ),
        )
        .await;

        assert_eq!(scripted.submit_count(), 2);
    }

    /// Validates that a submitted batch dates its cycle in epoch milliseconds:
    /// the request's `scanTime` falls between the wall-clock milliseconds
    /// before and after the cycle, and the cycle ID (`scanId`) carries the
    /// same start in seconds. A dry-run sender logs the request it would send.
    #[tokio::test]
    async fn submitted_batch_dates_the_cycle_in_milliseconds() {
        use crate::discovery::telemetry::testing::{dry_run_acm_sender, logged_requests};
        use crate::discovery::telemetry::SenderSubmitter;

        capture_logs();
        let submitter: Arc<dyn TelemetrySubmitter> =
            Arc::new(SenderSubmitter(dry_run_acm_sender()));
        let now_ms = || {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
        };

        let before = now_ms();
        run_single_cycle(
            &test_config(),
            &submitter,
            &test_identity(),
            &mut 0,
            &CancellationToken::new(),
            None,
            &send_observations(vec![successful_observation(443)]),
        )
        .await;
        let after = now_ms();

        let requests = logged_requests();
        assert_eq!(requests.len(), 1, "{requests:?}");
        let discovery = &requests[0]["telemetry"]["discovery"];
        let scan_time = discovery["scanTime"]
            .as_u64()
            .expect("scanTime is a number");
        assert!(
            (before..=after).contains(&scan_time),
            "scanTime {scan_time} outside {before}..={after}"
        );
        assert_eq!(
            discovery["scanId"],
            format!("{}:{}", test_identity().host_id, scan_time / 1000)
        );
    }

    /// Validates that the sender accepts full batches: a dry-run sender,
    /// which checks each request against the model's limits and the request
    /// size, logs requests of 100, 100 and 50 observations for a scan of 250
    /// small ones, and of 10, 10 and 5 for a scan of 25 with the largest leaf
    /// the model allows, which the byte limit splits.
    #[tokio::test]
    async fn sender_accepts_batches_at_the_observation_and_byte_limits() {
        use crate::discovery::telemetry::testing::{dry_run_acm_sender, logged_requests};
        use crate::discovery::telemetry::SenderSubmitter;
        use aws_workload_credentials_provider_common::telemetry::request::MAX_CERTIFICATE_BYTES;
        use base64ct::{Base64, Encoding};

        capture_logs();
        let submitter: Arc<dyn TelemetrySubmitter> =
            Arc::new(SenderSubmitter(dry_run_acm_sender()));
        let scan = |count: u16, leaf_len: usize| {
            let leaf = Base64::encode_string(&vec![0x30; leaf_len]);
            (1..=count)
                .map(|port| Observation {
                    certificate_der: Some(leaf.clone()),
                    ..successful_observation(port)
                })
                .collect::<Vec<_>>()
        };

        for observations in [scan(250, 3), scan(25, MAX_CERTIFICATE_BYTES)] {
            run_single_cycle(
                &test_config(),
                &submitter,
                &test_identity(),
                &mut 0,
                &CancellationToken::new(),
                None,
                &send_observations(observations),
            )
            .await;
        }

        let sizes: Vec<usize> = logged_requests()
            .iter()
            .map(|request| {
                request["telemetry"]["discovery"]["observations"]
                    .as_array()
                    .expect("observations is a list")
                    .len()
            })
            .collect();
        assert_eq!(sizes, [100, 100, 50, 10, 10, 5]);
    }

    #[tokio::test]
    async fn single_cycle_submits_observations() {
        let tmp = TempDir::new().unwrap();
        let config = test_config();
        let submitter: Arc<dyn TelemetrySubmitter> =
            Arc::new(MockSubmitter::with_directory(tmp.path().to_path_buf()));
        let cancel = CancellationToken::new();

        run_single_cycle(
            &config,
            &submitter,
            &test_identity(),
            &mut 41,
            &cancel,
            None,
            &send_observations(vec![Observation {
                port: 443,
                sni: None,
                outcome: ProbeOutcome::Success,
                certificate_der: Some("MIIB".into()),
                chain_der: None,
                mtls_detected: None,
                tls_version: None,
                cipher_suite: None,
                handshake_signature_scheme: None,
                key_algorithm: None,
            }]),
        )
        .await;

        let entries: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(entries.len(), 1);
        let content = std::fs::read_to_string(entries[0].path()).unwrap();
        let record: CertDiscoveryRecord = serde_json::from_str(&content).unwrap();
        assert_eq!(record.envelope.capability, Capability::Acm);
        assert_eq!(record.envelope.payload_type, PayloadType::CertDiscovery);
        assert_eq!(record.envelope.batch_sequence, 41);
        assert_eq!(record.envelope.batch_index, 0);
        assert_eq!(record.envelope.agent_version, AGENT_VERSION);
        assert_eq!(record.envelope.region, "us-west-2");
        assert_eq!(record.envelope.deployment_type, DeploymentType::Ec2);
        assert_eq!(record.envelope.host_id, "i-test");
        assert_eq!(record.envelope.boot_nonce, "boot-test");
        assert_eq!(
            record.envelope.idempotency_key,
            "i-test:boot-test:acm:cert_discovery:41:0"
        );
        assert_eq!(record.observations.len(), 1);
    }

    #[tokio::test]
    async fn single_cycle_filters_failures() {
        let tmp = TempDir::new().unwrap();
        let config = test_config();
        let submitter: Arc<dyn TelemetrySubmitter> =
            Arc::new(MockSubmitter::with_directory(tmp.path().to_path_buf()));
        let cancel = CancellationToken::new();

        run_single_cycle(
            &config,
            &submitter,
            &test_identity(),
            &mut 0,
            &cancel,
            None,
            &send_observations(vec![
                Observation {
                    port: 443,
                    sni: None,
                    outcome: ProbeOutcome::Success,
                    certificate_der: Some("cert".into()),
                    chain_der: None,
                    mtls_detected: None,
                    tls_version: None,
                    cipher_suite: None,
                    handshake_signature_scheme: None,
                    key_algorithm: None,
                },
                Observation {
                    port: 8443,
                    sni: None,
                    outcome: ProbeOutcome::ConnectionRefused,
                    certificate_der: None,
                    chain_der: None,
                    mtls_detected: None,
                    tls_version: None,
                    cipher_suite: None,
                    handshake_signature_scheme: None,
                    key_algorithm: None,
                },
            ]),
        )
        .await;

        let entries: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        let content = std::fs::read_to_string(entries[0].path()).unwrap();
        let record: CertDiscoveryRecord = serde_json::from_str(&content).unwrap();
        assert_eq!(record.observations.len(), 1);
    }

    /// Validates that a cycle with no observations creates no telemetry
    /// output file.
    #[tokio::test]
    async fn empty_cycle_writes_nothing() {
        let tmp = TempDir::new().unwrap();
        let config = test_config();
        let submitter: Arc<dyn TelemetrySubmitter> =
            Arc::new(MockSubmitter::with_directory(tmp.path().to_path_buf()));
        let cancel = CancellationToken::new();

        run_single_cycle(
            &config,
            &submitter,
            &test_identity(),
            &mut 0,
            &cancel,
            None,
            &send_observations(vec![]),
        )
        .await;

        let entries: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(entries.len(), 0);
    }

    /// Regression guard: with a bounded channel(1024), more than 1024
    /// observations would stall the sender into a false timeout.
    #[tokio::test]
    async fn unbounded_channel_handles_more_than_1024_observations() {
        tokio::time::pause();
        let config = DiscoveryConfig {
            timeout_secs: 60,
            ..test_config()
        };
        let submitter = Arc::new(MockSubmitter::log_only());
        let submitter_trait: Arc<dyn TelemetrySubmitter> = submitter.clone();
        let cancel = CancellationToken::new();
        let obs_count: usize = 1100;

        run_single_cycle(
            &config,
            &submitter_trait,
            &test_identity(),
            &mut 0,
            &cancel,
            None,
            &send_observations(
                (0..obs_count)
                    .map(|port| successful_observation(port as u16))
                    .collect(),
            ),
        )
        .await;

        assert_eq!(
            submitter.submit_count(),
            obs_count.div_ceil(MAX_OBSERVATIONS_PER_BATCH)
        );
    }

    /// Cancellation before the discovery cycle starts returns immediately with zero submissions.
    #[tokio::test]
    async fn cancel_before_cycle_produces_zero_submissions() {
        tokio::time::pause();
        let config = DiscoveryConfig {
            timeout_secs: 60,
            ..test_config()
        };
        let submitter = Arc::new(MockSubmitter::log_only());
        let submitter_trait: Arc<dyn TelemetrySubmitter> = submitter.clone();
        let cancel = CancellationToken::new();
        let probe_invoked = Arc::new(AtomicBool::new(false));
        let probe_invoked_for_probe = probe_invoked.clone();
        let mut batch_sequence = 7;

        // Cancel immediately so the biased select picks the cancel branch
        cancel.cancel();

        run_single_cycle(
            &config,
            &submitter_trait,
            &test_identity(),
            &mut batch_sequence,
            &cancel,
            None,
            &move |_: &DiscoveryConfig, sender: mpsc::UnboundedSender<Observation>| {
                let probe_invoked = probe_invoked_for_probe.clone();
                async move {
                    probe_invoked.store(true, Ordering::Relaxed);
                    let _ = sender.send(successful_observation(443));
                    ProbeStats {
                        total_targets_probed: 1,
                        successful_probes: 1,
                        failed_probes: 0,
                    }
                }
            },
        )
        .await;

        assert!(!probe_invoked.load(Ordering::Relaxed));
        assert_eq!(submitter.submit_count(), 0);
        assert_eq!(batch_sequence, 7);
    }

    /// Validates that cancellation during probing produces no submissions,
    /// preserves the batch sequence, and invokes the probe once.
    #[tokio::test]
    async fn cancel_during_cycle_produces_zero_submissions() {
        tokio::time::pause();
        let config = DiscoveryConfig {
            timeout_secs: 60,
            ..test_config()
        };
        let submitter = Arc::new(MockSubmitter::log_only());
        let submitter_trait: Arc<dyn TelemetrySubmitter> = submitter.clone();
        let cancel = CancellationToken::new();
        let cancel_for_probe = cancel.clone();
        let probe_invocations = Arc::new(AtomicUsize::new(0));
        let probe_invocations_for_probe = probe_invocations.clone();
        let mut batch_sequence = 7;

        run_single_cycle(
            &config,
            &submitter_trait,
            &test_identity(),
            &mut batch_sequence,
            &cancel,
            None,
            &move |_: &DiscoveryConfig, sender: mpsc::UnboundedSender<Observation>| {
                probe_invocations_for_probe.fetch_add(1, Ordering::Relaxed);
                let cancel = cancel_for_probe.clone();
                async move {
                    let _ = sender.send(successful_observation(443));
                    cancel.cancel();
                    std::future::pending::<ProbeStats>().await
                }
            },
        )
        .await;

        assert_eq!(probe_invocations.load(Ordering::Relaxed), 1);
        assert_eq!(submitter.submit_count(), 0);
        assert_eq!(batch_sequence, 7);
    }

    /// Shutdown interrupts a submit that is already in flight rather than
    /// waiting for the sender's full retry sequence (up to ~93 s). Without
    /// the `select!` around `submit`, a long submit blocks discovery's return
    /// and prevents the drain's final flush on Windows (15 s SCM stop).
    #[tokio::test]
    async fn cancel_during_submit_exits_promptly() {
        tokio::time::pause();
        let config = test_config();
        let pending = Arc::new(PendingSubmitter::new());
        let submitter: Arc<dyn TelemetrySubmitter> = pending.clone();
        let cancel = CancellationToken::new();
        let cancel_for_submit = cancel.clone();

        let cycle = tokio::spawn({
            let submitter = submitter.clone();
            async move {
                run_single_cycle(
                    &config,
                    &submitter,
                    &test_identity(),
                    &mut 0,
                    &cancel,
                    None,
                    &send_observations(vec![successful_observation(443)]),
                )
                .await;
            }
        });

        // Let the cycle start and enter the submit call.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert_eq!(pending.submit_count(), 1, "submit must have been entered");

        // Cancel while the submit is in flight.
        cancel_for_submit.cancel();

        tokio::time::timeout(std::time::Duration::from_secs(2), cycle)
            .await
            .expect("cycle must exit within 2 s of cancellation")
            .expect("cycle must not panic");
    }

    /// Validates the loop's schedule in virtual time: the first cycle runs
    /// within `MAX_STARTUP_JITTER` of startup, and the second no earlier than
    /// `DISCOVERY_INTERVAL` and no later than `DISCOVERY_INTERVAL` plus
    /// `MAX_CYCLE_JITTER` after the first.
    #[tokio::test]
    async fn cycles_run_within_their_jitter_bounds() {
        tokio::time::pause();
        let probes = Arc::new(AtomicUsize::new(0));
        let probes_for_loop = probes.clone();
        let send = send_observations(vec![successful_observation(443)]);
        let cancel = CancellationToken::new();
        let task = tokio::spawn(run_discovery_loop(
            test_config(),
            Arc::new(MockSubmitter::log_only()),
            test_identity(),
            cancel.clone(),
            None,
            move |config, sender| {
                probes_for_loop.fetch_add(1, Ordering::Relaxed);
                send(config, sender)
            },
        ));

        // Let the spawned loop reach its startup sleep before time moves.
        advance_time(Duration::ZERO).await;
        advance_time(MAX_STARTUP_JITTER + Duration::from_millis(1)).await;
        assert_eq!(probes.load(Ordering::Relaxed), 1, "first cycle");

        // The first cycle started at or after 0, so the second cannot start
        // before DISCOVERY_INTERVAL.
        advance_time(DISCOVERY_INTERVAL - MAX_STARTUP_JITTER - Duration::from_secs(1)).await;
        assert_eq!(probes.load(Ordering::Relaxed), 1, "second cycle ran early");

        // The first cycle started by MAX_STARTUP_JITTER, so the second starts
        // by MAX_STARTUP_JITTER + DISCOVERY_INTERVAL + MAX_CYCLE_JITTER.
        advance_time(MAX_STARTUP_JITTER + MAX_CYCLE_JITTER + Duration::from_secs(2)).await;
        assert_eq!(probes.load(Ordering::Relaxed), 2, "second cycle");

        cancel.cancel();
        task.await.expect("discovery loop task");
    }

    /// Validates that the startup log reports the configured port count and
    /// timeout, and that a loop cancelled before it starts logs nothing else:
    /// with two configured ports, a 77s timeout and an already cancelled
    /// token, the loop logs exactly the startup line and the cancellation
    /// during the startup delay.
    #[tokio::test]
    async fn startup_log_reports_configured_ports_and_timeout() {
        capture_logs();
        let config = DiscoveryConfig {
            timeout_secs: 77,
            discovery_targets: HashMap::from([(443, vec![]), (8443, vec![])]),
            ..test_config()
        };
        let cancel = CancellationToken::new();
        cancel.cancel();

        run_discovery_loop(
            config,
            Arc::new(MockSubmitter::log_only()),
            test_identity(),
            cancel,
            None,
            send_observations(vec![]),
        )
        .await;

        assert_eq!(
            logged_on_this_thread(),
            vec![
                "Certificate discovery starting: 2 ports, timeout 77s".to_string(),
                "Discovery cancelled during startup delay".to_string(),
            ]
        );
    }
}
