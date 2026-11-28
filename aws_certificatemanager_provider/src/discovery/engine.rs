//! Adapter from TLS probe-engine results to discovery telemetry observations.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use aws_certificatemanager_discovery::{
    DiscoveryTargetResolver, HostAgentResolver, ProbeConfig, ProbeOutcome as EngineProbeOutcome,
    ProbeSuccess, ProbeTarget, SidecarResolver,
};
use aws_workload_credentials_provider_common::telemetry::{AgentIdentity, DeploymentType};
use base64ct::{Base64, Encoding};
use log::{debug, info};
use rustls::pki_types::ServerName;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::discovery::config::DiscoveryConfig;
use crate::discovery::payload::{Observation, ProbeOutcome};

/// Per-cycle probe statistics for discovery telemetry metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProbeStats {
    /// Total (port × SNI) targets attempted (including failures).
    pub total_targets_probed: u32,
    /// Targets that returned a certificate.
    pub successful_probes: u32,
    /// Targets that failed (refused, timeout, not TLS, handshake error).
    pub failed_probes: u32,
}

/// The resolver a discovery cycle runs with, delegating [`DiscoveryTargetResolver`] to the
/// concrete resolver it wraps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SelectedResolver {
    HostAgent(HostAgentResolver),
    Sidecar(SidecarResolver),
}

impl DiscoveryTargetResolver for SelectedResolver {
    fn resolve_targets(
        &self,
        discovery_targets: &HashMap<u16, Vec<String>>,
        timeout: Duration,
    ) -> Vec<ProbeTarget> {
        match self {
            Self::HostAgent(resolver) => resolver.resolve_targets(discovery_targets, timeout),
            Self::Sidecar(resolver) => resolver.resolve_targets(discovery_targets, timeout),
        }
    }

    fn supports_sni(&self) -> bool {
        match self {
            Self::HostAgent(resolver) => resolver.supports_sni(),
            Self::Sidecar(resolver) => resolver.supports_sni(),
        }
    }

    fn fallback_address(&self) -> Option<IpAddr> {
        match self {
            Self::HostAgent(resolver) => resolver.fallback_address(),
            Self::Sidecar(resolver) => resolver.fallback_address(),
        }
    }
}

/// The host-agent resolver: the IPv4 loopback with the IPv6 loopback as
/// fallback.
fn host_agent_resolver() -> SelectedResolver {
    SelectedResolver::HostAgent(
        HostAgentResolver::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        )
        .expect("loopback addresses are connectable"),
    )
}

/// Why a deployment runs no discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NoDiscoveryMode {
    /// The compute has no supported discovery mode.
    Unsupported(DeploymentType),
    /// An ECS task whose network mode is not `awsvpc` (`None` when task
    /// metadata gives no single mode). Only `awsvpc` gives the containers of
    /// a task one shared network namespace.
    EcsNetworkMode(Option<String>),
}

impl std::fmt::Display for NoDiscoveryMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported(deployment_type) => write!(
                f,
                "no supported discovery mode for deployment type {deployment_type:?}"
            ),
            Self::EcsNetworkMode(mode) => write!(
                f,
                "ECS task network mode is {}, not awsvpc; discovery reaches the \
                 application only when the task uses awsvpc",
                mode.as_deref().unwrap_or("unknown")
            ),
        }
    }
}

/// EC2 uses the host agent; ECS and EKS use the sidecar; Lambda, OnPrem and
/// Other have no supported discovery mode.
///
/// The sidecar reaches the application only through loopback, so it requires
/// a network namespace shared with the application container. On ECS that is
/// the `awsvpc` network mode, so any other mode runs no discovery: with
/// `bridge` the sidecar reaches only itself, and with `host` it reaches every
/// service on the host. On EKS the pod must not set `hostNetwork`; that is a
/// documented customer requirement and is not checked here.
pub(crate) fn select_resolver(
    identity: &AgentIdentity,
) -> Result<SelectedResolver, NoDiscoveryMode> {
    match identity.deployment_type {
        DeploymentType::Ec2 => Ok(host_agent_resolver()),
        DeploymentType::Ecs if identity.ecs_network_mode.as_deref() != Some("awsvpc") => Err(
            NoDiscoveryMode::EcsNetworkMode(identity.ecs_network_mode.clone()),
        ),
        DeploymentType::Ecs | DeploymentType::Eks => Ok(SelectedResolver::Sidecar(SidecarResolver)),
        deployment_type @ (DeploymentType::Lambda
        | DeploymentType::OnPrem
        | DeploymentType::Other) => Err(NoDiscoveryMode::Unsupported(deployment_type)),
    }
}

/// Probes the targets `resolver` expands from the configuration and sends
/// reportable observations as each probe completes.
///
/// Checks the cancellation token between probes so shutdown stops the
/// discovery cycle early. Observations sent before a cycle timeout stay in the
/// channel.
pub(crate) async fn probe_targets_for(
    config: &DiscoveryConfig,
    resolver: &SelectedResolver,
    cancel_token: &CancellationToken,
    sender: mpsc::UnboundedSender<Observation>,
) -> ProbeStats {
    probe_targets_with(
        config,
        resolver,
        cancel_token,
        sender,
        |target, probe_config| async move { target.probe(&probe_config).await },
    )
    .await
}

pub(crate) async fn probe_targets_with<F, Fut>(
    config: &DiscoveryConfig,
    resolver: &SelectedResolver,
    cancel_token: &CancellationToken,
    sender: mpsc::UnboundedSender<Observation>,
    probe_fn: F,
) -> ProbeStats
where
    F: Fn(ProbeTarget, ProbeConfig) -> Fut,
    Fut: std::future::Future<Output = EngineProbeOutcome>,
{
    // The discovery-cycle timeout (config.timeout_secs, default 300s) is enforced
    // by the scheduler wrapping this function in tokio::time::timeout.
    // Neither resolver uses the duration argument; it exists in the
    // DiscoveryTargetResolver trait for resolvers that enumerate targets over time.
    // Per-probe timeout (5s TCP+TLS) is set by ProbeConfig::default().
    let targets = resolver.resolve_targets(
        &config.discovery_targets,
        Duration::from_secs(config.timeout_secs),
    );
    let probe_config = ProbeConfig::default();
    let mut stats = ProbeStats::default();

    for target in targets {
        if cancel_token.is_cancelled() {
            info!(
                "Discovery: shutdown requested, {} targets probed ({} successful)",
                stats.total_targets_probed, stats.successful_probes
            );
            break;
        }
        stats.total_targets_probed += 1;
        let outcome = probe_fn(target.clone(), probe_config.clone()).await;
        if let Some(observation) = map_probe_outcome(&target, outcome) {
            if sender.send(observation).is_err() {
                // The probe succeeded but the receiver closed (scheduler shutting
                // down). This target is counted in total_targets_probed but not
                // in successful or failed, so total != successful + failed for
                // this edge case. The stats are discarded with the cycle anyway.
                info!("Discovery: observation receiver closed; stopping discovery cycle");
                break;
            }
            stats.successful_probes += 1;
        } else {
            stats.failed_probes += 1;
        }
    }
    stats
}

fn map_probe_outcome(target: &ProbeTarget, outcome: EngineProbeOutcome) -> Option<Observation> {
    match outcome {
        EngineProbeOutcome::Success(success) => Some(success_observation(target, success)),
        outcome => {
            debug!("{target}: probe completed with {}", outcome.label());
            None
        }
    }
}

fn success_observation(target: &ProbeTarget, success: ProbeSuccess) -> Observation {
    Observation {
        port: target.port,
        sni: match &target.sni {
            Some(ServerName::DnsName(name)) => Some(name.as_ref().to_owned()),
            _ => None,
        },
        outcome: ProbeOutcome::Success,
        certificate_der: Some(Base64::encode_string(&success.leaf_der)),
        chain_der: Some(
            success
                .chain_der
                .iter()
                .map(|certificate| Base64::encode_string(certificate))
                .collect(),
        ),
        mtls_detected: Some(success.mtls_detected),
        tls_version: success.tls_version,
        cipher_suite: success.cipher_suite,
        handshake_signature_scheme: success.handshake_signature_scheme,
        key_algorithm: None, // requires parsing the leaf DER SubjectPublicKeyInfo
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::{Mutex, Once, PoisonError};
    use std::thread::ThreadId;

    use aws_certificatemanager_discovery::HostAgentResolver;
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;
    use tokio_util::sync::CancellationToken;

    use super::SelectedResolver;
    use crate::discovery::config::DiscoveryConfig;

    /// The resolver EC2 must select: the IPv4 loopback with the IPv6 loopback
    /// as fallback. Written out independently of production so that a change
    /// to either side fails a test.
    pub(crate) fn loopback_host_agent() -> SelectedResolver {
        SelectedResolver::HostAgent(
            HostAgentResolver::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            )
            .expect("loopback addresses are connectable"),
        )
    }

    /// An IPv4 loopback listener that counts and drops every connection, so a
    /// test can tell whether a real probe reached its port. Dropping the
    /// connection ends the probe's TLS handshake at once, so a probe of this
    /// port produces no observation.
    pub(crate) struct CountingListener {
        port: u16,
        stop: CancellationToken,
        task: JoinHandle<usize>,
    }

    impl CountingListener {
        pub(crate) async fn bind() -> Self {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("loopback bind succeeds");
            let port = listener
                .local_addr()
                .expect("bound listener has an address")
                .port();
            let stop = CancellationToken::new();
            let stopped = stop.clone();
            let task = tokio::spawn(async move {
                let mut accepted = 0;
                loop {
                    // Biased so a connection already queued is counted before
                    // the stop request ends the task.
                    tokio::select! {
                        biased;
                        connection = listener.accept() => {
                            drop(connection.expect("loopback accept succeeds"));
                            accepted += 1;
                        }
                        () = stopped.cancelled() => return accepted,
                    }
                }
            });
            Self { port, stop, task }
        }

        /// Stops the listener and returns the number of connections it
        /// accepted.
        pub(crate) async fn accepted(self) -> usize {
            self.stop.cancel();
            self.task.await.expect("listener task does not panic")
        }

        /// An enabled configuration whose only discovery target is this listener's
        /// port with no SNI, which every resolver expands to one target.
        pub(crate) fn config(&self) -> DiscoveryConfig {
            DiscoveryConfig {
                enabled: true,
                discovery_targets: HashMap::from([(self.port, Vec::new())]),
                ..DiscoveryConfig::default()
            }
        }
    }

    /// Records log messages so tests can assert on them. `log` evaluates a
    /// message's arguments only when a logger accepts its level, so without
    /// one the formatted values are never checked. `log::set_logger` succeeds
    /// once per test binary, so every test module shares this logger.
    struct CapturingLogger;

    /// Messages recorded by [`CapturingLogger`], each with the thread that
    /// logged it. Tests run concurrently and share it, so each test reads
    /// only its own thread's messages.
    static CAPTURED_LOGS: Mutex<Vec<(ThreadId, String)>> = Mutex::new(Vec::new());

    impl log::Log for CapturingLogger {
        fn enabled(&self, metadata: &log::Metadata) -> bool {
            metadata.level() <= log::Level::Info
        }

        fn log(&self, record: &log::Record) {
            if self.enabled(record.metadata()) {
                CAPTURED_LOGS
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push((std::thread::current().id(), record.args().to_string()));
            }
        }

        fn flush(&self) {}
    }

    /// Installs [`CapturingLogger`] once for the test binary.
    pub(crate) fn capture_logs() {
        static INSTALL: Once = Once::new();
        INSTALL.call_once(|| {
            log::set_logger(&CapturingLogger)
                .expect("no other logger is installed in the provider tests");
            log::set_max_level(log::LevelFilter::Info);
        });
    }

    /// The messages logged on the calling thread, in order. Each test runs
    /// on its own thread, and a `#[tokio::test]` runtime is single-threaded,
    /// so it polls the test's futures and the tasks they spawn on that
    /// thread: this is everything the test logged.
    pub(crate) fn logged_on_this_thread() -> Vec<String> {
        let current = std::thread::current().id();
        CAPTURED_LOGS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|(thread, _)| *thread == current)
            .map(|(_, message)| message.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::test_support::loopback_host_agent as host_agent;
    use super::*;

    /// An identity of `deployment_type` reporting `ecs_network_mode`.
    fn identity(deployment_type: DeploymentType, ecs_network_mode: Option<&str>) -> AgentIdentity {
        AgentIdentity {
            host_id: "host".to_string(),
            deployment_type,
            region: "us-west-2".to_string(),
            boot_nonce: "boot-test".to_string(),
            ecs_network_mode: ecs_network_mode.map(str::to_string),
        }
    }

    /// Validates the resolver `select_resolver` returns against a hard-coded
    /// table: EC2 selects the loopback host agent; ECS selects the sidecar
    /// only in `awsvpc` network mode and runs no discovery in any other or an
    /// unknown mode; EKS selects the sidecar; Lambda, OnPrem and Other run no
    /// discovery. The table must list every `DeploymentType` variant.
    #[test]
    fn every_deployment_type_selects_its_resolver() {
        let sidecar = Ok(SelectedResolver::Sidecar(SidecarResolver));
        let ecs_mode =
            |mode: Option<&str>| Err(NoDiscoveryMode::EcsNetworkMode(mode.map(str::to_string)));
        let expected = [
            (DeploymentType::Ec2, None, Ok(host_agent())),
            (DeploymentType::Ecs, Some("awsvpc"), sidecar.clone()),
            (
                DeploymentType::Ecs,
                Some("bridge"),
                ecs_mode(Some("bridge")),
            ),
            (DeploymentType::Ecs, Some("host"), ecs_mode(Some("host"))),
            (DeploymentType::Ecs, Some("none"), ecs_mode(Some("none"))),
            (DeploymentType::Ecs, None, ecs_mode(None)),
            (DeploymentType::Eks, None, sidecar),
            (
                DeploymentType::Lambda,
                None,
                Err(NoDiscoveryMode::Unsupported(DeploymentType::Lambda)),
            ),
            (
                DeploymentType::OnPrem,
                None,
                Err(NoDiscoveryMode::Unsupported(DeploymentType::OnPrem)),
            ),
            (
                DeploymentType::Other,
                None,
                Err(NoDiscoveryMode::Unsupported(DeploymentType::Other)),
            ),
        ];
        // A newly added variant fails to compile here, as a prompt to add
        // its row to the table above.
        let listed = |deployment_type: DeploymentType| match deployment_type {
            DeploymentType::Ec2
            | DeploymentType::Ecs
            | DeploymentType::Eks
            | DeploymentType::Lambda
            | DeploymentType::OnPrem
            | DeploymentType::Other => deployment_type,
        };

        for (deployment_type, network_mode, resolver) in expected {
            assert_eq!(
                select_resolver(&identity(listed(deployment_type), network_mode)),
                resolver,
                "unexpected resolver for {deployment_type:?} in {network_mode:?}"
            );
        }
    }

    /// Validates the message each reason for running no discovery logs.
    #[test]
    fn no_discovery_mode_names_the_reason() {
        let rows = [
            (
                NoDiscoveryMode::Unsupported(DeploymentType::Lambda),
                "no supported discovery mode for deployment type Lambda",
            ),
            (
                NoDiscoveryMode::EcsNetworkMode(Some("bridge".to_string())),
                "ECS task network mode is bridge, not awsvpc; discovery reaches the \
                 application only when the task uses awsvpc",
            ),
            (
                NoDiscoveryMode::EcsNetworkMode(None),
                "ECS task network mode is unknown, not awsvpc; discovery reaches the \
                 application only when the task uses awsvpc",
            ),
        ];
        for (reason, message) in rows {
            assert_eq!(reason.to_string(), message);
        }
    }

    /// Validates that `SelectedResolver` reports the wrapped resolver's
    /// fallback address: a host agent configured without a fallback reports
    /// none where the sidecar reports the IPv6 loopback.
    #[test]
    fn selected_resolver_reports_the_wrapped_resolvers_fallback() {
        let without_fallback = SelectedResolver::HostAgent(
            HostAgentResolver::new(IpAddr::V4(Ipv4Addr::LOCALHOST), None)
                .expect("loopback addresses are connectable"),
        );
        let sidecar = SelectedResolver::Sidecar(SidecarResolver);

        assert_eq!(without_fallback.fallback_address(), None);
        assert_eq!(
            sidecar.fallback_address(),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
    }

    /// Validates that `SelectedResolver` delegates SNI support to the wrapped
    /// resolver. Both resolvers support SNI, so this checks only that the
    /// delegation reports it for each variant.
    #[test]
    fn selected_resolver_reports_sni_support_for_each_variant() {
        assert!(host_agent().supports_sni());
        assert!(SelectedResolver::Sidecar(SidecarResolver).supports_sni());
    }

    /// Validates that `SelectedResolver` delegates target expansion to the
    /// wrapped resolver: a host agent on a documentation address with no
    /// fallback expands a port with one SNI name to two targets on that
    /// address with no fallback, not to the loopback targets either built-in
    /// resolver uses.
    #[test]
    fn selected_resolver_expands_targets_with_the_wrapped_resolver() {
        let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let resolver = SelectedResolver::HostAgent(
            HostAgentResolver::new(address, None).expect("documentation address is connectable"),
        );

        let targets = resolver.resolve_targets(
            &HashMap::from([(443, vec!["api.example.com".to_string()])]),
            Duration::from_secs(300),
        );

        assert_eq!(targets.len(), 2);
        assert!(targets
            .iter()
            .all(|target| target.address == address && target.fallback_address.is_none()));
    }

    async fn drain_observations(
        mut receiver: mpsc::UnboundedReceiver<Observation>,
    ) -> Vec<Observation> {
        let mut observations = Vec::new();
        while let Some(observation) = receiver.recv().await {
            observations.push(observation);
        }
        observations
    }

    /// Validates that a token cancelled before the discovery cycle starts stops the loop
    /// before the first target: the probe function is never called and no
    /// observation is sent.
    #[tokio::test]
    async fn cancellation_before_first_target_probes_nothing() {
        let config = DiscoveryConfig::default();
        let cancel_token = CancellationToken::new();
        cancel_token.cancel();
        let probe_count = AtomicUsize::new(0);
        let (sender, receiver) = mpsc::unbounded_channel();

        probe_targets_with(&config, &host_agent(), &cancel_token, sender, |_, _| {
            probe_count.fetch_add(1, Ordering::Relaxed);
            std::future::ready(EngineProbeOutcome::ConnectionRefused)
        })
        .await;

        assert_eq!(probe_count.load(Ordering::Relaxed), 0);
        assert!(drain_observations(receiver).await.is_empty());
    }

    /// Validates that cancelling during a probe stops the discovery cycle after that
    /// target: the first probe cancels the token, so exactly one of the
    /// configured targets is probed and its observation is kept.
    #[tokio::test]
    async fn cancellation_mid_cycle_stops_after_current_target() {
        let config = DiscoveryConfig::default();
        assert!(config.discovery_targets.len() >= 3);
        let cancel_token = CancellationToken::new();
        let cancel_from_probe = cancel_token.clone();
        let probe_count = AtomicUsize::new(0);
        let (sender, receiver) = mpsc::unbounded_channel();

        probe_targets_with(&config, &host_agent(), &cancel_token, sender, |_, _| {
            probe_count.fetch_add(1, Ordering::Relaxed);
            cancel_from_probe.cancel();
            std::future::ready(EngineProbeOutcome::Success(ProbeSuccess {
                leaf_der: vec![0x30],
                chain_der: vec![],
                mtls_detected: false,
                tls_version: None,
                cipher_suite: None,
                handshake_signature_scheme: None,
            }))
        })
        .await;

        let observations = drain_observations(receiver).await;
        assert_eq!(probe_count.load(Ordering::Relaxed), 1);
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].outcome, ProbeOutcome::Success);
    }

    /// Validates that a closed observation receiver stops the discovery cycle: the first
    /// successful probe fails to send, so exactly one of the configured targets
    /// is probed.
    #[tokio::test]
    async fn sender_closed_stops_probe_early() {
        let config = DiscoveryConfig::default();
        assert!(config.discovery_targets.len() >= 2);
        let cancel = CancellationToken::new();
        let probe_count = AtomicUsize::new(0);
        let (sender, receiver) = mpsc::unbounded_channel();
        drop(receiver);

        probe_targets_with(&config, &host_agent(), &cancel, sender, |_, _| {
            probe_count.fetch_add(1, Ordering::Relaxed);
            std::future::ready(EngineProbeOutcome::Success(ProbeSuccess {
                leaf_der: vec![0x30],
                chain_der: vec![],
                mtls_detected: false,
                tls_version: None,
                cipher_suite: None,
                handshake_signature_scheme: None,
            }))
        })
        .await;

        assert_eq!(probe_count.load(Ordering::Relaxed), 1);
    }

    /// Validates that a discovery cycle timed out by the caller keeps the observations
    /// already sent: the first probe succeeds, the second never completes, and
    /// after the 100ms timeout the channel still holds the first observation.
    #[tokio::test]
    async fn timeout_preserves_partial_observations() {
        tokio::time::pause();
        let config = DiscoveryConfig::default();
        assert!(config.discovery_targets.len() >= 2);
        let cancel_token = CancellationToken::new();
        let (sender, receiver) = mpsc::unbounded_channel();
        let probe_count = AtomicUsize::new(0);
        let resolver = host_agent();

        let timeout = tokio::time::timeout(
            Duration::from_millis(100),
            probe_targets_with(&config, &resolver, &cancel_token, sender, |_, _| {
                let current = probe_count.fetch_add(1, Ordering::Relaxed);
                async move {
                    if current == 0 {
                        EngineProbeOutcome::Success(ProbeSuccess {
                            leaf_der: vec![0x30],
                            chain_der: vec![],
                            mtls_detected: false,
                            tls_version: None,
                            cipher_suite: None,
                            handshake_signature_scheme: None,
                        })
                    } else {
                        std::future::pending::<EngineProbeOutcome>().await
                    }
                }
            }),
        );
        let (timeout_result, ()) = tokio::join!(timeout, async {
            tokio::task::yield_now().await;
            tokio::time::advance(Duration::from_millis(100)).await;
        });

        assert!(timeout_result.is_err(), "probe should time out");
        let observations = drain_observations(receiver).await;
        assert_eq!(probe_count.load(Ordering::Relaxed), 2);
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].outcome, ProbeOutcome::Success);
    }

    /// Validates that a successful probe maps to an observation carrying the
    /// target's port and SNI, the base64-encoded leaf and chain, and the mTLS
    /// flag.
    #[test]
    fn success_maps_certificate_chain_and_target_metadata() {
        let target = ProbeTarget::ipv4_loopback(8443)
            .with_sni("api.example.com")
            .expect("valid SNI");
        let success = ProbeSuccess {
            leaf_der: vec![0x00, 0x01, 0x02],
            chain_der: vec![vec![0xff], vec![0x10, 0x20]],
            mtls_detected: true,
            tls_version: None,
            cipher_suite: None,
            handshake_signature_scheme: None,
        };

        let observation = map_probe_outcome(&target, EngineProbeOutcome::Success(success))
            .expect("successful probes are reportable");

        assert_eq!(observation.port, 8443);
        assert_eq!(observation.sni.as_deref(), Some("api.example.com"));
        assert_eq!(observation.outcome, ProbeOutcome::Success);
        assert_eq!(observation.certificate_der.as_deref(), Some("AAEC"));
        assert_eq!(
            observation.chain_der,
            Some(vec!["/w==".to_string(), "ECA=".to_string()])
        );
        assert_eq!(observation.mtls_detected, Some(true));
    }

    /// Validates that every non-success probe outcome maps to no observation,
    /// so failures stay in local logs and are not reported.
    #[test]
    fn non_success_outcomes_are_not_reported() {
        let target = ProbeTarget::ipv4_loopback(443);
        let outcomes = [
            EngineProbeOutcome::ConnectionRefused,
            EngineProbeOutcome::ConnectionError("unreachable".to_string()),
            EngineProbeOutcome::Timeout,
            EngineProbeOutcome::NotTls,
            EngineProbeOutcome::HandshakeError("handshake failed".to_string()),
            EngineProbeOutcome::ConfigError("invalid target".to_string()),
        ];

        for outcome in outcomes {
            let label = outcome.label();
            assert!(
                map_probe_outcome(&target, outcome).is_none(),
                "{label} must remain local-only"
            );
        }
    }

    /// Validates that a successful probe of a target without SNI produces an
    /// observation with `sni: None`.
    #[test]
    fn success_without_sni_has_none_sni() {
        let target = ProbeTarget::ipv4_loopback(443);
        let success = ProbeSuccess {
            leaf_der: vec![0x30],
            chain_der: vec![],
            mtls_detected: false,
            tls_version: None,
            cipher_suite: None,
            handshake_signature_scheme: None,
        };

        let observation = map_probe_outcome(&target, EngineProbeOutcome::Success(success))
            .expect("successful probes are reportable");

        assert!(
            observation.sni.is_none(),
            "a target with no SNI must produce an observation with sni=None"
        );
    }

    /// Validates that a successful probe with no intermediate certificates
    /// produces `chain_der: Some(vec![])` rather than `None`.
    #[test]
    fn success_with_empty_chain() {
        let target = ProbeTarget::ipv4_loopback(443);
        let success = ProbeSuccess {
            leaf_der: vec![0x30],
            chain_der: vec![],
            mtls_detected: false,
            tls_version: None,
            cipher_suite: None,
            handshake_signature_scheme: None,
        };

        let observation = map_probe_outcome(&target, EngineProbeOutcome::Success(success))
            .expect("successful probes are reportable");

        assert_eq!(
            observation.chain_der,
            Some(vec![]),
            "an empty chain_der must map to Some(vec![]), not None"
        );
    }

    #[test]
    fn tls_metadata_none_when_probe_returns_none() {
        let target = ProbeTarget::ipv4_loopback(443);
        let success = ProbeSuccess {
            leaf_der: vec![0x30],
            chain_der: vec![],
            mtls_detected: false,
            tls_version: None,
            cipher_suite: None,
            handshake_signature_scheme: None,
        };
        let observation = map_probe_outcome(&target, EngineProbeOutcome::Success(success))
            .expect("successful probes are reportable");
        assert!(observation.tls_version.is_none());
        assert!(observation.cipher_suite.is_none());
        assert!(observation.handshake_signature_scheme.is_none());
        assert!(observation.key_algorithm.is_none());
    }

    #[test]
    fn tls_metadata_propagates_from_probe_to_observation() {
        let target = ProbeTarget::ipv4_loopback(443);
        let success = ProbeSuccess {
            leaf_der: vec![0x30],
            chain_der: vec![],
            mtls_detected: false,
            tls_version: Some("TLSv1.3".to_string()),
            cipher_suite: Some("TLS_AES_256_GCM_SHA384".to_string()),
            handshake_signature_scheme: Some("ecdsa_secp256r1_sha256".to_string()),
        };
        let observation = map_probe_outcome(&target, EngineProbeOutcome::Success(success))
            .expect("successful probes are reportable");
        assert_eq!(observation.tls_version.as_deref(), Some("TLSv1.3"));
        assert_eq!(
            observation.cipher_suite.as_deref(),
            Some("TLS_AES_256_GCM_SHA384")
        );
        assert_eq!(
            observation.handshake_signature_scheme.as_deref(),
            Some("ecdsa_secp256r1_sha256")
        );
        // key_algorithm requires DER parsing — not populated yet.
        assert!(observation.key_algorithm.is_none());
    }
}
