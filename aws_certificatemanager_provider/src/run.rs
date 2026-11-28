//! Entry point for running the ACM provider as a long-lived process.

use std::future::Future;
use std::sync::Arc;

use aws_config::BehaviorVersion;
use aws_workload_credentials_provider_common::config::types::{TelemetryConfig, ValidatedConfig};
use aws_workload_credentials_provider_common::filesystem::RealFileSystem;
#[cfg(unix)]
use aws_workload_credentials_provider_common::shutdown_signal;
use aws_workload_credentials_provider_common::telemetry::{
    drain, AgentIdentity, Capability, IdentityError, TelemetryQueue, TelemetrySender,
};
use log::{info, warn};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::acm_manager::AcmManager;
use crate::certificate_file_store::certificate_store::CertificateFileStore;
use crate::discovery::{
    probe_targets_for, run_discovery_loop, select_resolver, DiscoveryConfig, LogOnlySubmitter,
    Observation, ProbeStats, SelectedResolver, SenderSubmitter, TelemetrySubmitter,
};
use crate::refresh_executor::DefaultRefreshExecutor;
use crate::scheduler::AcmScheduler;
use crate::telemetry::automation::{AutomationTelemetry, IdentityFuture, SharedIdentity};
use crate::watcher_configs;
use aws_workload_credentials_provider_common::watcher_request::RequestsRoot;

/// Future returned by the probe callback, which the scheduler invokes once per
/// discovery cycle with the configuration and an observation sender.
type ProbeFuture = std::pin::Pin<Box<dyn std::future::Future<Output = ProbeStats> + Send>>;

/// Returns a probe callback that captures the selected resolver and the
/// cancellation token.
///
/// Clones `config` into an owned future so the scheduler can invoke this as
/// `Fn` on every discovery cycle rather than consuming the configuration as `FnOnce`.
/// The captured token lets the probe loop check for shutdown between probes.
fn make_probe_fn(
    resolver: SelectedResolver,
    cancel_token: CancellationToken,
) -> impl Fn(&DiscoveryConfig, mpsc::UnboundedSender<Observation>) -> ProbeFuture {
    move |config: &DiscoveryConfig, sender| {
        let config = config.clone();
        let token = cancel_token.clone();
        Box::pin(async move { probe_targets_for(&config, &resolver, &token, sender).await })
    }
}

/// Starts discovery with the given telemetry submitter and the production
/// probe callback. See [`start_discovery_task_with`].
fn start_discovery_task<F, Fut>(
    config: Option<DiscoveryConfig>,
    token: CancellationToken,
    submitter: Arc<dyn TelemetrySubmitter>,
    configured_cert_count: Option<u32>,
    detect: F,
) -> Option<JoinHandle<()>>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = Result<AgentIdentity, IdentityError>> + Send + 'static,
{
    start_discovery_task_with(
        config,
        token,
        detect,
        submitter,
        configured_cert_count,
        make_probe_fn,
    )
}

/// Spawns the discovery task, selecting the discovery resolver from the
/// detected identity. An identity with no supported discovery mode (an
/// unsupported deployment type, or an ECS task outside `awsvpc` network mode)
/// logs the reason and starts no discovery loop.
fn start_discovery_task_with<F, Fut, M, P, PFut>(
    config: Option<DiscoveryConfig>,
    token: CancellationToken,
    detect: F,
    submitter: Arc<dyn TelemetrySubmitter>,
    configured_cert_count: Option<u32>,
    make_probe: M,
) -> Option<JoinHandle<()>>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = Result<AgentIdentity, IdentityError>> + Send + 'static,
    M: FnOnce(SelectedResolver, CancellationToken) -> P + Send + 'static,
    P: Fn(&DiscoveryConfig, mpsc::UnboundedSender<Observation>) -> PFut + Send + Sync + 'static,
    PFut: Future<Output = ProbeStats> + Send,
{
    let config = config.filter(|config| config.enabled)?;

    Some(tokio::spawn(async move {
        // Detection runs inside the spawned task so it does not block
        // certificate-refresh startup.
        let identity = match detect().await {
            Ok(identity) => identity,
            Err(error) => {
                warn!("Discovery: identity detection failed: {error}");
                return;
            }
        };
        let resolver = match select_resolver(&identity) {
            Ok(resolver) => resolver,
            Err(reason) => {
                warn!("Discovery disabled: {reason}");
                return;
            }
        };
        run_discovery_loop(
            config,
            submitter,
            identity,
            token.clone(),
            configured_cert_count,
            make_probe(resolver, token),
        )
        .await;
    }))
}

/// Discovery's detector reads the shared identity, so both capabilities use one `boot_nonce`.
fn discovery_detect(identity: SharedIdentity) -> impl FnOnce() -> IdentityFuture {
    move || Box::pin(async move { identity.get().await.cloned() })
}

/// The drain gets the sender only with `[telemetry.acm]` on: `for_capability`
/// also returns one when only discovery is on.
fn drain_sender(
    telemetry: &TelemetryConfig,
    sender: Option<TelemetrySender>,
) -> Option<TelemetrySender> {
    sender.filter(|_| telemetry.acm_enabled)
}

/// Automation records go to the drain, which exists only when `[telemetry.acm]` is on.
fn automation_telemetry(
    queue: Option<&TelemetryQueue>,
    identity: SharedIdentity,
) -> Option<AutomationTelemetry> {
    queue.map(|queue| AutomationTelemetry::new(identity, Arc::new(queue.clone())))
}

/// Runs `run` with automation telemetry when there's a sender, then stops the
/// drain and waits for its final flush, so every record `run` queued is sent.
async fn with_drain<F, Fut, T>(
    sender: Option<TelemetrySender>,
    identity: SharedIdentity,
    run: F,
) -> T
where
    F: FnOnce(Option<AutomationTelemetry>) -> Fut,
    Fut: Future<Output = T>,
{
    // Its own token, so the final flush runs only after `run` has returned.
    let drain_token = CancellationToken::new();
    let drain = sender.map(|sender| drain::spawn(sender, drain_token.clone()));
    let output = run(automation_telemetry(
        drain.as_ref().map(|(queue, _)| queue),
        identity,
    ))
    .await;
    drain_token.cancel();
    if let Some((_, task)) = drain {
        if let Err(error) = task.await {
            warn!("Telemetry: drain terminated abnormally: {error}");
        }
    }
    output
}

async fn await_discovery_task(task: Option<JoinHandle<()>>) {
    if let Some(task) = task {
        if let Err(error) = task.await {
            warn!("Discovery: task terminated abnormally: {error}");
        }
    }
}

/// Runs the ACM certificate refresh loop until SIGINT/SIGTERM.
///
/// Creates a tokio runtime, constructs all internal components, sets up
/// signal handling, and blocks until shutdown. This is the only entry
/// point callers need.
#[cfg(unix)]
pub fn run_acm(config: ValidatedConfig) -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let cancel = CancellationToken::new();
        let token = cancel.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            token.cancel();
        });

        acm_workload(config, cancel)
            .await
            .map_err(|e| -> Box<dyn std::error::Error> { e })
    })
}

/// Builds the default ACM scheduler and runs it until `token` is cancelled.
///
/// Must be called from within a tokio runtime. This is the Windows/SCM
/// entry point: the Windows service runner owns the runtime and cancels
/// `token` from the SCM Stop/Shutdown callback.
pub async fn acm_workload(
    config: ValidatedConfig,
    token: CancellationToken,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ValidatedConfig { acm, telemetry, .. } = config;
    let acm_config = acm.ok_or("ACM is not configured")?;
    info!("Initializing ACM provider");

    // Opened first, after config validation found it canonical, so a bad
    // requests directory stops startup before anything is written or any
    // AWS call is made. Every request walks from it to its watcher's inbox.
    let requests_root = if acm_config
        .certificates
        .values()
        .any(|c| c.watcher_id.is_some())
    {
        let dir = &acm_config.watcher_requests_dir;
        let root = RequestsRoot::open(dir).map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!(
                    "opening the watcher requests directory {}: {e}",
                    dir.display()
                ),
            )
        })?;
        Some(Arc::new(root))
    } else {
        None
    };

    // Before any refresh, so a watcher that starts now reads every
    // certificate. A failure stops startup.
    let written =
        watcher_configs::generate(&acm_config.watcher_config_dir, &acm_config.certificates)?;
    if written > 0 {
        info!(
            "Wrote {} watcher config(s) to {}",
            written,
            acm_config.watcher_config_dir.display()
        );
    }

    let sdk_config = aws_config::defaults(BehaviorVersion::latest()).load().await;

    // One sender per process: None without an ACM opt-in, credentials or region.
    let sender = TelemetrySender::for_capability(&telemetry, Capability::Acm, &sdk_config);
    let submitter: Arc<dyn TelemetrySubmitter> = match sender.clone() {
        Some(s) => Arc::new(SenderSubmitter(s)),
        None => Arc::new(LogOnlySubmitter::new()),
    };

    let role_arns = acm_config
        .certificates
        .values()
        .map(|c| c.role_arn.as_str());
    let acm_manager = Arc::new(AcmManager::new(&sdk_config, role_arns).await);
    let cert_store = Arc::new(CertificateFileStore::new(Box::new(RealFileSystem))?);
    let executor = Arc::new(DefaultRefreshExecutor);

    let identity = SharedIdentity::default();
    let discovery_task = start_discovery_task(
        acm_config.discovery.clone(),
        token.clone(),
        submitter,
        Some(acm_config.certificates.len() as u32),
        discovery_detect(identity.clone()),
    );

    let automation_sender = drain_sender(&telemetry, sender);
    let result = with_drain(automation_sender, identity, |telemetry| async move {
        let mut scheduler =
            AcmScheduler::new(acm_config, acm_manager, cert_store, executor, requests_root);
        if let Some(telemetry) = telemetry {
            scheduler = scheduler.with_telemetry(telemetry);
        }
        let result = scheduler.run(token).await;
        await_discovery_task(discovery_task).await;
        result
    })
    .await;

    info!("ACM provider stopped");
    Ok(result?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::telemetry::SubmitError;
    use crate::discovery::test_support::{
        capture_logs, logged_on_this_thread, loopback_host_agent as host_agent_resolver,
        CountingListener,
    };
    use crate::discovery::{probe_targets_with, CertDiscoveryRecord};
    use aws_certificatemanager_discovery::{
        ProbeConfig, ProbeOutcome as EngineProbeOutcome, ProbeSuccess, ProbeTarget, SidecarResolver,
    };
    use aws_workload_credentials_provider_common::config::types::DEFAULT_DISCOVERY_PORTS;
    use aws_workload_credentials_provider_common::telemetry::{DeploymentType, TelemetryRecord};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc as StdArc;
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::sync::Notify;

    /// Bounds every wait on a submission. Virtual time under
    /// `tokio::time::pause()`, so a missing submission fails the test instead
    /// of hanging.
    const SUBMISSION_WAIT: Duration = Duration::from_secs(10 * 60);

    /// Bounds the wait for the spawned discovery task to end after its
    /// identity is rejected. Used only by
    /// `identity_without_discovery_mode_warns_and_starts_no_discovery`.
    /// Virtual time under `tokio::time::pause()`, so a task that entered the
    /// discovery loop fails the test instead of hanging: either this wait
    /// expires during the loop's startup delay (up to
    /// `discovery::scheduler::MAX_STARTUP_JITTER`), or the loop runs a
    /// discovery cycle that the probe recorder counts.
    const REJECTED_TASK_EXIT_WAIT: Duration = Duration::from_secs(5);

    /// Boxed form of the probe callback `make_probe_fn` returns, so the test
    /// factory can name its return type.
    type BoxedProbeFn = Box<
        dyn Fn(&DiscoveryConfig, mpsc::UnboundedSender<Observation>) -> ProbeFuture + Send + Sync,
    >;

    /// A dry-run ACM sender, as `acm_workload` builds when ACM telemetry is on.
    fn dry_run_sender() -> Option<TelemetrySender> {
        let mut telemetry = TelemetryConfig::default();
        telemetry.acm_enabled = true;
        let sender = sender_for(&telemetry);
        assert!(sender.is_some());
        sender
    }

    /// The dry-run sender `for_capability` builds for `telemetry`, with test credentials.
    fn sender_for(telemetry: &TelemetryConfig) -> Option<TelemetrySender> {
        let mut telemetry = telemetry.clone();
        telemetry.dry_run = true;
        let sdk_config = aws_config::SdkConfig::builder()
            .credentials_provider(
                aws_credential_types::provider::SharedCredentialsProvider::new(
                    aws_credential_types::Credentials::new(
                        "AKIDEXAMPLE",
                        "secret",
                        None,
                        None,
                        "test",
                    ),
                ),
            )
            .region(aws_config::Region::new("us-west-2"))
            .build();
        TelemetrySender::for_capability(&telemetry, Capability::Acm, &sdk_config)
    }

    fn discovery_config(enabled: bool) -> DiscoveryConfig {
        DiscoveryConfig {
            enabled,
            ..DiscoveryConfig::default()
        }
    }

    fn log_only_submitter() -> StdArc<dyn TelemetrySubmitter> {
        StdArc::new(LogOnlySubmitter::new())
    }

    /// Captures each submitted payload as serialized, and wakes the waiting
    /// test on each submission.
    ///
    /// Parsing happens in `records`, on the test's own thread, so a payload
    /// that fails to serialize or no longer parses as `CertDiscoveryRecord`
    /// panics the test with a message naming the cause. Rejecting it inside
    /// `submit` would only surface as a missing-submission timeout.
    struct RecordingSubmitter {
        payloads: Mutex<Vec<Result<Vec<u8>, serde_json::Error>>>,
        submitted: Notify,
    }

    impl RecordingSubmitter {
        fn new() -> Self {
            Self {
                payloads: Mutex::new(Vec::new()),
                submitted: Notify::new(),
            }
        }

        fn records(&self) -> Vec<CertDiscoveryRecord> {
            self.payloads
                .lock()
                .expect("payloads lock poisoned")
                .iter()
                .map(|payload| {
                    let bytes = payload.as_ref().expect("submitted record must serialize");
                    serde_json::from_slice(bytes)
                        .expect("submitted payload must parse as CertDiscoveryRecord")
                })
                .collect()
        }
    }

    #[async_trait::async_trait]
    impl TelemetrySubmitter for RecordingSubmitter {
        async fn submit(&self, record: &dyn TelemetryRecord) -> Result<(), SubmitError> {
            self.payloads
                .lock()
                .expect("payloads lock poisoned")
                .push(record.serialize());
            self.submitted.notify_one();
            Ok(())
        }
    }

    /// Returns an identity detector that resolves at once to an identity with
    /// the given deployment type, host ID and ECS network mode, so a test
    /// chooses which discovery mode the start path selects without touching
    /// the real environment.
    fn fixed_detect(
        deployment_type: DeploymentType,
        host_id: &str,
        ecs_network_mode: Option<&str>,
    ) -> impl FnOnce() -> std::pin::Pin<
        Box<dyn Future<Output = Result<AgentIdentity, IdentityError>> + Send>,
    > {
        let host_id = host_id.to_string();
        let ecs_network_mode = ecs_network_mode.map(str::to_string);
        move || {
            Box::pin(async move {
                Ok(AgentIdentity {
                    host_id,
                    deployment_type,
                    region: "us-west-2".to_string(),
                    boot_nonce: "boot-test".to_string(),
                    ecs_network_mode,
                })
            })
        }
    }

    /// Records the resolver the start path hands the probe factory, and counts
    /// how many targets the engine's probe loop passes to the stub probe,
    /// which reports a success for each without opening a connection.
    struct ProbeRecorder {
        resolvers: StdArc<Mutex<Vec<SelectedResolver>>>,
        probes: StdArc<AtomicUsize>,
    }

    impl ProbeRecorder {
        fn new() -> Self {
            Self {
                resolvers: StdArc::new(Mutex::new(Vec::new())),
                probes: StdArc::new(AtomicUsize::new(0)),
            }
        }

        fn selected(&self) -> Vec<SelectedResolver> {
            self.resolvers
                .lock()
                .expect("resolvers lock poisoned")
                .clone()
        }

        fn probe_count(&self) -> usize {
            self.probes.load(Ordering::Relaxed)
        }

        /// Builds the probe factory passed to `start_discovery_task_with`.
        fn factory(&self) -> impl FnOnce(SelectedResolver, CancellationToken) -> BoxedProbeFn {
            let resolvers = self.resolvers.clone();
            let probes = self.probes.clone();
            move |resolver, cancel_token| {
                resolvers
                    .lock()
                    .expect("resolvers lock poisoned")
                    .push(resolver);
                Box::new(move |config: &DiscoveryConfig, sender| {
                    let config = config.clone();
                    let token = cancel_token.clone();
                    let probes = probes.clone();
                    Box::pin(async move {
                        probe_targets_with(
                            &config,
                            &resolver,
                            &token,
                            sender,
                            move |_: ProbeTarget, _: ProbeConfig| {
                                probes.fetch_add(1, Ordering::Relaxed);
                                std::future::ready(EngineProbeOutcome::Success(ProbeSuccess {
                                    leaf_der: vec![0x30],
                                    chain_der: vec![],
                                    mtls_detected: false,
                                    tls_version: None,
                                    cipher_suite: None,
                                    handshake_signature_scheme: None,
                                }))
                            },
                        )
                        .await
                    }) as ProbeFuture
                })
            }
        }
    }

    /// Drives `start_discovery_task_with` for `deployment_type` in
    /// `ecs_network_mode` until the first submission, then asserts the
    /// selected resolver, the probe count, and the envelope identity.
    async fn assert_wiring(
        deployment_type: DeploymentType,
        ecs_network_mode: Option<&str>,
        host_id: &str,
        expected_resolver: SelectedResolver,
    ) {
        tokio::time::pause();
        let config = discovery_config(true);
        // The default configuration probes each default port once, without
        // SNI.
        let expected_probes = DEFAULT_DISCOVERY_PORTS.len();
        let recorder = ProbeRecorder::new();
        let submitter = StdArc::new(RecordingSubmitter::new());
        let token = CancellationToken::new();

        let task = start_discovery_task_with(
            Some(config),
            token.clone(),
            fixed_detect(deployment_type, host_id, ecs_network_mode),
            submitter.clone(),
            None,
            recorder.factory(),
        )
        .expect("enabled discovery starts a task");

        tokio::time::timeout(SUBMISSION_WAIT, submitter.submitted.notified())
            .await
            .expect("a discovery cycle must submit a record");
        token.cancel();
        tokio::time::timeout(SUBMISSION_WAIT, await_discovery_task(Some(task)))
            .await
            .expect("cancellation must end the discovery task");

        assert_eq!(
            recorder.selected(),
            vec![expected_resolver],
            "unexpected resolver for {deployment_type:?}"
        );
        assert_eq!(recorder.probe_count(), expected_probes);
        let records = submitter.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].envelope.deployment_type, deployment_type);
        assert_eq!(records[0].envelope.host_id, host_id);
    }

    /// Validates that an EC2 identity reaches the probe with the host-agent
    /// resolver and that the submitted envelope carries that identity.
    #[tokio::test]
    async fn ec2_identity_probes_with_the_host_agent_resolver() {
        assert_wiring(DeploymentType::Ec2, None, "i-ec2", host_agent_resolver()).await;
    }

    /// Validates that an ECS identity in `awsvpc` network mode reaches the
    /// probe with the sidecar resolver and that the submitted envelope
    /// carries that identity.
    #[tokio::test]
    async fn ecs_identity_probes_with_the_sidecar_resolver() {
        assert_wiring(
            DeploymentType::Ecs,
            Some("awsvpc"),
            "ecs-task",
            SelectedResolver::Sidecar(SidecarResolver),
        )
        .await;
    }

    /// Validates that an identity with no supported discovery mode, here an
    /// ECS task in `bridge` network mode, rejects inside the spawned task:
    /// the task ends, no probe callback is built, no target is probed,
    /// nothing is submitted, and the only message logged is the warning
    /// naming the reason. Every rejection reason takes this path;
    /// `engine.rs` tests map each identity to its reason.
    #[tokio::test]
    async fn identity_without_discovery_mode_warns_and_starts_no_discovery() {
        capture_logs();
        // Paused time keeps `REJECTED_TASK_EXIT_WAIT` virtual, so the test
        // does not wait in real time.
        tokio::time::pause();
        let recorder = ProbeRecorder::new();
        let submitter = StdArc::new(RecordingSubmitter::new());

        let task = start_discovery_task_with(
            Some(discovery_config(true)),
            CancellationToken::new(),
            fixed_detect(DeploymentType::Ecs, "ecs-task", Some("bridge")),
            submitter.clone(),
            None,
            recorder.factory(),
        );

        assert!(task.is_some());
        tokio::time::timeout(REJECTED_TASK_EXIT_WAIT, await_discovery_task(task))
            .await
            .expect("a rejected identity must not enter the discovery loop");

        assert!(recorder.selected().is_empty());
        assert_eq!(recorder.probe_count(), 0);
        assert!(submitter.records().is_empty());
        assert_eq!(
            logged_on_this_thread(),
            vec![
                "Discovery disabled: ECS task network mode is bridge, not awsvpc; discovery \
                 reaches the application only when the task uses awsvpc"
                    .to_string()
            ]
        );
    }

    fn recording_detect(
        invoked: StdArc<AtomicBool>,
    ) -> impl FnOnce() -> std::pin::Pin<
        Box<dyn Future<Output = Result<AgentIdentity, IdentityError>> + Send>,
    > {
        move || {
            invoked.store(true, Ordering::Relaxed);
            Box::pin(async {
                Ok(AgentIdentity {
                    host_id: "i-test".to_string(),
                    deployment_type: DeploymentType::Ec2,
                    region: "us-west-2".to_string(),
                    boot_nonce: "boot-test".to_string(),
                    ecs_network_mode: None,
                })
            })
        }
    }

    /// Validates that a configuration with no discovery section spawns no
    /// task: `start_discovery_task` returns `None`.
    #[tokio::test]
    async fn discovery_absent_does_not_spawn_task() {
        let task = start_discovery_task(
            None,
            CancellationToken::new(),
            log_only_submitter(),
            None,
            fixed_detect(DeploymentType::Ec2, "i-test", None),
        );
        assert!(task.is_none());
    }

    /// Validates that a discovery section with `enabled: false` spawns no
    /// task: `start_discovery_task` returns `None`.
    #[tokio::test]
    async fn discovery_disabled_does_not_spawn_task() {
        let task = start_discovery_task(
            Some(discovery_config(false)),
            CancellationToken::new(),
            log_only_submitter(),
            None,
            fixed_detect(DeploymentType::Ec2, "i-test", None),
        );
        assert!(task.is_none());
    }

    /// Validates that enabled discovery spawns a task, and that a task started
    /// with an already-cancelled token ends instead of waiting out the
    /// discovery loop's startup delay. A task that ignored the token would
    /// leave this test hanging.
    #[tokio::test]
    async fn discovery_enabled_spawns_and_honors_cancellation() {
        let token = CancellationToken::new();
        token.cancel();

        let task = start_discovery_task(
            Some(discovery_config(true)),
            token,
            log_only_submitter(),
            None,
            fixed_detect(DeploymentType::Ec2, "i-test", None),
        );

        assert!(task.is_some());
        await_discovery_task(task).await;
    }

    /// Validates that an identity detection failure ends the spawned task
    /// without entering the discovery loop: the task completes within 2s of
    /// real time.
    #[tokio::test]
    async fn detect_failure_exits_task_without_entering_loop() {
        let token = CancellationToken::new();
        let task = start_discovery_task(
            Some(discovery_config(true)),
            token,
            log_only_submitter(),
            None,
            || async { Err(IdentityError::NoIdentityFound) },
        );

        assert!(task.is_some());
        // The task should exit promptly (log + return). A task that fell
        // through into the discovery loop would wait out a random startup
        // delay of up to `discovery::scheduler::MAX_STARTUP_JITTER` and then
        // probe and sleep for 24h, so it would not finish within this 2s
        // bound.
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            await_discovery_task(task),
        )
        .await;
        assert!(
            result.is_ok(),
            "task should exit promptly on detection failure"
        );
    }

    /// Validates that the production probe callback runs a real probe against
    /// the configured port: the listener sees exactly one connection. The
    /// wiring tests above replace this callback, so only this test covers it.
    #[tokio::test]
    async fn production_probe_fn_probes_the_configured_port() {
        let listener = CountingListener::bind().await;
        let probe = make_probe_fn(host_agent_resolver(), CancellationToken::new());
        let (sender, _receiver) = mpsc::unbounded_channel();

        probe(&listener.config(), sender).await;

        assert_eq!(listener.accepted().await, 1);
    }

    /// Validates that the production probe callback checks the token captured
    /// when it was built: with that token cancelled, the listener sees no
    /// connection. A callback that ignored or replaced the token would probe.
    #[tokio::test]
    async fn production_probe_fn_honors_the_captured_cancellation_token() {
        let listener = CountingListener::bind().await;
        let token = CancellationToken::new();
        let probe = make_probe_fn(host_agent_resolver(), token.clone());
        token.cancel();
        let (sender, _receiver) = mpsc::unbounded_channel();

        probe(&listener.config(), sender).await;

        assert_eq!(listener.accepted().await, 0);
    }

    #[tokio::test]
    async fn acm_workload_needs_the_acm_config() {
        let result = acm_workload(ValidatedConfig::default(), CancellationToken::new()).await;
        assert_eq!(
            result.map_err(|err| err.to_string()),
            Err("ACM is not configured".to_string())
        );
    }

    #[test]
    fn drain_sender_needs_the_automation_opt_in() {
        let mut discovery_only = TelemetryConfig::default();
        discovery_only.acm_discovery_enabled = true;
        // for_capability builds a sender for discovery alone; the drain must not get it.
        let sender = sender_for(&discovery_only);
        assert!(sender.is_some());
        assert!(drain_sender(&discovery_only, sender).is_none());

        let mut automation = TelemetryConfig::default();
        automation.acm_enabled = true;
        assert!(drain_sender(&automation, sender_for(&automation)).is_some());
    }

    #[tokio::test]
    async fn a_queue_gives_automation_telemetry() {
        assert!(automation_telemetry(None, SharedIdentity::failing()).is_none());

        let token = CancellationToken::new();
        let (queue, drain_task) = drain::spawn(dry_run_sender().unwrap(), token.clone());
        assert!(automation_telemetry(Some(&queue), SharedIdentity::failing()).is_some());
        token.cancel();
        drain_task.await.unwrap();
    }

    fn test_identity() -> AgentIdentity {
        AgentIdentity {
            host_id: "i-test".to_string(),
            deployment_type: DeploymentType::Ec2,
            region: "us-west-2".to_string(),
            boot_nonce: "boot-test".to_string(),
            ecs_network_mode: None,
        }
    }

    #[tokio::test]
    async fn a_record_queued_while_running_is_sent_when_the_drain_stops() {
        use crate::telemetry::automation::{FlowStats, Refreshed};
        use crate::telemetry::payload::SuccessStatus;
        use aws_workload_credentials_provider_common::config::types::CertificateConfig;

        // The dry-run sender logs each request at INFO. The drain runs on this
        // test's single-threaded runtime, so its lines are this thread's.
        capture_logs();
        let dir = tempfile::tempdir().unwrap();
        let arn = "arn:aws:acm:us-west-2:111122223333:certificate/with-drain";
        let config = CertificateConfig {
            certificate_arn: arn.to_string(),
            certificate_path: dir.path().join("cert.pem"),
            private_key_path: dir.path().join("key.pem"),
            chain_path: None,
            role_arn: "arn:aws:iam::111122223333:role/r".to_string(),
            cert_and_chain_permission: None,
            key_permission: None,
            refresh_command: None,
            watcher_id: None,
        };

        with_drain(
            dry_run_sender(),
            SharedIdentity::ready(test_identity()),
            |telemetry| async move {
                let telemetry = telemetry.expect("a sender gives automation telemetry");
                // Let the drain run first, so a drain stopped too early drops the record.
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                let deployed = Ok(Refreshed {
                    status: SuccessStatus::Deployed,
                    certificate_pem: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
                        .to_string(),
                    chain_pem: String::new(),
                });
                telemetry
                    .report(&config, &deployed, FlowStats::default())
                    .await;
            },
        )
        .await;

        // The drain sends only at its hourly flush or when it stops, so this
        // line shows it was stopped after the push and awaited.
        let sent = logged_on_this_thread()
            .iter()
            .filter(|line| line.starts_with('{') && line.contains(arn))
            .count();
        assert_eq!(sent, 1);
    }

    #[tokio::test]
    async fn without_a_sender_the_run_gets_no_automation_telemetry() {
        let mut got_telemetry = None;
        with_drain(None, SharedIdentity::failing(), |telemetry| {
            got_telemetry = Some(telemetry.is_some());
            async {}
        })
        .await;
        assert_eq!(got_telemetry, Some(false));
    }

    #[tokio::test]
    async fn discovery_and_automation_share_one_identity() {
        static DETECTIONS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let shared = SharedIdentity::with_detector(|| {
            let n = DETECTIONS.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                Ok(AgentIdentity {
                    host_id: "i-test".to_string(),
                    deployment_type: DeploymentType::Ec2,
                    region: "us-west-2".to_string(),
                    boot_nonce: format!("boot-{n}"),
                    ecs_network_mode: None,
                })
            })
        });
        let for_discovery = discovery_detect(shared.clone())().await.unwrap();
        let for_automation = shared.get().await.unwrap();
        assert_eq!(for_discovery.boot_nonce, for_automation.boot_nonce);
        assert_eq!(DETECTIONS.load(Ordering::SeqCst), 1);
    }

    /// Validates that awaiting an absent discovery task returns immediately,
    /// so shutdown works when discovery never started.
    #[tokio::test]
    async fn discovery_join_accepts_absent_task() {
        await_discovery_task(None).await;
    }

    /// Validates that a panic inside the discovery task is logged by
    /// `await_discovery_task` rather than propagated: awaiting the panicked
    /// task returns, and this test would fail if it re-panicked.
    #[tokio::test]
    async fn discovery_join_does_not_propagate_panic() {
        let task = tokio::spawn(async { panic!("discovery task failed") });
        await_discovery_task(Some(task)).await;
    }

    /// Validates that identity detection is not called when the configuration
    /// has no discovery section: the recording detector's flag stays unset.
    #[tokio::test]
    async fn detect_not_invoked_when_discovery_absent() {
        let invoked = StdArc::new(AtomicBool::new(false));
        let detect = recording_detect(invoked.clone());
        let task = start_discovery_task(
            None,
            CancellationToken::new(),
            log_only_submitter(),
            None,
            detect,
        );
        assert!(task.is_none());
        assert!(!invoked.load(Ordering::Relaxed));
    }

    /// Validates that identity detection is not called when discovery is
    /// disabled: the recording detector's flag stays unset.
    #[tokio::test]
    async fn detect_not_invoked_when_discovery_disabled() {
        let invoked = StdArc::new(AtomicBool::new(false));
        let detect = recording_detect(invoked.clone());
        let task = start_discovery_task(
            Some(discovery_config(false)),
            CancellationToken::new(),
            log_only_submitter(),
            None,
            detect,
        );
        assert!(task.is_none());
        assert!(!invoked.load(Ordering::Relaxed));
    }

    /// Validates that identity detection runs inside the spawned task, not
    /// during `start_discovery_task`: the recording detector's flag is unset
    /// when the call returns and set once the task completes.
    #[tokio::test]
    async fn detect_invoked_inside_spawned_task() {
        let invoked = StdArc::new(AtomicBool::new(false));
        let detect = recording_detect(invoked.clone());
        let token = CancellationToken::new();
        token.cancel();

        // Detection is not called yet — start_discovery_task returns synchronously
        let task = start_discovery_task(
            Some(discovery_config(true)),
            token,
            log_only_submitter(),
            None,
            detect,
        );
        assert!(task.is_some());
        assert!(!invoked.load(Ordering::Relaxed));

        // Detection happens inside the spawned task
        await_discovery_task(task).await;
        assert!(invoked.load(Ordering::Relaxed));
    }
}

#[cfg(all(test, unix))]
mod unix_tests {
    use super::*;
    use aws_workload_credentials_provider_common::config::types::{AcmConfig, CertificateConfig};
    use std::collections::HashMap;
    use std::path::PathBuf;

    #[tokio::test]
    async fn a_watcher_config_that_cannot_be_written_stops_startup() {
        let dir = tempfile::tempdir().unwrap();
        // A file where the watcher's directory should be.
        std::fs::write(dir.path().join("nginx"), b"").unwrap();
        let arn =
            "arn:aws:acm:us-west-2:123456789012:certificate/00000001-1234-1234-1234-123456789012";
        let cert = CertificateConfig {
            certificate_arn: arn.into(),
            certificate_path: PathBuf::from("/certs/1.pem"),
            private_key_path: PathBuf::from("/certs/1.key"),
            chain_path: None,
            role_arn: "arn:aws:iam::123456789012:role/r".into(),
            refresh_command: Some("/usr/sbin/nginx -s reload".into()),
            cert_and_chain_permission: None,
            key_permission: None,
            watcher_id: Some("nginx".into()),
        };
        // A real requests directory, so startup opens it and reaches the write.
        let requests = tempfile::tempdir().unwrap();
        let mut config = ValidatedConfig::default();
        config.acm = Some(AcmConfig {
            enabled: true,
            certificates: HashMap::from([(arn.to_string(), cert)]),
            watcher_config_dir: dir.path().to_path_buf(),
            watcher_requests_dir: requests.path().to_path_buf(),
            ..Default::default()
        });

        // Bounded, so a startup that doesn't stop fails the test instead of hanging.
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            acm_workload(config, CancellationToken::new()),
        )
        .await
        .expect("startup should stop on the write error");
        let err = result.unwrap_err();

        assert!(
            err.to_string()
                .contains("writing the config for watcher nginx"),
            "{err}"
        );
    }

    /// A requests root that is a symlink is refused when it is opened, and
    /// that stops startup before any refresh.
    #[tokio::test]
    async fn a_requests_directory_that_cannot_be_opened_stops_startup() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join("config");
        let real_requests = dir.path().join("real-requests");
        let requests = dir.path().join("requests");
        std::fs::create_dir(&config_dir).unwrap();
        std::fs::create_dir(&real_requests).unwrap();
        std::os::unix::fs::symlink(&real_requests, &requests).unwrap();
        let arn =
            "arn:aws:acm:us-west-2:123456789012:certificate/00000001-1234-1234-1234-123456789012";
        let cert = CertificateConfig {
            certificate_arn: arn.into(),
            certificate_path: PathBuf::from("/certs/1.pem"),
            private_key_path: PathBuf::from("/certs/1.key"),
            chain_path: None,
            role_arn: "arn:aws:iam::123456789012:role/r".into(),
            refresh_command: Some("/usr/sbin/nginx -s reload".into()),
            cert_and_chain_permission: None,
            key_permission: None,
            watcher_id: Some("nginx".into()),
        };
        let mut config = ValidatedConfig::default();
        config.acm = Some(AcmConfig {
            enabled: true,
            certificates: HashMap::from([(arn.to_string(), cert)]),
            watcher_config_dir: config_dir,
            watcher_requests_dir: requests.clone(),
            ..Default::default()
        });

        // Bounded, so a startup that doesn't stop fails the test instead of hanging.
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            acm_workload(config, CancellationToken::new()),
        )
        .await
        .expect("startup should stop on the open error");
        let err = result.unwrap_err();

        assert!(
            err.to_string().contains(&format!(
                "opening the watcher requests directory {}",
                requests.display()
            )),
            "{err}"
        );
    }
}
