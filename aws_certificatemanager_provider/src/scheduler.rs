//! ACM Scheduler for managing certificate refresh tasks.
//!
//! The scheduler uses a task-per-certificate model where each configured
//! certificate has an independent refresh task. This provides fault isolation
//! so that one certificate's failure doesn't affect others.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use log::{error, info};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::certificate_file_store::certificate_store::UpdateStoreFile;
use crate::certificate_task::CertificateTask;
use crate::telemetry::automation::AutomationTelemetry;
use crate::traits::AcmCertificateExporter;
use crate::watcher_status::WatcherStatusTracker;
use aws_workload_credentials_provider_common::config::types::{AcmConfig, CertificateConfig};
use aws_workload_credentials_provider_common::refresh_executor::RefreshExecutor;
use aws_workload_credentials_provider_common::watcher_request::RequestsRoot;

/// Default refresh interval (24 hours).
const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_hours(24);

/// Default maximum jitter for refresh cycles (5 minutes).
const DEFAULT_MAX_REFRESH_JITTER: Duration = Duration::from_mins(5);

/// Default maximum jitter for staggering initial startup (5 seconds).
const DEFAULT_MAX_STARTUP_JITTER: Duration = Duration::from_secs(5);

/// Manages certificate refresh tasks.
///
/// Responsible for:
/// - Spawning one independent task per configured certificate
/// - Managing task lifecycle (start, stop)
pub struct AcmScheduler<Exporter, Store, Executor> {
    certificates: HashMap<String, CertificateConfig>,
    refresh_interval: Duration,
    max_jitter: Duration,
    acm_exporter: Arc<Exporter>,
    cert_store: Arc<Store>,
    refresh_executor: Arc<Executor>,
    telemetry: Option<AutomationTelemetry>,
    /// The watcher requests directory, shared by every watcher cert's task.
    requests_root: Option<Arc<RequestsRoot>>,
    /// The watcher status consumer shared by all certificate tasks.
    watcher_status_tracker: Arc<WatcherStatusTracker>,
}

impl<Exporter, Store, Executor> AcmScheduler<Exporter, Store, Executor>
where
    Exporter: AcmCertificateExporter + 'static,
    Store: UpdateStoreFile + Send + Sync + 'static,
    Executor: RefreshExecutor + 'static,
{
    /// Creates a new scheduler with default refresh intervals. Watcher certs
    /// queue their requests under `requests_root`; without it they fail.
    pub fn new(
        config: AcmConfig,
        acm_exporter: Arc<Exporter>,
        cert_store: Arc<Store>,
        refresh_executor: Arc<Executor>,
        requests_root: Option<Arc<RequestsRoot>>,
    ) -> Self {
        Self::with_intervals(
            config,
            acm_exporter,
            cert_store,
            refresh_executor,
            requests_root,
            DEFAULT_REFRESH_INTERVAL,
            DEFAULT_MAX_REFRESH_JITTER,
        )
    }

    /// Creates a new scheduler with custom refresh intervals.
    fn with_intervals(
        config: AcmConfig,
        acm_exporter: Arc<Exporter>,
        cert_store: Arc<Store>,
        refresh_executor: Arc<Executor>,
        requests_root: Option<Arc<RequestsRoot>>,
        refresh_interval: Duration,
        max_jitter: Duration,
    ) -> Self {
        let watcher_ids = config
            .certificates
            .values()
            .filter_map(|certificate| certificate.watcher_id.clone())
            .collect::<Vec<_>>();
        let watcher_status_tracker =
            WatcherStatusTracker::new(config.watcher_requests_dir.clone(), watcher_ids);
        Self {
            certificates: config.certificates,
            requests_root,
            watcher_status_tracker,
            refresh_interval,
            max_jitter,
            acm_exporter,
            cert_store,
            refresh_executor,
            telemetry: None,
        }
    }

    /// Sends every task's refresh results to `telemetry`, with the configured certificates.
    pub(crate) fn with_telemetry(mut self, telemetry: AutomationTelemetry) -> Self {
        self.telemetry = Some(telemetry.with_configured_certificates(self.certificates.keys()));
        self
    }

    /// Starts the scheduler and runs until cancellation.
    ///
    /// Spawns tasks for all configured certificates, then waits for shutdown.
    /// All tasks share the same cancellation token — cancelling it stops everything.
    ///
    /// Returns an error when the watcher status scanner ends before shutdown:
    /// every watcher request would otherwise wait out its deadline, so the
    /// workload is stopped instead.
    pub async fn run(
        &mut self,
        cancel_token: CancellationToken,
    ) -> Result<(), StatusScannerStopped> {
        info!(
            "ACM Scheduler starting with {} certificate(s)",
            self.certificates.len()
        );

        let mut handles = Vec::new();
        let status_handle =
            tokio::spawn(Arc::clone(&self.watcher_status_tracker).run(cancel_token.clone()));
        let certs: Vec<_> = self.certificates.drain().collect();
        for (_, config) in certs {
            handles.push(self.spawn_task(config, cancel_token.clone()));
        }

        supervise(handles, status_handle, cancel_token).await
    }

    /// Spawns a new certificate refresh task.
    fn spawn_task(
        &self,
        config: CertificateConfig,
        cancel_token: CancellationToken,
    ) -> JoinHandle<()> {
        let initial_delay = crate::utils::random_jitter(DEFAULT_MAX_STARTUP_JITTER);

        let is_watcher_cert = config.watcher_id.is_some();
        let mut task = CertificateTask::new(
            config,
            Arc::clone(&self.acm_exporter),
            Arc::clone(&self.cert_store),
            Arc::clone(&self.refresh_executor),
            self.refresh_interval,
            self.max_jitter,
            initial_delay,
        );
        if let Some(telemetry) = &self.telemetry {
            task = task.with_telemetry(telemetry.clone());
        }
        if let Some(root) = self.requests_root.as_ref().filter(|_| is_watcher_cert) {
            task = task.with_requests_root(Arc::clone(root));
        }
        task = task.with_watcher_status_tracker(Arc::clone(&self.watcher_status_tracker));

        tokio::spawn(async move {
            task.run(cancel_token).await;
        })
    }
}

/// The watcher status scanner ended before shutdown.
#[derive(Debug, thiserror::Error)]
#[error("the watcher status scanner stopped before shutdown")]
pub struct StatusScannerStopped;

/// Waits for shutdown while watching the status scanner, which serves every
/// watcher certificate. If it ends first, logs why and cancels the workload.
async fn supervise(
    handles: Vec<JoinHandle<()>>,
    mut status_handle: JoinHandle<()>,
    cancel_token: CancellationToken,
) -> Result<(), StatusScannerStopped> {
    let outcome = tokio::select! {
        biased;
        _ = cancel_token.cancelled() => {
            info!("ACM Scheduler shutting down");
            None
        }
        ended = &mut status_handle => Some(ended),
    };
    let result = match outcome {
        None => Ok(()),
        Some(ended) => {
            match ended {
                Ok(()) => error!(
                    "The watcher status scanner ended before shutdown; stopping the ACM provider"
                ),
                Err(e) => {
                    error!("The watcher status scanner failed: {e}; stopping the ACM provider")
                }
            }
            cancel_token.cancel();
            Err(StatusScannerStopped)
        }
    };

    for handle in handles {
        let _ = handle.await;
    }
    if result.is_ok() {
        let _ = status_handle.await;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn supervise_returns_ok_on_shutdown() {
        let cancel = CancellationToken::new();
        let scanner = tokio::spawn({
            let cancel = cancel.clone();
            async move { cancel.cancelled().await }
        });
        cancel.cancel();

        assert!(supervise(Vec::new(), scanner, cancel).await.is_ok());
    }

    /// A scanner that ends before shutdown stops every certificate task.
    #[tokio::test]
    async fn supervise_stops_the_workload_when_the_scanner_ends_early() {
        let cancel = CancellationToken::new();
        let task = tokio::spawn({
            let cancel = cancel.clone();
            async move { cancel.cancelled().await }
        });
        let scanner = tokio::spawn(async {});

        let result = supervise(vec![task], scanner, cancel.clone()).await;

        assert!(result.is_err());
        assert!(cancel.is_cancelled());
    }

    #[tokio::test]
    async fn supervise_stops_the_workload_when_the_scanner_panics() {
        let cancel = CancellationToken::new();
        let scanner = tokio::spawn(async { panic!("scanner bug") });

        let result = supervise(Vec::new(), scanner, cancel.clone()).await;

        assert!(result.is_err());
        assert!(cancel.is_cancelled());
    }
    use crate::acm_manager::ExportedCertificate;
    use crate::certificate_file_store::certificate_store::{
        TempFileWithDropCleanup, UpdateStoreFile,
    };
    use crate::certificate_file_store::error::StoreError;
    use crate::error::AcmManagerError;
    use aws_workload_credentials_provider_common::config::types::DiscoveryConfig;
    use aws_workload_credentials_provider_common::fs_permissions::PathPermission;
    use aws_workload_credentials_provider_common::watcher_request;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use zeroize::Zeroizing;

    struct MockExporter {
        should_fail: AtomicBool,
    }

    impl MockExporter {
        fn new(should_fail: bool) -> Self {
            Self {
                should_fail: AtomicBool::new(should_fail),
            }
        }
    }

    impl AcmCertificateExporter for MockExporter {
        async fn export_certificate(
            &self,
            _arn: &str,
            _role_arn: &str,
        ) -> Result<ExportedCertificate, AcmManagerError> {
            if self.should_fail.load(Ordering::SeqCst) {
                Err(AcmManagerError::InternalFailure("Export failed".into()))
            } else {
                Ok(ExportedCertificate {
                    certificate: "cert".into(),
                    private_key: Zeroizing::new("key".into()),
                    certificate_chain: "chain".into(),
                })
            }
        }
    }

    struct MockStore;

    impl UpdateStoreFile for MockStore {
        fn write_temp_file(
            &self,
            _path: &Path,
            _content: &str,
            _permission: Option<&PathPermission>,
            _force_update: bool,
        ) -> Result<Option<TempFileWithDropCleanup<'_>>, StoreError> {
            unimplemented!("mock only supports update_store_files")
        }

        fn atomic_rename(&self, _temp_path: &Path, _path: &Path) -> Result<(), StoreError> {
            unimplemented!("mock only supports update_store_files")
        }

        fn update_store_files(
            &self,
            _paths_contents: &[(&Path, &str, Option<&PathPermission>)],
            _force_update: bool,
        ) -> Result<bool, StoreError> {
            Ok(true)
        }
    }

    struct MockExecutor;

    impl RefreshExecutor for MockExecutor {
        async fn execute(&self, _cmd: &str, _arn: &str) -> Result<(), std::io::Error> {
            Ok(())
        }
    }

    fn test_cert(arn: &str) -> CertificateConfig {
        CertificateConfig {
            certificate_arn: arn.into(),
            certificate_path: PathBuf::from("/tmp/cert.pem"),
            private_key_path: PathBuf::from("/tmp/key.pem"),
            chain_path: Some(PathBuf::from("/tmp/chain.pem")),
            refresh_command: Some("echo refresh".into()),
            role_arn: "arn:aws:iam::123456789012:role/TestRole".into(),
            cert_and_chain_permission: None,
            key_permission: None,
            watcher_id: None,
        }
    }

    fn test_acm_config(
        certs: Vec<CertificateConfig>,
        discovery: Option<DiscoveryConfig>,
    ) -> AcmConfig {
        AcmConfig {
            enabled: true,
            certificates: certs
                .into_iter()
                .map(|c| (c.certificate_arn.clone(), c))
                .collect(),
            discovery: discovery,
            ..Default::default()
        }
    }

    fn test_scheduler_with_discovery(
        certs: Vec<CertificateConfig>,
        discovery: Option<DiscoveryConfig>,
    ) -> AcmScheduler<MockExporter, MockStore, MockExecutor> {
        AcmScheduler::with_intervals(
            test_acm_config(certs, discovery),
            Arc::new(MockExporter::new(false)),
            Arc::new(MockStore),
            Arc::new(MockExecutor),
            None,
            Duration::from_secs(60),
            Duration::from_secs(5),
        )
    }

    fn test_scheduler(
        certs: Vec<CertificateConfig>,
    ) -> AcmScheduler<MockExporter, MockStore, MockExecutor> {
        test_scheduler_with_discovery(certs, None)
    }

    const TEST_ARN: &str = "arn:aws:acm:us-east-1:123456789012:certificate/test";

    #[tokio::test(start_paused = true)]
    async fn run_spawns_tasks_and_shuts_down() {
        let mut scheduler = test_scheduler(vec![test_cert(TEST_ARN)]);
        let cancel = CancellationToken::new();

        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            scheduler.run(cancel_clone).await.unwrap();
        });

        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;

        cancel.cancel();
        handle.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn run_with_discovery_config_spawns_tasks_and_shuts_down() {
        let mut scheduler = test_scheduler_with_discovery(
            vec![test_cert(TEST_ARN)],
            Some(DiscoveryConfig::default()),
        );
        let cancel = CancellationToken::new();

        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            scheduler.run(cancel_clone).await.unwrap();
        });

        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;

        cancel.cancel();
        handle.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn with_telemetry_reports_every_task() {
        use crate::telemetry::automation::testing::RecordingSink;
        use crate::telemetry::automation::SharedIdentity;
        use aws_workload_credentials_provider_common::telemetry::{AgentIdentity, DeploymentType};

        let sink = Arc::new(RecordingSink::default());
        let identity = SharedIdentity::ready(AgentIdentity {
            host_id: "i-test".into(),
            deployment_type: DeploymentType::Ec2,
            region: "us-east-1".into(),
            boot_nonce: "boot-test".into(),
            ecs_network_mode: None,
        });
        let cancel = CancellationToken::new();
        let telemetry = AutomationTelemetry::new(identity, sink.clone());
        let mut scheduler = test_scheduler(vec![
            test_cert(TEST_ARN),
            test_cert("arn:aws:acm:us-east-1:123456789012:certificate/other"),
        ])
        .with_telemetry(telemetry);

        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            scheduler.run(cancel_clone).await.unwrap();
        });
        for _ in 0..20 {
            if sink.records().len() == 2 {
                break;
            }
            tokio::time::advance(Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
        }
        cancel.cancel();
        handle.await.unwrap();

        let records = sink.records();
        assert_eq!(records.len(), 2);
        // One sequence shared by both tasks, so the keys differ.
        assert_ne!(records[0]["idempotency_key"], records[1]["idempotency_key"]);
        assert!(records.iter().all(|r| r["total_configured_certs"] == 2));
        let mut indexes: Vec<_> = records.iter().map(|r| r["cert_index"].clone()).collect();
        indexes.sort_by_key(|index| index.as_u64());
        assert_eq!(indexes, [0, 1]);
    }

    #[tokio::test(start_paused = true)]
    async fn run_completes_initial_refresh_before_shutdown() {
        let mut scheduler = test_scheduler(vec![test_cert(TEST_ARN)]);
        let cancel = CancellationToken::new();

        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            scheduler.run(cancel_clone).await.unwrap();
        });

        // Advance past startup jitter + refresh
        tokio::time::advance(Duration::from_secs(10)).await;
        tokio::task::yield_now().await;

        cancel.cancel();
        handle.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn watcher_cert_requests_go_to_its_inbox() {
        let requests = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(requests.path().join("nginx").join("inbox")).unwrap();
        let config = test_acm_config(
            vec![CertificateConfig {
                watcher_id: Some("nginx".into()),
                ..test_cert(TEST_ARN)
            }],
            None,
        );
        let mut scheduler = AcmScheduler::with_intervals(
            config,
            Arc::new(MockExporter::new(false)),
            Arc::new(MockStore),
            Arc::new(MockExecutor),
            Some(Arc::new(RequestsRoot::open(requests.path()).unwrap())),
            Duration::from_secs(60),
            Duration::from_secs(5),
        );
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            scheduler.run(cancel_clone).await.unwrap();
        });

        let inbox = requests.path().join("nginx").join("inbox");
        for _ in 0..20 {
            tokio::time::advance(Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
            if std::fs::read_dir(&inbox).is_ok_and(|mut d| d.next().is_some()) {
                break;
            }
        }
        cancel.cancel();
        handle.await.unwrap();

        assert_eq!(std::fs::read_dir(&inbox).unwrap().count(), 1);
    }

    /// Records the certificate of each command it runs.
    #[derive(Default)]
    struct RecordingExecutor(std::sync::Mutex<Vec<String>>);

    impl RefreshExecutor for RecordingExecutor {
        async fn execute(&self, _cmd: &str, arn: &str) -> Result<(), std::io::Error> {
            self.0.lock().unwrap().push(arn.to_string());
            Ok(())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn watcher_and_direct_certs_refresh_their_own_way() {
        const WATCHED: &str = "arn:aws:acm:us-east-1:123456789012:certificate/watched";
        const DIRECT: &str = "arn:aws:acm:us-east-1:123456789012:certificate/direct";
        let requests = tempfile::tempdir().unwrap();
        let inbox = requests.path().join("nginx").join("inbox");
        std::fs::create_dir_all(&inbox).unwrap();
        let config = test_acm_config(
            vec![
                CertificateConfig {
                    watcher_id: Some("nginx".into()),
                    ..test_cert(WATCHED)
                },
                test_cert(DIRECT),
            ],
            None,
        );
        let executor = Arc::new(RecordingExecutor::default());
        let mut scheduler = AcmScheduler::with_intervals(
            config,
            Arc::new(MockExporter::new(false)),
            Arc::new(MockStore),
            executor.clone(),
            Some(Arc::new(RequestsRoot::open(requests.path()).unwrap())),
            Duration::from_secs(60),
            Duration::from_secs(5),
        );
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            scheduler.run(cancel_clone).await.unwrap();
        });

        for _ in 0..20 {
            tokio::time::advance(Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
            let queued = std::fs::read_dir(&inbox).is_ok_and(|mut d| d.next().is_some());
            if queued && !executor.0.lock().unwrap().is_empty() {
                break;
            }
        }
        cancel.cancel();
        handle.await.unwrap();

        let requests: Vec<watcher_request::RefreshRequest> = std::fs::read_dir(&inbox)
            .unwrap()
            .map(|e| serde_json::from_slice(&std::fs::read(e.unwrap().path()).unwrap()).unwrap())
            .collect();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].certificate_arn, WATCHED);
        assert_eq!(*executor.0.lock().unwrap(), vec![DIRECT.to_string()]);
    }
}
