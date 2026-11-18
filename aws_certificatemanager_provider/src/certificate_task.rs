//! Certificate task for managing refresh operations for a single certificate.
//!
//! Each certificate has an independent task that handles:
//! - Initial refresh on startup
//! - Periodic refresh at configurable intervals with jitter
//! - Failure handling with file preservation

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use super::error::RefreshError;
use crate::certificate_file_store::certificate_store::UpdateStoreFile;
use crate::traits::AcmCertificateExporter;
use aws_workload_credentials_provider_common::config::types::CertificateConfig;
use aws_workload_credentials_provider_common::fs_permissions::PathPermission;
use aws_workload_credentials_provider_common::refresh_executor::RefreshExecutor;
use aws_workload_credentials_provider_common::watcher_request::{self, RequestsRoot};
use log::{error, info, warn};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// Tracks the current status of a certificate's refresh cycle.
#[derive(Debug, Clone)]
struct CertificateRefreshState {
    pub last_refresh: Option<Instant>,
    pub next_refresh: Instant,
    pub failure_count: u32,
    /// True until the first refresh cycle completes (success or failure).
    /// Forces the refresh command to run on startup regardless of file changes.
    pub first_cycle: bool,
}

impl CertificateRefreshState {
    fn new(next_refresh: Instant) -> Self {
        Self {
            last_refresh: None,
            next_refresh,
            failure_count: 0,
            first_cycle: true,
        }
    }

    fn record_success(&mut self, next_refresh: Instant) {
        self.last_refresh = Some(Instant::now());
        self.next_refresh = next_refresh;
        self.failure_count = 0;
        self.first_cycle = false;
    }

    fn record_failure(&mut self, next_refresh: Instant) {
        self.next_refresh = next_refresh;
        self.failure_count = self.failure_count.saturating_add(1);
        self.first_cycle = false;
    }
}

/// Manages refresh operations for a single certificate.
///
/// Each task independently:
/// - Performs an initial refresh immediately on startup
/// - Schedules periodic refreshes with jitter
/// - Preserves existing files on failure
pub(crate) struct CertificateTask<Exporter, Store, Executor> {
    config: CertificateConfig,
    state: CertificateRefreshState,
    acm_exporter: Arc<Exporter>,
    cert_store: Arc<Store>,
    refresh_executor: Arc<Executor>,
    refresh_interval: Duration,
    max_jitter: Option<Duration>,
    initial_delay: Duration,
    requests_root: Option<Arc<RequestsRoot>>,
}

impl<Exporter: AcmCertificateExporter, Store: UpdateStoreFile, Executor: RefreshExecutor>
    CertificateTask<Exporter, Store, Executor>
{
    /// Creates a new certificate task.
    pub fn new(
        config: CertificateConfig,
        acm_exporter: Arc<Exporter>,
        cert_store: Arc<Store>,
        refresh_executor: Arc<Executor>,
        refresh_interval: Duration,
        max_jitter: Duration,
        initial_delay: Duration,
    ) -> Self {
        let max_jitter = if max_jitter.as_secs() > 0 {
            Some(max_jitter)
        } else {
            None
        };
        Self {
            config,
            state: CertificateRefreshState::new(Instant::now()),
            acm_exporter,
            cert_store,
            refresh_executor,
            refresh_interval,
            max_jitter,
            initial_delay,
            requests_root: None,
        }
    }

    /// Sends a watcher cert's refreshes to its watcher's inbox under `root`
    /// instead of running the command.
    pub fn with_requests_root(mut self, root: Arc<RequestsRoot>) -> Self {
        self.requests_root = Some(root);
        self
    }

    /// Runs the certificate task until cancellation.
    ///
    /// Performs an initial refresh immediately, then loops on a timer.
    /// Listens for configuration updates between refresh cycles.
    pub async fn run(&mut self, cancel_token: CancellationToken) {
        let certificate_arn = self.config.certificate_arn.clone();
        info!("Certificate task started for {}", certificate_arn);

        if !self.initial_delay.is_zero() {
            info!(
                "Waiting {}s before initial refresh for {}",
                self.initial_delay.as_secs(),
                certificate_arn
            );
            tokio::select! {
                _ = cancel_token.cancelled() => {
                    info!("Certificate task for {} cancelled during startup delay", certificate_arn);
                    return;
                }
                _ = tokio::time::sleep(self.initial_delay) => {}
            }
        }

        self.perform_refresh().await;

        loop {
            let sleep_duration = self
                .state
                .next_refresh
                .saturating_duration_since(Instant::now());

            tokio::select! {
                _ = cancel_token.cancelled() => {
                    info!("Certificate task for {} shutting down", certificate_arn);
                    break;
                }
                _ = tokio::time::sleep(sleep_duration) => {
                    self.perform_refresh().await;
                }
            }
        }
    }

    /// Executes the refresh workflow and updates state.
    async fn perform_refresh(&mut self) {
        let certificate_arn = self.config.certificate_arn.clone();
        info!("Starting certificate refresh for {}", certificate_arn);
        let next_refresh = self.next_refresh_time();

        match self.refresh().await {
            Ok(()) => {
                self.state.record_success(next_refresh);
                info!("Certificate refresh successful for {}", certificate_arn);
            }
            Err(e) => {
                self.state.record_failure(next_refresh);
                match &e {
                    RefreshError::ExportFailed { source, .. } if source.is_transient() => {
                        warn!(
                            "Transient error refreshing certificate {} (failure #{}): {}. Will retry next cycle.",
                            certificate_arn, self.state.failure_count, e
                        );
                    }
                    RefreshError::RequestFailed { .. } => {
                        warn!(
                            "Could not queue the refresh request for {} (failure #{}): {}. Will retry next cycle.",
                            certificate_arn, self.state.failure_count, e
                        );
                    }
                    _ => {
                        error!(
                            "Error refreshing certificate {} (failure #{}): {}. This may require configuration changes to resolve. Will retry next cycle.",
                            certificate_arn, self.state.failure_count, e
                        );
                    }
                }
            }
        }
    }

    /// Executes the three-step refresh workflow: export → store → notify, where
    /// notify runs the command or queues a request to the certificate's watcher.
    ///
    /// Returns `Err` on export, store, command or request failure.
    /// Only called serially from the run loop.
    async fn refresh(&mut self) -> Result<(), RefreshError> {
        let config = self.config.clone();
        let certificate_arn = &config.certificate_arn;

        let exported = self
            .acm_exporter
            .export_certificate(certificate_arn, &config.role_arn)
            .await
            .map_err(|e| RefreshError::ExportFailed {
                certificate_arn: certificate_arn.clone(),
                source: e,
            })?;

        let fullchain: String;
        let files: Vec<(&Path, &str, Option<&PathPermission>)> = match config.chain_path {
            Some(ref chain_path) => vec![
                (
                    &config.certificate_path,
                    &exported.certificate,
                    config.cert_and_chain_permission.as_ref(),
                ),
                (
                    &config.private_key_path,
                    &exported.private_key,
                    config.key_permission.as_ref(),
                ),
                (
                    chain_path,
                    &exported.certificate_chain,
                    config.cert_and_chain_permission.as_ref(),
                ),
            ],
            None => {
                fullchain = format!(
                    "{}\n{}",
                    exported.certificate.trim_end(),
                    exported.certificate_chain
                );
                vec![
                    (
                        &config.certificate_path,
                        fullchain.as_str(),
                        config.cert_and_chain_permission.as_ref(),
                    ),
                    (
                        &config.private_key_path,
                        &exported.private_key,
                        config.key_permission.as_ref(),
                    ),
                ]
            }
        };

        let changed = self
            .cert_store
            .update_store_files(&files, false)
            .map_err(|e| RefreshError::WriteFailed {
                certificate_arn: certificate_arn.clone(),
                source: e.into(),
            })?;

        if changed {
            info!("Certificate files written for {}", certificate_arn);
        }

        let failure_count = self.state.failure_count;
        let first_cycle = self.state.first_cycle;

        // Only the watcher runs a watcher cert's command, so its request doesn't depend on one.
        if config.watcher_id.is_some() || config.refresh_command.is_some() {
            let reason = if changed {
                "certificate files updated"
            } else if first_cycle {
                "first cycle after provider startup"
            } else if failure_count > 0 {
                "certificate files unchanged but previous cycle failed"
            } else {
                info!(
                    "Skipping refresh command for {}: certificate files unchanged",
                    certificate_arn
                );
                return Ok(());
            };

            if let Some(watcher_id) = &config.watcher_id {
                // The command belongs to the watcher, so never fall back to running it here.
                // A refused write (a link at `<watcher_id>` or `inbox`) is an
                // error here, so it fails the refresh rather than being logged
                // as queued.
                let name = self
                    .requests_root
                    .as_deref()
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "no watcher requests directory configured",
                        )
                    })
                    .and_then(|root| watcher_request::enqueue(root, watcher_id, certificate_arn))
                    .map_err(|e| RefreshError::RequestFailed {
                        certificate_arn: certificate_arn.clone(),
                        watcher_id: watcher_id.clone(),
                        source: e,
                    })?;
                info!(
                    "Queued refresh request {} for {} to watcher {}: {}",
                    name, certificate_arn, watcher_id, reason
                );
                return Ok(());
            }

            if let Some(command) = &config.refresh_command {
                info!(
                    "Running refresh command for {}: {}",
                    certificate_arn, reason
                );
                self.refresh_executor
                    .execute(command, certificate_arn)
                    .await
                    .map_err(|e| RefreshError::CommandFailed {
                        certificate_arn: certificate_arn.clone(),
                        source: e,
                    })?;
            }
        } else {
            let status = if changed { "updated" } else { "unchanged" };
            info!(
                "Certificate files {} for {}, no refresh command configured",
                status, certificate_arn
            );
        }

        Ok(())
    }

    /// Calculates next refresh time with random jitter.
    fn next_refresh_time(&self) -> Instant {
        let jitter = self
            .max_jitter
            .map(crate::utils::random_jitter)
            .unwrap_or(Duration::ZERO);
        Instant::now() + self.refresh_interval + jitter
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acm_manager::ExportedCertificate;
    use crate::certificate_file_store::certificate_store::{
        TempFileWithDropCleanup, UpdateStoreFile,
    };
    use crate::certificate_file_store::error::StoreError;
    use crate::error::AcmManagerError;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::Mutex;
    use zeroize::Zeroizing;

    struct MockAcmExporter {
        should_fail: AtomicBool,
        call_count: AtomicU32,
    }

    impl MockAcmExporter {
        fn new(should_fail: bool) -> Self {
            Self {
                should_fail: AtomicBool::new(should_fail),
                call_count: AtomicU32::new(0),
            }
        }
    }

    impl AcmCertificateExporter for MockAcmExporter {
        async fn export_certificate(
            &self,
            _certificate_arn: &str,
            _role_arn: &str,
        ) -> Result<ExportedCertificate, AcmManagerError> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            if self.should_fail.load(Ordering::SeqCst) {
                Err(AcmManagerError::InternalFailure("Export failed".into()))
            } else {
                Ok(ExportedCertificate {
                    certificate: "cert\n".into(),
                    private_key: Zeroizing::new("key".into()),
                    certificate_chain: "chain".into(),
                })
            }
        }
    }

    struct MockStore {
        should_fail: AtomicBool,
        call_count: AtomicU32,
        report_changed: AtomicBool,
        captured: Mutex<Vec<Vec<(String, String)>>>,
    }

    impl MockStore {
        fn new(should_fail: bool) -> Self {
            Self {
                should_fail: AtomicBool::new(should_fail),
                call_count: AtomicU32::new(0),
                report_changed: AtomicBool::new(true),
                captured: Mutex::new(Vec::new()),
            }
        }
    }

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
            self.call_count.fetch_add(1, Ordering::SeqCst);
            self.captured.lock().unwrap().push(
                _paths_contents
                    .iter()
                    .map(|(p, c, _)| (p.to_string_lossy().to_string(), c.to_string()))
                    .collect(),
            );
            if self.should_fail.load(Ordering::SeqCst) {
                Err(StoreError::UpdateFailed("Write failed".into()))
            } else {
                Ok(self.report_changed.load(Ordering::SeqCst))
            }
        }
    }

    struct MockExecutor {
        should_fail: AtomicBool,
        call_count: AtomicU32,
    }

    impl MockExecutor {
        fn new(should_fail: bool) -> Self {
            Self {
                should_fail: AtomicBool::new(should_fail),
                call_count: AtomicU32::new(0),
            }
        }
    }

    impl RefreshExecutor for MockExecutor {
        async fn execute(&self, _command: &str, _arn: &str) -> Result<(), std::io::Error> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            if self.should_fail.load(Ordering::SeqCst) {
                Err(std::io::Error::other("Execute failed"))
            } else {
                Ok(())
            }
        }
    }

    fn test_config() -> CertificateConfig {
        CertificateConfig {
            certificate_arn: "arn:aws:acm:us-east-1:123456789012:certificate/test".into(),
            certificate_path: PathBuf::from("/tmp/cert.pem"),
            private_key_path: PathBuf::from("/tmp/key.pem"),
            chain_path: Some(PathBuf::from("/tmp/chain.pem")),
            role_arn: "arn:aws:iam:us-east-1:123456789012:role/MyRole".into(),
            refresh_command: Some("echo refresh".into()),
            cert_and_chain_permission: None,
            key_permission: None,
            watcher_id: None,
        }
    }

    fn test_task(
        config: CertificateConfig,
        exporter: Arc<MockAcmExporter>,
        store: Arc<MockStore>,
        executor: Arc<MockExecutor>,
    ) -> CertificateTask<MockAcmExporter, MockStore, MockExecutor> {
        CertificateTask::new(
            config,
            exporter,
            store,
            executor,
            Duration::from_secs(60),
            Duration::from_secs(5),
            Duration::ZERO,
        )
    }

    // -- CertificateRefreshState tests --

    #[test]
    fn state_new() {
        let next = Instant::now() + Duration::from_secs(60);
        let state = CertificateRefreshState::new(next);
        assert!(state.last_refresh.is_none());
        assert_eq!(state.failure_count, 0);
    }

    #[test]
    fn state_record_success_clears_failures() {
        let mut state = CertificateRefreshState::new(Instant::now());
        state.failure_count = 3;

        state.record_success(Instant::now() + Duration::from_secs(60));
        assert!(state.last_refresh.is_some());
        assert_eq!(state.failure_count, 0);
    }

    #[test]
    fn state_record_failure_increments() {
        let mut state = CertificateRefreshState::new(Instant::now());
        let next = Instant::now() + Duration::from_secs(60);

        state.record_failure(next);
        assert_eq!(state.failure_count, 1);

        state.record_failure(next);
        assert_eq!(state.failure_count, 2);
    }

    // -- refresh workflow tests --

    #[tokio::test]
    async fn refresh_success_calls_all_components() {
        let exporter = Arc::new(MockAcmExporter::new(false));
        let store = Arc::new(MockStore::new(false));
        let executor = Arc::new(MockExecutor::new(false));
        let mut task = test_task(
            test_config(),
            exporter.clone(),
            store.clone(),
            executor.clone(),
        );

        assert!(task.refresh().await.is_ok());
        assert_eq!(exporter.call_count.load(Ordering::SeqCst), 1);
        assert_eq!(store.call_count.load(Ordering::SeqCst), 1);
        assert_eq!(executor.call_count.load(Ordering::SeqCst), 1);

        let captured = store.captured.lock().unwrap();
        let files = &captured[0];
        assert_eq!(files.len(), 3);
        assert_eq!(
            files[0],
            ("/tmp/cert.pem".to_string(), "cert\n".to_string())
        );
        assert_eq!(files[1], ("/tmp/key.pem".to_string(), "key".to_string()));
        assert_eq!(
            files[2],
            ("/tmp/chain.pem".to_string(), "chain".to_string())
        );
    }

    #[tokio::test]
    async fn refresh_fullchain_when_chain_path_none() {
        let mut config = test_config();
        config.chain_path = None;
        let exporter = Arc::new(MockAcmExporter::new(false));
        let store = Arc::new(MockStore::new(false));
        let executor = Arc::new(MockExecutor::new(false));
        let mut task = test_task(config, exporter.clone(), store.clone(), executor.clone());

        assert!(task.refresh().await.is_ok());
        assert_eq!(exporter.call_count.load(Ordering::SeqCst), 1);
        assert_eq!(store.call_count.load(Ordering::SeqCst), 1);
        assert_eq!(executor.call_count.load(Ordering::SeqCst), 1);

        let captured = store.captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        let files = &captured[0];
        assert_eq!(files.len(), 2);
        assert_eq!(
            files[0],
            ("/tmp/cert.pem".to_string(), "cert\nchain".to_string())
        );
        assert_eq!(files[1], ("/tmp/key.pem".to_string(), "key".to_string()));
    }

    #[tokio::test]
    async fn export_failure_short_circuits() {
        let exporter = Arc::new(MockAcmExporter::new(true));
        let store = Arc::new(MockStore::new(false));
        let executor = Arc::new(MockExecutor::new(false));
        let mut task = test_task(
            test_config(),
            exporter.clone(),
            store.clone(),
            executor.clone(),
        );

        let err = task.refresh().await.unwrap_err();
        assert!(matches!(err, RefreshError::ExportFailed { .. }));
        assert_eq!(store.call_count.load(Ordering::SeqCst), 0);
        assert_eq!(executor.call_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn store_failure_short_circuits() {
        let exporter = Arc::new(MockAcmExporter::new(false));
        let store = Arc::new(MockStore::new(true));
        let executor = Arc::new(MockExecutor::new(false));
        let mut task = test_task(
            test_config(),
            exporter.clone(),
            store.clone(),
            executor.clone(),
        );

        let err = task.refresh().await.unwrap_err();
        assert!(matches!(err, RefreshError::WriteFailed { .. }));
        assert_eq!(executor.call_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn executor_failure_fails_refresh() {
        let exporter = Arc::new(MockAcmExporter::new(false));
        let store = Arc::new(MockStore::new(false));
        let executor = Arc::new(MockExecutor::new(true));
        let mut task = test_task(
            test_config(),
            exporter.clone(),
            store.clone(),
            executor.clone(),
        );

        let err = task.refresh().await.unwrap_err();
        assert!(matches!(err, RefreshError::CommandFailed { .. }));
        assert_eq!(executor.call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn no_command_skips_executor() {
        let mut config = test_config();
        config.refresh_command = None;
        let exporter = Arc::new(MockAcmExporter::new(false));
        let store = Arc::new(MockStore::new(false));
        let executor = Arc::new(MockExecutor::new(false));
        let mut task = test_task(config, exporter.clone(), store.clone(), executor.clone());

        assert!(task.refresh().await.is_ok());
        assert_eq!(executor.call_count.load(Ordering::SeqCst), 0);
    }

    // -- jitter tests --

    // Paused clock: the bounds are exact however long the call takes.
    #[tokio::test(start_paused = true)]
    async fn next_refresh_time_within_bounds() {
        let exporter = Arc::new(MockAcmExporter::new(false));
        let store = Arc::new(MockStore::new(false));
        let executor = Arc::new(MockExecutor::new(false));
        let interval = Duration::from_secs(3600);
        let jitter = Duration::from_secs(60);
        let task = CertificateTask::new(
            test_config(),
            exporter,
            store,
            executor,
            interval,
            jitter,
            Duration::ZERO,
        );

        let now = Instant::now();
        let next = task.next_refresh_time();
        assert!(next >= now + interval);
        assert!(next < now + interval + jitter);
    }

    // Paused clock: the result is exact however long the call takes.
    #[tokio::test(start_paused = true)]
    async fn next_refresh_time_zero_jitter() {
        let exporter = Arc::new(MockAcmExporter::new(false));
        let store = Arc::new(MockStore::new(false));
        let executor = Arc::new(MockExecutor::new(false));
        let interval = Duration::from_secs(3600);
        let task = CertificateTask::new(
            test_config(),
            exporter,
            store,
            executor,
            interval,
            Duration::ZERO,
            Duration::ZERO,
        );

        let now = Instant::now();
        let next = task.next_refresh_time();
        assert_eq!(next, now + interval);
    }

    // -- skip refresh command tests --

    #[tokio::test]
    async fn unchanged_certs_skip_refresh_command() {
        let exporter = Arc::new(MockAcmExporter::new(false));
        let store = Arc::new(MockStore::new(false));
        store.report_changed.store(false, Ordering::SeqCst);
        let executor = Arc::new(MockExecutor::new(false));
        let mut task = test_task(
            test_config(),
            exporter.clone(),
            store.clone(),
            executor.clone(),
        );

        // Clear first_cycle so we're testing steady-state behavior
        task.state.first_cycle = false;

        assert!(task.refresh().await.is_ok());
        assert_eq!(store.call_count.load(Ordering::SeqCst), 1);
        assert_eq!(
            executor.call_count.load(Ordering::SeqCst),
            0,
            "executor should not be called when certs unchanged and not first cycle"
        );
    }

    #[tokio::test]
    async fn first_cycle_always_runs_refresh_command() {
        let exporter = Arc::new(MockAcmExporter::new(false));
        let store = Arc::new(MockStore::new(false));
        store.report_changed.store(false, Ordering::SeqCst);
        let executor = Arc::new(MockExecutor::new(false));
        let mut task = test_task(
            test_config(),
            exporter.clone(),
            store.clone(),
            executor.clone(),
        );

        // first_cycle is true by default
        assert!(task.refresh().await.is_ok());
        assert_eq!(
            executor.call_count.load(Ordering::SeqCst),
            1,
            "executor should be called on first cycle even when certs unchanged"
        );
    }

    #[tokio::test]
    async fn unchanged_certs_retry_command_after_prior_failure() {
        let exporter = Arc::new(MockAcmExporter::new(false));
        let store = Arc::new(MockStore::new(false));
        store.report_changed.store(false, Ordering::SeqCst);
        let executor = Arc::new(MockExecutor::new(false));
        let mut task = test_task(
            test_config(),
            exporter.clone(),
            store.clone(),
            executor.clone(),
        );

        // Simulate a prior failure so failure_count > 0
        // (record_failure also clears first_cycle, isolating the retry path)
        task.state.record_failure(Instant::now());

        assert!(task.refresh().await.is_ok());
        assert_eq!(
            executor.call_count.load(Ordering::SeqCst),
            1,
            "executor should be called when failure_count > 0 even if certs unchanged"
        );
    }

    // -- watcher tests --

    fn watcher_config() -> CertificateConfig {
        CertificateConfig {
            watcher_id: Some("nginx".into()),
            ..test_config()
        }
    }

    fn inbox_files(inbox: &Path) -> usize {
        std::fs::read_dir(inbox).map(|d| d.count()).unwrap_or(0)
    }

    fn requests_root(dir: &Path) -> Arc<RequestsRoot> {
        Arc::new(RequestsRoot::open(dir).unwrap())
    }

    #[tokio::test]
    async fn watcher_cert_queues_a_request_instead_of_running_the_command() {
        let root = tempfile::tempdir().unwrap();
        let inbox = root.path().join("nginx").join("inbox");
        std::fs::create_dir_all(&inbox).unwrap();
        let executor = Arc::new(MockExecutor::new(false));
        let mut task = test_task(
            watcher_config(),
            Arc::new(MockAcmExporter::new(false)),
            Arc::new(MockStore::new(false)),
            executor.clone(),
        )
        .with_requests_root(requests_root(root.path()));

        assert!(task.refresh().await.is_ok());
        assert_eq!(executor.call_count.load(Ordering::SeqCst), 0);
        assert_eq!(inbox_files(&inbox), 1);
    }

    #[tokio::test]
    async fn watcher_cert_without_a_command_still_queues_a_request() {
        let root = tempfile::tempdir().unwrap();
        let inbox = root.path().join("nginx").join("inbox");
        std::fs::create_dir_all(&inbox).unwrap();
        let mut config = watcher_config();
        config.refresh_command = None;
        let mut task = test_task(
            config,
            Arc::new(MockAcmExporter::new(false)),
            Arc::new(MockStore::new(false)),
            Arc::new(MockExecutor::new(false)),
        )
        .with_requests_root(requests_root(root.path()));

        assert!(task.refresh().await.is_ok());
        assert_eq!(inbox_files(&inbox), 1);
    }

    #[tokio::test]
    async fn unchanged_watcher_cert_queues_nothing() {
        let root = tempfile::tempdir().unwrap();
        let inbox = root.path().join("nginx").join("inbox");
        std::fs::create_dir_all(&inbox).unwrap();
        let store = Arc::new(MockStore::new(false));
        store.report_changed.store(false, Ordering::SeqCst);
        let mut task = test_task(
            watcher_config(),
            Arc::new(MockAcmExporter::new(false)),
            store,
            Arc::new(MockExecutor::new(false)),
        )
        .with_requests_root(requests_root(root.path()));
        task.state.record_success(Instant::now());

        assert!(task.refresh().await.is_ok());
        assert_eq!(inbox_files(&inbox), 0);
    }

    #[tokio::test]
    async fn failed_request_fails_the_refresh_and_is_queued_next_cycle() {
        let root = tempfile::tempdir().unwrap();
        let watcher_dir = root.path().join("nginx");
        let inbox = watcher_dir.join("inbox");
        let store = Arc::new(MockStore::new(false));
        let executor = Arc::new(MockExecutor::new(false));
        let mut task = test_task(
            watcher_config(),
            Arc::new(MockAcmExporter::new(false)),
            store.clone(),
            executor.clone(),
        )
        .with_requests_root(requests_root(root.path()));

        // The watcher's request volume isn't mounted yet.
        task.perform_refresh().await;
        assert_eq!(task.state.failure_count, 1);
        assert_eq!(executor.call_count.load(Ordering::SeqCst), 0);

        // Next cycle the files are unchanged, but the failed request is retried.
        std::fs::create_dir_all(&inbox).unwrap();
        store.report_changed.store(false, Ordering::SeqCst);
        task.perform_refresh().await;
        assert_eq!(task.state.failure_count, 0);
        assert_eq!(inbox_files(&inbox), 1);
        assert_eq!(executor.call_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn watcher_cert_without_an_inbox_never_runs_the_command() {
        let executor = Arc::new(MockExecutor::new(false));
        let mut task = test_task(
            watcher_config(),
            Arc::new(MockAcmExporter::new(false)),
            Arc::new(MockStore::new(false)),
            executor.clone(),
        );

        let err = task.refresh().await.unwrap_err();
        assert!(matches!(err, RefreshError::RequestFailed { .. }), "{err:?}");
        assert_eq!(executor.call_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn request_failure_is_a_request_error() {
        let root = tempfile::tempdir().unwrap();
        let mut task = test_task(
            watcher_config(),
            Arc::new(MockAcmExporter::new(false)),
            Arc::new(MockStore::new(false)),
            Arc::new(MockExecutor::new(false)),
        )
        .with_requests_root(requests_root(root.path()));

        let err = task.refresh().await.unwrap_err();
        assert!(
            matches!(&err, RefreshError::RequestFailed { watcher_id, .. } if watcher_id == "nginx"),
            "{err:?}"
        );
    }

    /// A symlink planted at `<requests_dir>/<watcher_id>` fails the refresh
    /// instead of queuing the request where the link points.
    #[cfg(unix)]
    #[tokio::test]
    async fn symlinked_watcher_directory_fails_the_refresh() {
        let root = tempfile::tempdir().unwrap();
        let requests = root.path().join("requests");
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir(&requests).unwrap();
        std::fs::create_dir_all(elsewhere.join("inbox")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, requests.join("nginx")).unwrap();
        let mut task = test_task(
            watcher_config(),
            Arc::new(MockAcmExporter::new(false)),
            Arc::new(MockStore::new(false)),
            Arc::new(MockExecutor::new(false)),
        )
        .with_requests_root(requests_root(&requests));

        task.perform_refresh().await;

        assert_eq!(task.state.failure_count, 1);
        assert_eq!(inbox_files(&elsewhere.join("inbox")), 0);
    }

    // -- run loop tests --

    #[tokio::test(start_paused = true)]
    async fn run_performs_initial_refresh_then_stops() {
        let exporter = Arc::new(MockAcmExporter::new(false));
        let store = Arc::new(MockStore::new(false));
        let executor = Arc::new(MockExecutor::new(false));
        let mut task = test_task(
            test_config(),
            exporter.clone(),
            store.clone(),
            executor.clone(),
        );

        let cancel = CancellationToken::new();

        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            task.run(cancel_clone).await;
            task
        });

        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        cancel.cancel();

        let task = handle.await.unwrap();

        assert!(task.state.last_refresh.is_some());
        assert_eq!(task.state.failure_count, 0);
        assert_eq!(exporter.call_count.load(Ordering::SeqCst), 1);
        assert_eq!(store.call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn run_records_failure_on_refresh_error() {
        let exporter = Arc::new(MockAcmExporter::new(true)); // export fails
        let store = Arc::new(MockStore::new(false));
        let executor = Arc::new(MockExecutor::new(false));
        let mut task = test_task(
            test_config(),
            exporter.clone(),
            store.clone(),
            executor.clone(),
        );

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            task.run(cancel_clone).await;
            task
        });

        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        cancel.cancel();

        let task = handle.await.unwrap();

        assert_eq!(task.state.failure_count, 1);
        assert!(task.state.last_refresh.is_none());
        assert_eq!(store.call_count.load(Ordering::SeqCst), 0);
        assert_eq!(executor.call_count.load(Ordering::SeqCst), 0);
    }
}
