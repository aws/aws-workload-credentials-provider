//! Certificate task for managing refresh operations for a single certificate.
//!
//! Each certificate has an independent task that handles:
//! - Initial refresh on startup
//! - Periodic refresh at configurable intervals with jitter
//! - Failure handling with file preservation

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use super::error::{RefreshError, WatcherFailureOutcome};
use crate::certificate_file_store::certificate_store::UpdateStoreFile;
use crate::telemetry::automation::{AutomationTelemetry, FlowStats, Refreshed};
use crate::telemetry::SuccessStatus;
use crate::traits::AcmCertificateExporter;
use aws_workload_credentials_provider_common::config::types::CertificateConfig;
use aws_workload_credentials_provider_common::fs_permissions::PathPermission;
use aws_workload_credentials_provider_common::refresh_executor::{
    RefreshExecutor, MAX_STARTUP_HOLD, REFRESH_COMMAND_TIMEOUT,
};
use aws_workload_credentials_provider_common::watcher_request::RequestsRoot;
use aws_workload_credentials_provider_common::watcher_status::StatusOutcome;

use crate::watcher_status::{PendingWaitError, WatcherStatusTracker, STATUS_RESCAN_INTERVAL};
use log::{error, info, warn};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// How long the provider waits for a watcher status before reporting no status.
///
/// Longer than the protocol's 15-minute window on purpose. A watcher runs one
/// reload per command at a time, so a request can queue behind a running
/// reload (one `REFRESH_COMMAND_TIMEOUT`) before its own runs (another), and a
/// starting watcher may hold requests for up to `MAX_STARTUP_HOLD`. One rescan
/// interval covers finding the status. 15 minutes would report a reload that
/// is still legitimately queued or running as missing.
pub(crate) const WATCHER_RESPONSE_TIMEOUT: Duration = Duration::from_secs(
    MAX_STARTUP_HOLD.as_secs()
        + 2 * REFRESH_COMMAND_TIMEOUT.as_secs()
        + STATUS_RESCAN_INTERVAL.as_secs(),
);

/// Tracks the current status of a certificate's refresh cycle.
#[derive(Debug, Clone)]
struct CertificateRefreshState {
    pub last_refresh: Option<Instant>,
    pub next_refresh: Instant,
    pub failure_count: u32,
    /// Refreshes completed since startup, successful or not.
    pub refreshes: u64,
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
            refreshes: 0,
            first_cycle: true,
        }
    }

    fn record_success(&mut self, next_refresh: Instant) {
        self.last_refresh = Some(Instant::now());
        self.next_refresh = next_refresh;
        self.failure_count = 0;
        self.refreshes += 1;
        self.first_cycle = false;
    }

    fn record_failure(&mut self, next_refresh: Instant) {
        self.next_refresh = next_refresh;
        self.failure_count = self.failure_count.saturating_add(1);
        self.refreshes += 1;
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
    telemetry: Option<AutomationTelemetry>,
    requests_root: Option<Arc<RequestsRoot>>,
    watcher_status_tracker: Option<Arc<WatcherStatusTracker>>,
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
            telemetry: None,
            requests_root: None,
            watcher_status_tracker: None,
        }
    }

    /// Consumes statuses for requests queued by this task.
    pub(crate) fn with_watcher_status_tracker(
        mut self,
        tracker: Arc<WatcherStatusTracker>,
    ) -> Self {
        self.watcher_status_tracker = Some(tracker);
        self
    }

    /// Reports an automation telemetry record after every refresh.
    pub fn with_telemetry(mut self, telemetry: AutomationTelemetry) -> Self {
        self.telemetry = Some(telemetry);
        self
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

        if !self.perform_refresh_with_cancel(&cancel_token).await {
            info!(
                "Certificate task for {} cancelled during refresh",
                certificate_arn
            );
            return;
        }

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
                    if !self.perform_refresh_with_cancel(&cancel_token).await {
                        info!("Certificate task for {} cancelled during refresh", certificate_arn);
                        break;
                    }
                }
            }
        }
    }

    /// Executes the refresh workflow and updates state.
    async fn perform_refresh_with_cancel(&mut self, cancel: &CancellationToken) -> bool {
        let certificate_arn = self.config.certificate_arn.clone();
        info!("Starting certificate refresh for {}", certificate_arn);
        let next_refresh = self.next_refresh_time();
        let consecutive_failures = self.state.failure_count;
        let cycle = self.state.refreshes;
        let started = Instant::now();

        let result = match self.refresh_with_cancel(cancel).await {
            Ok(Some(refreshed)) => Ok(refreshed),
            Ok(None) => return false,
            Err(error) => Err(error),
        };
        let stats = FlowStats {
            duration: started.elapsed(),
            consecutive_failures,
            cycle,
        };

        match &result {
            Ok(_) => {
                self.state.record_success(next_refresh);
                info!("Certificate refresh successful for {}", certificate_arn);
            }
            Err(e) => {
                self.state.record_failure(next_refresh);
                match e {
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

        // Last, so the next refresh time is already set and a slow report can't delay it.
        if let Some(telemetry) = &self.telemetry {
            telemetry.report(&self.config, &result, stats).await;
        }
        true
    }

    #[cfg(test)]
    async fn perform_refresh(&mut self) {
        assert!(
            self.perform_refresh_with_cancel(&CancellationToken::new())
                .await
        );
    }

    #[cfg(test)]
    async fn refresh(&mut self) -> Result<Refreshed, RefreshError> {
        Ok(self
            .refresh_with_cancel(&CancellationToken::new())
            .await?
            .expect("uncancelled test refresh"))
    }

    async fn refresh_with_cancel(
        &mut self,
        cancel: &CancellationToken,
    ) -> Result<Option<Refreshed>, RefreshError> {
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
        let refreshed = |status| Refreshed {
            status,
            certificate_pem: exported.certificate,
            chain_pem: exported.certificate_chain,
        };

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
                return Ok(Some(refreshed(SuccessStatus::Unchanged)));
            };

            if let Some(watcher_id) = &config.watcher_id {
                let tracker = self.watcher_status_tracker.as_ref().ok_or_else(|| {
                    RefreshError::RequestFailed {
                        certificate_arn: certificate_arn.clone(),
                        watcher_id: watcher_id.clone(),
                        files_changed: changed,
                        source: std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "no watcher status tracker configured",
                        ),
                    }
                })?;
                let root =
                    self.requests_root
                        .as_deref()
                        .ok_or_else(|| RefreshError::RequestFailed {
                            certificate_arn: certificate_arn.clone(),
                            watcher_id: watcher_id.clone(),
                            files_changed: changed,
                            source: std::io::Error::new(
                                std::io::ErrorKind::NotFound,
                                "no watcher requests directory configured",
                            ),
                        })?;
                // Checked before the request is visible: a current watcher creates
                // `outbox/` before `inbox/`. An outbox that can't be opened fails
                // now, since no status could be read from it.
                let reports_status = tracker.reports_status(watcher_id).map_err(|source| {
                    RefreshError::RequestFailed {
                        certificate_arn: certificate_arn.clone(),
                        watcher_id: watcher_id.clone(),
                        files_changed: changed,
                        source,
                    }
                })?;
                let (pending, name) = tracker
                    .enqueue_request(root, watcher_id, certificate_arn)
                    .map_err(|source| RefreshError::RequestFailed {
                        certificate_arn: certificate_arn.clone(),
                        watcher_id: watcher_id.clone(),
                        files_changed: changed,
                        source,
                    })?;
                info!(
                    "Queued refresh request {} for {} to watcher {}: {}",
                    name, certificate_arn, watcher_id, reason
                );
                // A watcher without an outbox still runs the request but never
                // reports back, so waiting would only end in a false timeout.
                if !reports_status {
                    tracker.warn_pre_status(watcher_id);
                    drop(pending);
                    return Ok(Some(refreshed(if changed {
                        SuccessStatus::WrittenNotReloaded
                    } else {
                        SuccessStatus::Unchanged
                    })));
                }
                let status = match pending
                    .wait(Instant::now() + WATCHER_RESPONSE_TIMEOUT, cancel)
                    .await
                {
                    Ok(status) => status,
                    Err(PendingWaitError::Cancelled) => return Ok(None),
                    Err(PendingWaitError::Deadline) => {
                        return Err(RefreshError::WatcherNoStatus {
                            certificate_arn: certificate_arn.clone(),
                            files_changed: changed,
                        });
                    }
                };
                return match status.outcome {
                    StatusOutcome::Success => Ok(Some(refreshed(if changed {
                        SuccessStatus::Deployed
                    } else {
                        SuccessStatus::Reloaded
                    }))),
                    StatusOutcome::Timeout => Err(RefreshError::WatcherTimeout {
                        certificate_arn: certificate_arn.clone(),
                        files_changed: changed,
                    }),
                    StatusOutcome::Failure => Err(RefreshError::WatcherFailed {
                        certificate_arn: certificate_arn.clone(),
                        files_changed: changed,
                        outcome: WatcherFailureOutcome::Failure,
                    }),
                    StatusOutcome::NotFound => Err(RefreshError::WatcherFailed {
                        certificate_arn: certificate_arn.clone(),
                        files_changed: changed,
                        outcome: WatcherFailureOutcome::NotFound,
                    }),
                    StatusOutcome::Superseded => Err(RefreshError::WatcherFailed {
                        certificate_arn: certificate_arn.clone(),
                        files_changed: changed,
                        outcome: WatcherFailureOutcome::Superseded,
                    }),
                };
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
                        files_changed: changed,
                        source: e,
                    })?;
                Ok(Some(refreshed(if changed {
                    SuccessStatus::Deployed
                } else {
                    SuccessStatus::Reloaded
                })))
            } else {
                unreachable!(
                    "refresh_command must be present when watcher_id is absent in the notify branch"
                )
            }
        } else {
            let status = if changed { "updated" } else { "unchanged" };
            info!(
                "Certificate files {} for {}, no refresh command configured",
                status, certificate_arn
            );
            Ok(Some(refreshed(if changed {
                SuccessStatus::WrittenNotReloaded
            } else {
                SuccessStatus::Unchanged
            })))
        }
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
    use crate::discovery::test_support::{capture_logs, logged_on_this_thread};
    use crate::error::AcmManagerError;
    use crate::telemetry::automation::testing::RecordingSink;
    use crate::telemetry::automation::SharedIdentity;
    use aws_workload_credentials_provider_common::telemetry::{AgentIdentity, DeploymentType};
    use aws_workload_credentials_provider_common::watcher_request::RefreshRequest;
    use aws_workload_credentials_provider_common::watcher_status::{
        status_filename, StatusOutcome, StatusRecord,
    };
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

        let refreshed = task.refresh().await.unwrap();
        assert_eq!(refreshed.status, SuccessStatus::Deployed);
        assert_eq!(refreshed.certificate_pem, "cert\n");
        assert_eq!(refreshed.chain_pem, "chain");
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

        assert_eq!(
            task.refresh().await.unwrap().status,
            SuccessStatus::WrittenNotReloaded
        );
        assert_eq!(executor.call_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn no_command_and_unchanged_is_unchanged() {
        let mut config = test_config();
        config.refresh_command = None;
        let store = Arc::new(MockStore::new(false));
        store.report_changed.store(false, Ordering::SeqCst);
        let executor = Arc::new(MockExecutor::new(false));
        let mut task = test_task(
            config,
            Arc::new(MockAcmExporter::new(false)),
            store,
            executor.clone(),
        );

        assert_eq!(
            task.refresh().await.unwrap().status,
            SuccessStatus::Unchanged
        );
        assert_eq!(executor.call_count.load(Ordering::SeqCst), 0);
    }

    // -- jitter tests --

    #[test]
    fn next_refresh_time_within_bounds() {
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
        assert!(next <= now + interval + jitter + Duration::from_millis(100));
    }

    #[test]
    fn next_refresh_time_zero_jitter() {
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
        assert!(next >= now + interval);
        assert!(next <= now + interval + Duration::from_millis(100));
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

        assert_eq!(
            task.refresh().await.unwrap().status,
            SuccessStatus::Unchanged
        );
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
        assert_eq!(
            task.refresh().await.unwrap().status,
            SuccessStatus::Reloaded
        );
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

        assert_eq!(
            task.refresh().await.unwrap().status,
            SuccessStatus::Reloaded
        );
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

    /// Creates `<root>/nginx/inbox` and `outbox` as a current watcher does at
    /// startup, and returns the inbox.
    fn create_watcher_dirs(root: &Path) -> PathBuf {
        let watcher = root.join("nginx");
        std::fs::create_dir_all(watcher.join("outbox")).unwrap();
        let inbox = watcher.join("inbox");
        std::fs::create_dir_all(&inbox).unwrap();
        inbox
    }

    fn inbox_files(inbox: &Path) -> usize {
        std::fs::read_dir(inbox).map(|d| d.count()).unwrap_or(0)
    }

    fn requests_root(dir: &Path) -> Arc<RequestsRoot> {
        Arc::new(RequestsRoot::open(dir).unwrap())
    }

    async fn complete_next_request(
        root: &Path,
        tracker: &WatcherStatusTracker,
        outcome: StatusOutcome,
    ) -> StatusRecord {
        complete_next_request_with_detail(root, tracker, outcome, None).await
    }

    async fn complete_next_request_with_detail(
        root: &Path,
        tracker: &WatcherStatusTracker,
        outcome: StatusOutcome,
        error_detail: Option<String>,
    ) -> StatusRecord {
        let inbox = root.join("nginx").join("inbox");
        // Real time, so a request that never arrives fails the test instead
        // of spinning until CI cancels the job.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let request_path = loop {
            if let Some(entry) = std::fs::read_dir(&inbox)
                .unwrap()
                .next()
                .transpose()
                .unwrap()
            {
                break entry.path();
            }
            assert!(
                std::time::Instant::now() < deadline,
                "no request reached {}",
                inbox.display()
            );
            tokio::task::yield_now().await;
        };
        let request: RefreshRequest =
            serde_json::from_slice(&std::fs::read(&request_path).unwrap()).unwrap();
        std::fs::remove_file(request_path).unwrap();
        let outbox = root.join("nginx").join("outbox");
        std::fs::create_dir_all(&outbox).unwrap();
        let ran = !matches!(outcome, StatusOutcome::NotFound | StatusOutcome::Superseded);
        let status = StatusRecord {
            command_id: request.command_id.clone(),
            cert_arn: request.certificate_arn,
            request_created_at: request.created_at,
            outcome,
            exit_code: match outcome {
                StatusOutcome::Success => Some(0),
                StatusOutcome::Failure => Some(17),
                _ => None,
            },
            started_at: ran.then(|| "2025-01-01T00:00:01Z".into()),
            completed_at: ran.then(|| "2025-01-01T00:00:02Z".into()),
            error_detail: error_detail.filter(|_| ran),
        };
        std::fs::write(
            outbox.join(status_filename(&request.command_id)),
            serde_json::to_vec(&status).unwrap(),
        )
        .unwrap();
        tracker.process_watcher("nginx");
        status
    }

    #[tokio::test]
    async fn watcher_cert_queues_a_request_instead_of_running_the_command() {
        let root = crate::test_dirs::tempdir();
        let inbox = create_watcher_dirs(root.path());
        let executor = Arc::new(MockExecutor::new(false));
        let tracker = WatcherStatusTracker::new(root.path().to_path_buf(), ["nginx".into()]);
        let mut task = test_task(
            watcher_config(),
            Arc::new(MockAcmExporter::new(false)),
            Arc::new(MockStore::new(false)),
            executor.clone(),
        )
        .with_requests_root(requests_root(root.path()))
        .with_watcher_status_tracker(Arc::clone(&tracker));

        let (result, _) = tokio::join!(
            task.refresh(),
            complete_next_request(root.path(), &tracker, StatusOutcome::Success)
        );
        assert!(result.is_ok());
        assert_eq!(executor.call_count.load(Ordering::SeqCst), 0);
        assert_eq!(inbox_files(&inbox), 0);
    }

    #[tokio::test]
    async fn watcher_cert_without_a_command_still_queues_a_request() {
        let root = crate::test_dirs::tempdir();
        let inbox = create_watcher_dirs(root.path());
        let mut config = watcher_config();
        config.refresh_command = None;
        let tracker = WatcherStatusTracker::new(root.path().to_path_buf(), ["nginx".into()]);
        let mut task = test_task(
            config,
            Arc::new(MockAcmExporter::new(false)),
            Arc::new(MockStore::new(false)),
            Arc::new(MockExecutor::new(false)),
        )
        .with_requests_root(requests_root(root.path()))
        .with_watcher_status_tracker(Arc::clone(&tracker));

        let (result, _) = tokio::join!(
            task.refresh(),
            complete_next_request(root.path(), &tracker, StatusOutcome::Success)
        );
        assert!(result.is_ok());
        assert_eq!(inbox_files(&inbox), 0);
    }

    #[tokio::test]
    async fn unchanged_watcher_cert_queues_nothing() {
        let root = crate::test_dirs::tempdir();
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
        let root = crate::test_dirs::tempdir();
        let watcher_dir = root.path().join("nginx");
        let inbox = watcher_dir.join("inbox");
        let store = Arc::new(MockStore::new(false));
        let executor = Arc::new(MockExecutor::new(false));
        let tracker = WatcherStatusTracker::new(root.path().to_path_buf(), ["nginx".into()]);
        let mut task = test_task(
            watcher_config(),
            Arc::new(MockAcmExporter::new(false)),
            store.clone(),
            executor.clone(),
        )
        .with_requests_root(requests_root(root.path()))
        .with_watcher_status_tracker(Arc::clone(&tracker));

        // The watcher's request volume isn't mounted yet.
        task.perform_refresh().await;
        assert_eq!(task.state.failure_count, 1);
        assert_eq!(executor.call_count.load(Ordering::SeqCst), 0);

        // Next cycle the files are unchanged, but the failed request is retried.
        create_watcher_dirs(root.path());
        store.report_changed.store(false, Ordering::SeqCst);
        let ((), _) = tokio::join!(
            task.perform_refresh(),
            complete_next_request(root.path(), &tracker, StatusOutcome::Success)
        );
        assert_eq!(task.state.failure_count, 0);
        assert_eq!(inbox_files(&inbox), 0);
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

    /// A watcher from before status reports (3.2.0 and earlier) has an inbox
    /// but never creates `outbox/`. Its request is queued and the refresh
    /// returns at once instead of waiting out `WATCHER_RESPONSE_TIMEOUT`.
    #[tokio::test(start_paused = true)]
    async fn pre_status_watcher_is_written_not_reloaded_without_waiting() {
        let root = crate::test_dirs::tempdir();
        let inbox = root.path().join("nginx").join("inbox");
        std::fs::create_dir_all(&inbox).unwrap();
        let tracker = WatcherStatusTracker::new(root.path().to_path_buf(), ["nginx".into()]);
        let mut task = test_task(
            watcher_config(),
            Arc::new(MockAcmExporter::new(false)),
            Arc::new(MockStore::new(false)),
            Arc::new(MockExecutor::new(false)),
        )
        .with_requests_root(requests_root(root.path()))
        .with_watcher_status_tracker(Arc::clone(&tracker));
        let start = Instant::now();

        let result = task.refresh().await.map(|refreshed| refreshed.status);

        assert!(
            matches!(result, Ok(SuccessStatus::WrittenNotReloaded)),
            "{result:?}"
        );
        assert_eq!(Instant::now() - start, Duration::ZERO);
        assert_eq!(
            inbox_files(&inbox),
            1,
            "the request is left for the watcher"
        );
        assert_eq!(tracker.pending_count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn pre_status_watcher_warning_is_logged_once() {
        capture_logs();
        let log_count = logged_on_this_thread().len();
        let root = crate::test_dirs::tempdir();
        let inbox = root.path().join("nginx").join("inbox");
        std::fs::create_dir_all(&inbox).unwrap();
        let tracker = WatcherStatusTracker::new(root.path().to_path_buf(), ["nginx".into()]);
        let mut task = test_task(
            watcher_config(),
            Arc::new(MockAcmExporter::new(false)),
            Arc::new(MockStore::new(false)),
            Arc::new(MockExecutor::new(false)),
        )
        .with_requests_root(requests_root(root.path()))
        .with_watcher_status_tracker(Arc::clone(&tracker));

        for _ in 0..2 {
            let result = task.refresh().await.map(|refreshed| refreshed.status);
            assert!(
                matches!(result, Ok(SuccessStatus::WrittenNotReloaded)),
                "{result:?}"
            );
        }

        assert_eq!(inbox_files(&inbox), 2);
        let warnings = logged_on_this_thread()[log_count..]
            .iter()
            .filter(|message| message.contains("predates status reports"))
            .count();
        assert_eq!(warnings, 1);
    }

    /// The first-cycle request to a pre-status watcher writes nothing, so it's unchanged.
    #[tokio::test(start_paused = true)]
    async fn pre_status_watcher_with_unchanged_files_is_unchanged() {
        let root = crate::test_dirs::tempdir();
        std::fs::create_dir_all(root.path().join("nginx").join("inbox")).unwrap();
        let tracker = WatcherStatusTracker::new(root.path().to_path_buf(), ["nginx".into()]);
        let store = Arc::new(MockStore::new(false));
        store.report_changed.store(false, Ordering::SeqCst);
        let mut task = test_task(
            watcher_config(),
            Arc::new(MockAcmExporter::new(false)),
            store,
            Arc::new(MockExecutor::new(false)),
        )
        .with_requests_root(requests_root(root.path()))
        .with_watcher_status_tracker(Arc::clone(&tracker));

        let result = task.refresh().await.map(|refreshed| refreshed.status);

        assert!(matches!(result, Ok(SuccessStatus::Unchanged)), "{result:?}");
    }

    /// An outbox that exists but can't be opened fails at once, before the
    /// request is published, instead of waiting out `WATCHER_RESPONSE_TIMEOUT`.
    #[cfg(unix)]
    #[tokio::test(start_paused = true)]
    async fn unreadable_outbox_fails_without_waiting() {
        use std::os::unix::fs::PermissionsExt;
        // Root bypasses directory permissions, so EACCES can't be produced.
        if rustix::process::geteuid().is_root() {
            eprintln!("skipping: running as root, permission checks are bypassed");
            return;
        }
        let root = crate::test_dirs::tempdir();
        let inbox = create_watcher_dirs(root.path());
        let outbox = root.path().join("nginx").join("outbox");
        std::fs::set_permissions(&outbox, std::fs::Permissions::from_mode(0o000)).unwrap();
        let tracker = WatcherStatusTracker::new(root.path().to_path_buf(), ["nginx".into()]);
        let mut task = test_task(
            watcher_config(),
            Arc::new(MockAcmExporter::new(false)),
            Arc::new(MockStore::new(false)),
            Arc::new(MockExecutor::new(false)),
        )
        .with_requests_root(requests_root(root.path()))
        .with_watcher_status_tracker(Arc::clone(&tracker));
        let start = Instant::now();

        let err = task.refresh().await.unwrap_err();
        std::fs::set_permissions(&outbox, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(matches!(err, RefreshError::RequestFailed { .. }), "{err:?}");
        assert_eq!(Instant::now() - start, Duration::ZERO);
        assert_eq!(tracker.pending_count(), 0);
        assert_eq!(inbox_files(&inbox), 0, "no request is published");
    }

    #[tokio::test]
    async fn request_failure_is_a_request_error() {
        let root = crate::test_dirs::tempdir();
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
        let root = crate::test_dirs::tempdir();
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

    async fn wait_for_pending(tracker: &WatcherStatusTracker) {
        for _ in 0..100 {
            if tracker.pending_count() == 1 {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("watcher request was not registered");
    }

    #[test]
    fn watcher_response_timeout_uses_shared_command_limits() {
        assert_eq!(WATCHER_RESPONSE_TIMEOUT, Duration::from_secs(2_130));
        assert_eq!(
            WATCHER_RESPONSE_TIMEOUT,
            MAX_STARTUP_HOLD + 2 * REFRESH_COMMAND_TIMEOUT + STATUS_RESCAN_INTERVAL
        );
    }

    #[tokio::test]
    async fn watcher_status_outcomes_map_for_changed_and_unchanged_files() {
        for changed in [true, false] {
            for status_outcome in [
                StatusOutcome::Success,
                StatusOutcome::Failure,
                StatusOutcome::NotFound,
                StatusOutcome::Superseded,
                StatusOutcome::Timeout,
            ] {
                let root = crate::test_dirs::tempdir();
                create_watcher_dirs(root.path());
                let store = Arc::new(MockStore::new(false));
                store.report_changed.store(changed, Ordering::SeqCst);
                let tracker =
                    WatcherStatusTracker::new(root.path().to_path_buf(), ["nginx".into()]);
                let mut task = test_task(
                    watcher_config(),
                    Arc::new(MockAcmExporter::new(false)),
                    store,
                    Arc::new(MockExecutor::new(false)),
                )
                .with_requests_root(requests_root(root.path()))
                .with_watcher_status_tracker(Arc::clone(&tracker));

                let (result, _) = tokio::join!(
                    task.refresh(),
                    complete_next_request(root.path(), &tracker, status_outcome)
                );

                match status_outcome {
                    StatusOutcome::Success => assert_eq!(
                        result.unwrap().status,
                        if changed {
                            SuccessStatus::Deployed
                        } else {
                            SuccessStatus::Reloaded
                        }
                    ),
                    StatusOutcome::Failure => assert!(matches!(
                        result,
                        Err(RefreshError::WatcherFailed {
                            files_changed,
                            outcome: WatcherFailureOutcome::Failure,
                            ..
                        }) if files_changed == changed
                    )),
                    StatusOutcome::NotFound => assert!(matches!(
                        result,
                        Err(RefreshError::WatcherFailed {
                            files_changed,
                            outcome: WatcherFailureOutcome::NotFound,
                            ..
                        }) if files_changed == changed
                    )),
                    StatusOutcome::Superseded => assert!(matches!(
                        result,
                        Err(RefreshError::WatcherFailed {
                            files_changed,
                            outcome: WatcherFailureOutcome::Superseded,
                            ..
                        }) if files_changed == changed
                    )),
                    StatusOutcome::Timeout => assert!(matches!(
                        result,
                        Err(RefreshError::WatcherTimeout { files_changed, .. })
                            if files_changed == changed
                    )),
                }
                assert_eq!(tracker.pending_count(), 0);
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn provider_deadline_is_no_status_for_changed_and_unchanged_files() {
        for changed in [true, false] {
            let root = crate::test_dirs::tempdir();
            create_watcher_dirs(root.path());
            let store = Arc::new(MockStore::new(false));
            store.report_changed.store(changed, Ordering::SeqCst);
            let tracker = WatcherStatusTracker::new(root.path().to_path_buf(), ["nginx".into()]);
            let mut task = test_task(
                watcher_config(),
                Arc::new(MockAcmExporter::new(false)),
                store,
                Arc::new(MockExecutor::new(false)),
            )
            .with_requests_root(requests_root(root.path()))
            .with_watcher_status_tracker(Arc::clone(&tracker));
            let cancel = CancellationToken::new();

            let advance_to_deadline = async {
                wait_for_pending(&tracker).await;
                tokio::time::advance(WATCHER_RESPONSE_TIMEOUT).await;
            };
            let (result, ()) = tokio::join!(task.refresh_with_cancel(&cancel), advance_to_deadline);

            let error = result.unwrap_err();
            assert!(
                matches!(
                    error,
                    RefreshError::WatcherNoStatus { files_changed, .. } if files_changed == changed
                ),
                "{error:?}"
            );
            assert!(error.to_string().contains("No watcher status"), "{error}");
            assert_eq!(tracker.pending_count(), 0);
        }
    }

    #[tokio::test]
    async fn watcher_failure_retries_unchanged_files_and_success_clears_failure_count() {
        let root = crate::test_dirs::tempdir();
        create_watcher_dirs(root.path());
        let store = Arc::new(MockStore::new(false));
        let tracker = WatcherStatusTracker::new(root.path().to_path_buf(), ["nginx".into()]);
        let mut task = test_task(
            watcher_config(),
            Arc::new(MockAcmExporter::new(false)),
            Arc::clone(&store),
            Arc::new(MockExecutor::new(false)),
        )
        .with_requests_root(requests_root(root.path()))
        .with_watcher_status_tracker(Arc::clone(&tracker));

        let ((), _) = tokio::join!(
            task.perform_refresh(),
            complete_next_request(root.path(), &tracker, StatusOutcome::Failure)
        );
        assert_eq!(task.state.failure_count, 1);

        store.report_changed.store(false, Ordering::SeqCst);
        let ((), _) = tokio::join!(
            task.perform_refresh(),
            complete_next_request(root.path(), &tracker, StatusOutcome::Success)
        );
        assert_eq!(task.state.failure_count, 0);
        assert_eq!(task.state.refreshes, 2);
        assert!(task.state.last_refresh.is_some());
    }

    #[tokio::test]
    async fn cancellation_during_watcher_wait_records_nothing_and_unregisters() {
        capture_logs();
        let log_count = logged_on_this_thread().len();
        let root = crate::test_dirs::tempdir();
        create_watcher_dirs(root.path());
        let tracker = WatcherStatusTracker::new(root.path().to_path_buf(), ["nginx".into()]);
        let scanner_cancel = CancellationToken::new();
        let scanner = tokio::spawn(Arc::clone(&tracker).run(scanner_cancel.clone()));
        let (telemetry, sink) = test_telemetry();
        let mut task = test_task(
            watcher_config(),
            Arc::new(MockAcmExporter::new(false)),
            Arc::new(MockStore::new(false)),
            Arc::new(MockExecutor::new(false)),
        )
        .with_requests_root(requests_root(root.path()))
        .with_watcher_status_tracker(Arc::clone(&tracker))
        .with_telemetry(telemetry);
        let cancel = CancellationToken::new();
        let cancel_wait = async {
            wait_for_pending(&tracker).await;
            assert!(sink.records().is_empty());
            cancel.cancel();
        };

        let (completed, ()) = tokio::join!(task.perform_refresh_with_cancel(&cancel), cancel_wait);

        assert!(!completed);
        assert_eq!(task.state.failure_count, 0);
        assert_eq!(task.state.refreshes, 0);
        assert!(task.state.first_cycle);
        assert!(task.state.last_refresh.is_none());
        assert!(sink.records().is_empty());
        let logs = logged_on_this_thread();
        assert!(logs[log_count..]
            .iter()
            .all(|message| !message.starts_with("Automation: produced")));
        assert_eq!(tracker.pending_count(), 0);

        scanner_cancel.cancel();
        tokio::time::timeout(Duration::from_secs(1), scanner)
            .await
            .expect("tracker shutdown must not deadlock")
            .unwrap();
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

    // -- telemetry tests --

    fn test_telemetry() -> (AutomationTelemetry, Arc<RecordingSink>) {
        let identity = AgentIdentity {
            host_id: "i-0abc".into(),
            deployment_type: DeploymentType::Ec2,
            region: "us-east-1".into(),
            boot_nonce: "boot-1".into(),
            ecs_network_mode: None,
        };
        let sink = Arc::new(RecordingSink::default());
        (
            AutomationTelemetry::new(SharedIdentity::ready(identity), sink.clone()),
            sink,
        )
    }

    fn outcome(record: &serde_json::Value) -> serde_json::Value {
        record["refresh_outcome"].clone()
    }

    #[tokio::test]
    async fn watcher_telemetry_waits_for_status_and_omits_protocol_details() {
        capture_logs();
        let log_count = logged_on_this_thread().len();
        let root = crate::test_dirs::tempdir();
        create_watcher_dirs(root.path());
        let tracker = WatcherStatusTracker::new(root.path().to_path_buf(), ["nginx".into()]);
        let (telemetry, sink) = test_telemetry();
        let mut task = test_task(
            watcher_config(),
            Arc::new(MockAcmExporter::new(false)),
            Arc::new(MockStore::new(false)),
            Arc::new(MockExecutor::new(false)),
        )
        .with_requests_root(requests_root(root.path()))
        .with_watcher_status_tracker(Arc::clone(&tracker))
        .with_telemetry(telemetry);
        let detail = "sensitive watcher stderr must stay in local logs".to_string();
        let finish = async {
            wait_for_pending(&tracker).await;
            assert!(
                sink.records().is_empty(),
                "telemetry preceded watcher status"
            );
            let logs = logged_on_this_thread();
            assert!(
                logs[log_count..]
                    .iter()
                    .all(|message| !message.starts_with("Automation: produced")),
                "automation log preceded watcher status"
            );
            complete_next_request_with_detail(
                root.path(),
                &tracker,
                StatusOutcome::Failure,
                Some(detail.clone()),
            )
            .await
        };

        let ((), status) = tokio::join!(task.perform_refresh(), finish);

        let records = sink.records();
        assert_eq!(records.len(), 1);
        let expected = format!(
            "Automation: produced 1 telemetry record for certificate refresh of {} and offered it for local queueing",
            test_config().certificate_arn
        );
        let logs = logged_on_this_thread();
        let automation_logs: Vec<&str> = logs[log_count..]
            .iter()
            .filter(|message| message.starts_with("Automation: produced"))
            .map(String::as_str)
            .collect();
        assert_eq!(automation_logs, [expected.as_str()]);
        assert_eq!(
            outcome(&records[0]),
            serde_json::json!({
                "result": "failed",
                "stage": "reload",
                "code": "CommandFailed",
                "files_on_disk": "replaced"
            })
        );
        let wire = serde_json::to_string(&records[0]).unwrap();
        for forbidden_field in [
            "watcher_id",
            "command_id",
            "exit_code",
            "request_created_at",
            "started_at",
            "completed_at",
            "stderr",
            "error_detail",
        ] {
            assert!(!wire.contains(forbidden_field), "leaked {forbidden_field}");
            assert!(
                automation_logs
                    .iter()
                    .all(|message| !message.contains(forbidden_field)),
                "logged {forbidden_field}"
            );
        }
        for forbidden_value in [
            "nginx",
            status.command_id.as_str(),
            status.request_created_at.as_str(),
            status.started_at.as_deref().unwrap(),
            status.completed_at.as_deref().unwrap(),
            detail.as_str(),
        ] {
            assert!(!wire.contains(forbidden_value), "leaked watcher value");
            assert!(
                automation_logs
                    .iter()
                    .all(|message| !message.contains(forbidden_value)),
                "logged watcher value"
            );
        }
    }

    #[tokio::test]
    async fn perform_refresh_reports_success_and_failure() {
        let (telemetry, sink) = test_telemetry();
        let executor = Arc::new(MockExecutor::new(false));
        let store = Arc::new(MockStore::new(false));
        let mut task = test_task(
            test_config(),
            Arc::new(MockAcmExporter::new(false)),
            store.clone(),
            executor.clone(),
        )
        .with_telemetry(telemetry);

        task.perform_refresh().await;
        executor.should_fail.store(true, Ordering::SeqCst);
        task.perform_refresh().await;
        // The retry after a failure reruns the command on unchanged files.
        store.report_changed.store(false, Ordering::SeqCst);
        task.perform_refresh().await;

        let records = sink.records();
        assert_eq!(records.len(), 3);
        assert_eq!(
            outcome(&records[0]),
            serde_json::json!({ "result": "succeeded", "status": "deployed" })
        );
        let reload_failed = |files_on_disk| {
            serde_json::json!({
                "result": "failed",
                "stage": "reload",
                "code": "CommandFailed",
                "files_on_disk": files_on_disk
            })
        };
        assert_eq!(outcome(&records[1]), reload_failed("replaced"));
        assert_eq!(outcome(&records[2]), reload_failed("not_replaced"));
    }

    #[tokio::test]
    async fn first_cycle_reload_failure_on_unchanged_files() {
        let (telemetry, sink) = test_telemetry();
        let store = Arc::new(MockStore::new(false));
        store.report_changed.store(false, Ordering::SeqCst);
        let mut task = test_task(
            test_config(),
            Arc::new(MockAcmExporter::new(false)),
            store,
            Arc::new(MockExecutor::new(true)),
        )
        .with_telemetry(telemetry);

        task.perform_refresh().await;

        let records = sink.records();
        assert_eq!(records.len(), 1);
        assert_eq!(outcome(&records[0])["stage"], "reload");
        assert_eq!(outcome(&records[0])["files_on_disk"], "not_replaced");
    }

    #[tokio::test]
    async fn records_count_failures_before_each_attempt() {
        let (telemetry, sink) = test_telemetry();
        let executor = Arc::new(MockExecutor::new(false));
        let mut task = test_task(
            test_config(),
            Arc::new(MockAcmExporter::new(false)),
            Arc::new(MockStore::new(false)),
            executor.clone(),
        )
        .with_telemetry(telemetry);

        task.perform_refresh().await;
        executor.should_fail.store(true, Ordering::SeqCst);
        task.perform_refresh().await;
        task.perform_refresh().await;
        executor.should_fail.store(false, Ordering::SeqCst);
        task.perform_refresh().await;
        task.perform_refresh().await;

        let records = sink.records();
        let failures: Vec<_> = records
            .iter()
            .map(|r| r["consecutive_failures"].clone())
            .collect();
        assert_eq!(failures, [0, 0, 1, 2, 0]);
        assert!(records.iter().all(|r| r["refresh_duration_ms"].is_u64()));
        // Every refresh, failed or not, starts the next cycle of the same run.
        let cycles: Vec<_> = records
            .iter()
            .map(|r| {
                r["refresh_cycle_id"]
                    .as_str()
                    .unwrap()
                    .rsplit_once('-')
                    .unwrap()
            })
            .collect();
        assert!(cycles.iter().all(|(run, _)| *run == cycles[0].0));
        let numbers: Vec<_> = cycles.iter().map(|(_, n)| *n).collect();
        assert_eq!(numbers, ["0", "1", "2", "3", "4"]);
    }

    #[tokio::test]
    async fn perform_refresh_works_without_telemetry() {
        let mut task = test_task(
            test_config(),
            Arc::new(MockAcmExporter::new(false)),
            Arc::new(MockStore::new(false)),
            Arc::new(MockExecutor::new(false)),
        );
        assert!(task.telemetry.is_none());

        task.perform_refresh().await;
        assert_eq!(task.state.failure_count, 0);
        assert!(!task.state.first_cycle);
    }
}
