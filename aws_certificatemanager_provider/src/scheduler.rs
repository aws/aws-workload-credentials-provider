//! ACM Scheduler for managing certificate refresh tasks.
//!
//! The scheduler uses a task-per-certificate model where each configured
//! certificate has an independent refresh task. This provides fault isolation
//! so that one certificate's failure doesn't affect others.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use log::info;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::certificate_file_store::certificate_store::UpdateStoreFile;
use crate::certificate_task::CertificateTask;
use crate::traits::{AcmCertificateExporter, RefreshExecutor};
use aws_workload_credentials_provider_common::config::types::{AcmConfig, CertificateConfig};

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
}

impl<Exporter, Store, Executor> AcmScheduler<Exporter, Store, Executor>
where
    Exporter: AcmCertificateExporter + 'static,
    Store: UpdateStoreFile + Send + Sync + 'static,
    Executor: RefreshExecutor + 'static,
{
    /// Creates a new scheduler with default refresh intervals.
    pub fn new(
        config: AcmConfig,
        acm_exporter: Arc<Exporter>,
        cert_store: Arc<Store>,
        refresh_executor: Arc<Executor>,
    ) -> Self {
        Self::with_intervals(
            config,
            acm_exporter,
            cert_store,
            refresh_executor,
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
        refresh_interval: Duration,
        max_jitter: Duration,
    ) -> Self {
        Self {
            certificates: config.certificates,
            refresh_interval,
            max_jitter,
            acm_exporter,
            cert_store,
            refresh_executor,
        }
    }

    /// Starts the scheduler and runs until cancellation.
    ///
    /// Spawns tasks for all configured certificates, then waits for shutdown.
    /// All tasks share the same cancellation token — cancelling it stops everything.
    pub async fn run(&mut self, cancel_token: CancellationToken) {
        info!(
            "ACM Scheduler starting with {} certificate(s)",
            self.certificates.len()
        );

        let mut handles = Vec::new();
        let certs: Vec<_> = self.certificates.drain().collect();
        for (_, config) in certs {
            handles.push(self.spawn_task(config, cancel_token.clone()));
        }

        cancel_token.cancelled().await;
        info!("ACM Scheduler shutting down");

        for handle in handles {
            let _ = handle.await;
        }
    }

    /// Spawns a new certificate refresh task.
    fn spawn_task(
        &self,
        config: CertificateConfig,
        cancel_token: CancellationToken,
    ) -> JoinHandle<()> {
        let initial_delay = crate::utils::random_jitter(DEFAULT_MAX_STARTUP_JITTER);

        let task = CertificateTask::new(
            config,
            Arc::clone(&self.acm_exporter),
            Arc::clone(&self.cert_store),
            Arc::clone(&self.refresh_executor),
            self.refresh_interval,
            self.max_jitter,
            initial_delay,
        );

        tokio::spawn(async move {
            let mut task = task;
            task.run(cancel_token).await;
        })
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
    use aws_workload_credentials_provider_common::fs_permissions::PathPermission;
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
        }
    }

    fn test_acm_config(certs: Vec<CertificateConfig>) -> AcmConfig {
        AcmConfig {
            enabled: true,
            certificates: certs
                .into_iter()
                .map(|c| (c.certificate_arn.clone(), c))
                .collect(),
        }
    }

    fn test_scheduler(
        certs: Vec<CertificateConfig>,
    ) -> AcmScheduler<MockExporter, MockStore, MockExecutor> {
        AcmScheduler::with_intervals(
            test_acm_config(certs),
            Arc::new(MockExporter::new(false)),
            Arc::new(MockStore),
            Arc::new(MockExecutor),
            Duration::from_secs(60),
            Duration::from_secs(5),
        )
    }

    const TEST_ARN: &str = "arn:aws:acm:us-east-1:123456789012:certificate/test";

    #[tokio::test(start_paused = true)]
    async fn run_spawns_tasks_and_shuts_down() {
        let mut scheduler = test_scheduler(vec![test_cert(TEST_ARN)]);
        let cancel = CancellationToken::new();

        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            scheduler.run(cancel_clone).await;
        });

        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;

        cancel.cancel();
        handle.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn run_completes_initial_refresh_before_shutdown() {
        let mut scheduler = test_scheduler(vec![test_cert(TEST_ARN)]);
        let cancel = CancellationToken::new();

        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            scheduler.run(cancel_clone).await;
        });

        // Advance past startup jitter + refresh
        tokio::time::advance(Duration::from_secs(10)).await;
        tokio::task::yield_now().await;

        cancel.cancel();
        handle.await.unwrap();
    }
}
