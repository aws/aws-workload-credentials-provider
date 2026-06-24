//! Entry point for running the ACM provider as a long-lived process.

use std::sync::Arc;

use aws_config::BehaviorVersion;
use log::info;
use tokio_util::sync::CancellationToken;

use crate::acm_manager::AcmManager;
use crate::certificate_file_store::certificate_store::CertificateFileStore;
use crate::refresh_executor::DefaultRefreshExecutor;
use crate::scheduler::AcmScheduler;
use aws_workload_credentials_provider_common::config::types::AcmConfig;
use aws_workload_credentials_provider_common::filesystem::RealFileSystem;
#[cfg(unix)]
use aws_workload_credentials_provider_common::shutdown_signal;

/// Runs the ACM certificate refresh loop until SIGINT/SIGTERM.
///
/// Creates a tokio runtime, constructs all internal components, sets up
/// signal handling, and blocks until shutdown. This is the only entry
/// point callers need.
#[cfg(unix)]
pub fn run_acm(acm_config: AcmConfig) -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let cancel = CancellationToken::new();
        let token = cancel.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            token.cancel();
        });

        acm_workload(acm_config, cancel)
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
    acm_config: AcmConfig,
    token: CancellationToken,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("Initializing ACM provider");

    let sdk_config = aws_config::defaults(BehaviorVersion::latest()).load().await;

    let role_arns = acm_config
        .certificates
        .values()
        .map(|c| c.role_arn.as_str());
    let acm_manager = Arc::new(AcmManager::new(&sdk_config, role_arns).await);
    let cert_store = Arc::new(CertificateFileStore::new(Box::new(RealFileSystem))?);
    let executor = Arc::new(DefaultRefreshExecutor);

    let mut scheduler = AcmScheduler::new(acm_config, acm_manager, cert_store, executor);
    scheduler.run(token).await;

    info!("ACM provider stopped");
    Ok(())
}
