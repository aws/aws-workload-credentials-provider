//! Entry point for running the ACM provider as a long-lived process.

use std::sync::Arc;

use std::time::Duration;

use aws_config::BehaviorVersion;
use aws_workload_credentials_provider_common::sdk_timeout::op_timeout_config;
use log::info;
use tokio_util::sync::CancellationToken;

/// Per-attempt SDK operation timeout for ACM `ExportCertificate` / inline
/// STS AssumeRole calls. Slow tier (ExportCertificate p99 ~193ms → ~5x headroom),
/// with extra margin for cold-connection TLS setup. Note: exceeds the SDK's 3.1s
/// default connect timeout, which still bounds TCP connect as a tighter sub-limit.
/// Overridable at startup via the SMA_ACM_OP_TIMEOUT env var (seconds).
const ACM_SDK_OP_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);

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

    // Bound every ACM/STS call with a per-attempt operation timeout so a hung
    // service response can't stall a certificate refresh (→ cert expiry). This
    // config flows into AcmManager's per-role `Builder::from(base_sdk_config)`
    // / `.configure(base_config)` clients, covering ACM ExportCertificate and
    // the inline AssumeRole.
    let sdk_config = aws_config::defaults(BehaviorVersion::latest())
        .timeout_config(op_timeout_config(
            "SMA_ACM_OP_TIMEOUT",
            ACM_SDK_OP_ATTEMPT_TIMEOUT,
        ))
        .load()
        .await;

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
