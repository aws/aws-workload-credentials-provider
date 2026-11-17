//! Entry point for running the ACM provider as a long-lived process.

use std::sync::Arc;

use aws_config::BehaviorVersion;
use log::info;
use tokio_util::sync::CancellationToken;

use crate::acm_manager::AcmManager;
use crate::certificate_file_store::certificate_store::CertificateFileStore;
use crate::refresh_executor::DefaultRefreshExecutor;
use crate::scheduler::AcmScheduler;
use crate::watcher_configs;
use aws_workload_credentials_provider_common::config::types::AcmConfig;
use aws_workload_credentials_provider_common::filesystem::RealFileSystem;
#[cfg(unix)]
use aws_workload_credentials_provider_common::shutdown_signal;
use aws_workload_credentials_provider_common::watcher_request::RequestsRoot;

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

    let role_arns = acm_config
        .certificates
        .values()
        .map(|c| c.role_arn.as_str());
    let acm_manager = Arc::new(AcmManager::new(&sdk_config, role_arns).await);
    let cert_store = Arc::new(CertificateFileStore::new(Box::new(RealFileSystem))?);
    let executor = Arc::new(DefaultRefreshExecutor);

    let mut scheduler =
        AcmScheduler::new(acm_config, acm_manager, cert_store, executor, requests_root);
    scheduler.run(token).await;

    info!("ACM provider stopped");
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use aws_workload_credentials_provider_common::config::types::CertificateConfig;
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
        let config = AcmConfig {
            enabled: true,
            certificates: HashMap::from([(arn.to_string(), cert)]),
            watcher_config_dir: dir.path().to_path_buf(),
            watcher_requests_dir: requests.path().to_path_buf(),
        };

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
        let config = AcmConfig {
            enabled: true,
            certificates: HashMap::from([(arn.to_string(), cert)]),
            watcher_config_dir: config_dir,
            watcher_requests_dir: requests.clone(),
        };

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
