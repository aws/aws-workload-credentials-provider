pub mod config;
pub mod constants;
pub mod filesystem;
pub mod fs_permissions;
pub mod logging;

#[cfg(windows)]
pub mod win_service;

/// Waits for SIGINT (Ctrl+C) or SIGTERM, then returns.
#[cfg(unix)]
pub async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
