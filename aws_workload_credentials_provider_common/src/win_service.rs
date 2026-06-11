//! Windows Service Control Manager (SCM) integration for the AWS
//! Workload Credentials Provider.
//!
//! [`run_service`] accepts a service name, a caller-owned
//! [`CancellationToken`], and an async workload. It handles SCM dispatch,
//! state transitions, and Stop/Shutdown control signaling by cancelling
//! the token. When the process isn't launched by SCM (local dev), it
//! falls back to a Ctrl+C-driven foreground mode that cancels the same
//! token.

use std::ffi::OsString;
use std::future::Future;
use std::pin::Pin;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use log::{error, info, warn};
use tokio_util::sync::CancellationToken;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

use crate::config::types::LoggingConfig;
use crate::logging::{init_logger, log_dir, provider_base_dir};

#[derive(Debug, Clone, Copy)]
pub enum ServiceKind {
    Acm,
    Sm,
}

impl ServiceKind {
    pub fn service_name(self) -> &'static str {
        match self {
            ServiceKind::Acm => crate::constants::ACM_SERVICE_NAME,
            ServiceKind::Sm => crate::constants::SM_SERVICE_NAME,
        }
    }

    fn log_file_name(self) -> &'static str {
        match self {
            ServiceKind::Acm => "acm_provider",
            ServiceKind::Sm => "secrets_manager_provider",
        }
    }
}

/// Returned when connecting to SCM fails because the current process wasn't
/// launched by SCM. Used to trigger the foreground fallback.
const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: i32 = 1063;

/// Max time to wait for the workload to exit after cancellation before
/// reporting Stopped to SCM anyway. SCM will force-kill if we exceed its
/// broader stop deadline.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(15);

/// `wait_hint` reported during StartPending so SCM gives initialization
/// time before declaring the service hung with error 1053.
const START_PENDING_WAIT_HINT: Duration = Duration::from_secs(10);

/// Result type used by [`run_service`] and the workload it drives. Errors
/// are boxed so they can cross threads and be reported back to the
/// platform runner.
pub type ServiceResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

type WorkloadFuture = Pin<Box<dyn Future<Output = ServiceResult> + Send>>;
type WorkloadBuilder = Box<dyn FnOnce() -> WorkloadFuture + Send>;

/// `service_main` is invoked by SCM on a thread we don't control via a
/// C-style function pointer, so per-invocation state is stashed in a static.
/// A single slot is sufficient because one process runs exactly one service.
static DISPATCH_SLOT: Mutex<Option<Dispatch>> = Mutex::new(None);

struct Dispatch {
    kind: ServiceKind,
    workload: WorkloadBuilder,
    token: CancellationToken,
    result_tx: mpsc::SyncSender<ServiceResult>,
    logging: LoggingConfig,
}

/// Runs an async workload as a Windows Service, or in the foreground when
/// not launched by SCM.
///
/// `token` is cancelled on SCM Stop/Shutdown (or Ctrl+C in foreground
/// mode). The `workload` closure must observe the token — typically by
/// capturing a clone — and return within [`SHUTDOWN_GRACE`] or SCM will
/// force-kill the process.
pub fn run_service<F, Fut>(
    kind: ServiceKind,
    logging: LoggingConfig,
    token: CancellationToken,
    workload: F,
) -> ServiceResult
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ServiceResult> + Send + 'static,
{
    let builder: WorkloadBuilder = Box::new(move || Box::pin(workload()));
    let (result_tx, result_rx) = mpsc::sync_channel::<ServiceResult>(1);

    {
        let Ok(mut slot) = DISPATCH_SLOT.lock() else {
            return Err("failed to initialize service".into());
        };
        *slot = Some(Dispatch {
            kind,
            workload: builder,
            token: token.clone(),
            result_tx,
            logging,
        });
    }

    match service_dispatcher::start(kind.service_name(), ffi_service_main) {
        Ok(()) => {
            // service_main sends the result on exit; default to Ok if it
            // bailed before running the workload so we don't hang the caller.
            result_rx.try_recv().unwrap_or(Ok(()))
        }
        Err(e) if is_not_launched_by_scm(&e) => {
            let Some(dispatch) = take_dispatch() else {
                return Err("failed to initialize service".into());
            };
            init_service_logger(dispatch.kind, &dispatch.logging)?;

            info!(
                "Service '{}' not launched by SCM; running in foreground (Ctrl+C to stop)",
                kind.service_name()
            );

            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            runtime.block_on(run_foreground(dispatch.workload, dispatch.token))
        }
        Err(e) => {
            if let Ok(mut slot) = DISPATCH_SLOT.lock() {
                *slot = None;
            }
            Err(Box::new(e))
        }
    }
}

fn init_service_logger(kind: ServiceKind, logging: &LoggingConfig) -> ServiceResult {
    let dir = log_dir().map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
        format!("failed to resolve log dir: {e}").into()
    })?;
    init_logger(
        logging.log_level,
        logging.log_to_file,
        kind.log_file_name(),
        &dir,
    )
    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
        format!("failed to initialize logger: {e}").into()
    })
}

/// Returns true when `e` indicates the process wasn't launched by SCM (Win32
/// error 1063, ERROR_FAILED_SERVICE_CONTROLLER_CONNECT). Used to distinguish
/// "run in foreground for local dev" from real dispatcher failures.
fn is_not_launched_by_scm(e: &windows_service::Error) -> bool {
    matches!(
        e,
        windows_service::Error::Winapi(io)
            if io.raw_os_error() == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
    )
}

/// Runs the workload until it returns, or until the token is cancelled and
/// the grace period elapses.
async fn drive_workload(workload: WorkloadBuilder, token: CancellationToken) -> ServiceResult {
    let workload_fut = workload();
    tokio::select! {
        r = workload_fut => r,
        _ = async {
            token.cancelled().await;
            tokio::time::sleep(SHUTDOWN_GRACE).await;
        } => {
            warn!("Workload did not exit within {:?} after cancel; giving up", SHUTDOWN_GRACE);
            Ok(())
        }
    }
}

/// Wires Ctrl+C to the caller-supplied cancellation token and drives the
/// workload.
async fn run_foreground(workload: WorkloadBuilder, token: CancellationToken) -> ServiceResult {
    run_foreground_with_signal(workload, token, async {
        match tokio::signal::ctrl_c().await {
            Ok(()) => info!("Received Ctrl+C, shutting down"),
            Err(e) => error!("Failed to listen for Ctrl+C: {e}; forcing shutdown"),
        }
    })
    .await
}

/// Inner foreground driver. Spawns a task that awaits `signal` and cancels
/// the caller-supplied token on completion, then runs the workload.
async fn run_foreground_with_signal<Sig>(
    workload: WorkloadBuilder,
    token: CancellationToken,
    signal: Sig,
) -> ServiceResult
where
    Sig: Future<Output = ()> + Send + 'static,
{
    let token_for_signal = token.clone();
    tokio::spawn(async move {
        signal.await;
        token_for_signal.cancel();
    });

    drive_workload(workload, token).await
}

define_windows_service!(ffi_service_main, service_main);

/// Invoked by SCM after [`service_dispatcher::start`] succeeds. Runs on a
/// plain OS thread, so it spins up its own tokio runtime.
fn service_main(_args: Vec<OsString>) {
    let Some(dispatch) = take_dispatch() else {
        // Logger may not be initialized yet on this path; fall back to stderr.
        eprintln!("SCM dispatcher invoked service_main but no workload was registered");
        return;
    };
    let Dispatch {
        kind,
        workload,
        token,
        result_tx,
        logging,
    } = dispatch;

    // SCM launches services with CWD = %SystemRoot%\System32. Anchor CWD to
    // the provider base dir so the relative log path resolves correctly.
    if let Err(e) = set_cwd() {
        eprintln!("failed to anchor CWD to provider base dir: {e}");
        let _ = result_tx.send(Err(e));
        return;
    }

    if let Err(e) = init_service_logger(kind, &logging) {
        eprintln!("failed to initialize logger: {e}");
        let _ = result_tx.send(Err(e));
        return;
    }

    let service_name = kind.service_name();
    let handler = ControlHandler::new(token);
    let status_handle = match handler.register(service_name) {
        Ok(h) => h,
        Err(e) => {
            error!("Failed to register SCM control handler: {e}");
            let _ = result_tx.send(Err(Box::new(e)));
            return;
        }
    };

    let result = run_lifecycle(service_name, status_handle, workload, handler.token());
    let _ = result_tx.send(result);
}

fn set_cwd() -> ServiceResult {
    let base = provider_base_dir().map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
        format!("failed to resolve provider base dir: {e}").into()
    })?;
    std::env::set_current_dir(&base).map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
        format!("failed to set CWD to {}: {e}", base.display()).into()
    })?;
    Ok(())
}

/// Drives the service through StartPending → Running → workload → Stopped,
/// reporting each transition to SCM. The workload runs on a freshly built
/// tokio runtime; on runtime build failure we report Stopped with a
/// service-specific exit code so SCM applies its failure recovery policy.
fn run_lifecycle(
    service_name: &str,
    status_handle: service_control_handler::ServiceStatusHandle,
    workload: WorkloadBuilder,
    token: CancellationToken,
) -> ServiceResult {
    if let Err(e) = set_status(
        &status_handle,
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        ServiceExitCode::Win32(0),
        START_PENDING_WAIT_HINT,
    ) {
        warn!("Failed to set StartPending status: {e}");
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            error!("Failed to build tokio runtime for service: {e}");
            let _ = set_status(
                &status_handle,
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                ServiceExitCode::ServiceSpecific(1),
                Duration::default(),
            );
            return Err(Box::new(e));
        }
    };

    runtime.block_on(async move {
        if let Err(e) = set_status(
            &status_handle,
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            ServiceExitCode::Win32(0),
            Duration::default(),
        ) {
            warn!("Failed to set Running status: {e}");
        }

        let outcome = drive_workload(workload, token).await;

        let exit_code = match &outcome {
            Ok(()) => ServiceExitCode::Win32(0),
            Err(_) => {
                error!("Workload for '{}' exited with an error", service_name);
                ServiceExitCode::ServiceSpecific(1)
            }
        };

        if let Err(e) = set_status(
            &status_handle,
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
            exit_code,
            Duration::default(),
        ) {
            warn!("Failed to set Stopped status: {e}");
        }

        outcome
    })
}

/// Owns the SCM control-handler side of the service. Cancels the
/// caller-supplied token on Stop/Shutdown so the workload's future
/// observes cancellation.
struct ControlHandler {
    token: CancellationToken,
    handle_slot: Arc<Mutex<Option<service_control_handler::ServiceStatusHandle>>>,
}

impl ControlHandler {
    fn new(token: CancellationToken) -> Self {
        Self {
            token,
            handle_slot: Arc::new(Mutex::new(None)),
        }
    }

    fn token(&self) -> CancellationToken {
        self.token.clone()
    }

    fn register(
        &self,
        service_name: &'static str,
    ) -> Result<service_control_handler::ServiceStatusHandle, windows_service::Error> {
        let token_for_handler = self.token.clone();
        let handle_for_handler = Arc::clone(&self.handle_slot);

        let status_handle = service_control_handler::register(service_name, move |control| {
            handle_control(
                control,
                service_name,
                &handle_for_handler,
                &token_for_handler,
            )
        })?;

        if let Ok(mut guard) = self.handle_slot.lock() {
            *guard = Some(status_handle);
        }
        Ok(status_handle)
    }
}

/// Callback invoked by SCM when a control signal (Stop, Shutdown, etc.) is received.
fn handle_control(
    control: ServiceControl,
    service_name: &str,
    handle_slot: &Arc<Mutex<Option<service_control_handler::ServiceStatusHandle>>>,
    token: &CancellationToken,
) -> ServiceControlHandlerResult {
    match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            info!("SCM requested stop for '{}'", service_name);
            let report_result = handle_slot
                .lock()
                .ok()
                .and_then(|g| g.as_ref().copied())
                .map(|h| {
                    set_status(
                        &h,
                        ServiceState::StopPending,
                        ServiceControlAccept::empty(),
                        ServiceExitCode::Win32(0),
                        SHUTDOWN_GRACE,
                    )
                });
            if let Some(Err(e)) = report_result {
                warn!("Failed to report StopPending: {e}");
            }
            token.cancel();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    }
}

/// Takes the pending dispatch out of the static slot. Returns `None` if
/// `run_service` didn't populate it.
fn take_dispatch() -> Option<Dispatch> {
    DISPATCH_SLOT.lock().ok()?.take()
}

/// Reports a service state. `exit_code` is only meaningful when `state` is
/// `Stopped`; pass `ServiceExitCode::Win32(0)` otherwise.
fn set_status(
    handle: &service_control_handler::ServiceStatusHandle,
    state: ServiceState,
    accepts: ServiceControlAccept,
    exit_code: ServiceExitCode,
    wait_hint: Duration,
) -> Result<(), windows_service::Error> {
    handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accepts,
        exit_code,
        checkpoint: 0,
        wait_hint,
        process_id: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workload<F, Fut>(f: F) -> WorkloadBuilder
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = ServiceResult> + Send + 'static,
    {
        Box::new(move || Box::pin(f()))
    }

    #[tokio::test]
    async fn drive_workload_returns_ok_when_workload_succeeds() {
        let w = workload(|| async { Ok(()) });
        let result = drive_workload(w, CancellationToken::new()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn drive_workload_propagates_workload_error() {
        let w = workload(|| async { Err("boom".into()) });
        let err = drive_workload(w, CancellationToken::new())
            .await
            .expect_err("expected workload error");
        assert_eq!(err.to_string(), "boom");
    }

    #[tokio::test]
    async fn drive_workload_returns_workload_result_on_fast_cancel() {
        let token = CancellationToken::new();
        let token_for_workload = token.clone();

        let w = workload(move || async move {
            token_for_workload.cancelled().await;
            Ok(())
        });

        let token_for_canceller = token.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            token_for_canceller.cancel();
        });

        let result = drive_workload(w, token).await;
        assert!(result.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn drive_workload_grace_timeout_fires_when_workload_ignores_cancel() {
        let token = CancellationToken::new();

        let w = workload(|| async {
            std::future::pending::<()>().await;
            Ok(())
        });

        token.cancel();

        let driver = tokio::spawn(drive_workload(w, token));
        tokio::time::advance(SHUTDOWN_GRACE + Duration::from_secs(1)).await;

        let result = driver.await.expect("driver task panicked");
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn drive_workload_returns_quickly_when_workload_finishes_first() {
        let w = workload(|| async {
            tokio::time::sleep(Duration::from_millis(5)).await;
            Ok(())
        });

        let start = std::time::Instant::now();
        let result = drive_workload(w, CancellationToken::new()).await;
        let elapsed = start.elapsed();

        assert!(result.is_ok());
        assert!(
            elapsed < Duration::from_secs(2),
            "driver took {:?}, expected under 2s",
            elapsed
        );
    }

    #[test]
    fn is_not_launched_by_scm_true_for_1063() {
        let io = std::io::Error::from_raw_os_error(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT);
        let err = windows_service::Error::Winapi(io);
        assert!(is_not_launched_by_scm(&err));
    }

    #[test]
    fn is_not_launched_by_scm_false_for_other_winapi_errors() {
        let io = std::io::Error::from_raw_os_error(5);
        let err = windows_service::Error::Winapi(io);
        assert!(!is_not_launched_by_scm(&err));
    }

    #[test]
    fn is_not_launched_by_scm_false_for_non_winapi_variants() {
        let err = windows_service::Error::LaunchArgumentsNotSupported;
        assert!(!is_not_launched_by_scm(&err));
    }

    #[tokio::test]
    async fn run_foreground_cancels_on_signal() {
        let token = CancellationToken::new();
        let token_for_workload = token.clone();
        let w = workload(move || async move {
            token_for_workload.cancelled().await;
            Ok(())
        });
        let result = run_foreground_with_signal(w, token, async {}).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn run_foreground_propagates_workload_error() {
        let w = workload(|| async { Err("boom".into()) });
        let err =
            run_foreground_with_signal(w, CancellationToken::new(), std::future::pending::<()>())
                .await
                .expect_err("expected workload error");
        assert_eq!(err.to_string(), "boom");
    }

    #[tokio::test(start_paused = true)]
    async fn run_foreground_returns_on_grace_timeout_when_signal_fires_and_workload_hangs() {
        let w = workload(|| async {
            std::future::pending::<()>().await;
            Ok(())
        });

        let driver = tokio::spawn(run_foreground_with_signal(
            w,
            CancellationToken::new(),
            async {},
        ));
        tokio::time::advance(SHUTDOWN_GRACE + Duration::from_secs(1)).await;

        let result = driver.await.expect("driver panicked");
        assert!(result.is_ok());
    }

    #[test]
    fn control_handler_token_is_shared() {
        let outer = CancellationToken::new();
        let handler = ControlHandler::new(outer.clone());
        let t1 = handler.token();
        let t2 = handler.token();

        assert!(!t1.is_cancelled());
        assert!(!t2.is_cancelled());

        outer.cancel();
        assert!(t1.is_cancelled());
        assert!(t2.is_cancelled());
    }
}
