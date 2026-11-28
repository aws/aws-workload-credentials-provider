//! Shared refresh-command execution: the [`RefreshExecutor`] interface, the
//! primitives used to run a refresh command as a child process, and the
//! [`DirectRefreshExecutor`] implementation.
//!
//! [`DirectRefreshExecutor`] is for container installations. It executes the
//! command directly without `sudo` or a scheduled task.

use std::future::Future;
use tokio::process::Command;
use tokio::time::{timeout, Duration};

/// Maximum time a refresh command is allowed to run before being considered hung.
pub const REFRESH_COMMAND_TIMEOUT: Duration = Duration::from_mins(15);

/// Largest startup hold accepted by a watcher.
pub const MAX_STARTUP_HOLD: Duration = Duration::from_mins(5);

/// Interface for executing refresh actions after certificate renewal.
pub trait RefreshExecutor: Send + Sync {
    fn execute(
        &self,
        command: &str,
        certificate_arn: &str,
    ) -> impl Future<Output = Result<(), std::io::Error>> + Send;
}

/// Container installation implementation of [`RefreshExecutor`].
///
/// Executes the refresh command directly without `sudo` or a scheduled task.
pub struct DirectRefreshExecutor;

impl RefreshExecutor for DirectRefreshExecutor {
    async fn execute(&self, command: &str, _certificate_arn: &str) -> Result<(), std::io::Error> {
        execute_direct(command).await?;
        Ok(())
    }
}

/// Runs the refresh command directly (no `sudo`, no scheduled task).
///
/// Used where the provider already has the privileges
/// needed to run the reload command. The command string is split on whitespace
/// into a program and its arguments and exec'd directly. Bounded by
/// [`REFRESH_COMMAND_TIMEOUT`] so a hung command can't stall the refresh loop.
async fn execute_direct(command: &str) -> Result<(), std::io::Error> {
    let mut parts = command.split_whitespace();
    let program = parts.next().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "refresh command is empty")
    })?;

    let mut cmd = Command::new(program);
    cmd.args(parts);

    execute_child_cmd(cmd).await
}

/// Spawns a prepared refresh [`Command`] and waits for it to exit.
///
/// The child is spawned with `kill_on_drop(true)` and bounded by
/// [`REFRESH_COMMAND_TIMEOUT`]; on timeout it is killed and a
/// [`std::io::ErrorKind::TimedOut`] error is returned. A non-zero exit status
/// is logged and returned as an error.
pub async fn execute_child_cmd(mut cmd: Command) -> Result<(), std::io::Error> {
    let mut child = cmd.kill_on_drop(true).spawn()?;

    let status = timeout(REFRESH_COMMAND_TIMEOUT, child.wait())
        .await
        .map_err(|_| {
            let _ = child.start_kill();
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("refresh command timed out after {REFRESH_COMMAND_TIMEOUT:?}"),
            )
        })??;

    if !status.success() {
        return Err(std::io::Error::other(format!(
            "command exited with {status}"
        )));
    }

    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// Tests for [`DirectRefreshExecutor`], which runs commands without sudo.
    mod direct_tests {
        use super::*;

        #[tokio::test]
        async fn execute_via_trait() {
            let executor = DirectRefreshExecutor;
            assert!(executor
                .execute("/bin/echo hello", "arn:test")
                .await
                .is_ok());
        }

        #[tokio::test]
        async fn failed_command_returns_error() {
            // `/bin/false` doesn't exist on macOS (it's `/usr/bin/false`), so
            // use `/bin/sh -c false`, which resolves on both Linux and macOS.
            let result = DirectRefreshExecutor
                .execute("/bin/sh -c false", "arn:test")
                .await;
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err.to_string().contains("exit"), "{}", err);
        }

        #[tokio::test]
        async fn invalid_command_returns_error() {
            let result = DirectRefreshExecutor
                .execute("/nonexistent_binary_12345", "arn:test")
                .await;
            assert!(result.is_err());
        }

        #[tokio::test]
        async fn empty_command_returns_error() {
            let result = DirectRefreshExecutor.execute("", "arn:test").await;
            assert!(result.is_err());
        }

        /// A command that outlives [`REFRESH_COMMAND_TIMEOUT`] is killed and
        /// reported as `TimedOut`. Uses a paused clock so the test doesn't
        /// actually wait 15 minutes.
        #[tokio::test(start_paused = true)]
        async fn command_times_out() {
            let handle = tokio::spawn(async move { execute_direct("/bin/sleep 600").await });
            tokio::time::advance(REFRESH_COMMAND_TIMEOUT).await;
            let err = handle.await.unwrap().unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
            assert!(
                err.to_string().contains("refresh command timed out"),
                "{}",
                err
            );
        }
    }
}
