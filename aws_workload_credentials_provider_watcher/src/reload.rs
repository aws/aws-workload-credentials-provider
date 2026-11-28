//! Running a reload command.
//!
//! The command arrives as an argv array, split by the ACM provider. `common`'s
//! `WatcherConfig::validate` decides which commands are accepted, at ACM
//! provider startup and at watcher startup; this module adds no check. On
//! Unix that validator requires an absolute path for element 0. On Windows it
//! accepts a bare name or a cmdlet such as `Restart-Service W3SVC`, which
//! PowerShell resolves, and rejects quotes, `&`, `$`, `%`, `;`, `|` and
//! parentheses.
//!
//! - **Linux/Unix:** the argv runs directly, with no shell and no `sudo`.
//! - **Windows:** `powershell.exe -NoProfile -NonInteractive -EncodedCommand`,
//!   the invocation `common.ps1` uses on EC2 installs. The script is rebuilt
//!   from the argv with every element single-quoted ([`powershell_script`],
//!   [`encode_powershell_command`]), so any argv is safe to pass. Unlike
//!   `common.ps1`, no scheduled task is created: the watcher runs as the
//!   container user inside the customer's container.
//!
//! Both paths spawn with `kill_on_drop(true)`, are bounded by
//! `REFRESH_COMMAND_TIMEOUT` (15 minutes), and wait only for the command to
//! exit. Stdout is inherited; stderr is read in its own task, which keeps the
//! first `MAX_ERROR_DETAIL_BYTES` for the result and the watcher log and
//! drains the rest, so a background child holding the pipe can't stall the
//! reload. On Windows, PowerShell reports any native non-zero exit as 1, and
//! a native process it started can outlive a timeout kill.

use std::future::Future;
use std::io;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use log::{error, warn};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::time::timeout;

use aws_workload_credentials_provider_common::refresh_executor::REFRESH_COMMAND_TIMEOUT;

use crate::status::{cap_error_detail, timestamp_now, MAX_ERROR_DETAIL_BYTES};

/// How long stderr is still read after the command exits, for output that was
/// written just before exit.
const STDERR_GRACE: Duration = Duration::from_secs(1);

#[cfg(windows)]
use log::debug;

/// The program Windows reloads run through, resolved by search as in
/// `common.ps1`.
#[cfg_attr(not(windows), allow(dead_code))]
pub const POWERSHELL_PROGRAM: &str = "powershell.exe";

/// `element` as a PowerShell single-quoted string literal: wrapped in `'`, with
/// each embedded `'` doubled. Nothing inside a single-quoted literal is
/// expanded.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn powershell_quote(element: &str) -> String {
    format!("'{}'", element.replace('\'', "''"))
}

/// The PowerShell script that runs `argv`: the call operator followed by each
/// element as a single-quoted literal, `& 'arg0' 'arg1' ...`.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn powershell_script(argv: &[String]) -> io::Result<String> {
    if argv.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refresh command is empty",
        ));
    }
    let quoted: Vec<String> = argv.iter().map(|e| powershell_quote(e)).collect();
    Ok(format!("& {}", quoted.join(" ")))
}

/// The `-EncodedCommand` value for `script`: standard Base64 of its UTF-16LE
/// bytes, no BOM. Equal to PowerShell's
/// `[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))`.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn encode_powershell_command(script: &str) -> String {
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The arguments passed to [`POWERSHELL_PROGRAM`] to run `argv`, in
/// `common.ps1`'s order. The program itself is not included.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn powershell_args(argv: &[String]) -> io::Result<Vec<String>> {
    let script = powershell_script(argv)?;
    Ok(vec![
        "-NoProfile".to_string(),
        "-NonInteractive".to_string(),
        "-EncodedCommand".to_string(),
        encode_powershell_command(&script),
    ])
}

/// The broad result of one command execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadOutcome {
    Success,
    Failure,
    Timeout,
}

/// A command result with the data needed by the status protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloadResult {
    pub outcome: ReloadOutcome,
    pub exit_code: Option<i32>,
    pub error_detail: Option<String>,
    pub started_at: String,
    pub completed_at: String,
}

impl ReloadResult {
    fn new(
        outcome: ReloadOutcome,
        exit_code: Option<i32>,
        error_detail: Option<String>,
        started_at: String,
    ) -> Self {
        Self {
            outcome,
            exit_code,
            error_detail,
            started_at,
            completed_at: timestamp_now(),
        }
    }

    #[cfg(test)]
    pub(crate) fn success() -> Self {
        let started_at = timestamp_now();
        Self::new(ReloadOutcome::Success, Some(0), None, started_at)
    }

    #[cfg(test)]
    pub(crate) fn failure(message: &str) -> Self {
        let started_at = timestamp_now();
        Self::new(
            ReloadOutcome::Failure,
            None,
            Some(message.to_string()),
            started_at,
        )
    }
}

/// Reads `pipe` to EOF, keeping the first `MAX_ERROR_DETAIL_BYTES` in `kept`.
async fn drain_stderr(mut pipe: impl AsyncRead + Unpin, kept: Arc<Mutex<Vec<u8>>>) {
    let mut chunk = [0u8; 4096];
    loop {
        match pipe.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                let mut kept = kept.lock().unwrap();
                let room = MAX_ERROR_DETAIL_BYTES.saturating_sub(kept.len());
                kept.extend_from_slice(&chunk[..read.min(room)]);
            }
        }
    }
}

/// Runs a prepared command, waiting only for it to exit.
async fn execute_command(command: Command) -> ReloadResult {
    execute_command_within(command, REFRESH_COMMAND_TIMEOUT).await
}

/// [`execute_command`] with the time limit as a parameter, for tests.
async fn execute_command_within(mut command: Command, limit: std::time::Duration) -> ReloadResult {
    let started_at = timestamp_now();
    let program = command.as_std().get_program().to_os_string();
    command.stdout(Stdio::inherit()).stderr(Stdio::piped());

    let mut child = match command.kill_on_drop(true).spawn() {
        Ok(child) => child,
        Err(e) => {
            error!("Could not start reload command {:?}: {}", program, e);
            return ReloadResult::new(ReloadOutcome::Failure, None, None, started_at);
        }
    };
    let kept = Arc::new(Mutex::new(Vec::new()));
    // Detached once the grace period ends, so it keeps draining for a background child.
    let reader = child
        .stderr
        .take()
        .map(|pipe| tokio::spawn(drain_stderr(pipe, Arc::clone(&kept))));

    let status = match timeout(limit, child.wait()).await {
        Err(_) => {
            // What it wrote before the deadline is often why it hung, so it's kept.
            let stderr = cap_error_detail(&kept.lock().unwrap());
            warn!(
                "Reload command {:?} timed out after {:?}; stderr: {}",
                program,
                limit,
                stderr.as_deref().unwrap_or("none")
            );
            return ReloadResult::new(ReloadOutcome::Timeout, None, stderr, started_at);
        }
        Ok(Err(e)) => {
            error!("Could not wait for reload command {:?}: {}", program, e);
            return ReloadResult::new(ReloadOutcome::Failure, None, None, started_at);
        }
        Ok(Ok(status)) => status,
    };
    if let Some(reader) = reader {
        let _ = timeout(STDERR_GRACE, reader).await;
    }
    let stderr = cap_error_detail(&kept.lock().unwrap());
    if let Some(stderr) = &stderr {
        warn!("Reload command {:?} wrote to stderr: {}", program, stderr);
    }

    let exit_code = status.code();
    if status.success() {
        ReloadResult::new(ReloadOutcome::Success, exit_code, None, started_at)
    } else {
        ReloadResult::new(ReloadOutcome::Failure, exit_code, stderr, started_at)
    }
}

/// Runs reload commands.
pub trait ReloadSink: Send + Sync + 'static {
    /// Runs `command`. `label` names the certificates this reload covers and is
    /// used only in log lines.
    fn reload(
        &self,
        command: Vec<String>,
        label: String,
    ) -> impl Future<Output = ReloadResult> + Send;
}

/// Runs the command in this container, as the container user, without `sudo`
/// and without a scheduled task. Unix runs directly; Windows uses
/// `powershell.exe -EncodedCommand`.
pub struct DirectReloadSink;

impl DirectReloadSink {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DirectReloadSink {
    fn default() -> Self {
        Self::new()
    }
}

impl ReloadSink for DirectReloadSink {
    #[cfg(not(windows))]
    async fn reload(&self, command: Vec<String>, _label: String) -> ReloadResult {
        let Some((program, args)) = command.split_first() else {
            let started_at = timestamp_now();
            return ReloadResult::new(ReloadOutcome::Failure, None, None, started_at);
        };
        let mut cmd = Command::new(program);
        cmd.args(args);
        execute_command(cmd).await
    }

    #[cfg(windows)]
    async fn reload(&self, command: Vec<String>, label: String) -> ReloadResult {
        let started_at = timestamp_now();
        let script = match powershell_script(&command) {
            Ok(script) => script,
            Err(_) => return ReloadResult::new(ReloadOutcome::Failure, None, None, started_at),
        };
        debug!(
            "Running reload for {label} through {POWERSHELL_PROGRAM} -EncodedCommand: \
             {command:?} as script {script}"
        );
        let mut cmd = Command::new(POWERSHELL_PROGRAM);
        match powershell_args(&command) {
            Ok(args) => cmd.args(args),
            Err(_) => return ReloadResult::new(ReloadOutcome::Failure, None, None, started_at),
        };
        execute_command(cmd).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64::engine::general_purpose::STANDARD;

    // Expected values computed independently with Python:
    // `base64.b64encode(s.encode('utf-16-le'))`, which equals PowerShell's
    // `[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes(s))`.
    const NGINX_SCRIPT: &str = r"& 'C:\Program Files\nginx\nginx.exe' '-s' 'reload'";
    const NGINX_B64: &str = "JgAgACcAQwA6AFwAUAByAG8AZwByAGEAbQAgAEYAaQBsAGUAcwBcAG4AZwBpAG4AeABcAG4AZwBpAG4AeAAuAGUAeABlACcAIAAnAC0AcwAnACAAJwByAGUAbABvAGEAZAAnAA==";
    const QUOTING_SCRIPT: &str = r"& 'C:\it''s\x.exe' 'café' '😀'";
    const QUOTING_B64: &str =
        "JgAgACcAQwA6AFwAaQB0ACcAJwBzAFwAeAAuAGUAeABlACcAIAAnAGMAYQBmAOkAJwAgACcAPdgA3icA";

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    fn nginx_argv() -> Vec<String> {
        argv(&[r"C:\Program Files\nginx\nginx.exe", "-s", "reload"])
    }

    fn quoting_argv() -> Vec<String> {
        argv(&[r"C:\it's\x.exe", "café", "😀"])
    }

    /// Inverse of [`encode_powershell_command`].
    fn decode(b64: &str) -> String {
        let bytes = STANDARD.decode(b64).unwrap();
        assert_eq!(bytes.len() % 2, 0, "UTF-16LE is two bytes per unit");
        let units: Vec<u16> = (0..bytes.len())
            .step_by(2)
            .map(|i| u16::from_le_bytes([bytes[i], bytes[i + 1]]))
            .collect();
        String::from_utf16(&units).unwrap()
    }

    #[test]
    fn encodes_fixed_vectors() {
        assert_eq!(encode_powershell_command("a"), "YQA=");
        assert_eq!(
            encode_powershell_command("Restart-Service W3SVC"),
            "UgBlAHMAdABhAHIAdAAtAFMAZQByAHYAaQBjAGUAIABXADMAUwBWAEMA"
        );
        assert_eq!(
            encode_powershell_command(r#"& "C:\Program Files\App\reload.exe" -x"#),
            "JgAgACIAQwA6AFwAUAByAG8AZwByAGEAbQAgAEYAaQBsAGUAcwBcAEEAcABwAFwAcgBlAGwAbwBhAGQALgBlAHgAZQAiACAALQB4AA=="
        );
        assert_eq!(encode_powershell_command(NGINX_SCRIPT), NGINX_B64);
        assert_eq!(encode_powershell_command(QUOTING_SCRIPT), QUOTING_B64);
    }

    #[test]
    fn encoding_round_trips() {
        for script in [
            "a",
            "Restart-Service W3SVC",
            r#"& "C:\Program Files\App\reload.exe" -x"#,
            NGINX_SCRIPT,
            QUOTING_SCRIPT,
        ] {
            assert_eq!(decode(&encode_powershell_command(script)), script);
        }
    }

    /// A space inside an element stays inside one literal.
    #[test]
    fn script_keeps_spaces_inside_one_literal() {
        assert_eq!(powershell_script(&nginx_argv()).unwrap(), NGINX_SCRIPT);
        assert_eq!(
            powershell_script(&argv(&[r"C:\x.exe", " ", "a  b"])).unwrap(),
            r"& 'C:\x.exe' ' ' 'a  b'"
        );
    }

    /// An embedded `'` is doubled; non-ASCII, including a surrogate pair
    /// (😀 is `D83D DE00`), passes through unchanged.
    #[test]
    fn script_quotes_apostrophes_and_non_ascii() {
        assert_eq!(powershell_quote("it's"), "'it''s'");
        assert_eq!(powershell_script(&quoting_argv()).unwrap(), QUOTING_SCRIPT);
    }

    #[test]
    fn args_are_exactly_common_ps1s() {
        assert_eq!(POWERSHELL_PROGRAM, "powershell.exe");
        assert_eq!(
            powershell_args(&nginx_argv()).unwrap(),
            argv(&[
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                NGINX_B64
            ])
        );
        assert_eq!(
            powershell_args(&quoting_argv()).unwrap(),
            argv(&[
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                QUOTING_B64
            ])
        );
    }

    #[test]
    fn args_decode_to_the_script() {
        let args = powershell_args(&nginx_argv()).unwrap();
        assert_eq!(decode(&args[3]), NGINX_SCRIPT);
    }

    #[test]
    fn empty_argv_is_rejected() {
        assert_eq!(
            powershell_script(&[]).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            powershell_args(&[]).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[cfg(unix)]
    mod execution {
        use super::*;

        #[tokio::test]
        async fn successful_execution_captures_exit_code() {
            let mut command = Command::new("/bin/sh");
            command.args(["-c", "printf stdout; exit 0"]);
            let result = execute_command(command).await;
            assert_eq!(result.outcome, ReloadOutcome::Success);
            assert_eq!(result.exit_code, Some(0));
            assert_eq!(result.error_detail, None);
        }

        #[tokio::test]
        async fn failed_execution_captures_stderr_and_exit_code() {
            let mut command = Command::new("/bin/sh");
            command.args(["-c", "printf stderr >&2; exit 7"]);
            let result = execute_command(command).await;
            assert_eq!(result.outcome, ReloadOutcome::Failure);
            assert_eq!(result.exit_code, Some(7));
            assert_eq!(result.error_detail.as_deref(), Some("stderr"));
        }

        #[tokio::test]
        async fn spawn_failure_has_no_fabricated_error_detail() {
            let command = Command::new("/no/such/reload-command");
            let result = execute_command(command).await;
            assert_eq!(result.outcome, ReloadOutcome::Failure);
            assert_eq!(result.exit_code, None);
            assert_eq!(result.error_detail, None);
        }

        /// A background child holding stderr open doesn't hold the reload.
        #[tokio::test]
        async fn background_child_holding_stderr_does_not_delay_success() {
            let mut command = Command::new("/bin/sh");
            command.args(["-c", "sleep 30 & exit 0"]);
            let result = timeout(Duration::from_secs(10), execute_command(command))
                .await
                .expect("the reload must finish when the command exits");
            assert_eq!(result.outcome, ReloadOutcome::Success);
            assert_eq!(result.exit_code, Some(0));
        }

        #[tokio::test]
        async fn stderr_is_capped_while_the_rest_is_drained() {
            let mut command = Command::new("/bin/sh");
            command.args(["-c", "head -c 100000 /dev/zero | tr '\\0' x >&2; exit 3"]);
            let result = execute_command(command).await;
            assert_eq!(result.outcome, ReloadOutcome::Failure);
            assert_eq!(result.exit_code, Some(3));
            let detail = result.error_detail.unwrap();
            assert!(detail.len() <= MAX_ERROR_DETAIL_BYTES);
            assert!(detail.starts_with("xxxx"));
        }

        /// Stderr written before the deadline is kept on a timeout.
        #[tokio::test]
        async fn timeout_keeps_the_stderr_written_before_it() {
            let mut command = Command::new("/bin/sh");
            command.args(["-c", "printf hung-here >&2; sleep 30"]);
            let result = execute_command_within(command, Duration::from_secs(2)).await;
            assert_eq!(result.outcome, ReloadOutcome::Timeout);
            assert_eq!(result.exit_code, None);
            assert_eq!(result.error_detail.as_deref(), Some("hung-here"));
        }

        #[tokio::test(start_paused = true)]
        async fn timeout_returns_timeout_outcome() {
            let mut command = Command::new("/bin/sleep");
            command.arg("600");
            let task = tokio::spawn(execute_command(command));
            tokio::time::advance(REFRESH_COMMAND_TIMEOUT).await;
            let result = task.await.unwrap();
            assert_eq!(result.outcome, ReloadOutcome::Timeout);
            assert_eq!(result.exit_code, None);
            assert_eq!(result.error_detail, None);
        }
    }

    /// so no command validation runs.
    ///
    /// The `.ps1` cases need an ExecutionPolicy that allows local scripts;
    /// under `Restricted` they fail. Every path handed to PowerShell is the
    /// non-verbatim [`canonical_root`] form, because cmdlets such as
    /// `Set-Content` reject `\\?\` paths.
    #[cfg(windows)]
    mod windows_runtime {
        use super::*;

        use std::fs;
        use std::path::{Path, PathBuf};

        use tempfile::TempDir;

        use crate::env::tests_support::canonical_root;

        /// Writes `ok` to the path in its first argument.
        const MARKER_SCRIPT: &str = "param($out) Set-Content -LiteralPath $out -Value ok";

        /// Writes `<a>|<b>` to `$out` as UTF-8. Without `-Encoding UTF8`,
        /// Windows PowerShell 5.1 writes the ANSI code page.
        const ECHO_SCRIPT: &str =
            r#"param($out, $a, $b) Set-Content -LiteralPath $out -Value "$a|$b" -Encoding UTF8"#;

        /// `%SystemRoot%\System32\cmd.exe`.
        fn cmd_exe() -> String {
            let system_root =
                std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
            path_arg(&Path::new(&system_root).join("System32").join("cmd.exe"))
        }

        fn path_arg(path: &Path) -> String {
            path.to_str().expect("a UTF-8 test path").to_string()
        }

        /// A temp directory and its canonical, non-verbatim path.
        fn temp_root() -> (TempDir, PathBuf) {
            let tmp = TempDir::new().unwrap();
            let root = canonical_root(tmp.path());
            (tmp, root)
        }

        /// Writes `body` as `<dir>\reload.ps1`. Keep `body` ASCII: Windows
        /// PowerShell 5.1 reads a BOM-less script as ANSI.
        fn write_script(dir: &Path, body: &str) -> PathBuf {
            assert!(body.is_ascii(), "the script body must be ASCII");
            let path = dir.join("reload.ps1");
            fs::write(&path, body).unwrap();
            path
        }

        /// The marker's text without the UTF-8 BOM and line ending that
        /// `Set-Content` writes.
        fn read_marker(path: &Path) -> String {
            let text = fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("marker '{}' should be readable: {e}", path.display()));
            text.trim_start_matches('\u{feff}')
                .trim_end_matches(['\r', '\n'])
                .to_string()
        }

        async fn reload(command: Vec<String>) -> ReloadResult {
            DirectReloadSink::new()
                .reload(command, "arn:test".to_string())
                .await
        }

        #[tokio::test]
        async fn an_absolute_native_program_runs() {
            let (_tmp, root) = temp_root();
            let marker = root.join("marker");

            let result = reload(argv(&[&cmd_exe(), "/c", "mkdir", &path_arg(&marker)])).await;
            assert_eq!(
                result.outcome,
                ReloadOutcome::Success,
                "cmd.exe should run through powershell.exe"
            );

            assert!(marker.is_dir(), "'{}' should exist", marker.display());
        }

        #[tokio::test]
        async fn a_ps1_by_absolute_path_runs() {
            let (_tmp, root) = temp_root();
            let script = write_script(&root, MARKER_SCRIPT);
            let marker = root.join("marker.txt");

            let result = reload(argv(&[&path_arg(&script), &path_arg(&marker)])).await;
            assert_eq!(
                result.outcome,
                ReloadOutcome::Success,
                "the .ps1 should run through powershell.exe"
            );

            assert_eq!(read_marker(&marker), "ok");
        }

        #[tokio::test]
        async fn a_ps1_in_a_directory_with_a_space_runs() {
            let (_tmp, root) = temp_root();
            let dir = root.join("with space");
            fs::create_dir(&dir).unwrap();
            let script = write_script(&dir, MARKER_SCRIPT);
            let marker = dir.join("marker.txt");

            let result = reload(argv(&[&path_arg(&script), &path_arg(&marker)])).await;
            assert_eq!(
                result.outcome,
                ReloadOutcome::Success,
                "a .ps1 under a spaced path should run"
            );

            assert_eq!(read_marker(&marker), "ok");
        }

        /// A native argument containing a space reaches the program as one
        /// argument. Split, `mkdir` would create `<root>\with` instead.
        #[tokio::test]
        async fn a_native_argument_with_a_space_stays_one_argument() {
            let (_tmp, root) = temp_root();
            let dir = root.join("with space");
            fs::create_dir(&dir).unwrap();
            let marker = dir.join("marker");

            let result = reload(argv(&[&cmd_exe(), "/c", "mkdir", &path_arg(&marker)])).await;
            assert_eq!(
                result.outcome,
                ReloadOutcome::Success,
                "cmd.exe should run through powershell.exe"
            );

            assert!(marker.is_dir(), "'{}' should exist", marker.display());
            assert!(
                !root.join("with").exists(),
                "the spaced argument was split in two"
            );
        }

        /// The `''` doubling and the UTF-16LE `-EncodedCommand` value survive
        /// the real parser: in the script path, including a surrogate pair,
        /// and in the arguments.
        #[tokio::test]
        async fn apostrophes_and_non_ascii_survive_quoting_and_encoding() {
            let (_tmp, root) = temp_root();
            let dir = root.join("it's café 😀");
            fs::create_dir(&dir).unwrap();
            let script = write_script(&dir, ECHO_SCRIPT);
            let marker = dir.join("marker.txt");
            let command = argv(&[&path_arg(&script), &path_arg(&marker), "a  b", "it's café"]);
            let script_text = powershell_script(&command).unwrap();
            assert!(
                script_text.contains("it''s café 😀") && script_text.contains("'it''s café'"),
                "the case must exercise the quote doubling: {script_text}"
            );

            let result = reload(command).await;
            assert_eq!(
                result.outcome,
                ReloadOutcome::Success,
                "the quoted .ps1 should run through powershell.exe: {result:?}"
            );

            assert_eq!(read_marker(&marker), "a  b|it's café");
        }

        /// PowerShell reports a native program's non-zero exit as 1, so the
        /// 3 here is lost. See the module docs.
        #[tokio::test]
        async fn a_native_non_zero_exit_is_reported_as_exit_code_1() {
            let result = reload(argv(&[&cmd_exe(), "/c", "exit", "3"])).await;
            assert_eq!(result.outcome, ReloadOutcome::Failure);
            assert_eq!(result.exit_code, Some(1));
            assert_eq!(result.error_detail, None);
        }

        /// `powershell.exe` itself starts, so this is not a spawn `NotFound`
        /// as it is on Unix: PowerShell fails the command and exits 1.
        #[tokio::test]
        async fn a_missing_program_fails_inside_powershell() {
            let result = reload(argv(&[r"C:\does\not\exist.exe"])).await;
            assert_eq!(result.outcome, ReloadOutcome::Failure);
            assert_eq!(result.exit_code, Some(1));
        }
    }
}
