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
//! Both spawn through `common`'s `execute_child_cmd`: killed on drop, bounded
//! by `REFRESH_COMMAND_TIMEOUT` (15 minutes), and a non-zero exit is an error.
//! On Windows, PowerShell reports any native non-zero exit as 1, and a native
//! process it started can outlive a timeout kill.

use std::future::Future;
use std::io;

use base64::Engine as _;

#[cfg(windows)]
use aws_workload_credentials_provider_common::refresh_executor::execute_child_cmd;
use aws_workload_credentials_provider_common::refresh_executor::DirectRefreshExecutor;
#[cfg(windows)]
use log::debug;

// TODO: drop once `DirectRefreshExecutor::execute_argv` lands in `common`.
#[cfg(not(windows))]
use crate::types::DirectRefreshExecutorArgv;

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

/// Runs reload commands.
///
/// Mirrors `common`'s `RefreshExecutor` on purpose — return-position `impl
/// Future`, so not object-safe, with consumers generic over the concrete type.
/// It exists so the event loop can be tested without spawning processes, which
/// is what makes the hold-window and merge tests deterministic.
pub trait ReloadSink: Send + Sync + 'static {
    /// Runs `command`. `label` names the certificates this reload covers and is
    /// used only in log lines.
    fn reload(
        &self,
        command: Vec<String>,
        label: String,
    ) -> impl Future<Output = Result<(), io::Error>> + Send;
}

/// Runs the command in this container, as the container user, without `sudo`
/// and without a scheduled task: directly on Unix, through `powershell.exe
/// -EncodedCommand` on Windows. See the module docs.
pub struct DirectReloadSink {
    #[cfg_attr(windows, allow(dead_code))]
    executor: DirectRefreshExecutor,
}

impl DirectReloadSink {
    pub fn new() -> Self {
        Self {
            executor: DirectRefreshExecutor,
        }
    }
}

impl Default for DirectReloadSink {
    fn default() -> Self {
        Self::new()
    }
}

impl ReloadSink for DirectReloadSink {
    #[cfg(not(windows))]
    async fn reload(&self, command: Vec<String>, label: String) -> Result<(), io::Error> {
        // `execute_argv`, not the `RefreshExecutor::execute` string method: the
        // command is already an argv array, split by the ACM provider, and
        // runs as-is.
        //
        // The executor's second parameter is named `certificate_arn` but
        // receives the whole set of ARNs this reload covers, which follows from
        // merging by command rather than by certificate. It is a log label
        // either way.
        //
        // Bounded by `REFRESH_COMMAND_TIMEOUT` inside the executor, so a hung
        // reload command cannot wedge this command's slot forever.
        self.executor.execute_argv(&command, &label).await
    }

    #[cfg(windows)]
    async fn reload(&self, command: Vec<String>, label: String) -> Result<(), io::Error> {
        // The script is rebuilt from the validated argv, split by the ACM
        // provider.
        // Log the plain-text script, never the Base64 value.
        let script = powershell_script(&command)?;
        debug!(
            "Running reload for {label} through {POWERSHELL_PROGRAM} -EncodedCommand: \
             {command:?} as script {script}"
        );
        let mut cmd = tokio::process::Command::new(POWERSHELL_PROGRAM);
        cmd.args(powershell_args(&command)?);
        // Bounded by `REFRESH_COMMAND_TIMEOUT` inside `execute_child_cmd`, so a
        // hung reload command cannot wedge this command's slot forever.
        execute_child_cmd(cmd).await
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

    /// Reloads through the real `powershell.exe`, calling the sink directly,
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

        async fn reload(command: Vec<String>) -> io::Result<()> {
            DirectReloadSink::new()
                .reload(command, "arn:test".to_string())
                .await
        }

        #[tokio::test]
        async fn an_absolute_native_program_runs() {
            let (_tmp, root) = temp_root();
            let marker = root.join("marker");

            reload(argv(&[&cmd_exe(), "/c", "mkdir", &path_arg(&marker)]))
                .await
                .expect("cmd.exe should run through powershell.exe");

            assert!(marker.is_dir(), "'{}' should exist", marker.display());
        }

        #[tokio::test]
        async fn a_ps1_by_absolute_path_runs() {
            let (_tmp, root) = temp_root();
            let script = write_script(&root, MARKER_SCRIPT);
            let marker = root.join("marker.txt");

            reload(argv(&[&path_arg(&script), &path_arg(&marker)]))
                .await
                .expect("the .ps1 should run through powershell.exe");

            assert_eq!(read_marker(&marker), "ok");
        }

        #[tokio::test]
        async fn a_ps1_in_a_directory_with_a_space_runs() {
            let (_tmp, root) = temp_root();
            let dir = root.join("with space");
            fs::create_dir(&dir).unwrap();
            let script = write_script(&dir, MARKER_SCRIPT);
            let marker = dir.join("marker.txt");

            reload(argv(&[&path_arg(&script), &path_arg(&marker)]))
                .await
                .expect("a .ps1 under a spaced path should run");

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

            reload(argv(&[&cmd_exe(), "/c", "mkdir", &path_arg(&marker)]))
                .await
                .expect("cmd.exe should run through powershell.exe");

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

            reload(command)
                .await
                .expect("the quoted .ps1 should run through powershell.exe");

            assert_eq!(read_marker(&marker), "a  b|it's café");
        }

        /// PowerShell reports a native program's non-zero exit as 1, so the
        /// 3 here is lost. See the module docs.
        #[tokio::test]
        async fn a_native_non_zero_exit_is_reported_as_exit_code_1() {
            let err = reload(argv(&[&cmd_exe(), "/c", "exit", "3"]))
                .await
                .expect_err("a non-zero exit must be an error");

            assert_eq!(err.kind(), io::ErrorKind::Other, "{err}");
            assert_eq!(err.to_string(), "command exited with exit code: 1");
        }

        /// `powershell.exe` itself starts, so this is not a spawn `NotFound`
        /// as it is on Unix: PowerShell fails the command and exits 1.
        #[tokio::test]
        async fn a_missing_program_fails_inside_powershell() {
            let err = reload(argv(&[r"C:\does\not\exist.exe"]))
                .await
                .expect_err("a missing program must be an error");

            assert_ne!(err.kind(), io::ErrorKind::NotFound, "{err}");
            assert_eq!(err.to_string(), "command exited with exit code: 1");
        }
    }
}
