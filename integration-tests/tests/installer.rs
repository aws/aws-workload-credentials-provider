//! Integration tests for the host installers: `install` / `uninstall` on
//! Linux and `install.ps1` / `acmReloadConfig.ps1` / `uninstall.ps1` on
//! Windows.
//!
//! The tests install the provider on the machine running them, as root or
//! Administrator, and replace any installation already there. They run only
//! when `WCP_INSTALLER_TESTS=1`, which the installer-test workflow sets on disposable runners.
//!
//! Most tests use a placeholder certificate: they check what the installer
//! sets up (accounts, services, permissions, sudoers, scheduled tasks), not
//! certificate exports, so they need no AWS access. The provider logs the
//! failed export and keeps running. The Linux export test runs only when
//! `ACM_TEST_CERTIFICATE_ARN`, `ACM_TEST_ROLE_ARN` and AWS credentials are set.

#[allow(dead_code)]
mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Environment variable that opts in to these host-modifying tests.
const ENABLE_VAR: &str = "WCP_INSTALLER_TESTS";
const REQUIRED_VAR: &str = "WCP_INSTALLER_TESTS_REQUIRED";

/// How long to wait for a service or file to reach an expected state.
const WAIT_TIMEOUT: Duration = Duration::from_secs(60);

const PLACEHOLDER_CERT_ARN: &str =
    "arn:aws:acm:us-west-2:111122223333:certificate/11111111-2222-3333-4444-555555555555";
const OTHER_PLACEHOLDER_CERT_ARN: &str =
    "arn:aws:acm:us-west-2:111122223333:certificate/66666666-7777-8888-9999-000000000000";
const PLACEHOLDER_ROLE_ARN: &str = "arn:aws:iam::111122223333:role/InstallerTestRole";

/// Every test installs into the same host-wide locations, so the tests hold
/// this lock for their whole run instead of relying on `--test-threads=1`.
static HOST: Mutex<()> = Mutex::new(());

/// Takes [`HOST`], also after a test that held it panicked.
fn lock_host() -> MutexGuard<'static, ()> {
    HOST.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Returns false, and prints why, unless the tests are enabled.
fn enabled() -> bool {
    if std::env::var(ENABLE_VAR).as_deref() == Ok("1") {
        return true;
    }
    if std::env::var(REQUIRED_VAR).as_deref() == Ok("1") {
        panic!("{ENABLE_VAR}=1 is required when {REQUIRED_VAR}=1");
    }
    println!("SKIPPED: set {ENABLE_VAR}=1 to run the installer tests; they modify this host");
    false
}

/// The directory holding the installer scripts.
fn configuration_dir() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .join("../aws_workload_credentials_provider_common/configuration")
        .canonicalize()
        .expect("could not find the installer scripts")
}

/// The directory holding the provider binary the installer copies.
fn provider_source_dir() -> PathBuf {
    dunce::canonicalize(common::locate_provider_binary())
        .expect("could not resolve the provider binary")
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Polls `check` until it returns true or [`WAIT_TIMEOUT`] passes.
fn wait_until(what: &str, mut check: impl FnMut() -> bool) {
    let start = Instant::now();
    while start.elapsed() < WAIT_TIMEOUT {
        if check() {
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!("timed out after {WAIT_TIMEOUT:?} waiting for {what}");
}

/// One certificate entry of a test config.
struct TestCert<'a> {
    arn: &'a str,
    role_arn: &'a str,
    dir: &'a Path,
    refresh_command: Option<String>,
}

impl TestCert<'_> {
    fn toml(&self) -> String {
        let path = |name: &str| self.dir.join(name).display().to_string();
        let mut entry = format!(
            "[[capabilities.acm.certificates]]\n\
             certificate_arn = \"{}\"\n\
             role_arn = \"{}\"\n\
             certificate_path = '{}'\n\
             private_key_path = '{}'\n\
             chain_path = '{}'\n",
            self.arn,
            self.role_arn,
            path("server.pem"),
            path("server.key"),
            path("chain.pem"),
        );
        if let Some(cmd) = &self.refresh_command {
            entry.push_str(&format!(
                "refresh_command = \"{}\"\n",
                cmd.replace('\\', "\\\\")
            ));
        }
        entry
    }
}

/// A config enabling ACM for `certs`, or with ACM disabled when empty.
fn config_toml(certs: &[TestCert]) -> String {
    if certs.is_empty() {
        return "[capabilities.acm]\nenabled = false\n".to_string();
    }
    let mut toml = "[capabilities.acm]\nenabled = true\n\n".to_string();
    for cert in certs {
        toml.push_str(&cert.toml());
        toml.push('\n');
    }
    toml
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    const PROVIDER_DIR: &str = "/opt/aws/workload-credentials-provider";
    const CONFIG_DIR: &str = "/etc/aws-workload-credentials-provider";
    const SYSTEMD_DIR: &str = "/etc/systemd/system";
    const SUDOERS_FILE: &str = "/etc/sudoers.d/aws-workload-credentials-provider";
    const DROPIN_DIR: &str = "/etc/systemd/system/aws-workload-credentials-provider-acm.service.d";
    const TOKEN_FILE: &str = "/var/run/awssmatoken";
    const TOKEN_SERVICE: &str = "aws-workload-credentials-provider-token";
    const SM_SERVICE: &str = "aws-workload-credentials-provider-sm";
    const ACM_SERVICE: &str = "aws-workload-credentials-provider-acm";
    const PROVIDER_USER: &str = "aws-wcp";
    /// Root of the test certificate directories. Not under /tmp: the ACM unit
    /// has PrivateTmp, so it could not see a directory there.
    const TEST_ROOT: &str = "/srv/wcp-installer-tests";

    fn run(program: &str, args: &[&str]) -> (bool, String) {
        let out = Command::new(program)
            .args(args)
            .output()
            .unwrap_or_else(|e| panic!("could not run {program}: {e}"));
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.success(), text)
    }

    fn systemctl(args: &[&str]) -> String {
        run("systemctl", args).1.trim().to_string()
    }

    fn service_property(service: &str, property: &str) -> String {
        systemctl(&["show", "--value", "-p", property, service])
    }

    /// A fresh installer test: removes any installation on entry and on drop,
    /// and owns a certificate directory per name it is asked for.
    struct Host {
        name: &'static str,
        credentials_dropin: Option<PathBuf>,
        _lock: MutexGuard<'static, ()>,
    }

    impl Host {
        fn new(name: &'static str) -> Option<Self> {
            if !enabled() {
                return None;
            }
            assert_eq!(
                unsafe { libc::geteuid() },
                0,
                "installer tests must run as root"
            );
            let host = Self {
                name,
                credentials_dropin: None,
                _lock: lock_host(),
            };
            host.clean();
            std::fs::create_dir_all(host.root()).unwrap();
            Some(host)
        }

        fn root(&self) -> PathBuf {
            Path::new(TEST_ROOT).join(self.name)
        }

        /// A certificate directory under this test's root.
        fn cert_dir(&self, sub: &str) -> PathBuf {
            let dir = self.root().join(sub);
            std::fs::create_dir_all(&dir).unwrap();
            dir
        }

        /// Writes `toml` to a config file in this test's root.
        fn write_config(&self, file: &str, toml: &str) -> PathBuf {
            let path = self.root().join(file);
            std::fs::write(&path, toml).unwrap();
            path
        }

        /// Runs `install` with `args` from `cwd` and returns success and output.
        fn try_install_in(&self, cwd: &Path, args: &[&str]) -> (bool, String) {
            let out = Command::new(configuration_dir().join("install"))
                .args(args)
                .current_dir(cwd)
                .env("WCP_PROVIDER_SOURCE_DIR", provider_source_dir())
                .output()
                .expect("could not run install");
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            (out.status.success(), text)
        }

        /// Runs `install` with `args` from `cwd` and asserts success.
        fn install_in(&self, cwd: &Path, args: &[&str]) -> String {
            let (ok, text) = self.try_install_in(cwd, args);
            assert!(ok, "install {args:?} failed:\n{text}");
            text
        }

        fn install(&self, args: &[&str]) -> String {
            self.install_in(&configuration_dir(), args)
        }

        fn uninstall(&self) -> String {
            let (ok, text) = run(configuration_dir().join("uninstall").to_str().unwrap(), &[]);
            assert!(ok, "uninstall failed:\n{text}");
            text
        }

        fn clean(&self) {
            // The installer can create users, groups, directories, and unit
            // files before the ACM unit. Always invoke the cleanup path so a
            // partial install is removed too.
            let _ = run(configuration_dir().join("uninstall").to_str().unwrap(), &[]);
            let _ = run("groupdel", &["wcp-unrelated"]);
            let _ = std::fs::remove_dir_all(CONFIG_DIR);
            let _ = std::fs::remove_dir_all(DROPIN_DIR);
            let _ = std::fs::remove_dir_all(self.root());
            let _ = run("systemctl", &["daemon-reload"]);
        }

        /// Passes the test's AWS credentials to the ACM service through a
        /// root-only EnvironmentFile, since the service does not inherit this
        /// process's environment. Removed on drop.
        fn pass_aws_credentials(&mut self) {
            let mut lines = Vec::new();
            for var in [
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
                "AWS_SESSION_TOKEN",
                "AWS_REGION",
            ] {
                if let Ok(value) = std::env::var(var) {
                    lines.push(format!("{var}={value}"));
                }
            }
            std::fs::create_dir_all(DROPIN_DIR).unwrap();
            let path = Path::new(DROPIN_DIR).join("test-credentials.env");
            let _ = std::fs::remove_file(&path);
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            file.write_all((lines.join("\n") + "\n").as_bytes())
                .unwrap();
            file.sync_all().unwrap();
            drop(file);
            let dropin = Path::new(DROPIN_DIR).join("test-credentials.conf");
            std::fs::write(
                &dropin,
                format!("[Service]\nEnvironmentFile={}\n", path.display()),
            )
            .unwrap();
            self.credentials_dropin = Some(path);
            run("systemctl", &["daemon-reload"]);
            run("systemctl", &["restart", ACM_SERVICE]);
        }
    }

    impl Drop for Host {
        fn drop(&mut self) {
            if let Some(path) = &self.credentials_dropin {
                let _ = std::fs::remove_file(path);
            }
            self.clean();
        }
    }

    fn placeholder_cert<'a>(arn: &'a str, dir: &'a Path) -> TestCert<'a> {
        TestCert {
            arn,
            role_arn: PLACEHOLDER_ROLE_ARN,
            dir,
            refresh_command: Some(format!(
                "/usr/bin/touch {}",
                dir.join("refreshed").display()
            )),
        }
    }

    fn assert_active(service: &str) {
        wait_until(&format!("{service} to be active"), || {
            systemctl(&["is-active", service]) == "active"
        });
    }

    fn mode(path: &str) -> u32 {
        std::fs::metadata(path)
            .unwrap_or_else(|e| panic!("could not stat {path}: {e}"))
            .permissions()
            .mode()
            & 0o7777
    }

    fn read(path: &str) -> String {
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("could not read {path}: {e}"))
    }

    #[test]
    fn installer_sets_up_acm_service_and_permissions() {
        let Some(host) = Host::new("setup") else {
            return;
        };
        let certs = host.cert_dir("certs");
        let config = host.write_config(
            "config.toml",
            &config_toml(&[placeholder_cert(PLACEHOLDER_CERT_ARN, &certs)]),
        );

        host.install(&["--config", config.to_str().unwrap()]);

        // Account and groups.
        let (_, groups) = run("id", &["-nG", PROVIDER_USER]);
        for group in ["awscreds", "aws-wcp-token"] {
            assert!(
                groups.split_whitespace().any(|g| g == group),
                "groups: {groups}"
            );
        }

        // Installed files.
        assert_eq!(
            mode(&format!(
                "{PROVIDER_DIR}/bin/aws-workload-credentials-provider"
            )),
            0o755
        );
        let config_path = format!("{CONFIG_DIR}/config.toml");
        assert_eq!(mode(&config_path), 0o440);
        assert_eq!(std::fs::metadata(&config_path).unwrap().uid(), 0);

        // Sudoers: exact rule, valid syntax, read-only.
        assert_eq!(mode(SUDOERS_FILE), 0o440);
        let sudoers = read(SUDOERS_FILE);
        let rule = format!(
            "{PROVIDER_USER} ALL=(root) NOPASSWD: /usr/bin/touch {}",
            certs.join("refreshed").display()
        );
        assert!(
            sudoers.lines().any(|l| l == rule),
            "missing {rule:?} in:\n{sudoers}"
        );
        let (ok, text) = run("visudo", &["-c", "-f", SUDOERS_FILE]);
        assert!(ok, "visudo rejected the sudoers file: {text}");

        // Drop-in grants write access to the certificate directory.
        let dropin = read(&format!("{DROPIN_DIR}/cert-paths.conf"));
        assert!(dropin.contains(&certs.display().to_string()), "{dropin}");

        // Services: enabled, active, ACM as the provider user with its capability.
        for service in [TOKEN_SERVICE, SM_SERVICE, ACM_SERVICE] {
            assert_eq!(systemctl(&["is-enabled", service]), "enabled", "{service}");
            assert_active(service);
        }
        let pid = service_property(ACM_SERVICE, "MainPID");
        let (_, user) = run("ps", &["-o", "user=", "-p", &pid]);
        assert_eq!(user.trim(), PROVIDER_USER);
        assert!(read(&format!("{SYSTEMD_DIR}/{ACM_SERVICE}.service"))
            .contains("AmbientCapabilities=CAP_DAC_OVERRIDE"));
        let rw = service_property(ACM_SERVICE, "ReadWritePaths");
        assert!(
            rw.contains(&certs.display().to_string()),
            "ReadWritePaths: {rw}"
        );
    }

    #[test]
    fn installed_sudoers_rules_allow_refresh_commands() {
        let Some(host) = Host::new("sudoers-commands") else {
            return;
        };
        let true_dir = host.cert_dir("true");
        let echo_dir = host.cert_dir("echo");
        let config = host.write_config(
            "config.toml",
            &config_toml(&[
                TestCert {
                    arn: PLACEHOLDER_CERT_ARN,
                    role_arn: PLACEHOLDER_ROLE_ARN,
                    dir: &true_dir,
                    refresh_command: Some("/usr/bin/true".to_string()),
                },
                TestCert {
                    arn: OTHER_PLACEHOLDER_CERT_ARN,
                    role_arn: PLACEHOLDER_ROLE_ARN,
                    dir: &echo_dir,
                    refresh_command: Some("/usr/bin/echo --mode=reload".to_string()),
                },
            ]),
        );

        host.install(&["--config", config.to_str().unwrap()]);
        let (ok, text) = run("visudo", &["-c", "-f", SUDOERS_FILE]);
        assert!(ok, "visudo rejected the sudoers file: {text}");

        for args in [
            (
                true,
                vec!["-u", PROVIDER_USER, "--", "sudo", "-n", "/usr/bin/true"],
            ),
            (
                true,
                vec![
                    "-u",
                    PROVIDER_USER,
                    "--",
                    "sudo",
                    "-n",
                    "/usr/bin/echo",
                    "--mode=reload",
                ],
            ),
            (
                false,
                vec![
                    "-u",
                    PROVIDER_USER,
                    "--",
                    "sudo",
                    "-n",
                    "/usr/bin/true",
                    "extra",
                ],
            ),
            (
                false,
                vec![
                    "-u",
                    PROVIDER_USER,
                    "--",
                    "sudo",
                    "-n",
                    "/usr/bin/echo",
                    "--mode=other",
                ],
            ),
            (
                false,
                vec![
                    "-u",
                    PROVIDER_USER,
                    "--",
                    "sudo",
                    "-n",
                    "/usr/bin/echo",
                    "--mode=reload",
                    "extra",
                ],
            ),
        ] {
            let (expected_ok, args) = args;
            let (ok, text) = run("runuser", &args);
            assert_eq!(ok, expected_ok, "sudo -n command {args:?}: {text}");
        }
    }

    /// A re-run rewrites the permissions for the new config and leaves running
    /// services as they are, as the README states; a restart applies it.
    #[test]
    fn reinstall_rewrites_permissions_and_leaves_running_services() {
        let Some(host) = Host::new("reinstall") else {
            return;
        };
        let old_certs = host.cert_dir("old");
        let new_certs = host.cert_dir("new");
        let old_config = host.write_config(
            "old.toml",
            &config_toml(&[placeholder_cert(PLACEHOLDER_CERT_ARN, &old_certs)]),
        );
        let new_config = host.write_config(
            "new.toml",
            &config_toml(&[placeholder_cert(OTHER_PLACEHOLDER_CERT_ARN, &new_certs)]),
        );

        host.install(&["--config", old_config.to_str().unwrap()]);
        assert_active(ACM_SERVICE);
        let acm_started = service_property(ACM_SERVICE, "ExecMainStartTimestampMonotonic");
        let token = read(TOKEN_FILE);

        host.install(&["--config", new_config.to_str().unwrap()]);

        assert_eq!(
            service_property(ACM_SERVICE, "ExecMainStartTimestampMonotonic"),
            acm_started,
            "install restarted the running ACM service"
        );
        assert_eq!(read(TOKEN_FILE), token, "the SSRF token changed");

        // Permissions follow the new config only.
        let sudoers = read(SUDOERS_FILE);
        assert!(
            sudoers.contains(&new_certs.display().to_string()),
            "{sudoers}"
        );
        assert!(
            !sudoers.contains(&old_certs.display().to_string()),
            "{sudoers}"
        );
        let rw = service_property(ACM_SERVICE, "ReadWritePaths");
        assert!(rw.contains(&new_certs.display().to_string()), "{rw}");
        assert!(!rw.contains(&old_certs.display().to_string()), "{rw}");

        run("systemctl", &["restart", ACM_SERVICE]);
        assert_active(ACM_SERVICE);
    }

    #[test]
    fn install_without_acm_removes_acm_permissions() {
        let Some(host) = Host::new("acm-disabled") else {
            return;
        };
        let certs = host.cert_dir("certs");
        let acm_config = host.write_config(
            "acm.toml",
            &config_toml(&[placeholder_cert(PLACEHOLDER_CERT_ARN, &certs)]),
        );
        let no_acm_config = host.write_config("no-acm.toml", &config_toml(&[]));

        host.install(&["--config", acm_config.to_str().unwrap()]);
        assert!(Path::new(SUDOERS_FILE).exists());
        assert!(Path::new(DROPIN_DIR).join("cert-paths.conf").exists());

        host.install(&["--config", no_acm_config.to_str().unwrap()]);

        assert!(
            !Path::new(SUDOERS_FILE).exists(),
            "sudoers file left behind"
        );
        assert!(
            !Path::new(DROPIN_DIR).join("cert-paths.conf").exists(),
            "drop-in left behind"
        );
        assert_active(SM_SERVICE);
    }

    #[test]
    fn install_with_no_config_runs_secrets_manager() {
        let Some(host) = Host::new("no-config") else {
            return;
        };

        host.install(&[]);

        assert_active(SM_SERVICE);
        assert!(!Path::new(SUDOERS_FILE).exists());
    }

    #[test]
    fn install_accepts_relative_config_path() {
        let Some(host) = Host::new("relative-config") else {
            return;
        };
        let certs = host.cert_dir("certs");
        host.write_config(
            "config.toml",
            &config_toml(&[placeholder_cert(PLACEHOLDER_CERT_ARN, &certs)]),
        );

        host.install_in(&host.root(), &["--config", "config.toml"]);

        assert_eq!(
            read(&format!("{CONFIG_DIR}/config.toml")),
            read(host.root().join("config.toml").to_str().unwrap())
        );
    }

    #[test]
    fn invalid_config_leaves_previous_installation_unchanged() {
        let Some(host) = Host::new("invalid-config") else {
            return;
        };
        let certs = host.cert_dir("certs");
        let valid = host.write_config(
            "valid.toml",
            &config_toml(&[placeholder_cert(PLACEHOLDER_CERT_ARN, &certs)]),
        );
        let invalid = host.write_config("invalid.toml", "[capabilities.acm\n");

        host.install(&["--config", valid.to_str().unwrap(), "--no-start"]);
        let before_config = std::fs::read(format!("{CONFIG_DIR}/config.toml")).unwrap();
        let before_sudoers = std::fs::read(SUDOERS_FILE).unwrap();
        let before_dropin = std::fs::read(format!("{DROPIN_DIR}/cert-paths.conf")).unwrap();

        let (ok, output) = host.try_install_in(
            &host.root(),
            &["--config", invalid.file_name().unwrap().to_str().unwrap()],
        );
        assert!(!ok, "invalid config was accepted:\n{output}");

        assert_eq!(
            std::fs::read(format!("{CONFIG_DIR}/config.toml")).unwrap(),
            before_config
        );
        assert_eq!(std::fs::read(SUDOERS_FILE).unwrap(), before_sudoers);
        assert_eq!(
            std::fs::read(format!("{DROPIN_DIR}/cert-paths.conf")).unwrap(),
            before_dropin
        );
    }

    /// Clears the immutable attribute on drop so cleanup can modify the path.
    struct Immutable(&'static str);

    impl Drop for Immutable {
        fn drop(&mut self) {
            run("chattr", &["-i", self.0]);
        }
    }

    #[test]
    fn failed_permission_generation_restores_previous_permissions() {
        let Some(host) = Host::new("failed-generation") else {
            return;
        };
        let old_certs = host.cert_dir("old");
        let new_certs = host.cert_dir("new");
        let old_config = host.write_config(
            "old.toml",
            &config_toml(&[placeholder_cert(PLACEHOLDER_CERT_ARN, &old_certs)]),
        );
        let new_config = host.write_config(
            "new.toml",
            &config_toml(&[placeholder_cert(PLACEHOLDER_CERT_ARN, &new_certs)]),
        );

        host.install(&["--config", old_config.to_str().unwrap(), "--no-start"]);
        let before_config = std::fs::read(format!("{CONFIG_DIR}/config.toml")).unwrap();
        let before_sudoers = std::fs::read(SUDOERS_FILE).unwrap();
        let before_dropin = std::fs::read(format!("{DROPIN_DIR}/cert-paths.conf")).unwrap();

        // An immutable drop-in directory makes the drop-in write fail after the
        // sudoers file for the new config has been written.
        let (ok, text) = run("chattr", &["+i", DROPIN_DIR]);
        if !ok {
            println!("SKIPPED: chattr +i is unsupported here: {text}");
            return;
        }
        let guard = Immutable(DROPIN_DIR);
        let (ok, output) =
            host.try_install_in(&host.root(), &["--config", new_config.to_str().unwrap()]);
        drop(guard);
        assert!(
            !ok,
            "install succeeded with an unwritable drop-in:\n{output}"
        );
        assert!(
            !output.contains("WARNING: Could not"),
            "restore reported a failure:\n{output}"
        );

        assert_eq!(
            std::fs::read(format!("{CONFIG_DIR}/config.toml")).unwrap(),
            before_config
        );
        assert_eq!(std::fs::read(SUDOERS_FILE).unwrap(), before_sudoers);
        assert_eq!(
            std::fs::read(format!("{DROPIN_DIR}/cert-paths.conf")).unwrap(),
            before_dropin
        );
    }

    /// The installer checks the variable before it changes anything, so this
    /// test does not need the host opt-in.
    #[test]
    fn install_rejects_missing_provider_source_dir() {
        let missing = "/nonexistent/wcp-installer-tests/provider";
        let out = Command::new(configuration_dir().join("install"))
            .env("WCP_PROVIDER_SOURCE_DIR", missing)
            .output()
            .expect("could not run install");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "install accepted {missing}");
        assert!(
            stderr.contains(&format!(
                "WCP_PROVIDER_SOURCE_DIR is not a directory: {missing}"
            )),
            "missing WCP_PROVIDER_SOURCE_DIR error: {stderr}"
        );
    }

    /// Uninstall never reads the provider source, so a stale value must not
    /// stop it.
    #[test]
    fn uninstall_ignores_missing_provider_source_dir() {
        let Some(host) = Host::new("uninstall-stale-source-dir") else {
            return;
        };
        host.install(&["--no-start"]);

        let missing = "/nonexistent/wcp-installer-tests/provider";
        let out = Command::new(configuration_dir().join("uninstall"))
            .env("WCP_PROVIDER_SOURCE_DIR", missing)
            .output()
            .expect("could not run uninstall");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.status.success(), "uninstall failed:\n{text}");
        assert!(
            !text.contains("WCP_PROVIDER_SOURCE_DIR"),
            "uninstall checked WCP_PROVIDER_SOURCE_DIR:\n{text}"
        );
        assert!(
            !Path::new(&format!("{SYSTEMD_DIR}/{ACM_SERVICE}.service")).exists(),
            "uninstall left the ACM unit"
        );
    }

    #[test]
    fn install_no_privileges_omits_capabilities() {
        let Some(host) = Host::new("no-privileges") else {
            return;
        };
        let certs = host.cert_dir("certs");
        let config = host.write_config(
            "config.toml",
            &config_toml(&[placeholder_cert(PLACEHOLDER_CERT_ARN, &certs)]),
        );

        host.install(&["--config", config.to_str().unwrap(), "--no-privileges"]);

        let unit = read(&format!("{SYSTEMD_DIR}/{ACM_SERVICE}.service"));
        assert!(!unit.contains("AmbientCapabilities"), "{unit}");
        assert_active(ACM_SERVICE);
    }

    #[test]
    fn install_no_start_registers_stopped_services_then_allows_start() {
        let Some(host) = Host::new("no-start") else {
            return;
        };
        let certs = host.cert_dir("certs");
        let config = host.write_config(
            "config.toml",
            &config_toml(&[placeholder_cert(PLACEHOLDER_CERT_ARN, &certs)]),
        );

        host.install(&["--config", config.to_str().unwrap(), "--no-start"]);

        let (_, groups) = run("id", &["-nG", PROVIDER_USER]);
        for group in ["awscreds", "aws-wcp-token"] {
            assert!(groups.split_whitespace().any(|g| g == group), "{groups}");
        }
        let config_path = format!("{CONFIG_DIR}/config.toml");
        let config_metadata = std::fs::metadata(&config_path).unwrap();
        assert_eq!(mode(&config_path), 0o440);
        let (_, group_entry) = run("getent", &["group", "awscreds"]);
        let awscreds_gid = group_entry
            .split(':')
            .nth(2)
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap();
        assert_eq!(config_metadata.gid(), awscreds_gid);
        assert!(Path::new(SUDOERS_FILE).exists());
        assert!(Path::new(DROPIN_DIR).join("cert-paths.conf").exists());
        let rw = service_property(ACM_SERVICE, "ReadWritePaths");
        assert!(rw.contains(&certs.display().to_string()), "{rw}");

        for service in [TOKEN_SERVICE, SM_SERVICE, ACM_SERVICE] {
            assert_eq!(systemctl(&["is-enabled", service]), "enabled", "{service}");
            assert_eq!(systemctl(&["is-active", service]), "inactive", "{service}");
        }

        for service in [TOKEN_SERVICE, SM_SERVICE, ACM_SERVICE] {
            let (ok, text) = run("systemctl", &["start", service]);
            assert!(ok, "could not start {service}: {text}");
            assert_active(service);
        }
    }

    #[test]
    fn install_no_sudoers_removes_previous_sudoers_but_writes_dropin() {
        let Some(host) = Host::new("no-sudoers") else {
            return;
        };
        let certs = host.cert_dir("certs");
        let config = host.write_config(
            "config.toml",
            &config_toml(&[placeholder_cert(PLACEHOLDER_CERT_ARN, &certs)]),
        );

        host.install(&["--config", config.to_str().unwrap()]);
        assert!(Path::new(SUDOERS_FILE).exists());

        host.install(&["--config", config.to_str().unwrap(), "--no-sudoers"]);

        assert!(!Path::new(SUDOERS_FILE).exists());
        assert!(
            read(&format!("{DROPIN_DIR}/cert-paths.conf")).contains(&certs.display().to_string())
        );
    }

    #[test]
    fn install_repairs_existing_user_groups_and_config_read_access() {
        let Some(host) = Host::new("existing-user") else {
            return;
        };
        let certs = host.cert_dir("certs");
        let config = host.write_config(
            "config.toml",
            &config_toml(&[placeholder_cert(PLACEHOLDER_CERT_ARN, &certs)]),
        );

        // An account left by an older install, with an unrelated primary group
        // and neither provider supplementary group.
        run("groupadd", &["-f", "wcp-unrelated"]);
        let (ok, text) = run(
            "useradd",
            &[
                "-r",
                "-M",
                "-s",
                "/sbin/nologin",
                "-g",
                "wcp-unrelated",
                PROVIDER_USER,
            ],
        );
        assert!(ok, "could not create {PROVIDER_USER}: {text}");

        host.install(&["--config", config.to_str().unwrap()]);

        let (_, groups) = run("id", &["-nG", PROVIDER_USER]);
        for group in ["awscreds", "aws-wcp-token"] {
            assert!(
                groups.split_whitespace().any(|g| g == group),
                "missing {group} in groups: {groups}"
            );
        }
        let (ok, text) = run(
            "runuser",
            &[
                "-u",
                PROVIDER_USER,
                "--",
                "cat",
                "/etc/aws-workload-credentials-provider/config.toml",
            ],
        );
        assert!(ok, "aws-wcp could not read the installed config: {text}");
    }

    #[test]
    fn uninstall_removes_installation_and_keeps_config() {
        let Some(host) = Host::new("uninstall") else {
            return;
        };
        let certs = host.cert_dir("certs");
        let config = host.write_config(
            "config.toml",
            &config_toml(&[placeholder_cert(PLACEHOLDER_CERT_ARN, &certs)]),
        );
        host.install(&["--config", config.to_str().unwrap()]);

        host.uninstall();

        for path in [
            format!("{SYSTEMD_DIR}/{TOKEN_SERVICE}.service"),
            format!("{SYSTEMD_DIR}/{SM_SERVICE}.service"),
            format!("{SYSTEMD_DIR}/{ACM_SERVICE}.service"),
            DROPIN_DIR.to_string(),
            SUDOERS_FILE.to_string(),
            PROVIDER_DIR.to_string(),
            TOKEN_FILE.to_string(),
        ] {
            assert!(!Path::new(&path).exists(), "{path} left behind");
        }
        let (exists, _) = run("id", &[PROVIDER_USER]);
        assert!(!exists, "{PROVIDER_USER} left behind");
        assert!(
            Path::new(CONFIG_DIR).join("config.toml").exists(),
            "config was removed"
        );
    }

    /// The installed ACM service exports a real certificate inside its
    /// sandbox, as the provider user, and runs the refresh command via sudo.
    #[test]
    fn installed_service_exports_certificate_and_runs_refresh_command() {
        let (Ok(cert_arn), Ok(role_arn), Ok(_)) = (
            std::env::var("ACM_TEST_CERTIFICATE_ARN"),
            std::env::var("ACM_TEST_ROLE_ARN"),
            std::env::var("AWS_ACCESS_KEY_ID"),
        ) else {
            println!(
                "SKIPPED: needs ACM_TEST_CERTIFICATE_ARN, ACM_TEST_ROLE_ARN and AWS credentials"
            );
            return;
        };
        let Some(mut host) = Host::new("export") else {
            return;
        };
        let certs = host.cert_dir("certs");
        let config = host.write_config(
            "config.toml",
            &config_toml(&[TestCert {
                arn: &cert_arn,
                role_arn: &role_arn,
                dir: &certs,
                refresh_command: Some(format!(
                    "/usr/bin/touch {}",
                    certs.join("refreshed").display()
                )),
            }]),
        );
        host.install(&["--config", config.to_str().unwrap()]);
        host.pass_aws_credentials();

        let marker = certs.join("refreshed");
        wait_until("the certificate files and refresh marker", || {
            ["server.pem", "server.key", "chain.pem"]
                .iter()
                .all(|f| certs.join(f).exists())
                && marker.exists()
        });
        let cert = read(certs.join("server.pem").to_str().unwrap());
        assert!(common::is_pem_certificate(&cert), "not a PEM certificate");
        // Written by the provider user, through CAP_DAC_OVERRIDE into a
        // root-owned directory.
        let (_, owner) = run(
            "stat",
            &["-c", "%U", certs.join("server.pem").to_str().unwrap()],
        );
        assert_eq!(owner.trim(), PROVIDER_USER);
        // Created by root through the sudoers rule.
        assert_eq!(std::fs::metadata(&marker).unwrap().uid(), 0);
    }
}

#[cfg(windows)]
mod windows {
    use super::*;

    const ACM_SERVICE: &str = "AWSWorkloadCredentialsProvider-ACM";
    const SM_SERVICE: &str = "AWSWorkloadCredentialsProvider-SecretsManager";
    const ACM_ACCOUNT: &str = r"NT SERVICE\AWSWorkloadCredentialsProvider-ACM";
    // This is S-1-5-80 plus the five uint32 values from the SHA-1 hash of
    // the uppercased service name, as derived by Get-VirtualServiceAccountSid in common.ps1.
    const ACM_SERVICE_SID: &str = "S-1-5-80-3819941693-3350293558-4292787775-1171676324-3924222043";
    const SM_ACCOUNT: &str = r"NT SERVICE\AWSWorkloadCredentialsProvider-SecretsManager";
    const SEED_TOKEN_TASK: &str = "AWSWorkloadCredentialsProvider-SeedToken";
    const RELOAD_TASK_PREFIX: &str = "AWSWorkloadCredentialsProvider-Reload-";

    fn program_data_dir() -> PathBuf {
        PathBuf::from(std::env::var("ProgramData").unwrap())
            .join(r"AWS\WorkloadCredentialsProvider")
    }

    fn install_dir() -> PathBuf {
        PathBuf::from(std::env::var("ProgramFiles").unwrap())
            .join(r"AWS\WorkloadCredentialsProvider")
    }

    /// Windows PowerShell 5.1, as the installer docs run it. A parent pwsh 7
    /// process puts its own module folders in PSModulePath, which makes 5.1
    /// load the 7.x Microsoft.PowerShell.Security module and fail in Get-Acl,
    /// so 5.1 starts with its default module path instead.
    fn windows_powershell() -> Command {
        let mut command = Command::new("powershell.exe");
        command.env_remove("PSModulePath");
        command
    }

    /// Runs a PowerShell command and returns (success, output).
    fn ps(command: &str) -> (bool, String) {
        let out = windows_powershell()
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                command,
            ])
            .env("WCP_PROVIDER_SOURCE_DIR", provider_source_dir())
            .output()
            .expect("could not run powershell");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.success(), text.trim().to_string())
    }

    /// Runs a script from the configuration directory and returns its exit
    /// code and output.
    fn script(name: &str, args: &str) -> (i32, String) {
        let path = configuration_dir().join(name);
        let out = windows_powershell()
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
            ])
            .arg(format!("& '{}' {args}; exit $LASTEXITCODE", path.display()))
            .env("WCP_PROVIDER_SOURCE_DIR", provider_source_dir())
            .output()
            .expect("could not run powershell");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.code().unwrap_or(-1), text)
    }

    fn run_script(name: &str, args: &str) -> String {
        let (code, text) = script(name, args);
        assert_eq!(code, 0, "{name} {args} failed:\n{text}");
        text
    }

    /// The scheduled task name install.ps1 derives from a certificate ARN.
    fn task_name(arn: &str) -> String {
        let suffix: String = arn
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' {
                    c
                } else {
                    '-'
                }
            })
            .collect();
        format!("{RELOAD_TASK_PREFIX}{suffix}")
    }

    fn task_exists(name: &str) -> bool {
        ps(&format!(
            "if (Get-ScheduledTask -TaskName '{name}' -ErrorAction SilentlyContinue) {{ 'yes' }}"
        ))
        .1 == "yes"
    }

    fn reload_task_names() -> Vec<String> {
        let (ok, output) = ps(&format!(
            "Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {{ $_.TaskName.StartsWith('{RELOAD_TASK_PREFIX}', [StringComparison]::Ordinal) }} | Select-Object -ExpandProperty TaskName"
        ));
        assert!(ok, "could not enumerate reload tasks: {output}");
        output
            .lines()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_owned)
            .collect()
    }

    /// The identities with an access rule on `path`.
    fn acl_identities(path: &Path) -> String {
        ps(&format!(
            "(Get-Acl -LiteralPath '{}').Access | ForEach-Object {{ $_.IdentityReference.Value }}",
            path.display()
        ))
        .1
    }

    fn service_field(name: &str, field: &str) -> String {
        ps(&format!(
            "(Get-CimInstance Win32_Service -Filter \"Name='{name}'\").{field}"
        ))
        .1
    }

    fn service_status(name: &str) -> String {
        ps(&format!(
            "(Get-Service -Name '{name}' -ErrorAction SilentlyContinue).Status"
        ))
        .1
    }

    fn diagnostics_dir() -> PathBuf {
        std::env::var_os("RUNNER_TEMP")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join("wcp-installer-diagnostics")
    }

    fn copy_tree(source: &Path, destination: &Path) {
        if !source.exists() || std::fs::create_dir_all(destination).is_err() {
            return;
        }
        let Ok(entries) = std::fs::read_dir(source) else {
            return;
        };
        for entry in entries.flatten() {
            let source_path = entry.path();
            let destination_path = destination.join(entry.file_name());
            if source_path.is_dir() {
                copy_tree(&source_path, &destination_path);
            } else {
                let _ = std::fs::copy(source_path, destination_path);
            }
        }
    }

    /// Captures service state and provider logs before cleanup can remove them.
    fn capture_diagnostics(name: &str) {
        let dir = diagnostics_dir().join(name);
        let _ = std::fs::create_dir_all(&dir);
        let (_, services) = ps(
            "Get-Service AWSWorkloadCredentialsProvider-* -ErrorAction SilentlyContinue | Format-List Name,Status,StartType",
        );
        let _ = std::fs::write(dir.join("services.txt"), services);
        copy_tree(&program_data_dir().join("logs"), &dir.join("logs"));
    }

    /// A fresh installer test: removes any installation on entry and on drop.
    struct Host {
        root: PathBuf,
        _lock: MutexGuard<'static, ()>,
    }

    impl Host {
        fn new(name: &str) -> Option<Self> {
            if !enabled() {
                return None;
            }
            let root = PathBuf::from(std::env::var("SystemDrive").unwrap() + r"\")
                .join("wcp-installer-tests")
                .join(name);
            let host = Self {
                root,
                _lock: lock_host(),
            };
            host.clean();
            std::fs::create_dir_all(&host.root).unwrap();
            Some(host)
        }

        fn cert_dir(&self, sub: &str) -> PathBuf {
            let dir = self.root.join(sub);
            std::fs::create_dir_all(&dir).unwrap();
            dunce::canonicalize(dir).unwrap()
        }

        fn write_config(&self, file: &str, toml: &str) -> PathBuf {
            let path = self.root.join(file);
            std::fs::write(&path, toml).unwrap();
            path
        }

        fn clean(&self) {
            let _ = script("uninstall.ps1", "-RemoveAll");
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    impl Drop for Host {
        fn drop(&mut self) {
            if std::thread::panicking() {
                capture_diagnostics(self.root.file_name().unwrap().to_str().unwrap());
            }
            self.clean();
        }
    }

    fn placeholder_cert<'a>(arn: &'a str, dir: &'a Path) -> TestCert<'a> {
        TestCert {
            arn,
            role_arn: PLACEHOLDER_ROLE_ARN,
            dir,
            refresh_command: Some(format!(
                "New-Item -ItemType File -Force {}",
                dir.join("refreshed").display()
            )),
        }
    }

    fn assert_cert_grants(arn: &str, dir: &Path) {
        assert!(task_exists(&task_name(arn)), "no scheduled task for {arn}");
        let identities = acl_identities(dir);
        assert!(
            identities.contains(ACM_ACCOUNT),
            "{}: {identities}",
            dir.display()
        );
        let (_, principal) = ps(&format!(
            "(Get-ScheduledTask -TaskName '{}').Principal.UserId",
            task_name(arn)
        ));
        assert_eq!(principal, "SYSTEM");
        // The ACM service account can trigger the SYSTEM task.
        let (_, sddl) = ps(&format!(
            "$s = New-Object -ComObject Schedule.Service; $s.Connect(); \
             $s.GetFolder('\\').GetTask('{}').GetSecurityDescriptor(4)",
            task_name(arn)
        ));
        let (_, sid) = ps(&format!(
            "(New-Object System.Security.Principal.NTAccount('{ACM_ACCOUNT}')).Translate(\
             [System.Security.Principal.SecurityIdentifier]).Value"
        ));
        assert!(
            sddl.contains(&format!("(A;;GRGX;;;{sid})")),
            "task SDDL: {sddl}"
        );
    }

    fn assert_no_cert_grants(arn: &str, dir: &Path) {
        assert!(
            !task_exists(&task_name(arn)),
            "scheduled task for {arn} left behind"
        );
        let identities = acl_identities(dir);
        assert!(
            !identities.contains(ACM_ACCOUNT) && !identities.contains(ACM_SERVICE_SID),
            "{} still grants {ACM_ACCOUNT} or {ACM_SERVICE_SID}: {identities}",
            dir.display()
        );
    }

    #[test]
    fn installer_sets_up_services_and_certificate_permissions() {
        let Some(host) = Host::new("setup") else {
            return;
        };
        let certs = host.cert_dir("certs");
        let config = host.write_config(
            "config.toml",
            &config_toml(&[placeholder_cert(PLACEHOLDER_CERT_ARN, &certs)]),
        );

        run_script("install.ps1", &format!("-Config '{}'", config.display()));

        assert!(install_dir()
            .join(r"bin\aws-workload-credentials-provider.exe")
            .exists());
        assert_eq!(service_field(ACM_SERVICE, "StartName"), ACM_ACCOUNT);
        assert_eq!(service_field(SM_SERVICE, "StartName"), SM_ACCOUNT);
        assert_eq!(service_field(ACM_SERVICE, "StartMode"), "Auto");
        wait_until("both services to run", || {
            service_status(ACM_SERVICE) == "Running" && service_status(SM_SERVICE) == "Running"
        });
        assert_cert_grants(PLACEHOLDER_CERT_ARN, &certs);
        assert!(task_exists(SEED_TOKEN_TASK));

        // Only the expected identities can reach the provider directory.
        let identities = acl_identities(&program_data_dir());
        assert!(!identities.contains(r"BUILTIN\Users"), "{identities}");
        let config_acl = acl_identities(&program_data_dir().join("config.toml"));
        assert!(config_acl.contains(ACM_ACCOUNT), "{config_acl}");
    }

    #[test]
    fn install_no_start_registers_stopped_services_then_allows_start() {
        let Some(host) = Host::new("no-start") else {
            return;
        };
        let certs = host.cert_dir("certs");
        let config = host.write_config(
            "config.toml",
            &config_toml(&[placeholder_cert(PLACEHOLDER_CERT_ARN, &certs)]),
        );

        run_script(
            "install.ps1",
            &format!("-Config '{}' -NoStart", config.display()),
        );

        assert_eq!(service_field(ACM_SERVICE, "StartName"), ACM_ACCOUNT);
        assert_eq!(service_field(SM_SERVICE, "StartName"), SM_ACCOUNT);
        assert_eq!(service_status(ACM_SERVICE), "Stopped");
        assert_eq!(service_status(SM_SERVICE), "Stopped");
        assert_cert_grants(PLACEHOLDER_CERT_ARN, &certs);

        let (ok, text) = ps(&format!("Start-Service '{SM_SERVICE}', '{ACM_SERVICE}'"));
        assert!(ok, "could not start services: {text}");
        wait_until("both services to run", || {
            service_status(ACM_SERVICE) == "Running" && service_status(SM_SERVICE) == "Running"
        });
    }

    #[test]
    fn uninstall_with_malformed_config_removes_reload_tasks_and_warns_about_permissions() {
        let Some(host) = Host::new("uninstall-malformed-config") else {
            return;
        };
        let certs = host.cert_dir("certs");
        let config = host.write_config(
            "config.toml",
            &config_toml(&[placeholder_cert(PLACEHOLDER_CERT_ARN, &certs)]),
        );
        run_script(
            "install.ps1",
            &format!("-Config '{}' -NoStart", config.display()),
        );
        assert_eq!(reload_task_names(), vec![task_name(PLACEHOLDER_CERT_ARN)]);

        std::fs::write(program_data_dir().join("config.toml"), "not valid = [\n").unwrap();

        let output = run_script("uninstall.ps1", "");

        assert!(
            output.contains("Certificate permissions may remain"),
            "missing certificate-permission warning: {output}"
        );
        let remaining_tasks = reload_task_names();
        assert!(
            remaining_tasks.is_empty(),
            "reload tasks left behind: {remaining_tasks:?}"
        );
    }

    #[test]
    fn malformed_previous_config_reports_manual_cleanup_scope() {
        let Some(host) = Host::new("malformed-config") else {
            return;
        };
        let old_certs = host.cert_dir("old");
        let new_certs = host.cert_dir("new");
        let old_config = host.write_config(
            "old.toml",
            &config_toml(&[placeholder_cert(PLACEHOLDER_CERT_ARN, &old_certs)]),
        );
        let new_config = host.write_config(
            "new.toml",
            &config_toml(&[placeholder_cert(OTHER_PLACEHOLDER_CERT_ARN, &new_certs)]),
        );

        run_script(
            "install.ps1",
            &format!("-Config '{}' -NoStart", old_config.display()),
        );
        std::fs::write(program_data_dir().join("config.toml"), "not valid = [\n").unwrap();

        let output = run_script(
            "install.ps1",
            &format!("-Config '{}' -NoStart", new_config.display()),
        );

        assert!(
            output.contains("Old certificate permissions and scheduled tasks were not cleaned"),
            "missing cleanup warning: {output}"
        );
        assert!(
            output.contains("affected certificate paths and task names are unknown"),
            "missing unknown-scope warning: {output}"
        );
        assert_cert_grants(PLACEHOLDER_CERT_ARN, &old_certs);
        assert_cert_grants(OTHER_PLACEHOLDER_CERT_ARN, &new_certs);
    }

    #[test]
    fn invoke_icacls_reports_command_output_on_failure() {
        if !enabled() {
            return;
        }
        let common = configuration_dir().join("common.ps1");
        let (ok, output) = ps(&format!(
            "$ErrorActionPreference = 'Stop'; . '{}' ; try {{ Invoke-Icacls 'C:\\path\\that\\does\\not\\exist' /verify; Write-Host 'AFTER' }} catch {{ $_.Exception.Message }}",
            common.display()
        ));
        assert!(ok, "PowerShell probe failed: {output}");
        let marker = "failed (exit ";
        let start = output.find(marker).expect("missing failure marker");
        let suffix = &output[start + marker.len()..];
        let (exit_code, details) = suffix.split_once("): ").expect("missing exit details");
        assert!(!exit_code.is_empty() && exit_code.chars().all(|c| c.is_ascii_digit()));
        assert!(
            details.chars().next().is_some_and(|c| !c.is_whitespace()),
            "missing icacls output in: {output}"
        );
        assert!(
            !output.contains("AFTER"),
            "probe continued after failure: {output}"
        );
    }

    #[test]
    fn reload_replaces_old_certificate_permissions() {
        let Some(host) = Host::new("reload") else {
            return;
        };
        let old_certs = host.cert_dir("old");
        let new_certs = host.cert_dir("new");
        let old_config = host.write_config(
            "old.toml",
            &config_toml(&[placeholder_cert(PLACEHOLDER_CERT_ARN, &old_certs)]),
        );
        let new_config = host.write_config(
            "new.toml",
            &config_toml(&[placeholder_cert(OTHER_PLACEHOLDER_CERT_ARN, &new_certs)]),
        );
        run_script(
            "install.ps1",
            &format!("-Config '{}'", old_config.display()),
        );

        run_script(
            "acmReloadConfig.ps1",
            &format!("-Config '{}'", new_config.display()),
        );

        assert_no_cert_grants(PLACEHOLDER_CERT_ARN, &old_certs);
        assert_cert_grants(OTHER_PLACEHOLDER_CERT_ARN, &new_certs);
        wait_until("ACM service to run", || {
            service_status(ACM_SERVICE) == "Running"
        });
    }

    #[test]
    fn reload_restarts_acm_when_granting_permissions_fails() {
        let Some(host) = Host::new("reload-grant-failure") else {
            return;
        };
        let old_certs = host.cert_dir("old");
        let new_certs = host.cert_dir("new");
        let old_config = host.write_config(
            "old.toml",
            &config_toml(&[placeholder_cert(PLACEHOLDER_CERT_ARN, &old_certs)]),
        );
        let new_config = host.write_config(
            "new.toml",
            &config_toml(&[placeholder_cert(OTHER_PLACEHOLDER_CERT_ARN, &new_certs)]),
        );
        run_script(
            "install.ps1",
            &format!("-Config '{}'", old_config.display()),
        );

        // Administrators can't change permissions on a folder they don't own
        // when denied WRITE_DAC, so the reload's icacls /grant fails.
        let dir = new_certs.display();
        let (ok, text) = ps(&format!(
            "icacls '{dir}' /setowner '*S-1-5-18' /Q; if ($LASTEXITCODE) {{ exit 1 }}; \
             icacls '{dir}' /deny '*S-1-5-32-544:(WDAC)' /Q; exit $LASTEXITCODE"
        ));
        assert!(ok, "could not block permission changes: {text}");

        let (code, output) = script(
            "acmReloadConfig.ps1",
            &format!("-Config '{}'", new_config.display()),
        );

        let (ok, text) = ps(&format!(
            "icacls '{dir}' /setowner '*S-1-5-32-544' /Q; if ($LASTEXITCODE) {{ exit 1 }}; \
             icacls '{dir}' /remove:d '*S-1-5-32-544' /Q; exit $LASTEXITCODE"
        ));
        assert!(ok, "could not unblock permission changes: {text}");

        assert_ne!(
            code, 0,
            "reload succeeded without granting permissions:\n{output}"
        );
        assert!(
            output.contains("Restarted"),
            "missing permission failure message: {output}"
        );
        wait_until("ACM service to run", || {
            service_status(ACM_SERVICE) == "Running"
        });
        // The old grants were removed before the config was replaced, so the
        // failed reload left none behind, and a rerun completes the new ones.
        assert_no_cert_grants(PLACEHOLDER_CERT_ARN, &old_certs);

        run_script(
            "acmReloadConfig.ps1",
            &format!("-Config '{}'", new_config.display()),
        );

        assert_no_cert_grants(PLACEHOLDER_CERT_ARN, &old_certs);
        assert_cert_grants(OTHER_PLACEHOLDER_CERT_ARN, &new_certs);
    }

    /// With services running, the installer exits 0 and makes no changes, as
    /// the README states.
    #[test]
    fn install_over_running_services_makes_no_changes() {
        let Some(host) = Host::new("running") else {
            return;
        };
        let old_certs = host.cert_dir("old");
        let new_certs = host.cert_dir("new");
        let old_config = host.write_config(
            "old.toml",
            &config_toml(&[placeholder_cert(PLACEHOLDER_CERT_ARN, &old_certs)]),
        );
        let new_config = host.write_config(
            "new.toml",
            &config_toml(&[placeholder_cert(OTHER_PLACEHOLDER_CERT_ARN, &new_certs)]),
        );
        run_script(
            "install.ps1",
            &format!("-Config '{}'", old_config.display()),
        );
        wait_until("ACM service to run", || {
            service_status(ACM_SERVICE) == "Running"
        });

        run_script(
            "install.ps1",
            &format!("-Config '{}'", new_config.display()),
        );

        assert_cert_grants(PLACEHOLDER_CERT_ARN, &old_certs);
        assert!(!task_exists(&task_name(OTHER_PLACEHOLDER_CERT_ARN)));
        assert_eq!(
            std::fs::read_to_string(program_data_dir().join("config.toml")).unwrap(),
            std::fs::read_to_string(&old_config).unwrap()
        );
    }

    #[test]
    fn reinstall_with_new_config_replaces_old_certificate_permissions() {
        let Some(host) = Host::new("reinstall") else {
            return;
        };
        let old_certs = host.cert_dir("old");
        let new_certs = host.cert_dir("new");
        let old_config = host.write_config(
            "old.toml",
            &config_toml(&[placeholder_cert(PLACEHOLDER_CERT_ARN, &old_certs)]),
        );
        let new_config = host.write_config(
            "new.toml",
            &config_toml(&[placeholder_cert(OTHER_PLACEHOLDER_CERT_ARN, &new_certs)]),
        );
        run_script(
            "install.ps1",
            &format!("-Config '{}'", old_config.display()),
        );
        let (ok, text) = ps(&format!(
            "Stop-Service -Force '{ACM_SERVICE}', '{SM_SERVICE}'"
        ));
        assert!(ok, "could not stop services: {text}");

        run_script(
            "install.ps1",
            &format!("-Config '{}'", new_config.display()),
        );

        assert_no_cert_grants(PLACEHOLDER_CERT_ARN, &old_certs);
        assert_cert_grants(OTHER_PLACEHOLDER_CERT_ARN, &new_certs);
        wait_until("ACM service to run", || {
            service_status(ACM_SERVICE) == "Running"
        });
    }

    #[test]
    fn reinstall_after_acm_service_deletion_removes_sid_certificate_acl() {
        let Some(host) = Host::new("reinstall-service-deleted") else {
            return;
        };
        let old_certs = host.cert_dir("old");
        let new_certs = host.cert_dir("new");
        let old_config = host.write_config(
            "old.toml",
            &config_toml(&[placeholder_cert(PLACEHOLDER_CERT_ARN, &old_certs)]),
        );
        let new_config = host.write_config(
            "new.toml",
            &config_toml(&[placeholder_cert(OTHER_PLACEHOLDER_CERT_ARN, &new_certs)]),
        );

        run_script(
            "install.ps1",
            &format!("-Config '{}'", old_config.display()),
        );
        let (ok, text) = ps(&format!(
            "Stop-Service -Force '{ACM_SERVICE}', '{SM_SERVICE}'"
        ));
        assert!(ok, "could not stop services: {text}");
        let (ok, text) = ps(&format!(
            "sc.exe delete {ACM_SERVICE} | Out-Null; if ($LASTEXITCODE -ne 0) {{ throw 'sc.exe delete failed' }}"
        ));
        assert!(ok, "could not delete ACM service: {text}");
        let identities = acl_identities(&old_certs);
        assert!(
            identities.contains(ACM_SERVICE_SID),
            "expected orphaned service SID in {identities}"
        );

        run_script(
            "install.ps1",
            &format!("-Config '{}'", new_config.display()),
        );

        assert_no_cert_grants(PLACEHOLDER_CERT_ARN, &old_certs);
        assert_cert_grants(OTHER_PLACEHOLDER_CERT_ARN, &new_certs);
        wait_until("ACM service to run", || {
            service_status(ACM_SERVICE) == "Running"
        });
    }

    #[test]
    fn uninstall_preserves_config_and_allows_reinstall_with_new_config() {
        let Some(host) = Host::new("uninstall-reinstall") else {
            return;
        };
        let old_certs = host.cert_dir("old");
        let new_certs = host.cert_dir("new");
        let old_config = host.write_config(
            "old.toml",
            &config_toml(&[placeholder_cert(PLACEHOLDER_CERT_ARN, &old_certs)]),
        );
        let new_config = host.write_config(
            "new.toml",
            &config_toml(&[placeholder_cert(OTHER_PLACEHOLDER_CERT_ARN, &new_certs)]),
        );

        run_script(
            "install.ps1",
            &format!("-Config '{}'", old_config.display()),
        );
        run_script("uninstall.ps1", "");

        assert_no_cert_grants(PLACEHOLDER_CERT_ARN, &old_certs);
        assert!(program_data_dir().join("config.toml").exists());

        run_script(
            "install.ps1",
            &format!("-Config '{}'", new_config.display()),
        );

        assert_no_cert_grants(PLACEHOLDER_CERT_ARN, &old_certs);
        assert_cert_grants(OTHER_PLACEHOLDER_CERT_ARN, &new_certs);
        wait_until("ACM service to run", || {
            service_status(ACM_SERVICE) == "Running"
        });
    }

    #[test]
    fn install_without_acm_does_not_start_acm() {
        let Some(host) = Host::new("acm-disabled") else {
            return;
        };
        let config = host.write_config("config.toml", &config_toml(&[]));

        run_script("install.ps1", &format!("-Config '{}'", config.display()));

        assert_ne!(service_status(ACM_SERVICE), "Running");
        wait_until("Secrets Manager service to run", || {
            service_status(SM_SERVICE) == "Running"
        });
    }

    #[test]
    fn uninstall_rerun_does_not_warn_about_permissions() {
        let Some(host) = Host::new("uninstall-rerun") else {
            return;
        };
        let certs = host.cert_dir("certs");
        let config = host.write_config(
            "config.toml",
            &config_toml(&[placeholder_cert(PLACEHOLDER_CERT_ARN, &certs)]),
        );
        run_script(
            "install.ps1",
            &format!("-Config '{}' -NoStart", config.display()),
        );
        run_script("uninstall.ps1", "");
        assert!(program_data_dir().join("config.toml").exists());

        let output = run_script("uninstall.ps1", "");

        assert!(
            !output.contains("Certificate permissions may remain"),
            "unexpected certificate-permission warning: {output}"
        );
        assert!(
            output.contains("Provider binary not found"),
            "missing binary-not-found message: {output}"
        );
    }

    #[test]
    fn uninstall_without_config_does_not_warn_about_permissions() {
        let Some(_host) = Host::new("uninstall-no-config") else {
            return;
        };
        run_script("install.ps1", "-NoStart");
        assert!(!program_data_dir().join("config.toml").exists());

        let output = run_script("uninstall.ps1", "");

        assert!(
            !output.contains("Certificate permissions may remain"),
            "unexpected certificate-permission warning: {output}"
        );
        assert!(
            output.contains("No config found"),
            "missing no-config message: {output}"
        );
    }

    #[test]
    fn uninstall_removes_services_tasks_and_permissions() {
        let Some(host) = Host::new("uninstall") else {
            return;
        };
        let certs = host.cert_dir("certs");
        let config = host.write_config(
            "config.toml",
            &config_toml(&[placeholder_cert(PLACEHOLDER_CERT_ARN, &certs)]),
        );
        run_script("install.ps1", &format!("-Config '{}'", config.display()));

        run_script("uninstall.ps1", "");

        assert_eq!(service_status(ACM_SERVICE), "");
        assert_eq!(service_status(SM_SERVICE), "");
        assert!(!task_exists(SEED_TOKEN_TASK));
        assert_no_cert_grants(PLACEHOLDER_CERT_ARN, &certs);
        assert!(!install_dir().exists(), "install directory left behind");
        assert!(
            program_data_dir().join("config.toml").exists(),
            "config was removed"
        );

        run_script("uninstall.ps1", "-RemoveAll");
        assert!(
            !program_data_dir().exists(),
            "provider directory left behind"
        );
    }
}
