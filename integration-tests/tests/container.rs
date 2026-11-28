//! Integration tests that run the provider, and for the sidecar test the
//! watcher too, in Docker containers, the way they run on ECS and EKS: as a
//! non-root user, with no `sudo`, writing to mounted volumes.
//!
//! The containers run the binaries `cargo build` produced on the host, mounted
//! read-only into `ubuntu:24.04` from Docker Hub. That image has the glibc of
//! `ubuntu-latest`, where CI builds them. It has no CA bundle, so the host's
//! bundle is mounted in and named by `SSL_CERT_FILE`.
//!
//! When Docker isn't available the tests print `SKIPPED: <reason>` and pass,
//! unless `WCP_CONTAINER_TESTS_REQUIRED=1` makes them fail.
//!
//! The tests in `mod requests` export a real certificate and need:
//!
//!   ACM_TEST_CERTIFICATE_ARN — Certificate the provider exports
//!   ACM_TEST_ROLE_ARN        — IAM role the provider assumes when exporting
//!
//! The provider container gets the host's `AWS_*` credential variables, so it
//! reaches the same credentials as the host: the variables in CI, and the
//! instance profile on EC2. It uses the host network, except in an ECS task.
//!
//! The identity and discovery tests use placeholder ARNs and dry-run
//! telemetry: each request the provider would send is written to
//! `logs/acm_provider_telemetry_dryrun.log`. An ECS task is a network
//! namespace owned by a busybox container that serves the task metadata
//! endpoint at the ECS agent's fixed address, `169.254.170.2`, on its
//! loopback; the provider and a TLS container join it. An EKS pod is the
//! service account token the provider reads, mounted where EKS projects it.
#![cfg(target_os = "linux")]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use common::{
    discovery_observation, locate_provider_binary, locate_watcher_binary, TelemetryTestCertificate,
    TelemetryTestConfig, TestCertificate,
};
use serde_json::Value;

const IMAGE: &str = "ubuntu:24.04";

/// The non-root user the ACM sidecar image (`Dockerfile.acm`) runs as.
const CONTAINER_USER: &str = "65532:65532";

/// Set to `1` to turn a missing-Docker skip into a failure.
const REQUIRED_VAR: &str = "WCP_CONTAINER_TESTS_REQUIRED";

/// Time for the first refresh cycle: container start, startup jitter (up to
/// 5s), the ACM export and the file writes.
const FIRST_CYCLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Time for a container to start and log its first line.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(20);

/// `docker stop` sends SIGTERM, then SIGKILL after this many seconds.
const STOP_GRACE_SECONDS: u64 = 10;

const WATCHER_ID: &str = "tls";

/// Host CA bundles, Debian/Ubuntu first, then Amazon Linux/RHEL.
const CA_BUNDLES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
];

/// The provider's credential variables, passed through when set on the host.
const AWS_VARS: &[&str] = &[
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
];

/// Paths inside the containers.
const BIN: &str = "/opt/wcp";
const WORK: &str = "/work";
const CERTS: &str = "/certs";
const WATCHER_CONFIG: &str = "/shared/wcp-watchers/config";
const WATCHER_REQUESTS: &str = "/shared/wcp-watchers/requests";
const RELOAD: &str = "/reload";
const CA_FILE: &str = "/etc/wcp-test/ca.crt";

/// The dry-run telemetry log, under the provider's working directory.
const DRY_RUN_LOG_FILE: &str = "work/logs/acm_provider_telemetry_dryrun.log";

/// Well-formed ARNs no account holds: the export fails, and the provider
/// still reports the flow.
const PLACEHOLDER_CERT_ARN: &str =
    "arn:aws:acm:us-west-2:123456789012:certificate/12345678-1234-1234-1234-123456789012";
const PLACEHOLDER_ROLE_ARN: &str = "arn:aws:iam::123456789012:role/PlaceholderRole";

/// Owns an ECS task's network namespace and serves the task metadata
/// endpoint at the ECS agent's address, as `ip` and `httpd` from busybox.
const TASK_NETWORK_IMAGE: &str = "busybox:stable";

/// The official nginx image, Debian-based as the README recommends for the
/// watcher's TLS container. Its glibc is newer than `ubuntu-latest`'s, so the
/// host-built watcher runs in it.
const NGINX_IMAGE: &str = "nginx:stable";

/// nginx's config inside its container.
const NGINX_CONF: &str = "/etc/wcp-test/nginx.conf";

/// Serves TLS with `openssl s_server`. The httpd image is the Docker
/// official image with the `openssl` CLI.
const TLS_IMAGE: &str = "httpd:2.4";

/// The ECS agent's task metadata address, fixed by the provider.
const ECS_AGENT_IP: &str = "169.254.170.2";
const ECS_METADATA_ID: &str = "0123456789abcdef-integ";
const ECS_TASK_ARN: &str =
    "arn:aws:ecs:us-west-2:111122223333:task/IntegCluster/0123456789abcdef0123456789abcdef";

/// The port the TLS container listens on, inside the task.
const TLS_PORT: u16 = 8443;

/// Deadline for discovery's first completed cycle: a random startup delay of
/// up to 5 min, the probes, and the submission. Not the per-scan timeout the
/// config sets.
const FIRST_DISCOVERY_CYCLE_TIMEOUT: Duration = Duration::from_secs(6 * 60);

/// Returns `None` and prints why when Docker can't run the tests, or panics
/// when `WCP_CONTAINER_TESTS_REQUIRED=1`.
fn docker_available() -> Option<()> {
    let reason = match Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .output()
    {
        Ok(out) if out.status.success() => return Some(()),
        Ok(out) => format!(
            "docker daemon unavailable: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(e) => format!("docker not found: {e}"),
    };
    if std::env::var(REQUIRED_VAR).as_deref() == Ok("1") {
        panic!("{reason}, and {REQUIRED_VAR}=1");
    }
    println!("SKIPPED: {reason}");
    None
}

fn docker(args: &[&str]) -> Output {
    Command::new("docker")
        .args(args)
        .output()
        .expect("could not run docker")
}

/// A host directory the container user can write to and the test can clean
/// up: mode 0777, so files the container creates in it can be deleted.
fn shared_dir(path: &Path) -> PathBuf {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o777)).unwrap();
    path.to_path_buf()
}

/// A test directory holding everything the containers mount.
struct TestDirs {
    _tmp: tempfile::TempDir,
    root: PathBuf,
}

impl TestDirs {
    fn new() -> Self {
        let tmp = tempfile::TempDir::new().expect("could not create test dir");
        let root = tmp.path().canonicalize().unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        for sub in ["work", "work/logs", "certs", "config", "requests", "reload"] {
            shared_dir(&root.join(sub));
        }
        Self { _tmp: tmp, root }
    }

    /// The marker the watcher's reload command creates.
    fn marker(&self) -> PathBuf {
        self.host("reload/reloaded")
    }

    fn host(&self, sub: &str) -> PathBuf {
        self.root.join(sub)
    }

    fn provider_log(&self) -> PathBuf {
        self.host("work/logs/acm_provider.log")
    }

    fn inbox(&self) -> PathBuf {
        self.host("requests").join(WATCHER_ID).join("inbox")
    }

    /// Writes the provider's config for `cert_arn`, as the container sees it.
    /// With a `watcher_id`, the provider queues a request instead of running
    /// `refresh_command`, so it never needs `sudo`.
    fn write_config(&self, cert_arn: &str, role_arn: &str) {
        self.write_config_with_reload(
            cert_arn,
            role_arn,
            &format!("/usr/bin/touch {RELOAD}/reloaded"),
        );
    }

    /// [`Self::write_config`] with the watcher running `reload` instead.
    fn write_config_with_reload(&self, cert_arn: &str, role_arn: &str, reload: &str) {
        let config = TelemetryTestConfig {
            watcher_config_dir: Some(WATCHER_CONFIG.into()),
            watcher_requests_dir: Some(WATCHER_REQUESTS.into()),
            certificates: vec![TelemetryTestCertificate::in_dir(cert_arn, role_arn, CERTS)
                .for_watcher(WATCHER_ID, reload)],
            ..TelemetryTestConfig::default()
        };
        std::fs::write(self.host("work/config.toml"), config.to_toml()).unwrap();
    }

    /// Writes a config with dry-run telemetry, as the container sees it:
    /// automation telemetry for the placeholder certificate when `certificate`
    /// is set, and discovery of `discovery_ports` on loopback when there are
    /// any.
    fn write_telemetry_config(&self, certificate: bool, discovery_ports: &[u16]) {
        let config = TelemetryTestConfig {
            dry_run: true,
            automation_telemetry: certificate,
            discovery_ports: discovery_ports.to_vec(),
            certificates: if certificate {
                vec![TelemetryTestCertificate::in_dir(
                    PLACEHOLDER_CERT_ARN,
                    PLACEHOLDER_ROLE_ARN,
                    CERTS,
                )]
            } else {
                Vec::new()
            },
            ..TelemetryTestConfig::default()
        };
        std::fs::write(self.host("work/config.toml"), config.to_toml()).unwrap();
    }

    /// The dry-run requests carrying `kind` (`automation` or `discovery`) records.
    fn requests_with(&self, kind: &str) -> Vec<Value> {
        common::dry_run_requests_with(&self.host(DRY_RUN_LOG_FILE), kind)
    }
}

/// The watcher creates directories the host user can't delete, so remove
/// everything as root in a container before `TempDir` cleans up.
impl Drop for TestDirs {
    fn drop(&mut self) {
        let _ = docker(&[
            "run",
            "--rm",
            "--network",
            "none",
            "--mount",
            &mount(&self.root, "/cleanup", ""),
            IMAGE,
            "find",
            "/cleanup",
            "-mindepth",
            "1",
            "-delete",
        ]);
    }
}

/// How the provider container mounts the certificate directory.
enum CertMount {
    /// The host's `certs/` directory, read-write.
    Bind,
    /// A tmpfs, which disappears with the container.
    Tmpfs,
}

/// A running container, removed when the test ends, pass or fail.
struct Container {
    name: String,
}

impl Container {
    fn run(name_hint: &str, args: &[String]) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let name = format!(
            "wcp-integ-{name_hint}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        );
        let mut all = vec!["run", "-d", "--name", &name];
        all.extend(args.iter().map(String::as_str));
        let out = docker(&all);
        assert!(
            out.status.success(),
            "docker run failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        Self { name }
    }

    fn is_running(&self) -> bool {
        let out = docker(&["inspect", "-f", "{{.State.Running}}", &self.name]);
        String::from_utf8_lossy(&out.stdout).trim() == "true"
    }

    fn exit_code(&self) -> i64 {
        let out = docker(&["inspect", "-f", "{{.State.ExitCode}}", &self.name]);
        String::from_utf8_lossy(&out.stdout).trim().parse().unwrap()
    }

    fn logs(&self) -> String {
        let out = docker(&["logs", &self.name]);
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    }

    /// Runs `args` in the container and returns its stdout.
    fn exec(&self, args: &[&str]) -> String {
        let mut all = vec!["exec", &self.name];
        all.extend(args);
        let out = docker(&all);
        assert!(
            out.status.success(),
            "docker exec {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// Sends SIGTERM and waits for the container to exit, up to the grace
    /// period, after which Docker sends SIGKILL.
    fn stop(&self) -> Duration {
        let started = Instant::now();
        let grace = STOP_GRACE_SECONDS.to_string();
        let out = docker(&["stop", "-t", &grace, &self.name]);
        assert!(out.status.success(), "docker stop failed");
        started.elapsed()
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        let _ = docker(&["rm", "-f", &self.name]);
    }
}

fn mount(host: &Path, container: &str, mode: &str) -> String {
    format!("type=bind,src={},dst={container}{mode}", host.display())
}

/// `docker run` arguments shared by every container: the user, the binaries
/// and the CA bundle.
fn base_args() -> Vec<String> {
    let bin_dir = locate_provider_binary()
        .canonicalize()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let ca = CA_BUNDLES
        .iter()
        .map(Path::new)
        .find(|p| p.exists())
        .expect("no CA bundle found on the host");
    vec![
        "--user".into(),
        CONTAINER_USER.into(),
        "--mount".into(),
        mount(&bin_dir, BIN, ",readonly"),
        "--mount".into(),
        mount(ca, CA_FILE, ",readonly"),
        "-e".into(),
        format!("SSL_CERT_FILE={CA_FILE}"),
    ]
}

/// Starts the provider container on `network` (`host`, or `container:<name>`
/// to join a task's network namespace). `extra` comes before the image name.
fn start_provider(dirs: &TestDirs, certs: CertMount, network: &str, extra: &[String]) -> Container {
    let mut args = base_args();
    args.extend([
        "--network".into(),
        network.into(),
        "--workdir".into(),
        WORK.into(),
        "--mount".into(),
        mount(&dirs.host("work"), WORK, ""),
        "--mount".into(),
        mount(&dirs.host("config"), WATCHER_CONFIG, ""),
        "--mount".into(),
        mount(&dirs.host("requests"), WATCHER_REQUESTS, ""),
    ]);
    match certs {
        CertMount::Bind => args.extend(["--mount".into(), mount(&dirs.host("certs"), CERTS, "")]),
        CertMount::Tmpfs => args.extend([
            "--tmpfs".into(),
            format!("{CERTS}:uid=65532,gid=65532,mode=0700"),
        ]),
    }
    for var in AWS_VARS {
        if std::env::var_os(var).is_some() {
            args.extend(["-e".into(), (*var).into()]);
        }
    }
    // The telemetry sender needs a region. AWS_REGION would override a host's
    // AWS_DEFAULT_REGION, so it is set only when neither is.
    if std::env::var_os("AWS_REGION").is_none() && std::env::var_os("AWS_DEFAULT_REGION").is_none()
    {
        args.extend(["-e".into(), "AWS_REGION=us-west-2".into()]);
    }
    args.extend(extra.iter().cloned());
    args.extend([
        IMAGE.into(),
        format!("{BIN}/aws-workload-credentials-provider"),
        "acm".into(),
        "start".into(),
        "--config".into(),
        format!("{WORK}/config.toml"),
    ]);
    Container::run("provider", &args)
}

/// Starts the watcher in a TLS container, with the mounts a TLS container
/// gets: the config root and the certificate directory read-only, the
/// requests root read-write. The reload command writes its marker to a
/// separate mount.
fn start_watcher(dirs: &TestDirs) -> Container {
    let mut args = base_args();
    args.extend([
        "--network".into(),
        "none".into(),
        "--mount".into(),
        mount(&dirs.host("config"), WATCHER_CONFIG, ",readonly"),
        "--mount".into(),
        mount(&dirs.host("requests"), WATCHER_REQUESTS, ""),
        "--mount".into(),
        mount(&dirs.host("certs"), CERTS, ",readonly"),
        "--mount".into(),
        mount(&dirs.host("reload"), RELOAD, ""),
        "-e".into(),
        format!("WCP_WATCHER_ID={WATCHER_ID}"),
        "-e".into(),
        format!("WCP_WATCHER_CONFIG_DIR={WATCHER_CONFIG}"),
        "-e".into(),
        format!("WCP_WATCHER_REQUESTS_DIR={WATCHER_REQUESTS}"),
        "-e".into(),
        "WCP_WATCHER_STARTUP_HOLD_MS=1000".into(),
        IMAGE.into(),
        format!("{BIN}/{}", file_name(&locate_watcher_binary())),
    ]);
    Container::run("watcher", &args)
}

fn file_name(path: &Path) -> String {
    path.file_name().unwrap().to_string_lossy().into_owned()
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// Polls `done` until it returns true, or panics after `timeout` naming
/// `what` and showing the provider's log and the containers' output. Every
/// container in `containers` must keep running: one that exits fails the wait
/// at once with its exit code.
async fn wait_until(
    what: &str,
    timeout: Duration,
    dirs: &TestDirs,
    containers: &[&Container],
    mut done: impl FnMut() -> bool,
) {
    let diagnostics = || {
        let output: Vec<String> = containers
            .iter()
            .map(|c| format!("{} output:\n{}", c.name, c.logs()))
            .collect();
        format!(
            "Provider log:\n{}\n{}",
            read(&dirs.provider_log()),
            output.join("\n")
        )
    };
    let result = tokio::time::timeout(timeout, async {
        while !done() {
            if let Some(exited) = containers.iter().find(|c| !c.is_running()) {
                return Err(exited);
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        Ok(())
    })
    .await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(exited)) => panic!(
            "{} exited with code {} while waiting for {what}.\n{}",
            exited.name,
            exited.exit_code(),
            diagnostics()
        ),
        Err(_) => panic!(
            "timed out after {timeout:?} waiting for {what}.\n{}",
            diagnostics()
        ),
    }
}

/// SIGTERM stops the provider cleanly as PID 1. A PID 1 with no handler
/// ignores SIGTERM, so a missing handler shows up as SIGKILL (exit 137) at the
/// end of the grace period.
#[tokio::test]
async fn test_container_graceful_shutdown() {
    let Some(()) = docker_available() else {
        return;
    };
    let dirs = TestDirs::new();
    // Placeholder ARNs: the export fails, which doesn't matter for shutdown.
    dirs.write_config(PLACEHOLDER_CERT_ARN, PLACEHOLDER_ROLE_ARN);
    let provider = start_provider(&dirs, CertMount::Bind, "host", &[]);
    wait_until(
        "the provider to start",
        STARTUP_TIMEOUT,
        &dirs,
        &[&provider],
        || read(&dirs.provider_log()).contains("Certificate task started"),
    )
    .await;

    let took = provider.stop();

    assert_eq!(
        provider.exit_code(),
        0,
        "the provider didn't exit cleanly on SIGTERM:\n{}",
        read(&dirs.provider_log())
    );
    assert!(
        took < Duration::from_secs(STOP_GRACE_SECONDS),
        "stopping took {took:?}, the full grace period"
    );
    assert!(
        read(&dirs.provider_log()).contains("ACM provider stopped"),
        "no shutdown line in the log:\n{}",
        read(&dirs.provider_log())
    );
}

/// The tests that export the real `ACM_TEST_CERTIFICATE_ARN` certificate.
mod requests {
    use super::*;

    /// Waits for the first cycle: the certificate files written and the
    /// refresh request queued for the watcher.
    async fn wait_for_first_cycle(dirs: &TestDirs, provider: &Container) {
        wait_until(
            "the request in the inbox",
            FIRST_CYCLE_TIMEOUT,
            dirs,
            &[provider],
            || {
                std::fs::read_dir(dirs.inbox())
                    .map(|e| {
                        e.filter_map(Result::ok)
                            .any(|e| e.path().extension().is_some_and(|x| x == "cmd"))
                    })
                    .unwrap_or(false)
            },
        )
        .await;
    }

    /// The provider exports a certificate as a non-root user with no `sudo`
    /// in the container: it writes the files and queues the reload for the
    /// watcher instead of running the command.
    #[tokio::test]
    async fn test_container_export_no_sudo() {
        let Some(()) = docker_available() else {
            return;
        };
        let cert = TestCertificate::from_env();
        let dirs = TestDirs::new();
        dirs.write_config(cert.arn(), cert.role_arn());
        shared_dir(&dirs.inbox());

        // The reload directory is mounted so the provider could create the
        // marker if it ran the command.
        let reload = [
            "--mount".to_string(),
            mount(&dirs.host("reload"), RELOAD, ""),
        ];
        let provider = start_provider(&dirs, CertMount::Bind, "host", &reload);
        wait_for_first_cycle(&dirs, &provider).await;

        assert_eq!(provider.exec(&["id", "-u"]).trim(), "65532");
        assert!(
            provider
                .exec(&["sh", "-c", "command -v sudo || true"])
                .is_empty(),
            "the image has sudo, so this doesn't prove the provider needs none"
        );
        for file in ["cert.pem", "key.pem", "chain.pem"] {
            assert!(dirs.host("certs").join(file).exists(), "{file} not written");
        }
        let log = read(&dirs.provider_log());
        assert!(log.contains("Certificate refresh successful"), "{log}");
        assert!(!log.contains("Running refresh command"), "{log}");
        assert!(!dirs.marker().exists(), "the provider ran the command");
    }

    /// The ECS/EKS sidecar layout: the provider writes the certificate to a
    /// volume the TLS container also mounts, and the watcher in the TLS
    /// container, with its config mounted read-only, runs the reload.
    #[tokio::test]
    async fn test_container_cert_write_mounted_volume() {
        let Some(()) = docker_available() else {
            return;
        };
        let cert = TestCertificate::from_env();
        let dirs = TestDirs::new();
        dirs.write_config(cert.arn(), cert.role_arn());
        assert!(
            std::fs::read_dir(dirs.host("certs"))
                .unwrap()
                .next()
                .is_none(),
            "the certificate volume must start empty"
        );

        // First run: the provider writes the watcher's config. The watcher
        // hasn't created its inbox, so the request can't be queued yet.
        let watcher_config = dirs
            .host("config")
            .join(WATCHER_ID)
            .join("watcher.config.toml");
        {
            let provider = start_provider(&dirs, CertMount::Bind, "host", &[]);
            wait_until(
                "the watcher config and first cycle",
                FIRST_CYCLE_TIMEOUT,
                &dirs,
                &[&provider],
                || {
                    watcher_config.exists()
                        && read(&dirs.provider_log())
                            .contains("Could not queue the refresh request")
                },
            )
            .await;
        }

        let watcher = start_watcher(&dirs);
        wait_until(
            "the watcher's inbox",
            STARTUP_TIMEOUT,
            &dirs,
            &[&watcher],
            || watcher.logs().contains("Startup hold window closed"),
        )
        .await;

        // Second run: the first cycle after a restart queues a request, and the
        // watcher reloads.
        let provider = start_provider(&dirs, CertMount::Bind, "host", &[]);
        let marker = dirs.marker();
        wait_until(
            "the watcher's reload",
            FIRST_CYCLE_TIMEOUT,
            &dirs,
            &[&provider, &watcher],
            || marker.exists(),
        )
        .await;

        // The TLS container reads, through its read-only mount, the
        // certificate the provider wrote to the volume, which started empty.
        // The host can't read uid 65532's files, so only the watcher reads it.
        let served = watcher.exec(&["cat", &format!("{CERTS}/cert.pem")]);
        assert!(common::is_pem_certificate(&served), "{served}");
        let output = watcher.logs();
        assert!(output.contains("Running reload"), "{output}");
        assert!(output.contains(cert.arn()), "{output}");
    }

    /// The TLS container runs nginx and the watcher, as in the README's
    /// sidecar setup. nginx starts on a placeholder certificate. The provider
    /// writes the exported certificate to the shared volume, the watcher runs
    /// `nginx -s reload`, and nginx then serves the certificate the provider
    /// wrote.
    #[tokio::test]
    async fn test_container_nginx_reload_serves_the_exported_certificate() {
        let Some(()) = docker_available() else {
            return;
        };
        let cert = TestCertificate::from_env();
        let dirs = TestDirs::new();
        let port = free_port();
        dirs.write_config_with_reload(
            cert.arn(),
            cert.role_arn(),
            &format!("/usr/sbin/nginx -c {NGINX_CONF} -s reload"),
        );
        let conf = dirs.host("nginx.conf");
        std::fs::write(&conf, nginx_conf(port)).unwrap();

        // First run: the provider writes the watcher's config. The watcher
        // hasn't created its inbox, so the request can't be queued yet.
        let watcher_config = dirs
            .host("config")
            .join(WATCHER_ID)
            .join("watcher.config.toml");
        {
            let provider = start_provider(&dirs, CertMount::Bind, "host", &[]);
            wait_until(
                "the watcher config and first cycle",
                FIRST_CYCLE_TIMEOUT,
                &dirs,
                &[&provider],
                || {
                    watcher_config.exists()
                        && read(&dirs.provider_log())
                            .contains("Could not queue the refresh request")
                },
            )
            .await;
        }

        // nginx starts on a placeholder, so serving the exported certificate
        // later shows the reload took effect.
        write_placeholder_certificate(&dirs);
        let tls = start_nginx(&dirs, &conf);
        wait_until(
            "nginx and the watcher's inbox",
            STARTUP_TIMEOUT,
            &dirs,
            &[&tls],
            || {
                tls.logs().contains("Startup hold window closed")
                    && served_der(&tls, port).is_some()
            },
        )
        .await;
        let placeholder = served_der(&tls, port).unwrap();
        assert_eq!(placeholder, file_der(&tls), "nginx serves the placeholder");

        // Second run: the files differ from the export, so the provider
        // writes them and queues a request, and the watcher reloads nginx.
        let provider = start_provider(&dirs, CertMount::Bind, "host", &[]);
        wait_until(
            "nginx to serve the exported certificate",
            FIRST_CYCLE_TIMEOUT,
            &dirs,
            &[&provider, &tls],
            || served_der(&tls, port).is_some_and(|served| served != placeholder),
        )
        .await;

        let served = served_der(&tls, port).unwrap();
        assert_eq!(
            served,
            file_der(&tls),
            "nginx serves the certificate the provider wrote"
        );
        let output = tls.logs();
        assert!(output.contains("Running reload"), "{output}");
        assert!(output.contains(cert.arn()), "{output}");
    }

    /// The provider writes the certificate to a tmpfs, as with an ECS
    /// ephemeral volume or an EKS `emptyDir` with `medium: Memory`.
    #[tokio::test]
    async fn test_container_cert_write_ephemeral_fs() {
        let Some(()) = docker_available() else {
            return;
        };
        let cert = TestCertificate::from_env();
        let dirs = TestDirs::new();
        dirs.write_config(cert.arn(), cert.role_arn());
        shared_dir(&dirs.inbox());

        let provider = start_provider(&dirs, CertMount::Tmpfs, "host", &[]);
        wait_for_first_cycle(&dirs, &provider).await;

        let fs_type = provider.exec(&["stat", "-f", "-c", "%T", CERTS]);
        assert_eq!(fs_type.trim(), "tmpfs");
        let pem = provider.exec(&["cat", &format!("{CERTS}/cert.pem")]);
        assert!(common::is_pem_certificate(&pem), "{pem}");
        let key = provider.exec(&["cat", &format!("{CERTS}/key.pem")]);
        assert!(common::is_pem_private_key(&key), "the key wasn't written");
        assert!(
            std::fs::read_dir(dirs.host("certs"))
                .unwrap()
                .next()
                .is_none(),
            "the tmpfs leaked into the host directory"
        );
    }

    /// With a read-only root filesystem, the provider writes only to its
    /// mounted volumes: certificate, logs and the watcher directories.
    #[tokio::test]
    async fn test_container_readonly_rootfs() {
        let Some(()) = docker_available() else {
            return;
        };
        let cert = TestCertificate::from_env();
        let dirs = TestDirs::new();
        dirs.write_config(cert.arn(), cert.role_arn());
        shared_dir(&dirs.inbox());

        let provider = start_provider(&dirs, CertMount::Bind, "host", &["--read-only".into()]);
        wait_for_first_cycle(&dirs, &provider).await;

        let probe = provider.exec(&["sh", "-c", "touch /probe 2>&1 || true"]);
        assert!(probe.contains("Read-only file system"), "{probe}");
        for file in ["cert.pem", "key.pem", "chain.pem"] {
            assert!(dirs.host("certs").join(file).exists(), "{file} not written");
        }
        let log = read(&dirs.provider_log());
        assert!(!log.contains("Read-only file system"), "{log}");
    }
}

/// An ECS task's network namespace: a container that owns it, with the ECS
/// agent's address on its loopback serving `${ECS_CONTAINER_METADATA_URI_V4}/task`.
/// The provider and the TLS container join it, as containers in an `awsvpc`
/// task share one namespace.
fn start_task_network(dirs: &TestDirs) -> Container {
    start_task_network_in_mode(dirs, "awsvpc")
}

/// [`start_task_network`] with the task metadata reporting `network_mode`.
fn start_task_network_in_mode(dirs: &TestDirs, network_mode: &str) -> Container {
    let task_dir = dirs.host("metadata/v4").join(ECS_METADATA_ID);
    std::fs::create_dir_all(&task_dir).unwrap();
    let task = format!(
        r#"{{"Cluster":"IntegCluster","TaskARN":"{ECS_TASK_ARN}","Containers":[{{"Name":"provider","Networks":[{{"NetworkMode":"{network_mode}"}}]}}]}}"#
    );
    std::fs::write(task_dir.join("task"), task).unwrap();
    let task_network = Container::run(
        "task",
        &[
            "--cap-add".into(),
            "NET_ADMIN".into(),
            "--mount".into(),
            mount(&dirs.host("metadata"), "/www", ",readonly"),
            TASK_NETWORK_IMAGE.into(),
            "sh".into(),
            "-c".into(),
            format!("ip addr add {ECS_AGENT_IP}/32 dev lo && exec httpd -f -p {ECS_AGENT_IP}:80 -h /www"),
        ],
    );
    let url = format!("http://{ECS_AGENT_IP}/v4/{ECS_METADATA_ID}/task");
    let ready = (0..50).any(|_| {
        let ok = docker(&["exec", &task_network.name, "wget", "-qO-", &url])
            .status
            .success();
        if !ok {
            std::thread::sleep(Duration::from_millis(200));
        }
        ok
    });
    assert!(
        ready,
        "task metadata never served:\n{}",
        task_network.logs()
    );
    task_network
}

/// `docker run` arguments that make the provider an ECS task container.
fn ecs_task_args(task_network: &Container) -> (String, Vec<String>) {
    (
        format!("container:{}", task_network.name),
        vec![
            "-e".into(),
            format!("ECS_CONTAINER_METADATA_URI_V4=http://{ECS_AGENT_IP}/v4/{ECS_METADATA_ID}"),
        ],
    )
}

/// A TLS server in the task, on loopback port [`TLS_PORT`], with a
/// self-signed certificate for `tls.integ.test`. Returns the container and the
/// certificate's DER, base64.
fn start_tls_server(task_network: &Container) -> (Container, String) {
    let tls = Container::run(
        "tls",
        &[
            "--network".into(),
            format!("container:{}", task_network.name),
            TLS_IMAGE.into(),
            "sh".into(),
            "-c".into(),
            format!(
                "openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/key.pem -out /tmp/cert.pem \
                 -subj /CN=tls.integ.test -days 1 2>/dev/null && \
                 exec openssl s_server -accept 127.0.0.1:{TLS_PORT} -cert /tmp/cert.pem -key /tmp/key.pem -www"
            ),
        ],
    );
    let ready = (0..100).any(|_| {
        let ok = tls.logs().contains("ACCEPT");
        if !ok {
            std::thread::sleep(Duration::from_millis(200));
        }
        ok
    });
    assert!(ready, "the TLS server never started:\n{}", tls.logs());
    let der = tls.exec(&[
        "sh",
        "-c",
        "openssl x509 -in /tmp/cert.pem -outform DER | openssl base64 -A",
    ]);
    (tls, der.trim().to_string())
}

/// A loopback port nothing listens on right now.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// An nginx config a non-root user can run: everything it writes is under
/// `/tmp`, and it serves TLS from the shared certificate volume on `port`.
fn nginx_conf(port: u16) -> String {
    format!(
        "daemon off;\npid /tmp/nginx.pid;\nerror_log /dev/stderr info;\nevents {{}}\n\
         http {{\n  access_log off;\n  client_body_temp_path /tmp/client_body;\n\
         proxy_temp_path /tmp/proxy;\n  fastcgi_temp_path /tmp/fastcgi;\n\
         uwsgi_temp_path /tmp/uwsgi;\n  scgi_temp_path /tmp/scgi;\n\
         server {{\n    listen 127.0.0.1:{port} ssl;\n\
         ssl_certificate {CERTS}/cert.pem;\n    ssl_certificate_key {CERTS}/key.pem;\n\
         return 200 ok;\n  }}\n}}\n"
    )
}

/// Replaces the certificate files the provider wrote with a self-signed
/// placeholder. The host can't read the provider's files, but the volume is
/// mode 0777, so it can replace them.
fn write_placeholder_certificate(dirs: &TestDirs) {
    let placeholder = rcgen::generate_simple_self_signed(vec!["placeholder.integ.test".into()])
        .expect("could not generate the placeholder certificate");
    for (name, pem) in [
        ("cert.pem", pem("CERTIFICATE", placeholder.cert.der())),
        (
            "key.pem",
            pem("PRIVATE KEY", &placeholder.key_pair.serialize_der()),
        ),
    ] {
        let path = dirs.host("certs").join(name);
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, pem).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
}

/// `der` as a PEM block with `label`.
fn pem(label: &str, der: &[u8]) -> String {
    use base64::Engine as _;
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .map(|line| std::str::from_utf8(line).unwrap())
        .collect();
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        lines.join("\n")
    )
}

/// Starts nginx and the watcher in one container, as the README's TLS
/// entrypoint does, on the host network.
fn start_nginx(dirs: &TestDirs, conf: &Path) -> Container {
    let mut args = base_args();
    args.extend([
        "--network".into(),
        "host".into(),
        "--mount".into(),
        mount(&dirs.host("config"), WATCHER_CONFIG, ",readonly"),
        "--mount".into(),
        mount(&dirs.host("requests"), WATCHER_REQUESTS, ""),
        "--mount".into(),
        mount(&dirs.host("certs"), CERTS, ",readonly"),
        "--mount".into(),
        mount(conf, NGINX_CONF, ",readonly"),
        "-e".into(),
        format!("WCP_WATCHER_ID={WATCHER_ID}"),
        "-e".into(),
        format!("WCP_WATCHER_CONFIG_DIR={WATCHER_CONFIG}"),
        "-e".into(),
        format!("WCP_WATCHER_REQUESTS_DIR={WATCHER_REQUESTS}"),
        "-e".into(),
        "WCP_WATCHER_STARTUP_HOLD_MS=1000".into(),
        "--entrypoint".into(),
        "sh".into(),
        NGINX_IMAGE.into(),
        "-c".into(),
        format!(
            "{BIN}/{} & /usr/sbin/nginx -c {NGINX_CONF} & wait",
            file_name(&locate_watcher_binary())
        ),
    ]);
    Container::run("nginx", &args)
}

/// The base64 DER of the leaf nginx serves on `port`, or `None` while it
/// isn't serving.
fn served_der(tls: &Container, port: u16) -> Option<String> {
    let out = docker(&[
        "exec",
        &tls.name,
        "sh",
        "-c",
        &format!(
            "openssl s_client -connect 127.0.0.1:{port} </dev/null 2>/dev/null \
             | openssl x509 -outform DER | openssl base64 -A"
        ),
    ]);
    let der = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (out.status.success() && !der.is_empty()).then_some(der)
}

/// The base64 DER of the leaf in the shared volume's `cert.pem`.
fn file_der(tls: &Container) -> String {
    tls.exec(&[
        "sh",
        "-c",
        &format!("openssl x509 -in {CERTS}/cert.pem -outform DER | openssl base64 -A"),
    ])
    .trim()
    .to_string()
}

/// RFC 4648 base64url without padding, as a JWT segment.
fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

/// Waits for the placeholder certificate's failed export, stops the provider
/// so the drain flushes, and returns the one automation request.
async fn stopped_automation_request(dirs: &TestDirs, provider: &Container) -> Value {
    wait_until(
        "the placeholder certificate's failed export",
        FIRST_CYCLE_TIMEOUT,
        dirs,
        &[provider],
        || {
            read(&dirs.provider_log()).contains(&format!(
                "Error refreshing certificate {PLACEHOLDER_CERT_ARN}"
            ))
        },
    )
    .await;
    provider.stop();
    assert_eq!(provider.exit_code(), 0, "{}", read(&dirs.provider_log()));
    let requests = dirs.requests_with("automation");
    assert_eq!(
        requests.len(),
        1,
        "{requests:?}\n{}",
        read(&dirs.provider_log())
    );
    let request = requests.into_iter().next().unwrap();
    assert_eq!(
        request["telemetry"]["automation"]["records"][0]["certificateArn"], PLACEHOLDER_CERT_ARN,
        "{request}"
    );
    request
}

/// In an ECS task, the provider identifies itself by the task ARN from the
/// task metadata endpoint, and its automation record carries that identity.
#[tokio::test]
async fn test_container_identity_ecs_metadata() {
    let Some(()) = docker_available() else {
        return;
    };
    let dirs = TestDirs::new();
    dirs.write_telemetry_config(true, &[]);
    let task_network = start_task_network(&dirs);
    let (network, env) = ecs_task_args(&task_network);

    let provider = start_provider(&dirs, CertMount::Bind, &network, &env);
    let request = stopped_automation_request(&dirs, &provider).await;

    assert_eq!(request["computeType"], "ECS", "{request}");
    assert_eq!(request["computeId"], ECS_TASK_ARN, "{request}");
    assert!(
        request["idempotencyKey"]
            .as_str()
            .is_some_and(|k| k.starts_with(&format!("{ECS_TASK_ARN}:"))),
        "{request}"
    );
}

/// In an EKS pod, the provider identifies itself by `namespace/pod/uid` from
/// its projected service account token, and its automation record carries
/// that identity. The token is an unsigned JWT with an EKS issuer: the
/// provider reads the claims without verifying them.
#[tokio::test]
async fn test_container_identity_eks_pod() {
    let Some(()) = docker_available() else {
        return;
    };
    let dirs = TestDirs::new();
    dirs.write_telemetry_config(true, &[]);

    let provider = start_provider(&dirs, CertMount::Bind, "host", &eks_pod_args(&dirs));
    let request = stopped_automation_request(&dirs, &provider).await;

    assert_eq!(request["computeType"], "EKS", "{request}");
    assert_eq!(request["computeId"], EKS_POD_HOST_ID, "{request}");
}

const EKS_POD_UID: &str = "a1b2c3d4-5678-90ab-cdef-1234567890ab";
const EKS_POD_HOST_ID: &str = "integ/provider-0/a1b2c3d4-5678-90ab-cdef-1234567890ab";

/// `docker run` arguments that make the provider an EKS pod container: the
/// Kubernetes service variable, and an unsigned service account token with an
/// EKS issuer at the IRSA path. The provider reads the claims without
/// verifying them.
fn eks_pod_args(dirs: &TestDirs) -> Vec<String> {
    let claims = format!(
        r#"{{"iss":"https://oidc.eks.us-west-2.amazonaws.com/id/D43CF17C27A865933144EA99A26FB128","kubernetes.io":{{"namespace":"integ","pod":{{"name":"provider-0","uid":"{EKS_POD_UID}"}}}}}}"#
    );
    let token = dirs.host("token");
    std::fs::write(&token, format!("e30.{}.c2ln", base64url(claims.as_bytes()))).unwrap();
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o644)).unwrap();
    vec![
        "-e".into(),
        "KUBERNETES_SERVICE_HOST=10.100.0.1".into(),
        "--mount".into(),
        mount(
            &token,
            "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
            ",readonly",
        ),
    ]
}

/// Asserts that `request` has one observation of [`TLS_PORT`] reporting the
/// certificate the TLS container serves.
fn assert_observes_served_certificate(request: &Value, served_der: &str) {
    let observation = discovery_observation(request, TLS_PORT);
    assert_eq!(observation["port"], TLS_PORT, "{observation:#}");
    assert_eq!(observation["outcome"], "SUCCESS", "{observation:#}");
    assert_eq!(
        observation["certificateDer"].as_str(),
        Some(served_der),
        "the observation doesn't carry the served certificate: {observation:#}"
    );
}

/// In an EKS pod, discovery probes the pod's loopback, which is the TLS
/// container's, and the discovery request carries the pod identity. The
/// busybox container stands in for the pod's network namespace.
#[tokio::test]
async fn test_container_discovery_eks_pod() {
    let Some(()) = docker_available() else {
        return;
    };
    let dirs = TestDirs::new();
    dirs.write_telemetry_config(false, &[TLS_PORT]);
    let pod_network = start_task_network(&dirs);
    let (tls, served_der) = start_tls_server(&pod_network);

    let network = format!("container:{}", pod_network.name);
    let provider = start_provider(&dirs, CertMount::Bind, &network, &eks_pod_args(&dirs));
    wait_for_discovery(&dirs, &[&provider, &tls]).await;

    let request = &dirs.requests_with("discovery")[0];
    assert_eq!(request["computeType"], "EKS", "{request}");
    assert_eq!(request["computeId"], EKS_POD_HOST_ID, "{request}");
    assert_observes_served_certificate(request, &served_der);
}

/// In an ECS task in `bridge` mode, the provider's loopback isn't the
/// application's, so discovery turns itself off and says why.
#[tokio::test]
async fn test_container_discovery_disabled_in_ecs_bridge_mode() {
    let Some(()) = docker_available() else {
        return;
    };
    let dirs = TestDirs::new();
    dirs.write_telemetry_config(false, &[TLS_PORT]);
    let task_network = start_task_network_in_mode(&dirs, "bridge");
    let (network, env) = ecs_task_args(&task_network);

    let provider = start_provider(&dirs, CertMount::Bind, &network, &env);
    wait_until(
        "discovery to be disabled",
        STARTUP_TIMEOUT,
        &dirs,
        &[&provider],
        || {
            read(&dirs.provider_log())
                .contains("Discovery disabled: ECS task network mode is bridge")
        },
    )
    .await;

    // Discovery logs its startup line before the random startup delay, so a
    // discovery loop that started would show up here already.
    let log = read(&dirs.provider_log());
    assert!(!log.contains("Certificate discovery starting"), "{log}");
    assert!(dirs.requests_with("discovery").is_empty());
}

/// The watcher runs the reload for a request in the provider's format, with
/// no AWS call: the provider writes the watcher's config at startup, before
/// any export, and the test queues the request itself.
#[tokio::test]
async fn test_container_watcher_handoff() {
    let Some(()) = docker_available() else {
        return;
    };
    let dirs = TestDirs::new();
    dirs.write_config(PLACEHOLDER_CERT_ARN, PLACEHOLDER_ROLE_ARN);
    let watcher_config = dirs
        .host("config")
        .join(WATCHER_ID)
        .join("watcher.config.toml");
    {
        let provider = start_provider(&dirs, CertMount::Bind, "host", &[]);
        wait_until(
            "the watcher config",
            STARTUP_TIMEOUT,
            &dirs,
            &[&provider],
            || watcher_config.exists(),
        )
        .await;
    }

    let watcher = start_watcher(&dirs);
    // The watcher's request directory is 0710 and owned by its user, so the
    // host can't see the inbox; wait for the watcher's startup hold to end.
    wait_until(
        "the watcher's inbox",
        STARTUP_TIMEOUT,
        &dirs,
        &[&watcher],
        || watcher.logs().contains("Startup hold window closed"),
    )
    .await;

    // The inbox belongs to the watcher's user, so queue the request as that
    // user: a temp file renamed into place, as the provider writes it.
    let command_id = "00000000-0000-4000-8000-000000000001";
    let body = format!(
        r#"{{"command_id":"{command_id}","certificate_arn":"{PLACEHOLDER_CERT_ARN}","created_at":"2026-11-20T00:00:00Z"}}"#
    );
    let inbox = format!("{WATCHER_REQUESTS}/{WATCHER_ID}/inbox");
    watcher.exec(&[
        "sh",
        "-c",
        &format!(
            "printf '%s' '{body}' > {inbox}/.request.tmp && mv {inbox}/.request.tmp {inbox}/1795130000000-000-{command_id}.cmd"
        ),
    ]);

    wait_until(
        "the watcher's reload",
        STARTUP_TIMEOUT,
        &dirs,
        &[&watcher],
        || dirs.marker().exists(),
    )
    .await;
    let output = watcher.logs();
    assert!(
        output
            .lines()
            .any(|line| line.contains("Running reload") && line.contains(PLACEHOLDER_CERT_ARN)),
        "no reload for the request's certificate:\n{output}"
    );
    assert!(!output.contains("failed"), "{output}");
    wait_until(
        "the request to be deleted",
        STARTUP_TIMEOUT,
        &dirs,
        &[&watcher],
        || {
            let empty = |sub: &str| {
                watcher
                    .exec(&[
                        "ls",
                        "-A",
                        &format!("{WATCHER_REQUESTS}/{WATCHER_ID}/{sub}"),
                    ])
                    .trim()
                    .is_empty()
            };
            empty("inbox") && empty("pending")
        },
    )
    .await;
}

/// Waits for the first discovery request in the dry-run log.
async fn wait_for_discovery(dirs: &TestDirs, containers: &[&Container]) {
    wait_until(
        "a discovery request",
        FIRST_DISCOVERY_CYCLE_TIMEOUT,
        dirs,
        containers,
        || !dirs.requests_with("discovery").is_empty(),
    )
    .await;
}

/// In an ECS task, discovery probes `127.0.0.1` in the task's network
/// namespace, which is the TLS container's loopback, and reports the
/// certificate the TLS container serves.
#[tokio::test]
async fn test_container_discovery_localhost() {
    let Some(()) = docker_available() else {
        return;
    };
    let dirs = TestDirs::new();
    dirs.write_telemetry_config(false, &[TLS_PORT]);
    let task_network = start_task_network(&dirs);
    let (tls, served_der) = start_tls_server(&task_network);
    let (network, env) = ecs_task_args(&task_network);

    let provider = start_provider(&dirs, CertMount::Bind, &network, &env);
    wait_for_discovery(&dirs, &[&provider, &tls]).await;

    let requests = dirs.requests_with("discovery");
    let request = &requests[0];
    assert_eq!(request["computeType"], "ECS", "{request}");
    assert_eq!(request["computeId"], ECS_TASK_ARN, "{request}");
    assert_observes_served_certificate(request, &served_der);
}

/// Discovery and automation run in the same process and both report: the
/// discovery request as discovery finds certificates, the automation request
/// at shutdown, both with the task's identity.
#[tokio::test]
async fn test_discovery_plus_automation_concurrent() {
    let Some(()) = docker_available() else {
        return;
    };
    let dirs = TestDirs::new();
    dirs.write_telemetry_config(true, &[TLS_PORT]);
    let task_network = start_task_network(&dirs);
    let (tls, served_der) = start_tls_server(&task_network);
    let (network, env) = ecs_task_args(&task_network);

    let provider = start_provider(&dirs, CertMount::Bind, &network, &env);
    wait_for_discovery(&dirs, &[&provider, &tls]).await;
    let automation = stopped_automation_request(&dirs, &provider).await;

    let discovery = dirs.requests_with("discovery");
    assert_observes_served_certificate(&discovery[0], &served_der);
    for request in [&discovery[0], &automation] {
        assert_eq!(request["computeId"], ECS_TASK_ARN, "{request}");
    }
    // One process identity: both records share the boot nonce in their key,
    // `{task ARN}:{boot nonce}:...`. The ARN has colons of its own, so strip
    // it before splitting.
    let nonce = |r: &Value| {
        r["idempotencyKey"]
            .as_str()
            .and_then(|key| key.strip_prefix(&format!("{ECS_TASK_ARN}:")))
            .and_then(|rest| rest.split(':').next())
            .map(str::to_string)
    };
    let automation_nonce = nonce(&automation);
    assert!(
        automation_nonce.as_deref().is_some_and(|n| !n.is_empty()),
        "{automation}"
    );
    assert_eq!(nonce(&discovery[0]), automation_nonce);
}

/// Placeholder: export with the ECS task role as the base credential.
#[test]
#[ignore = "needs a real ECS task: the provider assumes role_arn on top of the default chain, so a mock metadata endpoint can't produce a real export"]
fn test_ecs_task_role_credential() {}

/// Placeholder: export with IRSA as the base credential.
#[test]
#[ignore = "needs a real EKS pod: the provider assumes role_arn on top of the default chain, so a mock IRSA token can't produce a real export"]
fn test_eks_irsa_credential() {}
