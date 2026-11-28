//! Integration tests for the certificate discovery capability.
//!
//! Each test starts local listeners (TLS via `rcgen` + `tokio-rustls`, or
//! plain TCP), points the provider's `discovery_targets` at their ports, runs
//! the real `acm start` binary, and checks what discovery would send.
//!
//! ## What the tests assert on
//!
//! The provider runs with `[telemetry] dry_run = true` and fake credentials
//! and region. Its telemetry sender then writes each request it would send,
//! as JSON, to `logs/acm_provider_telemetry_dryrun.log`, and sends nothing.
//! The tests parse those requests and compare the reported certificate, SNI,
//! mTLS flag, TLS version and counts with what the listeners served. Probes
//! that fail are not reported, so for those the tests check the cycle's
//! summary line (`N targets, M failed`) and the probe's debug line.
//!
//! ## IMDS selection
//!
//! Discovery needs an identity (`AgentIdentity::detect()`), which on EC2 comes
//! from the instance metadata service (IMDS). The tests serve a mock IMDS by
//! default; set `DISCOVERY_INTEG_REAL_IMDS=1` or `true` to use real IMDS on EC2.
//!
//! The tests run one at a time: each takes the [`serial`] lock as its first
//! step, before it sets up any port, and holds it until the provider has
//! stopped. Tests pick free ports by binding and closing them, so a test
//! running in parallel could otherwise take a port another test just freed.

mod common;
mod mock_imds;

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use common::AcmProviderProcess;
use mock_imds::{start_mock_imds, MockImds, MockImdsConfig};
use rcgen::CertifiedKey;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, SupportedProtocolVersion};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, MutexGuard};
use tokio_rustls::TlsAcceptor;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Discovery waits a random 0-5 min after it starts, then scans.
const DISCOVERY_SCAN_TIMEOUT: Duration = Duration::from_secs(6 * 60);

/// How long to wait for a line that follows one already seen.
const FOLLOW_UP_TIMEOUT: Duration = Duration::from_secs(30);

const ACM_LOG_FILE: &str = "logs/acm_provider.log";

/// Where the dry-run sender writes each request, one JSON object per line.
const DRY_RUN_LOG_FILE: &str = "logs/acm_provider_telemetry_dryrun.log";

/// The instance ID the default mock IMDS serves.
const MOCK_INSTANCE_ID: &str = "i-mocktest123456";

/// For a server that negotiates TLS 1.2 only.
static TLS12_ONLY: &[&SupportedProtocolVersion] = &[&rustls::version::TLS12];

// ---------------------------------------------------------------------------
// Serial execution
// ---------------------------------------------------------------------------

static SERIAL: Mutex<()> = Mutex::const_new(());

/// Taken first in every test and held for the whole test, so the tests run
/// one at a time even without `--test-threads=1`. A test that panics
/// releases it on unwind.
async fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().await
}

// ---------------------------------------------------------------------------
// TLS listeners
// ---------------------------------------------------------------------------

fn ensure_crypto_provider() {
    // Later calls in the same process are no-ops.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// A self-signed ECDSA P-256 certificate for `sans`.
fn generate_cert(sans: &[&str]) -> CertifiedKey {
    ensure_crypto_provider();
    rcgen::generate_simple_self_signed(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        .expect("failed to generate self-signed certificate")
}

/// The certificate's DER, base64-encoded as the telemetry request carries it.
fn der_base64(cert: &CertifiedKey) -> String {
    BASE64.encode(cert.cert.der().as_ref())
}

/// How a test TLS listener is set up.
#[derive(Default)]
struct ListenerOptions {
    /// Ask the client for a certificate (and accept a client without one).
    request_client_cert: bool,
    /// Limit the server to these TLS versions. Default: rustls's defaults.
    versions: Option<&'static [&'static SupportedProtocolVersion]>,
}

fn build_server_config(cert: &CertifiedKey, options: &ListenerOptions) -> Arc<ServerConfig> {
    ensure_crypto_provider();
    let builder = match options.versions {
        Some(versions) => ServerConfig::builder_with_protocol_versions(versions),
        None => ServerConfig::builder(),
    };
    let builder = if options.request_client_cert {
        let mut roots = RootCertStore::empty();
        roots
            .add(cert.cert.der().clone())
            .expect("failed to add trust anchor");
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .allow_unauthenticated()
            .build()
            .expect("failed to build client verifier");
        builder.with_client_cert_verifier(verifier)
    } else {
        builder.with_no_client_auth()
    };
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    let config = builder
        .with_single_cert(vec![cert.cert.der().clone()], key)
        .expect("failed to build ServerConfig");
    Arc::new(config)
}

/// Starts a TLS listener on `127.0.0.1:0` serving `cert`, and returns its port.
/// The task ends when the test's runtime shuts down.
async fn start_tls_listener(cert: &CertifiedKey, options: ListenerOptions) -> u16 {
    serve_tls(TlsAcceptor::from(build_server_config(cert, &options))).await
}

/// Picks the certificate for the SNI name in the ClientHello, and `default`
/// when there is no name or an unknown one, as most TLS servers do. rustls's
/// `ResolvesServerCertUsingSni` has no default and rejects a ClientHello
/// without SNI, so it can't answer discovery's no-SNI probe.
#[derive(Debug)]
struct SniResolver {
    by_name: HashMap<String, Arc<rustls::sign::CertifiedKey>>,
    default: Arc<rustls::sign::CertifiedKey>,
}

impl rustls::server::ResolvesServerCert for SniResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let cert = client_hello
            .server_name()
            .and_then(|name| self.by_name.get(name))
            .unwrap_or(&self.default);
        Some(Arc::clone(cert))
    }
}

fn signing_cert(cert: &CertifiedKey) -> Arc<rustls::sign::CertifiedKey> {
    ensure_crypto_provider();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    let signing_key =
        rustls::crypto::aws_lc_rs::sign::any_supported_type(&key).expect("unsupported key");
    Arc::new(rustls::sign::CertifiedKey::new(
        vec![cert.cert.der().clone()],
        signing_key,
    ))
}

/// Starts a TLS listener on `127.0.0.1:0` that serves the certificate for
/// the SNI name the client sent, or `default`, and returns its port. A probe
/// gets a name's certificate only if it put that name in the ClientHello.
async fn start_sni_listener(default: &CertifiedKey, by_name: &[(&str, &CertifiedKey)]) -> u16 {
    let resolver = SniResolver {
        by_name: by_name
            .iter()
            .map(|(name, cert)| (name.to_string(), signing_cert(cert)))
            .collect(),
        default: signing_cert(default),
    };
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    serve_tls(TlsAcceptor::from(Arc::new(config))).await
}

/// Accepts TLS connections with `acceptor` on `127.0.0.1:0`, and returns
/// the port.
async fn serve_tls(acceptor: TlsAcceptor) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind TLS listener");
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let _ = acceptor.accept(stream).await;
            });
        }
    });
    port
}

/// Starts a plain TCP listener that reads the probe's first bytes, writes
/// `reply`, and drains the rest before closing. Draining keeps Windows from
/// turning the close into a reset that discards the reply.
async fn start_raw_listener(reply: &'static [u8]) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind plain listener");
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut first = [0u8; 1];
                if stream.read_exact(&mut first).await.is_err() {
                    return;
                }
                let _ = stream.write_all(reply).await;
                let _ = stream.shutdown().await;
                let mut rest = Vec::new();
                let _ = stream.read_to_end(&mut rest).await;
            });
        }
    });
    port
}

/// A port nothing listens on: bound by the OS, then closed.
fn closed_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("failed to bind");
    listener.local_addr().unwrap().port()
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// `discovery_targets` entries: a port and its SNI names.
fn targets(entries: &[(u16, &[&str])]) -> String {
    let mut toml = String::from("[capabilities.acm.discovery.discovery_targets]\n");
    for (port, snis) in entries {
        let snis: Vec<String> = snis.iter().map(|s| format!("\"{s}\"")).collect();
        toml.push_str(&format!("{port} = [{}]\n", snis.join(", ")));
    }
    toml
}

/// Writes a config with discovery on, the telemetry dry run on, and
/// `extra_discovery` (such as `timeout_secs_override = 75`) in the
/// discovery section.
fn write_discovery_config(config_path: &Path, extra_discovery: &str, targets_toml: &str) {
    let config = format!(
        r#"[logging]
log_to_file = true
log_level = "debug"

[telemetry]
dry_run = true

[capabilities.acm]
enabled = true

[capabilities.acm.discovery]
enabled = true
{extra_discovery}

{targets_toml}
"#
    );
    std::fs::write(config_path, config).expect("failed to write config");
}

fn write_no_discovery_config(config_path: &Path) {
    let config = r#"[logging]
log_to_file = true
log_level = "debug"

[telemetry]
dry_run = true

[capabilities.acm]
enabled = true
"#;
    std::fs::write(config_path, config).expect("failed to write config");
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

/// Variables that would make identity detection pick ECS, EKS or Lambda over
/// the mock IMDS, and inherited credentials the fake ones must replace.
const REMOVED_ENV: &[&str] = &[
    "ECS_CONTAINER_METADATA_URI_V4",
    "ECS_CONTAINER_METADATA_URI",
    "KUBERNETES_SERVICE_HOST",
    "AWS_LAMBDA_FUNCTION_NAME",
    "AWS_LAMBDA_FUNCTION_VERSION",
    "AWS_SESSION_TOKEN",
    "AWS_PROFILE",
];

/// Fake credentials and a region, so the provider builds its telemetry
/// sender. With `dry_run` it signs nothing and sends nothing.
const FAKE_AWS_ENV: &[(&str, &str)] = &[
    ("AWS_ACCESS_KEY_ID", "AKIAINTEGTESTFAKE000"),
    ("AWS_SECRET_ACCESS_KEY", "integ-test-fake-secret"),
    ("AWS_REGION", "us-west-2"),
];

fn use_real_imds() -> bool {
    std::env::var("DISCOVERY_INTEG_REAL_IMDS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// One running provider and what it needs: its directory, the mock IMDS (if
/// any) and the test's lock.
///
/// Fields drop in declaration order, after [`Drop::drop`] has stopped the
/// provider: the mock IMDS, then the temp directory, then the lock. On
/// Windows the directory can't be removed while the provider has its log
/// files open, and the lock must outlive everything the test set up.
struct Discovery {
    provider: AcmProviderProcess,
    _imds: Option<MockImds>,
    _tmp: tempfile::TempDir,
    _serial: MutexGuard<'static, ()>,
    dir: PathBuf,
}

impl Drop for Discovery {
    fn drop(&mut self) {
        self.provider.stop_blocking(Duration::from_secs(5));
    }
}

impl Discovery {
    /// Starts the provider with the default mock IMDS, or real IMDS when
    /// opted in. `serial` is the lock the test took before setting up ports.
    async fn start(serial: MutexGuard<'static, ()>, write_config: impl FnOnce(&Path)) -> Self {
        if use_real_imds() {
            eprintln!("[discovery-integ] DISCOVERY_INTEG_REAL_IMDS=1: using real IMDS");
            Self::start_with(serial, write_config, None, &[], &[]).await
        } else {
            Self::start_with(
                serial,
                write_config,
                Some(MockImdsConfig::default()),
                &[],
                &[],
            )
            .await
        }
    }

    /// Starts the provider. With `imds`, a mock IMDS serves that identity.
    /// `extra_env` is set and `removed_env` removed after the defaults.
    /// `serial` is held until the provider and its directory are gone.
    async fn start_with(
        serial: MutexGuard<'static, ()>,
        write_config: impl FnOnce(&Path),
        imds: Option<MockImdsConfig>,
        extra_env: &[(&str, &str)],
        removed_env: &[&str],
    ) -> Self {
        let tmp = tempfile::tempdir().expect("failed to create temp dir");
        // Canonical, so macOS's /var is /private/var as the provider sees it.
        let dir = tmp.path().canonicalize().expect("failed to canonicalize");
        let config_path = dir.join("config.toml");
        write_config(&config_path);

        let imds = match imds {
            Some(config) => Some(start_mock_imds(config).await),
            None => None,
        };
        let mut env: Vec<(&str, &str)> = FAKE_AWS_ENV.to_vec();
        if let Some(imds) = &imds {
            env.push(("AWS_EC2_METADATA_SERVICE_ENDPOINT", &imds.endpoint));
            env.push(("AWS_EC2_METADATA_DISABLED", "false"));
        }
        env.extend_from_slice(extra_env);
        let mut removed: Vec<&str> = REMOVED_ENV.to_vec();
        removed.retain(|key| !extra_env.iter().any(|(k, _)| k == key));
        removed.extend_from_slice(removed_env);

        let provider =
            AcmProviderProcess::start_with_env_overrides(&config_path, &dir, &env, &removed).await;
        Self {
            provider,
            _imds: imds,
            _tmp: tmp,
            _serial: serial,
            dir,
        }
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join(ACM_LOG_FILE)).unwrap_or_default()
    }

    /// Waits for a provider log line containing `target` and returns it.
    async fn wait_for_line(&self, target: &str, timeout: Duration) -> String {
        let found = tokio::time::timeout(timeout, async {
            loop {
                if let Some(line) = self.log().lines().find(|l| l.contains(target)) {
                    return line.to_string();
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        })
        .await;
        found.unwrap_or_else(|_| {
            panic!(
                "timed out after {timeout:?} waiting for {target:?}.\nLog:\n{}",
                self.log()
            )
        })
    }

    /// Asserts that, after `settle`, no provider log line contains `forbidden`.
    async fn assert_no_line(&self, forbidden: &str, settle: Duration) {
        tokio::time::sleep(settle).await;
        let log = self.log();
        assert!(
            !log.lines().any(|l| l.contains(forbidden)),
            "log unexpectedly contains {forbidden:?}.\nLog:\n{log}"
        );
    }

    /// Waits for the first discovery cycle to finish and returns its counts.
    async fn wait_for_cycle(&self) -> CycleSummary {
        let line = self
            .wait_for_line("Discovery cycle completed: ", DISCOVERY_SCAN_TIMEOUT)
            .await;
        CycleSummary::parse(&line)
    }

    /// The discovery requests the dry-run sender wrote so far.
    fn discovery_requests(&self) -> Vec<Value> {
        let content = std::fs::read_to_string(self.dir.join(DRY_RUN_LOG_FILE)).unwrap_or_default();
        content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                serde_json::from_str::<Value>(line)
                    .unwrap_or_else(|e| panic!("dry-run line is not JSON ({e}): {line}"))
            })
            .filter(|request| request["telemetry"].get("discovery").is_some())
            .collect()
    }

    /// Waits for the cycle's batches to be sent, then returns the single
    /// discovery request (every test here fits in one batch).
    async fn wait_for_one_request(&self) -> Value {
        self.wait_for_line("Discovery: submitted 1 batch(es)", FOLLOW_UP_TIMEOUT)
            .await;
        let mut requests = self.discovery_requests();
        assert_eq!(
            requests.len(),
            1,
            "expected one discovery request: {requests:#?}"
        );
        requests.remove(0)
    }

    /// Asserts that a cycle with nothing to report sent no request.
    async fn assert_nothing_sent(&self) {
        self.wait_for_line(
            "Discovery: no successful observations to report",
            FOLLOW_UP_TIMEOUT,
        )
        .await;
        assert!(
            self.discovery_requests().is_empty(),
            "nothing should be sent: {:#?}",
            self.discovery_requests()
        );
    }

    /// Asserts that the probe of `port` (with no SNI) ended with `label`.
    async fn assert_probe_outcome(&self, port: u16, label: &str) {
        self.wait_for_line(
            &format!("127.0.0.1:{port} (no sni): probe completed with {label}"),
            FOLLOW_UP_TIMEOUT,
        )
        .await;
    }
}

/// The counts in `Discovery cycle completed: N observations in Tms
/// (X targets, Y failed)`.
#[derive(Debug, PartialEq, Eq)]
struct CycleSummary {
    observations: u32,
    targets: u32,
    failed: u32,
}

impl CycleSummary {
    fn parse(line: &str) -> Self {
        let rest = line
            .split_once("Discovery cycle completed: ")
            .map(|(_, rest)| rest)
            .unwrap();
        let number_before = |text: &str, word: &str| -> u32 {
            let end = text
                .find(word)
                .unwrap_or_else(|| panic!("no {word:?} in {line:?}"));
            text[..end]
                .split(|c: char| !c.is_ascii_digit())
                .rfind(|s| !s.is_empty())
                .and_then(|n| n.parse().ok())
                .unwrap_or_else(|| panic!("no count before {word:?} in {line:?}"))
        };
        Self {
            observations: number_before(rest, " observations"),
            targets: number_before(rest, " targets"),
            failed: number_before(rest, " failed"),
        }
    }

    fn new(observations: u32, targets: u32, failed: u32) -> Self {
        Self {
            observations,
            targets,
            failed,
        }
    }
}

/// The request's observations, keyed by (port, SNI).
fn observations(request: &Value) -> HashMap<(u16, Option<String>), Value> {
    request["telemetry"]["discovery"]["observations"]
        .as_array()
        .expect("observations is an array")
        .iter()
        .map(|o| {
            let port = o["port"].as_u64().expect("port") as u16;
            let sni = o.get("sni").and_then(Value::as_str).map(str::to_string);
            ((port, sni), o.clone())
        })
        .collect()
}

/// Asserts that `observation` reports `cert` as the server's certificate.
fn assert_reports_cert(observation: &Value, cert: &CertifiedKey) {
    assert_eq!(observation["outcome"], "SUCCESS", "{observation:#}");
    assert_eq!(
        observation["certificateDer"].as_str(),
        Some(der_base64(cert).as_str()),
        "the reported certificate is not the one served: {observation:#}"
    );
}

// ---------------------------------------------------------------------------
// P0: scan, filtering, enablement, identity
// ---------------------------------------------------------------------------

/// One TLS port. The request reports that port with no SNI, the exact
/// certificate the listener served, no mTLS, and counts of 1 probed, 1
/// successful, 0 failed. Discovery uses the default 300 s timeout.
#[tokio::test]
async fn test_discovery_scan_finds_tls_cert() {
    let serial = serial().await;
    let cert = generate_cert(&["localhost"]);
    let port = start_tls_listener(&cert, ListenerOptions::default()).await;
    let run = Discovery::start(serial, |c| {
        write_discovery_config(c, "", &targets(&[(port, &[])]))
    })
    .await;

    run.wait_for_line(
        "Certificate discovery starting: 1 ports, timeout 300s",
        FOLLOW_UP_TIMEOUT,
    )
    .await;
    assert_eq!(run.wait_for_cycle().await, CycleSummary::new(1, 1, 0));
    let request = run.wait_for_one_request().await;

    let discovery = &request["telemetry"]["discovery"];
    assert_eq!(discovery["totalTargetsProbed"], 1);
    assert_eq!(discovery["successfulProbes"], 1);
    assert_eq!(discovery["failedProbes"], 0);
    assert_eq!(discovery["scanComplete"], true);
    assert_eq!(discovery["batchIndex"], 1);
    assert_eq!(discovery["totalBatches"], 1);

    let observations = observations(&request);
    assert_eq!(observations.len(), 1, "{request:#}");
    let observation = &observations[&(port, None)];
    assert_reports_cert(observation, &cert);
    assert_eq!(observation["mtlsDetected"], false);
}

/// A closed port is probed (1 target, 1 failed), its probe ends with
/// `connection_refused`, and nothing is sent.
#[tokio::test]
async fn test_discovery_connection_refused_filtered() {
    let serial = serial().await;
    let port = closed_port();
    let run = Discovery::start(serial, |c| {
        write_discovery_config(c, "", &targets(&[(port, &[])]))
    })
    .await;

    assert_eq!(run.wait_for_cycle().await, CycleSummary::new(0, 1, 1));
    run.assert_probe_outcome(port, "connection_refused").await;
    run.assert_nothing_sent().await;
}

/// With no discovery section, the provider starts but discovery never does.
/// Identity detection against the mock IMDS takes milliseconds, and the
/// provider logs `Certificate discovery starting` before its random delay,
/// so a few seconds after startup that line would be there if discovery ran.
#[tokio::test]
async fn test_discovery_disabled_does_not_scan() {
    let serial = serial().await;
    let run = Discovery::start(serial, write_no_discovery_config).await;

    run.wait_for_line("ACM Scheduler starting", FOLLOW_UP_TIMEOUT)
        .await;
    run.assert_no_line("Certificate discovery starting", Duration::from_secs(5))
        .await;
    assert!(run.discovery_requests().is_empty());
}

/// Two TLS ports and a closed one: 3 probed, 1 failed, and the request
/// reports exactly the two TLS ports.
#[tokio::test]
async fn test_discovery_multiple_ports() {
    let serial = serial().await;
    let cert = generate_cert(&["localhost"]);
    let port1 = start_tls_listener(&cert, ListenerOptions::default()).await;
    let port2 = start_tls_listener(&cert, ListenerOptions::default()).await;
    let closed = closed_port();
    let run = Discovery::start(serial, |c| {
        write_discovery_config(
            c,
            "",
            &targets(&[(port1, &[]), (port2, &[]), (closed, &[])]),
        )
    })
    .await;

    assert_eq!(run.wait_for_cycle().await, CycleSummary::new(2, 3, 1));
    let request = run.wait_for_one_request().await;
    assert_eq!(request["telemetry"]["discovery"]["totalTargetsProbed"], 3);
    assert_eq!(request["telemetry"]["discovery"]["failedProbes"], 1);

    let observations = observations(&request);
    let ports: BTreeSet<u16> = observations.keys().map(|(port, _)| *port).collect();
    assert_eq!(ports, BTreeSet::from([port1, port2]));
    for observation in observations.values() {
        assert_reports_cert(observation, &cert);
    }
}

/// The identity IMDS serves is the one the request carries: compute ID,
/// compute type, and the instance ID at the start of the scan ID and
/// idempotency key. With real IMDS, the compute ID is an instance ID.
#[tokio::test]
async fn test_discovery_identity_resolution() {
    let serial = serial().await;
    let cert = generate_cert(&["localhost"]);
    let port = start_tls_listener(&cert, ListenerOptions::default()).await;
    let write = |c: &Path| write_discovery_config(c, "", &targets(&[(port, &[])]));
    let real = use_real_imds();
    let run = if real {
        Discovery::start(serial, write).await
    } else {
        let imds = MockImdsConfig {
            instance_id: "i-mockidentity999".to_string(),
            account_id: "111222333444".to_string(),
            region: "eu-west-1".to_string(),
        };
        Discovery::start_with(serial, write, Some(imds), &[], &[]).await
    };

    run.wait_for_cycle().await;
    let request = run.wait_for_one_request().await;
    assert!(!run.log().contains("identity detection failed"));
    assert_eq!(request["computeType"], "EC2");

    let compute_id = request["computeId"].as_str().expect("computeId");
    if real {
        assert!(compute_id.starts_with("i-"), "{compute_id}");
    } else {
        assert_eq!(compute_id, "i-mockidentity999");
    }
    let scan_id = request["telemetry"]["discovery"]["scanId"]
        .as_str()
        .expect("scanId");
    assert!(scan_id.starts_with(&format!("{compute_id}:")), "{scan_id}");
    let key = request["idempotencyKey"].as_str().expect("idempotencyKey");
    assert!(key.starts_with(&format!("{compute_id}:")), "{key}");
}

/// When identity detection fails (IMDS doesn't answer), discovery logs why
/// and never starts, and the provider keeps running.
#[tokio::test]
async fn test_discovery_identity_failure_skips_discovery() {
    let serial = serial().await;
    let cert = generate_cert(&["localhost"]);
    let port = start_tls_listener(&cert, ListenerOptions::default()).await;
    let unreachable = format!("http://127.0.0.1:{}", closed_port());
    let mut run = Discovery::start_with(
        serial,
        |c| write_discovery_config(c, "", &targets(&[(port, &[])])),
        None,
        &[
            ("AWS_EC2_METADATA_SERVICE_ENDPOINT", &unreachable),
            ("AWS_EC2_METADATA_DISABLED", "false"),
        ],
        &[],
    )
    .await;

    run.wait_for_line("Discovery: identity detection failed", FOLLOW_UP_TIMEOUT)
        .await;
    run.assert_no_line("Certificate discovery starting", Duration::from_secs(2))
        .await;
    assert!(run.discovery_requests().is_empty());
    assert!(
        run.provider.is_running(),
        "the provider should keep running"
    );
}

/// An identity with no discovery mode (Lambda) turns discovery off with the
/// reason, and nothing is probed or sent.
#[tokio::test]
async fn test_discovery_unsupported_compute_skips_discovery() {
    let serial = serial().await;
    let cert = generate_cert(&["localhost"]);
    let port = start_tls_listener(&cert, ListenerOptions::default()).await;
    let run = Discovery::start_with(
        serial,
        |c| write_discovery_config(c, "", &targets(&[(port, &[])])),
        None,
        &[
            ("AWS_LAMBDA_FUNCTION_NAME", "integ-test"),
            ("AWS_LAMBDA_FUNCTION_VERSION", "$LATEST"),
        ],
        &[],
    )
    .await;

    run.wait_for_line(
        "Discovery disabled: no supported discovery mode for deployment type Lambda",
        FOLLOW_UP_TIMEOUT,
    )
    .await;
    run.assert_no_line("Certificate discovery starting", Duration::from_secs(2))
        .await;
    assert!(run.discovery_requests().is_empty());
}

// ---------------------------------------------------------------------------
// P1: request shape, SNI, failures, config, TLS metadata
// ---------------------------------------------------------------------------

/// The request has the envelope the service expects: schema version 1, the
/// host's OS and architecture, and an idempotency key of the form
/// `<computeId>:<bootNonce>:acm:cert_discovery:<sequence>:<batch>`, which is
/// `...:0:0` for the first batch of the first cycle. The provider warns that
/// telemetry is a dry run.
#[tokio::test]
async fn test_discovery_dry_run_request_shape() {
    let serial = serial().await;
    let cert = generate_cert(&["localhost"]);
    let port = start_tls_listener(&cert, ListenerOptions::default()).await;
    let run = Discovery::start(serial, |c| {
        write_discovery_config(c, "", &targets(&[(port, &[])]))
    })
    .await;

    run.wait_for_line("Telemetry dry run for acm", FOLLOW_UP_TIMEOUT)
        .await;
    run.wait_for_cycle().await;
    let request = run.wait_for_one_request().await;

    assert_eq!(request["schemaVersion"], 1);
    let os = if cfg!(target_os = "macos") {
        "MACOS"
    } else if cfg!(windows) {
        "WINDOWS"
    } else {
        "LINUX"
    };
    assert_eq!(request["os"], os);
    let arch = if cfg!(target_arch = "aarch64") {
        "ARM64"
    } else {
        "X86_64"
    };
    assert_eq!(request["arch"], arch);
    assert_eq!(
        request["telemetry"]["discovery"]["configuredCertificateCount"],
        0
    );

    let compute_id = request["computeId"].as_str().expect("computeId");
    if !use_real_imds() {
        assert_eq!(compute_id, MOCK_INSTANCE_ID);
    }
    let key = request["idempotencyKey"].as_str().expect("idempotencyKey");
    let parts: Vec<&str> = key.split(':').collect();
    assert_eq!(parts.len(), 6, "{key}");
    assert_eq!(parts[0], compute_id, "{key}");
    assert!(!parts[1].is_empty(), "boot nonce is empty: {key}");
    assert_eq!(&parts[2..], ["acm", "cert_discovery", "0", "0"], "{key}");
}

/// One SNI name on a port whose server picks its certificate by SNI: the
/// probe without SNI gets the default certificate, and the probe with the
/// name gets that name's certificate, which it can only get if it sent the
/// name in the ClientHello.
#[tokio::test]
async fn test_discovery_sni_hostname() {
    let serial = serial().await;
    let default = generate_cert(&["localhost"]);
    let api = generate_cert(&["api.example.com"]);
    let port = start_sni_listener(&default, &[("api.example.com", &api)]).await;
    let run = Discovery::start(serial, |c| {
        write_discovery_config(c, "", &targets(&[(port, &["api.example.com"])]))
    })
    .await;

    assert_eq!(run.wait_for_cycle().await, CycleSummary::new(2, 2, 0));
    let observations = observations(&run.wait_for_one_request().await);
    let keys: BTreeSet<_> = observations.keys().cloned().collect();
    let with_sni = (port, Some("api.example.com".to_string()));
    assert_eq!(keys, BTreeSet::from([(port, None), with_sni.clone()]));
    assert_reports_cert(&observations[&(port, None)], &default);
    assert_reports_cert(&observations[&with_sni], &api);
}

/// Two SNI names on one port whose server picks its certificate by SNI:
/// three probes, and each reports its own certificate (alpha, beta, or the
/// default for the probe without SNI).
#[tokio::test]
async fn test_discovery_multi_sni_per_port() {
    let serial = serial().await;
    let default = generate_cert(&["localhost"]);
    let alpha = generate_cert(&["alpha.example.com"]);
    let beta = generate_cert(&["beta.example.com"]);
    let port = start_sni_listener(
        &default,
        &[("alpha.example.com", &alpha), ("beta.example.com", &beta)],
    )
    .await;
    let run = Discovery::start(serial, |c| {
        write_discovery_config(
            c,
            "",
            &targets(&[(port, &["alpha.example.com", "beta.example.com"])]),
        )
    })
    .await;

    assert_eq!(run.wait_for_cycle().await, CycleSummary::new(3, 3, 0));
    let observations = observations(&run.wait_for_one_request().await);
    let snis: BTreeSet<Option<String>> = observations.keys().map(|(_, sni)| sni.clone()).collect();
    assert_eq!(
        snis,
        BTreeSet::from([
            None,
            Some("alpha.example.com".to_string()),
            Some("beta.example.com".to_string()),
        ])
    );
    assert_reports_cert(&observations[&(port, None)], &default);
    assert_reports_cert(
        &observations[&(port, Some("alpha.example.com".to_string()))],
        &alpha,
    );
    assert_reports_cert(
        &observations[&(port, Some("beta.example.com".to_string()))],
        &beta,
    );
}

/// Two ports serving different certificates, each with its own SNI name:
/// every observation reports the certificate its own port served. This
/// covers choosing the certificate per port; the two tests above cover
/// choosing it per SNI name on one port.
#[tokio::test]
async fn test_discovery_multi_cert_sni() {
    let serial = serial().await;
    let alpha = generate_cert(&["alpha.example.com"]);
    let beta = generate_cert(&["beta.example.com"]);
    let port_alpha = start_tls_listener(&alpha, ListenerOptions::default()).await;
    let port_beta = start_tls_listener(&beta, ListenerOptions::default()).await;
    let run = Discovery::start(serial, |c| {
        write_discovery_config(
            c,
            "",
            &targets(&[
                (port_alpha, &["alpha.example.com"]),
                (port_beta, &["beta.example.com"]),
            ]),
        )
    })
    .await;

    assert_eq!(run.wait_for_cycle().await, CycleSummary::new(4, 4, 0));
    let observations = observations(&run.wait_for_one_request().await);
    assert_eq!(observations.len(), 4);
    for ((port, sni), observation) in &observations {
        let (cert, name) = if *port == port_alpha {
            (&alpha, "alpha.example.com")
        } else {
            assert_eq!(*port, port_beta);
            (&beta, "beta.example.com")
        };
        if let Some(sni) = sni {
            assert_eq!(sni, name, "port {port} was probed with the wrong SNI");
        }
        assert_reports_cert(observation, cert);
    }
}

/// A port that answers with HTTP: the probe ends with `not_tls`, and nothing
/// is sent.
#[tokio::test]
async fn test_discovery_not_tls() {
    let serial = serial().await;
    let port = start_raw_listener(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
    let run = Discovery::start(serial, |c| {
        write_discovery_config(c, "", &targets(&[(port, &[])]))
    })
    .await;

    assert_eq!(run.wait_for_cycle().await, CycleSummary::new(0, 1, 1));
    run.assert_probe_outcome(port, "not_tls").await;
    run.assert_nothing_sent().await;
}

/// A port that answers the ClientHello with a TLS `handshake_failure` alert:
/// the probe ends with `handshake_error`, and nothing is sent.
#[tokio::test]
async fn test_discovery_handshake_error() {
    let serial = serial().await;
    // Alert record: content type 21, TLS 1.2, length 2, fatal (2),
    // handshake_failure (40).
    let port = start_raw_listener(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]).await;
    let run = Discovery::start(serial, |c| {
        write_discovery_config(c, "", &targets(&[(port, &[])]))
    })
    .await;

    assert_eq!(run.wait_for_cycle().await, CycleSummary::new(0, 1, 1));
    run.assert_probe_outcome(port, "handshake_error").await;
    run.assert_nothing_sent().await;
}

/// `timeout_secs_override` replaces the default 300 s cycle timeout.
#[tokio::test]
async fn test_discovery_timeout_override_applied() {
    let serial = serial().await;
    let cert = generate_cert(&["localhost"]);
    let port1 = start_tls_listener(&cert, ListenerOptions::default()).await;
    let port2 = start_tls_listener(&cert, ListenerOptions::default()).await;
    let run = Discovery::start(serial, |c| {
        write_discovery_config(
            c,
            "timeout_secs_override = 75",
            &targets(&[(port1, &[]), (port2, &[])]),
        )
    })
    .await;

    run.wait_for_line(
        "Certificate discovery starting: 2 ports, timeout 75s",
        FOLLOW_UP_TIMEOUT,
    )
    .await;
    assert_eq!(run.wait_for_cycle().await, CycleSummary::new(2, 2, 0));
}

/// A server that asks for a client certificate is reported with
/// `mtlsDetected: true`, and its certificate is still captured.
#[tokio::test]
async fn test_discovery_mtls_detected() {
    let serial = serial().await;
    let cert = generate_cert(&["localhost"]);
    let options = ListenerOptions {
        request_client_cert: true,
        ..Default::default()
    };
    let port = start_tls_listener(&cert, options).await;
    let run = Discovery::start(serial, |c| {
        write_discovery_config(c, "", &targets(&[(port, &[])]))
    })
    .await;

    assert_eq!(run.wait_for_cycle().await, CycleSummary::new(1, 1, 0));
    let observations = observations(&run.wait_for_one_request().await);
    let observation = &observations[&(port, None)];
    assert_reports_cert(observation, &cert);
    assert_eq!(observation["mtlsDetected"], true, "{observation:#}");
}

/// The negotiated TLS version and cipher suite are reported: TLS 1.3 by
/// default, and TLS 1.2 with an ECDHE-ECDSA suite from a TLS 1.2-only server.
#[tokio::test]
async fn test_discovery_tls_version_and_cipher_suite() {
    let serial = serial().await;
    let cert = generate_cert(&["localhost"]);
    let tls13 = start_tls_listener(&cert, ListenerOptions::default()).await;
    let tls12 = start_tls_listener(
        &cert,
        ListenerOptions {
            versions: Some(TLS12_ONLY),
            ..Default::default()
        },
    )
    .await;
    let run = Discovery::start(serial, |c| {
        write_discovery_config(c, "", &targets(&[(tls13, &[]), (tls12, &[])]))
    })
    .await;

    assert_eq!(run.wait_for_cycle().await, CycleSummary::new(2, 2, 0));
    let observations = observations(&run.wait_for_one_request().await);

    let o13 = &observations[&(tls13, None)];
    assert_eq!(o13["tlsVersion"], "TLSv1.3", "{o13:#}");
    let suite13 = o13["cipherSuite"].as_str().expect("cipherSuite");
    assert!(
        [
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256"
        ]
        .contains(&suite13),
        "{o13:#}"
    );

    let o12 = &observations[&(tls12, None)];
    assert_eq!(o12["tlsVersion"], "TLSv1.2", "{o12:#}");
    let suite12 = o12["cipherSuite"].as_str().expect("cipherSuite");
    assert!(suite12.starts_with("TLS_ECDHE_ECDSA_WITH_"), "{o12:#}");
}
