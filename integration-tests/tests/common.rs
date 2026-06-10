//! # Integration Test Common Utilities
//!
//! This module provides shared utilities and helper functions for AWS Workload Credentials Provider
//! integration tests. It includes test secret management, provider process control, and
//! HTTP request building functionality.

use aws_config;
use aws_sdk_secretsmanager;
use aws_sdk_sts;
use derive_builder::Builder;
use std::env;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command as TokioCommand;
use url::Url;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum SecretType {
    Basic,
    Binary,
    Versioned,
    Large,
    Tagged { tag_key: String },
}

impl fmt::Display for SecretType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretType::Basic => write!(f, "basic"),
            SecretType::Binary => write!(f, "binary"),
            SecretType::Versioned => write!(f, "versioned"),
            SecretType::Large => write!(f, "large"),
            SecretType::Tagged { .. } => write!(f, "tagged"),
        }
    }
}

#[derive(Debug, Clone, Builder)]
#[builder(setter(into, strip_option))]
pub struct ProviderQuery {
    pub secret_id: String,
    #[builder(default)]
    pub version_id: Option<String>,
    #[builder(default)]
    pub version_stage: Option<String>,
    #[builder(default)]
    pub refresh_now: Option<bool>,
    #[builder(default)]
    pub role_arn: Option<String>,
}

impl ProviderQuery {
    pub fn to_query_string(&self) -> String {
        let mut url = Url::parse("http://localhost/").unwrap();
        {
            let mut query_pairs = url.query_pairs_mut();
            query_pairs.append_pair("secretId", &self.secret_id);

            if let Some(version_id) = &self.version_id {
                query_pairs.append_pair("versionId", version_id);
            }

            if let Some(version_stage) = &self.version_stage {
                query_pairs.append_pair("versionStage", version_stage);
            }

            if let Some(refresh_now) = self.refresh_now {
                query_pairs.append_pair("refreshNow", &refresh_now.to_string());
            }

            if let Some(role_arn) = &self.role_arn {
                query_pairs.append_pair("roleArn", role_arn);
            }
        }
        url.query().unwrap_or("").to_string()
    }
}

pub struct ProviderProcess {
    pub _child: tokio::process::Child,
    pub port: u16,
}

impl ProviderProcess {
    pub async fn start() -> ProviderProcess {
        Self::start_with_config(2775, 5_u64).await
    }

    pub async fn start_with_config(port: u16, ttl_seconds: u64) -> ProviderProcess {
        let config_content = format!(
            r#"
[logging]
log_level = "info"

[capabilities.secrets_manager]
http_port = {}
validate_credentials = true

[capabilities.secrets_manager.cache]
ttl_seconds = {}
"#,
            port, ttl_seconds
        );

        Self::start_with_config_content(port, &config_content).await
    }

    /// Start the provider with a fully custom config string.
    pub async fn start_with_config_content(port: u16, config_content: &str) -> ProviderProcess {
        let config_path = std::env::temp_dir().join(format!("test_config_{}.toml", port));
        std::fs::write(&config_path, config_content).expect("Failed to write test config");

        env::set_var("AWS_TOKEN", "test-token-123");

        let provider_path = locate_provider_binary();

        let mut child = TokioCommand::new(&provider_path)
            .arg("sm")
            .arg("start")
            .arg("--config")
            .arg(&config_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("Failed to start provider");

        // Read stdout until we see the "listening" message
        let stdout = child.stdout.take().expect("Failed to get stdout");
        let mut reader = BufReader::new(stdout).lines();

        match reader.next_line().await {
            Ok(Some(line)) => {
                if !line.contains("listening on") {
                    panic!("Provider failed to start - no listening message found");
                }
            }
            Ok(None) => {
                panic!("Stream ended without finding listening message");
            }
            Err(e) => {
                panic!("Failed to read provider output: {}", e);
            }
        }

        ProviderProcess {
            _child: child,
            port,
        }
    }

    #[allow(dead_code)]
    pub async fn make_request(&self, query: &ProviderQuery) -> String {
        let response = self.make_request_raw(query).await;
        let status = response.status();
        if status != 200 {
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read error body".to_string());
            panic!("Provider returned status {}: {}", status, error_body);
        }
        response.text().await.expect("Failed to read response body")
    }

    pub async fn make_request_raw(&self, query: &ProviderQuery) -> reqwest::Response {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .build()
            .expect("Failed to build HTTP client");
        let mut url = Url::parse(&format!(
            "http://localhost:{}/secretsmanager/get",
            self.port
        ))
        .expect("Failed to parse URL");
        url.set_query(Some(&query.to_query_string()));

        // CodeQL suppression: This is localhost-only communication in test environment
        // The provider is designed to only accept requests on localhost for security
        client
            .get(url)
            .header("X-Aws-Parameters-Secrets-Token", "test-token-123")
            .send()
            .await
            .expect("Failed to make provider request")
    }

    #[allow(dead_code)]
    pub async fn make_request_without_token(&self, query: &ProviderQuery) -> reqwest::Response {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .build()
            .expect("Failed to build HTTP client");
        let mut url = Url::parse(&format!(
            "http://localhost:{}/secretsmanager/get",
            self.port
        ))
        .expect("Failed to parse URL");
        url.set_query(Some(&query.to_query_string()));

        // CodeQL suppression: This is localhost-only communication in test environment
        client
            .get(url)
            .send()
            .await
            .expect("Failed to make provider request")
    }

    #[allow(dead_code)]
    pub async fn make_request_with_invalid_token(
        &self,
        query: &ProviderQuery,
    ) -> reqwest::Response {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .build()
            .expect("Failed to build HTTP client");
        let mut url = Url::parse(&format!(
            "http://localhost:{}/secretsmanager/get",
            self.port
        ))
        .expect("Failed to parse URL");
        url.set_query(Some(&query.to_query_string()));

        // CodeQL suppression: This is localhost-only communication in test environment
        client
            .get(url)
            .header("X-Aws-Parameters-Secrets-Token", "invalid-token-456")
            .send()
            .await
            .expect("Failed to make provider request")
    }

    #[allow(dead_code)]
    pub async fn make_request_with_x_forwarded_for(
        &self,
        query: &ProviderQuery,
    ) -> reqwest::Response {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .build()
            .expect("Failed to build HTTP client");
        let mut url = Url::parse(&format!(
            "http://localhost:{}/secretsmanager/get",
            self.port
        ))
        .expect("Failed to parse URL");
        url.set_query(Some(&query.to_query_string()));

        // CodeQL suppression: This is localhost-only communication in test environment
        client
            .get(url)
            .header("X-Aws-Parameters-Secrets-Token", "test-token-123")
            .header("X-Forwarded-For", "192.168.1.100")
            .send()
            .await
            .expect("Failed to make provider request")
    }

    #[allow(dead_code)]
    pub async fn make_ping_request(&self) -> reqwest::Response {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .build()
            .expect("Failed to build HTTP client");
        let url = Url::parse(&format!("http://localhost:{}/ping", self.port))
            .expect("Failed to parse URL");

        // CodeQL suppression: This is localhost-only communication in test environment
        client
            .get(url)
            .send()
            .await
            .expect("Failed to make ping request")
    }

    #[allow(dead_code)]
    pub async fn make_ping_request_with_token(&self) -> reqwest::Response {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .build()
            .expect("Failed to build HTTP client");
        let url = Url::parse(&format!("http://localhost:{}/ping", self.port))
            .expect("Failed to parse URL");

        // CodeQL suppression: This is localhost-only communication in test environment
        client
            .get(url)
            .header("X-Aws-Parameters-Secrets-Token", "test-token-123")
            .send()
            .await
            .expect("Failed to make ping request")
    }

    #[allow(dead_code)]
    pub async fn make_path_based_request(&self, secret_name: &str) -> reqwest::Response {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .build()
            .expect("Failed to build HTTP client");
        let url = Url::parse(&format!(
            "http://localhost:{}/v1/{}",
            self.port, secret_name
        ))
        .expect("Failed to parse URL");

        // CodeQL suppression: This is localhost-only communication in test environment
        client
            .get(url)
            .header("X-Aws-Parameters-Secrets-Token", "test-token-123")
            .send()
            .await
            .expect("Failed to make path-based request")
    }
}

pub struct TestSecrets {
    pub prefix: String,
    pub created_types: Vec<SecretType>,
}

impl TestSecrets {
    pub fn secret_name(&self, secret_type: &SecretType) -> String {
        format!("{}-{}", self.prefix, secret_type)
    }

    #[allow(dead_code)]
    pub async fn setup_basic() -> Self {
        Self::setup_with_types(vec![SecretType::Basic]).await
    }

    #[allow(dead_code)]
    pub async fn setup_tagged(tag_key: &str) -> Self {
        Self::setup_with_types(vec![SecretType::Tagged {
            tag_key: tag_key.to_string(),
        }])
        .await
    }

    #[allow(dead_code)]
    pub async fn setup_binary() -> Self {
        Self::setup_with_types(vec![SecretType::Binary]).await
    }

    #[allow(dead_code)]
    pub async fn setup_versioned() -> Self {
        Self::setup_with_types(vec![SecretType::Versioned]).await
    }

    #[allow(dead_code)]
    pub async fn setup_large() -> Self {
        Self::setup_with_types(vec![SecretType::Large]).await
    }

    async fn setup_with_types(types: Vec<SecretType>) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let test_prefix = format!("aws-workload-credentials-provider-test-{}", timestamp);

        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = aws_sdk_secretsmanager::Client::new(&config);

        let temp_secrets = Self {
            prefix: test_prefix.clone(),
            created_types: types.clone(),
        };

        for secret_type in types {
            match secret_type {
                SecretType::Basic => {
                    let secret_name = temp_secrets.secret_name(&SecretType::Basic);
                    client
                        .create_secret()
                        .name(&secret_name)
                        .description("Basic test secret for aws-workload-credentials-provider")
                        .secret_string(r#"{"username":"testuser","password":"testpass123"}"#)
                        .send()
                        .await
                        .expect("Failed to create test secret");
                }
                SecretType::Binary => {
                    let binary_secret_name = temp_secrets.secret_name(&SecretType::Binary);
                    let binary_data = b"\x00\x01\x02\x03\xFF\xFE\xFD";
                    client
                        .create_secret()
                        .name(&binary_secret_name)
                        .description("Binary test secret for aws-workload-credentials-provider")
                        .secret_binary(aws_sdk_secretsmanager::primitives::Blob::new(binary_data))
                        .send()
                        .await
                        .expect("Failed to create binary test secret");
                }
                SecretType::Versioned => {
                    let versioned_secret_name = temp_secrets.secret_name(&SecretType::Versioned);
                    client
                        .create_secret()
                        .name(&versioned_secret_name)
                        .description("Versioned test secret for aws-workload-credentials-provider")
                        .secret_string(r#"{"username":"currentuser","password":"currentpass"}"#)
                        .send()
                        .await
                        .expect("Failed to create versioned test secret");

                    // Create AWSPENDING version using put_secret_value
                    client
                        .put_secret_value()
                        .secret_id(&versioned_secret_name)
                        .secret_string(r#"{"username":"pendinguser","password":"pendingpass"}"#)
                        .version_stages("AWSPENDING")
                        .send()
                        .await
                        .expect("Failed to create AWSPENDING version");
                }
                SecretType::Large => {
                    let large_secret_name = temp_secrets.secret_name(&SecretType::Large);
                    let large_data = "x".repeat(60000); // ~60KB of data
                    let large_secret_json = format!(r#"{{"data":"{}","size":"60KB"}}"#, large_data);
                    client
                        .create_secret()
                        .name(&large_secret_name)
                        .description("Large test secret for aws-workload-credentials-provider")
                        .secret_string(&large_secret_json)
                        .send()
                        .await
                        .expect("Failed to create large test secret");
                }
                SecretType::Tagged { tag_key } => {
                    let tagged_secret_name = temp_secrets.secret_name(&SecretType::Tagged {
                        tag_key: tag_key.clone(),
                    });
                    client
                        .create_secret()
                        .name(&tagged_secret_name)
                        .description("Tagged test secret for prefetch integration tests")
                        .secret_string(r#"{"username":"testuser","password":"testpass123"}"#)
                        .tags(
                            aws_sdk_secretsmanager::types::Tag::builder()
                                .key(&tag_key)
                                .value("integration-testing")
                                .build(),
                        )
                        .send()
                        .await
                        .expect("Failed to create tagged test secret");
                }
            }
        }

        temp_secrets
    }

    #[allow(dead_code)]
    pub async fn wait_for_tag(
        &self,
        secret_type: &SecretType,
        tag_key: &str,
    ) -> Result<(), tokio::time::error::Elapsed> {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = aws_sdk_secretsmanager::Client::new(&config);
        let secret_name = self.secret_name(secret_type);

        tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                let resp = client
                    .batch_get_secret_value()
                    .filters(
                        aws_sdk_secretsmanager::types::Filter::builder()
                            .key(aws_sdk_secretsmanager::types::FilterNameStringType::TagKey)
                            .values(tag_key)
                            .build(),
                    )
                    .send()
                    .await;
                if let Ok(output) = resp {
                    if output
                        .secret_values()
                        .iter()
                        .any(|s| s.name() == Some(secret_name.as_str()))
                    {
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        })
        .await
    }

    #[allow(dead_code)]
    pub async fn wait_for_pending_version(
        &self,
        secret_type: &SecretType,
    ) -> Result<(), tokio::time::error::Elapsed> {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let (_, pending_version) = self.get_version_ids(secret_type).await;
                if !pending_version.is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await
    }

    #[allow(dead_code)]
    pub async fn get_version_ids(&self, secret_type: &SecretType) -> (String, String) {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = aws_sdk_secretsmanager::Client::new(&config);
        let secret_name = self.secret_name(secret_type);

        let describe_response = client
            .describe_secret()
            .secret_id(&secret_name)
            .send()
            .await
            .expect("Failed to describe secret");

        let version_ids_to_stages = describe_response.version_ids_to_stages().unwrap();
        let mut current_version = String::new();
        let mut pending_version = String::new();

        for (version_id, stages) in version_ids_to_stages {
            if stages.contains(&"AWSCURRENT".to_string()) {
                current_version = version_id.clone();
            }
            if stages.contains(&"AWSPENDING".to_string()) {
                pending_version = version_id.clone();
            }
        }

        (current_version, pending_version)
    }
}

impl Drop for TestSecrets {
    fn drop(&mut self) {
        let prefix = self.prefix.clone();
        let created_types = self.created_types.clone();
        tokio::spawn(async move {
            let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
            let client = aws_sdk_secretsmanager::Client::new(&config);

            for secret_type in created_types {
                let secret_name = format!("{}-{}", prefix, secret_type);
                let _ = client
                    .delete_secret()
                    .secret_id(&secret_name)
                    .force_delete_without_recovery(true)
                    .send()
                    .await;
            }
        });
    }
}

// ---- Role assumption helpers ----

/// Well-known role names for integration tests.
pub const ROLE_CHAINING_ROLE_NAME: &str = "asm-role-chaining-role";
#[allow(dead_code)]
pub const NO_ACCESS_ROLE_NAME: &str = "provider-no-access-role";

/// Helper for role-chaining integration tests.
/// Discovers the account ID and provides role ARN construction with pre-flight validation.
pub struct RoleChainingHelper {
    pub client: aws_sdk_sts::Client,
    pub account_id: String,
}

impl RoleChainingHelper {
    #[allow(dead_code)]
    pub async fn new() -> Self {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = aws_sdk_sts::Client::new(&config);
        let account_id = client
            .get_caller_identity()
            .send()
            .await
            .expect("Failed to call GetCallerIdentity")
            .account()
            .expect("No account ID in response")
            .to_string();
        Self { client, account_id }
    }

    /// Pre-flight check: verify the role can be assumed, panic with a clear message if not.
    /// Returns the full role ARN on success.
    #[allow(dead_code)]
    pub async fn get_role_arn(&self, role_name: &str) -> String {
        let role_arn = format!("arn:aws:iam::{}:role/{role_name}", self.account_id);
        self.client
            .assume_role()
            .role_arn(&role_arn)
            .role_session_name("role-chaining-integration-tests")
            .send()
            .await
            .unwrap_or_else(|e| panic!("Failed to assume role {role_name}: {e}"));
        role_arn
    }

    /// Build a role ARN without pre-flight validation.
    #[allow(dead_code)]
    pub fn build_role_arn(&self, role_name: &str) -> String {
        format!("arn:aws:iam::{}:role/{role_name}", self.account_id)
    }
}

/// References a pre-existing ACM certificate that the integ test points the
/// provider at. The certificate is owned by the test operator — these tests do
/// not create or delete certificates.
#[allow(dead_code)]
pub struct TestCertificate {
    arn: String,
    role_arn: String,
}

impl TestCertificate {
    /// Reads the test certificate and assume-role ARNs from the environment.
    ///
    /// Panics if either is missing — the integ test runner is responsible for
    /// verifying both are set before invoking ACM tests.
    #[allow(dead_code)]
    pub fn from_env() -> Self {
        let arn = env::var("ACM_TEST_CERTIFICATE_ARN")
            .expect("ACM_TEST_CERTIFICATE_ARN must be set for ACM integ tests");
        let role_arn = env::var("ACM_TEST_ROLE_ARN")
            .expect("ACM_TEST_ROLE_ARN must be set for ACM integ tests");

        Self { arn, role_arn }
    }

    #[allow(dead_code)]
    pub fn arn(&self) -> &str {
        &self.arn
    }

    #[allow(dead_code)]
    pub fn role_arn(&self) -> &str {
        &self.role_arn
    }
}

/// Returns true if the given content has PEM certificate framing.
#[allow(dead_code)]
pub fn is_pem_certificate(content: &str) -> bool {
    content.contains("-----BEGIN CERTIFICATE-----") && content.contains("-----END CERTIFICATE-----")
}

/// Returns true if the given content has PEM private-key framing for any of
/// the formats the provider may emit (PKCS#8, RSA, EC).
#[allow(dead_code)]
pub fn is_pem_private_key(content: &str) -> bool {
    content.contains("-----BEGIN PRIVATE KEY-----")
        || content.contains("-----BEGIN RSA PRIVATE KEY-----")
        || content.contains("-----BEGIN EC PRIVATE KEY-----")
}

/// Locates the `aws-workload-credentials-provider` binary in a debug or release build
/// directory, searching both the current directory and one level up so the
/// helper works whether `cargo test` was invoked from the workspace root or
/// from `integration-tests/`.
pub fn locate_provider_binary() -> PathBuf {
    #[cfg(unix)]
    let provider_name = "aws-workload-credentials-provider";
    #[cfg(windows)]
    let provider_name = "aws-workload-credentials-provider.exe";

    let possible_paths = [
        PathBuf::from("target").join("release").join(provider_name),
        PathBuf::from("target").join("debug").join(provider_name),
        PathBuf::from("..")
            .join("target")
            .join("release")
            .join(provider_name),
        PathBuf::from("..")
            .join("target")
            .join("debug")
            .join(provider_name),
    ];

    possible_paths
        .into_iter()
        .find(|path| path.exists())
        .expect("Provider binary not found — run `cargo build` first")
}

/// Filesystem paths the provider writes during a single ACM integ test.
///
/// All paths sit under one test directory so a `rm -rf <test_dir>` cleans up
/// every artifact the provider and the refresh command produced.
#[allow(dead_code)]
pub struct AcmTestPaths {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub chain: PathBuf,
    pub refresh_marker: PathBuf,
}

impl AcmTestPaths {
    #[allow(dead_code)]
    pub fn under(test_dir: &Path) -> Self {
        Self {
            certificate: test_dir.join("server.pem"),
            private_key: test_dir.join("server.key"),
            chain: test_dir.join("chain.pem"),
            refresh_marker: test_dir.join("refresh_marker"),
        }
    }
}

/// Options controlling the generated TOML for ACM integ tests.
///
/// All fields have sensible defaults. Use [`Self::for_cert`] for happy-path
/// tests (ARNs from env), [`Self::placeholder`] for validation tests (well-
/// formed placeholder ARNs that don't hit AWS), and override individual
/// fields with the struct-update syntax:
///
/// ```ignore
/// create_test_config(test_dir, AcmTestConfigOptions {
///     bundled: true,
///     ..AcmTestConfigOptions::for_cert(&cert)
/// })
/// ```
#[allow(dead_code)]
#[derive(Clone)]
pub struct AcmTestConfigOptions {
    /// `certificate_arn` field on the certificate entry.
    pub certificate_arn: String,

    /// `role_arn` field on the certificate entry.
    pub role_arn: String,

    /// Override `certificate_path`. `None` derives it from the test_dir
    /// (absolute, valid). Callers pass `Some` to inject malformed values
    /// (e.g. relative paths) for negative-path validation tests.
    pub certificate_path: Option<String>,

    /// When true, omits `chain_path` so the provider emits a fullchain file
    /// at `certificate_path` instead of writing the chain separately.
    pub bundled: bool,

    /// Octal mode string for the cert and chain files (e.g. `"644"`).
    pub cert_and_chain_mode: Option<String>,

    /// Octal mode string for the private key file (e.g. `"400"`).
    pub key_mode: Option<String>,

    /// Whether to emit a `refresh_command` field. When false, the field is
    /// omitted entirely so the provider runs without any post-write command.
    pub include_refresh_command: bool,
}

impl AcmTestConfigOptions {
    /// Defaults for happy-path tests. ARNs come from
    /// `ACM_TEST_CERTIFICATE_ARN` and `ACM_TEST_ROLE_ARN`.
    #[allow(dead_code)]
    pub fn for_cert(cert: &TestCertificate) -> Self {
        Self {
            certificate_arn: cert.arn().to_string(),
            role_arn: cert.role_arn().to_string(),
            certificate_path: None,
            bundled: false,
            cert_and_chain_mode: None,
            key_mode: None,
            include_refresh_command: true,
        }
    }

    /// Defaults for validation tests. Uses well-formed placeholder ARNs so
    /// individual fields can be overridden to inject one malformed value at
    /// a time. The placeholders are syntactically valid; tests that want to
    /// exercise a specific failure override exactly that field.
    #[allow(dead_code)]
    pub fn placeholder() -> Self {
        Self {
	            certificate_arn:
	                "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"
	                    .to_string(),
	            role_arn: "arn:aws:iam::123456789012:role/PlaceholderRole".to_string(),
	            certificate_path: None,
	            bundled: false,
	            cert_and_chain_mode: None,
	            key_mode: None,
	            include_refresh_command: true,
	        }
    }
}

#[allow(dead_code)]
pub fn create_test_config(test_dir: &Path, opts: AcmTestConfigOptions) -> String {
    use serde::Serialize;

    #[derive(Serialize)]
    struct Config {
        capabilities: Capabilities,
    }

    #[derive(Serialize)]
    struct Capabilities {
        acm: AcmCapability,
    }

    #[derive(Serialize)]
    struct AcmCapability {
        enabled: bool,
        certificates: Vec<CertificateEntry>,
    }

    #[derive(Serialize)]
    struct CertificateEntry {
        certificate_arn: String,
        role_arn: String,
        certificate_path: String,
        private_key_path: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        chain_path: Option<String>,
        #[cfg(unix)]
        #[serde(skip_serializing_if = "Option::is_none")]
        certificate_and_chain_permission: Option<Permission>,
        #[cfg(unix)]
        #[serde(skip_serializing_if = "Option::is_none")]
        key_permission: Option<Permission>,
        #[serde(skip_serializing_if = "Option::is_none")]
        refresh_command: Option<String>,
    }

    #[cfg(unix)]
    #[derive(Serialize)]
    struct Permission {
        mode: String,
    }

    #[cfg(unix)]
    fn make_permission(value: &str) -> Permission {
        Permission {
            mode: value.to_string(),
        }
    }

    // The provider doesn't apply per-file ACLs from config on Windows
    // (install.ps1 does), so the permission parameters are unused here.
    #[cfg(windows)]
    let _ = (opts.cert_and_chain_mode, opts.key_mode);

    let paths = AcmTestPaths::under(test_dir);

    let certificate_path = opts
        .certificate_path
        .unwrap_or_else(|| paths.certificate.display().to_string());

    #[cfg(unix)]
    let refresh_command = if opts.include_refresh_command {
        Some(format!(
            "{} {}",
            locate_touch().display(),
            paths.refresh_marker.display()
        ))
    } else {
        None
    };

    #[cfg(windows)]
    let refresh_command = if opts.include_refresh_command {
        Some(format!("scheduled-task:{}", opts.certificate_arn))
    } else {
        None
    };

    let config = Config {
        capabilities: Capabilities {
            acm: AcmCapability {
                enabled: true,
                certificates: vec![CertificateEntry {
                    certificate_arn: opts.certificate_arn,
                    role_arn: opts.role_arn,
                    certificate_path,
                    private_key_path: paths.private_key.display().to_string(),
                    chain_path: if opts.bundled {
                        None
                    } else {
                        Some(paths.chain.display().to_string())
                    },
                    #[cfg(unix)]
                    certificate_and_chain_permission: opts
                        .cert_and_chain_mode
                        .map(|m| Permission { mode: m }),
                    #[cfg(unix)]
                    key_permission: opts.key_mode.map(|m| Permission { mode: m }),
                    refresh_command,
                }],
            },
        },
    };

    toml::to_string(&config).expect("failed to serialize test config")
}

/// Finds the absolute path to the `touch` binary. The provider's config
/// validator requires absolute paths in `refresh_command`
#[cfg(unix)]
fn locate_touch() -> PathBuf {
    for candidate in ["/usr/bin/touch", "/bin/touch"] {
        let p = PathBuf::from(candidate);
        if p.exists() {
            return p;
        }
    }
    panic!("could not locate `touch` at /usr/bin/touch or /bin/touch");
}

#[cfg(unix)]
#[allow(dead_code)]
pub fn assert_mode(path: &Path, expected: u32) {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(path)
        .unwrap_or_else(|e| panic!("could not stat {}: {}", path.display(), e));
    let mode = metadata.permissions().mode() & 0o777;
    assert_eq!(
        mode,
        expected,
        "expected 0o{:o} on {}, got 0o{:o}",
        expected,
        path.display(),
        mode
    );
}

/// A spawned `aws-workload-credentials-provider acm start` child process.
///
/// `kill_on_drop(true)` ties the provider's lifetime to the test, so the provider
/// stops the moment the test function returns or panics. There is no port —
/// ACM has no HTTP surface — so observability is via filesystem state and
/// the provider's log file (written to `logs/acm_provider.log` under `working_dir`).
#[allow(dead_code)]
pub struct AcmProviderProcess {
    _child: tokio::process::Child,
}

impl AcmProviderProcess {
    /// Spawns the provider in ACM mode against the given config file.
    ///
    /// `working_dir` sets the provider's CWD, which determines where the log
    /// file (`logs/acm_provider.log`) is written. Callers can then poll the
    /// log for specific messages to confirm the provider completed a cycle.
    #[allow(dead_code)]
    pub async fn start(config_path: &Path, working_dir: &Path) -> AcmProviderProcess {
        let provider_path = locate_provider_binary()
            .canonicalize()
            .expect("could not resolve provider binary to absolute path");

        let child = TokioCommand::new(&provider_path)
            .arg("acm")
            .arg("start")
            .arg("--config")
            .arg(config_path)
            .current_dir(working_dir)
            .kill_on_drop(true)
            .spawn()
            .expect("Failed to start provider");

        AcmProviderProcess { _child: child }
    }
}

/// Maximum time to wait for the provider to validate config and exit with a
/// non-zero status. Validation is synchronous and runs before any I/O, so
/// startup-failure cases finish well within this budget.
const PROVIDER_STARTUP_FAILURE_TIMEOUT: Duration = Duration::from_secs(15);

/// Spawns the provider in ACM mode against `config_path`, waits for it to
/// exit, and returns its captured (stdout, stderr) plus exit status.
///
/// Use this for negative-path tests where the provider is expected to fail
/// validation and exit on its own. `AcmProviderProcess` is for happy-path
/// tests where the provider runs indefinitely until dropped.
pub async fn run_provider_until_exit(
    config_path: &Path,
    working_dir: &Path,
) -> (std::process::ExitStatus, String, String) {
    let provider_path = locate_provider_binary()
        .canonicalize()
        .expect("could not resolve provider binary to absolute path");

    let child = TokioCommand::new(&provider_path)
        .arg("acm")
        .arg("start")
        .arg("--config")
        .arg(config_path)
        .current_dir(working_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("Failed to start provider");

    let output = tokio::time::timeout(PROVIDER_STARTUP_FAILURE_TIMEOUT, child.wait_with_output())
        .await
        .unwrap_or_else(|_| {
            panic!(
                "provider did not exit within {:?}; expected immediate validation failure",
                PROVIDER_STARTUP_FAILURE_TIMEOUT
            )
        })
        .expect("failed to wait on provider process");

    (
        output.status,
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// Re-export from production code to keep test and provider in sync.
#[cfg(windows)]
#[allow(unused_imports)]
pub use aws_certificatemanager_provider::scheduled_task_name;

/// Per-test scheduled task that creates a marker file when triggered.
/// Drop unregisters it.
#[cfg(windows)]
#[allow(dead_code)]
pub struct AcmTestScheduledTask {
    task_name: String,
}

#[cfg(windows)]
impl AcmTestScheduledTask {
    /// Registers a scheduled task that will create `marker_path` when triggered.
    /// Panics if registration fails.
    #[allow(dead_code)]
    pub fn register(certificate_arn: &str, marker_path: &Path) -> Self {
        use base64::Engine;

        let task_name = scheduled_task_name(certificate_arn);
        let marker_str = marker_path
            .to_str()
            .expect("marker path must be valid unicode");

        // Encode the action command as UTF-16LE Base64 and pass via PowerShell
        // -EncodedCommand. Avoids quote/escape issues through the
        // Task Scheduler -> PowerShell argument parsers.
        let action_script = format!("New-Item -Path '{marker_str}' -ItemType File -Force");
        let action_utf16: Vec<u8> = action_script
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let action_encoded = base64::engine::general_purpose::STANDARD.encode(&action_utf16);

        let ps_command = format!(
            "$action = New-ScheduledTaskAction -Execute powershell.exe -Argument '-NoProfile -NonInteractive -EncodedCommand {action_encoded}'; \
             $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries; \
             Register-ScheduledTask -TaskName '{task_name}' -Action $action -Settings $settings -Force | Out-Null"
        );

        let output = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &ps_command])
            .output()
            .expect("failed to invoke PowerShell to register scheduled task");

        if !output.status.success() {
            panic!(
                "Register-ScheduledTask failed for {task_name}:\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }

        Self { task_name }
    }
}

#[cfg(windows)]
impl Drop for AcmTestScheduledTask {
    fn drop(&mut self) {
        let output = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!(
                    "Unregister-ScheduledTask -TaskName '{}' -Confirm:$false",
                    self.task_name
                ),
            ])
            .output();

        match output {
            Ok(o) if o.status.success() => {}
            Ok(o) => eprintln!(
                "warning: failed to unregister scheduled task '{}':\nstdout: {}\nstderr: {}",
                self.task_name,
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr),
            ),
            Err(e) => eprintln!(
                "warning: failed to invoke PowerShell to unregister scheduled task '{}': {e}",
                self.task_name
            ),
        }
    }
}
