//! # Integration Test Common Utilities
//!
//! This module provides shared utilities and helper functions for AWS Secrets Manager Agent
//! integration tests. It includes test secret management, agent process control, and
//! HTTP request building functionality.

use aws_config;
use aws_sdk_secretsmanager;
use derive_builder::Builder;
use std::env;
use std::fmt;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command as TokioCommand;
use url::Url;

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum SecretType {
    Basic,
    Binary,
    Versioned,
    Large,
}

impl fmt::Display for SecretType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretType::Basic => write!(f, "basic"),
            SecretType::Binary => write!(f, "binary"),
            SecretType::Versioned => write!(f, "versioned"),
            SecretType::Large => write!(f, "large"),
        }
    }
}

#[derive(Debug, Clone, Builder)]
#[builder(setter(into, strip_option))]
pub struct AgentQuery {
    pub secret_id: String,
    #[builder(default)]
    pub version_id: Option<String>,
    #[builder(default)]
    pub version_stage: Option<String>,
    #[builder(default)]
    pub refresh_now: Option<bool>,
}

impl AgentQuery {
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
        }
        url.query().unwrap_or("").to_string()
    }
}

pub struct AgentProcess {
    pub _child: tokio::process::Child,
    pub port: u16,
}

impl AgentProcess {
    pub async fn start() -> AgentProcess {
        Self::start_with_config(2775, 5_u64).await
    }

    pub async fn start_with_config(port: u16, ttl_seconds: u64) -> AgentProcess {
        let config_content = format!(
            r#"
http_port = {}
log_level = "info"
ttl_seconds = {}
validate_credentials = true
"#,
            port, ttl_seconds
        );

        let config_path = format!("/tmp/test_config_{}.toml", port);
        std::fs::write(&config_path, config_content).expect("Failed to write test config");

        env::set_var("AWS_TOKEN", "test-token-123");

        let possible_paths = [
            PathBuf::from("target")
                .join("release")
                .join("aws_secretsmanager_agent"),
            PathBuf::from("target")
                .join("debug")
                .join("aws_secretsmanager_agent"),
            PathBuf::from("..")
                .join("target")
                .join("release")
                .join("aws_secretsmanager_agent"),
            PathBuf::from("..")
                .join("target")
                .join("debug")
                .join("aws_secretsmanager_agent"),
        ];

        let agent_path = possible_paths
            .iter()
            .find(|path| path.exists())
            .expect("Agent binary not found");

        let mut child = TokioCommand::new(agent_path)
            .arg("--config")
            .arg(&config_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("Failed to start agent");

        // Read stdout until we see the "listening" message
        let stdout = child.stdout.take().expect("Failed to get stdout");
        let mut reader = BufReader::new(stdout).lines();

        match reader.next_line().await {
            Ok(Some(line)) => {
                if !line.contains("listening on") {
                    panic!("Agent failed to start - no listening message found");
                }
            }
            Ok(None) => {
                panic!("Stream ended without finding listening message");
            }
            Err(e) => {
                panic!("Failed to read agent output: {}", e);
            }
        }

        AgentProcess {
            _child: child,
            port,
        }
    }

    #[allow(dead_code)]
    pub async fn make_request(&self, query: &AgentQuery) -> String {
        let response = self.make_request_raw(query).await;
        let status = response.status();
        if status != 200 {
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read error body".to_string());
            panic!("Agent returned status {}: {}", status, error_body);
        }
        response.text().await.expect("Failed to read response body")
    }

    pub async fn make_request_raw(&self, query: &AgentQuery) -> reqwest::Response {
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
        // The agent is designed to only accept requests on localhost for security
        client
            .get(url)
            .header("X-Aws-Parameters-Secrets-Token", "test-token-123")
            .send()
            .await
            .expect("Failed to make agent request")
    }

    #[allow(dead_code)]
    pub async fn make_request_without_token(&self, query: &AgentQuery) -> reqwest::Response {
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
            .expect("Failed to make agent request")
    }

    #[allow(dead_code)]
    pub async fn make_request_with_invalid_token(&self, query: &AgentQuery) -> reqwest::Response {
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
            .expect("Failed to make agent request")
    }

    #[allow(dead_code)]
    pub async fn make_request_with_x_forwarded_for(&self, query: &AgentQuery) -> reqwest::Response {
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
            .expect("Failed to make agent request")
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
    pub fn secret_name(&self, secret_type: SecretType) -> String {
        format!("{}-{}", self.prefix, secret_type)
    }

    #[allow(dead_code)]
    pub async fn setup_basic() -> Self {
        Self::setup_with_types(vec![SecretType::Basic]).await
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

        let test_prefix = format!("aws-sm-agent-test-{}", timestamp);

        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = aws_sdk_secretsmanager::Client::new(&config);

        let temp_secrets = Self {
            prefix: test_prefix.clone(),
            created_types: types.clone(),
        };

        for secret_type in types {
            match secret_type {
                SecretType::Basic => {
                    let secret_name = temp_secrets.secret_name(SecretType::Basic);
                    client
                        .create_secret()
                        .name(&secret_name)
                        .description("Basic test secret for aws-secretsmanager-agent")
                        .secret_string(r#"{"username":"testuser","password":"testpass123"}"#)
                        .send()
                        .await
                        .expect("Failed to create test secret");
                }
                SecretType::Binary => {
                    let binary_secret_name = temp_secrets.secret_name(SecretType::Binary);
                    let binary_data = b"\x00\x01\x02\x03\xFF\xFE\xFD";
                    client
                        .create_secret()
                        .name(&binary_secret_name)
                        .description("Binary test secret for aws-secretsmanager-agent")
                        .secret_binary(aws_sdk_secretsmanager::primitives::Blob::new(binary_data))
                        .send()
                        .await
                        .expect("Failed to create binary test secret");
                }
                SecretType::Versioned => {
                    let versioned_secret_name = temp_secrets.secret_name(SecretType::Versioned);
                    client
                        .create_secret()
                        .name(&versioned_secret_name)
                        .description("Versioned test secret for aws-secretsmanager-agent")
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
                    let large_secret_name = temp_secrets.secret_name(SecretType::Large);
                    let large_data = "x".repeat(60000); // ~60KB of data
                    let large_secret_json = format!(r#"{{"data":"{}","size":"60KB"}}"#, large_data);
                    client
                        .create_secret()
                        .name(&large_secret_name)
                        .description("Large test secret for aws-secretsmanager-agent")
                        .secret_string(&large_secret_json)
                        .send()
                        .await
                        .expect("Failed to create large test secret");
                }
            }
        }

        temp_secrets
    }

    #[allow(dead_code)]
    pub async fn wait_for_pending_version(
        &self,
        secret_type: SecretType,
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
    pub async fn get_version_ids(&self, secret_type: SecretType) -> (String, String) {
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
