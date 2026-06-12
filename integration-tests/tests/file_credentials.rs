//! # File-Based Credentials Integration Tests
//!
//! Tests for the FileBasedCredentialsProvider feature, verifying the agent
//! correctly handles various credential file scenarios.
//!
//! **Note:** `test_self_healing_credentials_appear_after_startup` and
//! `test_credential_rotation_while_running` use `SMA_CREDENTIALS_RELOAD_SECS`.
//! This env-var override is only active in debug builds of the provider binary.

mod common;

use aws_credential_types::provider::ProvideCredentials;
use common::*;
use std::io::Write;
use tempfile::NamedTempFile;

/// Helper to write real AWS credentials from the environment to a temp file.
async fn write_real_credentials(file: &mut NamedTempFile) {
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let creds = config
        .credentials_provider()
        .expect("No credentials provider")
        .provide_credentials()
        .await
        .expect("Failed to resolve credentials");

    let mut content = format!(
        "[default]\naws_access_key_id={}\naws_secret_access_key={}\n",
        creds.access_key_id(),
        creds.secret_access_key()
    );
    if let Some(token) = creds.session_token() {
        content.push_str(&format!("aws_session_token={}\n", token));
    }
    file.write_all(content.as_bytes()).unwrap();
    file.flush().unwrap();
}

/// Valid credentials via explicit path: provider starts and can fetch a secret.
#[tokio::test]
async fn test_valid_credentials_explicit_path() {
    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(&SecretType::Basic);

    let mut creds_file = NamedTempFile::new().unwrap();
    write_real_credentials(&mut creds_file).await;

    let config_content = format!(
        r#"
[logging]
log_level = "debug"

[capabilities.secrets_manager]
http_port = 2885
credentials_file_path = "{}"
"#,
        creds_file.path().display()
    );

    let provider = ProviderProcess::start_with_config_content(2885, &config_content).await;

    let query = ProviderQueryBuilder::default()
        .secret_id(&secret_name)
        .build()
        .unwrap();
    let response = provider.make_request(&query).await;
    let json: serde_json::Value = serde_json::from_str(&response).unwrap();

    assert_eq!(json["Name"], secret_name);
    assert!(json["SecretString"].as_str().unwrap().contains("testuser"));
}

/// Invalid credentials: provider starts but secret fetch returns auth error.
#[tokio::test]
async fn test_invalid_credentials_provider_starts() {
    let mut creds_file = NamedTempFile::new().unwrap();
    writeln!(
        creds_file,
        "[default]\naws_access_key_id=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\naws_session_token=FakeSessionToken"
    )
    .unwrap();

    let config_content = format!(
        r#"
[logging]
log_level = "debug"

[capabilities.secrets_manager]
http_port = 2886
credentials_file_path = "{}"
"#,
        creds_file.path().display()
    );

    let provider = ProviderProcess::start_with_config_content(2886, &config_content).await;

    let query = ProviderQueryBuilder::default()
        .secret_id("any-secret")
        .build()
        .unwrap();
    let response = provider.make_request_raw(&query).await;

    assert_ne!(response.status(), 200);
}

/// Long-term credentials (no session token): provider starts but credentials are rejected.
#[tokio::test]
async fn test_long_term_credentials_rejected() {
    let mut creds_file = NamedTempFile::new().unwrap();
    writeln!(
        creds_file,
        "[default]\naws_access_key_id=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    )
    .unwrap();

    let config_content = format!(
        r#"
[logging]
log_level = "debug"

[capabilities.secrets_manager]
http_port = 2887
credentials_file_path = "{}"
"#,
        creds_file.path().display()
    );

    let provider = ProviderProcess::start_with_config_content(2887, &config_content).await;

    let query = ProviderQueryBuilder::default()
        .secret_id("any-secret")
        .build()
        .unwrap();
    let response = provider.make_request_raw(&query).await;

    assert_ne!(response.status(), 200);
}

/// Malformed credentials file: provider starts, request returns error.
#[tokio::test]
async fn test_malformed_credentials_file() {
    let mut creds_file = NamedTempFile::new().unwrap();
    writeln!(creds_file, "this is not a credentials file").unwrap();

    let config_content = format!(
        r#"
[logging]
log_level = "debug"

[capabilities.secrets_manager]
http_port = 2890
credentials_file_path = "{}"
"#,
        creds_file.path().display()
    );

    let provider = ProviderProcess::start_with_config_content(2890, &config_content).await;

    let query = ProviderQueryBuilder::default()
        .secret_id("any-secret")
        .build()
        .unwrap();
    let response = provider.make_request_raw(&query).await;

    assert_ne!(response.status(), 200);
}

/// Empty credentials file: provider starts, request returns error.
#[tokio::test]
async fn test_empty_credentials_file() {
    let creds_file = NamedTempFile::new().unwrap();

    let config_content = format!(
        r#"
[logging]
log_level = "debug"

[capabilities.secrets_manager]
http_port = 2891
credentials_file_path = "{}"
"#,
        creds_file.path().display()
    );

    let provider = ProviderProcess::start_with_config_content(2891, &config_content).await;

    let query = ProviderQueryBuilder::default()
        .secret_id("any-secret")
        .build()
        .unwrap();
    let response = provider.make_request_raw(&query).await;

    assert_ne!(response.status(), 200);
}

/// Missing credentials path: provider starts, request fails.
#[tokio::test]
async fn test_missing_credentials_path() {
    let config_content = r#"
[logging]
log_level = "debug"

[capabilities.secrets_manager]
http_port = 2888
credentials_file_path = "/tmp/nonexistent_creds_file_integ_test"
"#;

    let provider = ProviderProcess::start_with_config_content(2888, config_content).await;

    let query = ProviderQueryBuilder::default()
        .secret_id("any-secret")
        .build()
        .unwrap();
    let response = provider.make_request_raw(&query).await;

    assert_ne!(response.status(), 200);
}

/// Self-healing: provider starts with missing credentials, valid creds are written later,
/// provider picks them up on the next reload cycle.
#[tokio::test]
async fn test_self_healing_credentials_appear_after_startup() {
    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(&SecretType::Basic);

    let tmp_dir = tempfile::tempdir().unwrap();
    let creds_path = tmp_dir.path().join("credentials");

    let config_content = format!(
        r#"
[logging]
log_level = "debug"

[capabilities.secrets_manager]
http_port = 2889
credentials_file_path = "{}"
"#,
        creds_path.display()
    );

    let provider = ProviderProcess::start_with_config_content_and_env(
        2889,
        &config_content,
        &[("SMA_CREDENTIALS_RELOAD_SECS", "3")],
    )
    .await;

    // First request should fail — no credentials yet
    let query = ProviderQueryBuilder::default()
        .secret_id(&secret_name)
        .build()
        .unwrap();
    let response = provider.make_request_raw(&query).await;
    assert_ne!(response.status(), 200);

    // Write valid credentials
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let creds = config
        .credentials_provider()
        .expect("No credentials provider")
        .provide_credentials()
        .await
        .expect("Failed to resolve credentials");

    let mut content = format!(
        "[default]\naws_access_key_id={}\naws_secret_access_key={}\n",
        creds.access_key_id(),
        creds.secret_access_key()
    );
    if let Some(token) = creds.session_token() {
        content.push_str(&format!("aws_session_token={}\n", token));
    }
    std::fs::write(&creds_path, content).unwrap();

    // Poll until the provider picks up credentials
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let resp = provider.make_request_raw(&query).await;
        if resp.status() == 200 {
            let body = resp.text().await.unwrap();
            let json: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(json["Name"], secret_name);
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "Timed out waiting for credentials reload"
        );
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

/// Credential rotation: provider starts with valid credentials, credentials are
/// rotated to invalid, provider fails, then valid credentials are restored and
/// provider recovers. Proves the provider is actively re-reading the file.
#[tokio::test]
async fn test_credential_rotation_while_running() {
    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(&SecretType::Basic);

    let tmp_dir = tempfile::tempdir().unwrap();
    let creds_path = tmp_dir.path().join("credentials");

    // Write initial valid credentials
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let creds = config
        .credentials_provider()
        .expect("No credentials provider")
        .provide_credentials()
        .await
        .expect("Failed to resolve credentials");

    let mut valid_content = format!(
        "[default]\naws_access_key_id={}\naws_secret_access_key={}\n",
        creds.access_key_id(),
        creds.secret_access_key()
    );
    if let Some(token) = creds.session_token() {
        valid_content.push_str(&format!("aws_session_token={}\n", token));
    }
    std::fs::write(&creds_path, &valid_content).unwrap();

    // Start provider with short reload delay
    let config_content = format!(
        r#"
[logging]
log_level = "debug"

[capabilities.secrets_manager]
http_port = 2893
credentials_file_path = "{}"
"#,
        creds_path.display()
    );

    let provider = ProviderProcess::start_with_config_content_and_env(
        2893,
        &config_content,
        &[
            ("SMA_CREDENTIALS_RELOAD_SECS", "3"),
            ("SMA_DISABLE_IDENTITY_CACHE", "1"),
        ],
    )
    .await;

    // Step 1: Verify provider works with initial valid credentials
    let query = ProviderQueryBuilder::default()
        .secret_id(&secret_name)
        .build()
        .unwrap();
    let response = provider.make_request(&query).await;
    let json: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(json["Name"], secret_name);

    // Step 2: Overwrite with invalid credentials (has session token to pass gate)
    std::fs::write(
        &creds_path,
        "[default]\naws_access_key_id=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\naws_session_token=FakeSessionToken\n",
    )
    .unwrap();

    // Poll until provider returns errors (proves it picked up invalid creds)
    let refresh_query = ProviderQueryBuilder::default()
        .secret_id(&secret_name)
        .refresh_now(true)
        .build()
        .unwrap();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let resp = provider.make_request_raw(&refresh_query).await;
        if resp.status() != 200 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "Timed out waiting for provider to pick up invalid credentials"
        );
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    // Step 3: Restore valid credentials
    std::fs::write(&creds_path, &valid_content).unwrap();

    // Poll until provider recovers
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let resp = provider.make_request_raw(&refresh_query).await;
        if resp.status() == 200 {
            let body = resp.text().await.unwrap();
            let json: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(json["Name"], secret_name);
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "Timed out waiting for provider to recover with valid credentials"
        );
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}
