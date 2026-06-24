//! # Pre-fetch Integration Tests
//!
//! Tests that the provider pre-fetches secrets into the cache at startup.
//!
//! Strategy: create a secret, start the provider with prefetch config, wait for
//! prefetch to complete (jitter + buffer), update the secret via SDK, then
//! request it from the provider. If prefetch worked, the provider returns the old
//! (cached) value. If it didn't, the provider fetches fresh and returns the new value.

mod common;

use common::*;

/// Verify that a prefetched secret is served from cache (stale value)
/// after the underlying secret is updated.
#[tokio::test]
async fn test_prefetch_serves_cached_value() {
    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(&SecretType::Basic);

    // Start provider with prefetch config for this secret, high TTL so cache doesn't expire
    let port = 2790;
    let config_content = format!(
        r#"
[logging]
log_level = "info"

[capabilities.secrets_manager]
http_port = {}
validate_credentials = true

[capabilities.secrets_manager.cache]
ttl_seconds = 300

[[capabilities.secrets_manager.prefetch.secrets]]
secret_id = "{}"
"#,
        port, secret_name
    );

    let provider = ProviderProcess::start_with_config_content(port, &config_content).await;

    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let client = aws_sdk_secretsmanager::Client::new(&config);

    let updated_value = r#"{"username":"updateduser","password":"updatedpass"}"#;
    client
        .update_secret()
        .secret_id(&secret_name)
        .secret_string(updated_value)
        .send()
        .await
        .expect("Failed to update secret");

    let query = ProviderQueryBuilder::default()
        .secret_id(&secret_name)
        .build()
        .unwrap();

    let response = provider.make_request(&query).await;
    let json: serde_json::Value = serde_json::from_str(&response).unwrap();

    // Prefetch cached the original value, so we should see "testuser" not "updateduser"
    assert!(
        json["SecretString"].as_str().unwrap().contains("testuser"),
        "Expected cached (old) value with 'testuser', got: {}",
        json["SecretString"]
    );
}

/// Verify that prefetch with no matching secrets doesn't crash the provider.
#[tokio::test]
async fn test_prefetch_nonexistent_secret_doesnt_crash() {
    let port = 2791;
    let config_content = format!(
        r#"
[logging]
log_level = "info"

[capabilities.secrets_manager]
http_port = {}
validate_credentials = false

[capabilities.secrets_manager.cache]
ttl_seconds = 300

[[capabilities.secrets_manager.prefetch.secrets]]
secret_id = "nonexistent-secret-that-does-not-exist"
"#,
        port
    );

    let provider = ProviderProcess::start_with_config_content(port, &config_content).await;

    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // provider should still be healthy
    let response = provider.make_ping_request().await;
    assert_eq!(response.status(), 200);
}

/// Verify that inline array syntax for prefetch secrets works the same as array-of-tables.
#[tokio::test]
async fn test_prefetch_inline_syntax_serves_cached_value() {
    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(&SecretType::Basic);

    let port = 2792;
    let config_content = format!(
        r#"
[logging]
log_level = "info"

[capabilities.secrets_manager]
http_port = {}
validate_credentials = true

[capabilities.secrets_manager.cache]
ttl_seconds = 300

[capabilities.secrets_manager.prefetch]
secrets = [
  {{ secret_id = "{}" }},
]
"#,
        port, secret_name
    );

    let provider = ProviderProcess::start_with_config_content(port, &config_content).await;

    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let client = aws_sdk_secretsmanager::Client::new(&config);

    client
        .update_secret()
        .secret_id(&secret_name)
        .secret_string(r#"{"username":"updateduser","password":"updatedpass"}"#)
        .send()
        .await
        .expect("Failed to update secret");

    let query = ProviderQueryBuilder::default()
        .secret_id(&secret_name)
        .build()
        .unwrap();

    let response = provider.make_request(&query).await;
    let json: serde_json::Value = serde_json::from_str(&response).unwrap();

    assert!(
        json["SecretString"].as_str().unwrap().contains("testuser"),
        "Expected cached (old) value with 'testuser', got: {}",
        json["SecretString"]
    );
}

/// Verify that a prefetched secret with role_arn is served from cache
/// after the underlying secret is updated.
#[tokio::test]
async fn test_prefetch_with_role_chaining_serves_cached_value() {
    let helper = RoleChainingHelper::new().await;
    let role_arn = helper.get_role_arn(ROLE_CHAINING_ROLE_NAME).await;

    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(&SecretType::Basic);

    let port = 2793;
    let config_content = format!(
        r#"
[logging]
log_level = "info"

[capabilities.secrets_manager]
http_port = {}
validate_credentials = true

[capabilities.secrets_manager.cache]
ttl_seconds = 300

[[capabilities.secrets_manager.prefetch.secrets]]
secret_id = "{}"
role_arn = "{}"
"#,
        port, secret_name, role_arn
    );

    let provider = ProviderProcess::start_with_config_content(port, &config_content).await;

    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let client = aws_sdk_secretsmanager::Client::new(&config);

    client
        .update_secret()
        .secret_id(&secret_name)
        .secret_string(r#"{"username":"updateduser","password":"updatedpass"}"#)
        .send()
        .await
        .expect("Failed to update secret");

    let query = ProviderQueryBuilder::default()
        .secret_id(&secret_name)
        .role_arn(&role_arn)
        .build()
        .unwrap();

    let response = provider.make_request(&query).await;
    let json: serde_json::Value = serde_json::from_str(&response).unwrap();

    assert!(
        json["SecretString"].as_str().unwrap().contains("testuser"),
        "Expected cached (old) value with 'testuser', got: {}",
        json["SecretString"]
    );
}

/// Verify that tag-based prefetch discovers and caches secrets, serving from cache
#[tokio::test]
async fn test_prefetch_with_tags_serves_cached_value() {
    let tag_key = format!(
        "aws-sm-provider-prefetch-integ-test-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let secrets = TestSecrets::setup_tagged(&tag_key).await;
    let secret_type = SecretType::Tagged {
        tag_key: tag_key.to_string(),
    };
    let secret_name = secrets.secret_name(&secret_type);

    secrets
        .wait_for_tag(&secret_type, &tag_key)
        .await
        .expect("Timed out waiting for tag to propagate on secret");

    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let client = aws_sdk_secretsmanager::Client::new(&config);

    let port = 2794;
    let config_content = format!(
        r#"
[logging]
log_level = "info"

[capabilities.secrets_manager]
http_port = {}
validate_credentials = true

[capabilities.secrets_manager.cache]
ttl_seconds = 300

[capabilities.secrets_manager.prefetch]
filter_tags = [
  {{ key = "{}" }},
]
"#,
        port, tag_key
    );

    let provider = ProviderProcess::start_with_config_content(port, &config_content).await;

    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    client
        .update_secret()
        .secret_id(&secret_name)
        .secret_string(r#"{"username":"updateduser","password":"updatedpass"}"#)
        .send()
        .await
        .expect("Failed to update secret");

    let query = ProviderQueryBuilder::default()
        .secret_id(&secret_name)
        .build()
        .unwrap();

    let response = provider.make_request(&query).await;
    let json: serde_json::Value = serde_json::from_str(&response).unwrap();

    assert!(
        json["SecretString"].as_str().unwrap().contains("testuser"),
        "Expected cached (old) value with 'testuser', got: {}",
        json["SecretString"]
    );
}
