//! # Cache Behavior Integration Tests
//!
//! This module contains integration tests for AWS Secrets Manager Provider's caching functionality.
//! These tests verify that the provider correctly caches secrets, respects TTL settings, handles
//! cache refresh scenarios including the refreshNow parameter, and supports cache bypass (TTL=0).

mod common;

use common::*;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn test_refresh_now_on_updated_secret_succeeds() {
    let secrets = TestSecrets::setup_basic().await;
    let secret_name: String = secrets.secret_name(&SecretType::Basic);

    let provider = ProviderProcess::start().await;

    // First request - populate cache with original value
    let query = ProviderQueryBuilder::default()
        .secret_id(&secret_name)
        .build()
        .unwrap();
    let response1 = provider.make_request(&query).await;
    let json1: serde_json::Value = serde_json::from_str(&response1).unwrap();
    let original_secret = json1["SecretString"].as_str().unwrap();
    assert!(original_secret.contains("testuser"));

    // Update the secret in AWS (simulating manual update, not automatic rotation)
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let client = aws_sdk_secretsmanager::Client::new(&config);

    let updated_secret_value = r#"{"username":"rotateduser","password":"rotatedpass123"}"#;
    let update_response = client
        .update_secret()
        .secret_id(&secret_name)
        .secret_string(updated_secret_value)
        .send()
        .await
        .expect("Failed to update secret");

    let new_version_id = update_response
        .version_id()
        .expect("No version ID returned");

    // Allow time for update to propagate across Secrets Manager nodes
    sleep(Duration::from_millis(500)).await;

    // Second request without refreshNow - should return stale cached value
    let response2 = provider.make_request(&query).await;
    let json2: serde_json::Value = serde_json::from_str(&response2).unwrap();
    let cached_secret = json2["SecretString"].as_str().unwrap();

    // Should still have the old value from cache
    assert!(cached_secret.contains("testuser"));

    // Third request with refreshNow=true - should get fresh value
    let refresh_query = ProviderQueryBuilder::default()
        .secret_id(&secret_name)
        .refresh_now(true)
        .build()
        .unwrap();
    let response3 = provider.make_request(&refresh_query).await;
    let json3: serde_json::Value = serde_json::from_str(&response3).unwrap();
    let fresh_secret = json3["SecretString"].as_str().unwrap();

    // Should now have the updated value with new version ID and AWSCURRENT label
    assert_eq!(json3["VersionId"].as_str().unwrap(), new_version_id);
    assert!(json3["VersionStages"]
        .as_array()
        .unwrap()
        .contains(&serde_json::Value::String("AWSCURRENT".to_string())));
    assert!(fresh_secret.contains("rotateduser"));
}

#[tokio::test]
async fn test_cache_expiration_and_refresh() {
    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(&SecretType::Basic);

    // Start provider with short TTL for faster testing
    const TTL_SECONDS: u64 = 5;
    let provider = ProviderProcess::start_with_config(2777, TTL_SECONDS).await;

    let query = ProviderQueryBuilder::default()
        .secret_id(&secret_name)
        .build()
        .unwrap();

    // First request - populate cache
    let response1 = provider.make_request(&query).await;
    let json1: serde_json::Value = serde_json::from_str(&response1).unwrap();
    let version1 = json1["VersionId"].as_str().unwrap();
    assert!(json1["SecretString"].as_str().unwrap().contains("testuser"));

    // Update secret while cache is still valid
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let client = aws_sdk_secretsmanager::Client::new(&config);

    let update_response = client
        .update_secret()
        .secret_id(&secret_name)
        .secret_string(r#"{"username":"expireduser","password":"expiredpass789"}"#)
        .send()
        .await
        .expect("Failed to update secret");

    let new_version_id = update_response
        .version_id()
        .expect("No version ID returned");

    // Allow time for update to propagate across Secrets Manager nodes
    sleep(Duration::from_millis(500)).await;

    // Second request before TTL expires - should still return cached value
    let response2 = provider.make_request(&query).await;
    let json2: serde_json::Value = serde_json::from_str(&response2).unwrap();
    assert_eq!(json2["VersionId"], version1); // Same version as cached
    assert!(json2["SecretString"].as_str().unwrap().contains("testuser"));

    // Wait for TTL to expire (TTL + buffer to ensure expiry)
    sleep(Duration::from_secs(TTL_SECONDS + 1)).await;

    // Third request after TTL expiry - should fetch fresh value from AWS
    let response3 = provider.make_request(&query).await;
    let json3: serde_json::Value = serde_json::from_str(&response3).unwrap();

    // Should now have the updated value with new version ID and AWSCURRENT label
    assert_eq!(json3["VersionId"].as_str().unwrap(), new_version_id);
    assert!(json3["VersionStages"]
        .as_array()
        .unwrap()
        .contains(&serde_json::Value::String("AWSCURRENT".to_string())));
    assert!(json3["SecretString"]
        .as_str()
        .unwrap()
        .contains("expireduser"));
}

#[tokio::test]
async fn test_ttl_zero_disables_caching() {
    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(&SecretType::Basic);

    // Start provider with TTL=0 to disable caching
    const TTL_SECONDS: u64 = 0;
    let provider = ProviderProcess::start_with_config(2780, TTL_SECONDS).await;

    let query = ProviderQueryBuilder::default()
        .secret_id(&secret_name)
        .build()
        .unwrap();

    // First request - should fetch from AWS
    let response1 = provider.make_request(&query).await;
    let json1: serde_json::Value = serde_json::from_str(&response1).unwrap();
    let version1 = json1["VersionId"].as_str().unwrap();
    assert!(json1["SecretString"].as_str().unwrap().contains("testuser"));

    // Update secret immediately
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let client = aws_sdk_secretsmanager::Client::new(&config);

    let update_response = client
        .update_secret()
        .secret_id(&secret_name)
        .secret_string(r#"{"username":"nocacheuser","password":"nocachepass456"}"#)
        .send()
        .await
        .expect("Failed to update secret");

    let new_version_id = update_response
        .version_id()
        .expect("No version ID returned");

    // Allow time for update to propagate
    sleep(Duration::from_millis(500)).await;

    // Second request - with TTL=0, should always fetch fresh value from AWS
    let response2 = provider.make_request(&query).await;
    let json2: serde_json::Value = serde_json::from_str(&response2).unwrap();

    // Should immediately have the updated value (no caching)
    assert_eq!(json2["VersionId"].as_str().unwrap(), new_version_id);
    assert!(json2["VersionStages"]
        .as_array()
        .unwrap()
        .contains(&serde_json::Value::String("AWSCURRENT".to_string())));
    assert!(json2["SecretString"]
        .as_str()
        .unwrap()
        .contains("nocacheuser"));

    // Verify version changed (proving no caching occurred)
    assert_ne!(version1, new_version_id);
}
