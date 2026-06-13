//! # Role Chaining Integration Tests
//!
//! Tests for secret retrieval via IAM role assumption.
//!
//! These tests assume target roles exist in the same account as the caller.
//! The account ID is discovered automatically via `sts:GetCallerIdentity`.
//!
//! Required roles:
//! - `workload-credentials-provider` — can be assumed by the provider and has Secrets Manager read permissions
//! - `workload-credentials-provider-no-access` — can be assumed by the provider but has no Secrets Manager permissions
//!
//! Tests will panic during setup if the required roles cannot be assumed.

mod common;

use common::*;

#[tokio::test]
async fn test_role_chaining_basic_retrieval() {
    let helper = RoleChainingHelper::new().await;
    let role_arn = helper.get_role_arn(ROLE_CHAINING_ROLE_NAME).await;
    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(&SecretType::Basic);

    let provider = ProviderProcess::start().await;

    let query = ProviderQueryBuilder::default()
        .secret_id(&secret_name)
        .role_arn(&role_arn)
        .build()
        .unwrap();

    let response = provider.make_request_raw(&query).await;
    assert_eq!(response.status(), 200);

    let body = response.text().await.expect("Failed to read response body");
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["Name"], secret_name);
    assert!(json["SecretString"].as_str().unwrap().contains("testuser"));
}

#[tokio::test]
async fn test_role_chaining_invalid_role_arn_format() {
    let provider = ProviderProcess::start().await;

    let query = ProviderQueryBuilder::default()
        .secret_id("any-secret")
        .role_arn("not-a-valid-arn")
        .build()
        .unwrap();

    let response = provider.make_request_raw(&query).await;
    assert_eq!(response.status(), 400);

    let body = response.text().await.expect("Failed to read response body");
    assert!(body.contains("invalid roleArn format"));
}

#[tokio::test]
async fn test_role_chaining_nonexistent_role() {
    let provider = ProviderProcess::start().await;

    let query = ProviderQueryBuilder::default()
        .secret_id("any-secret")
        .role_arn("arn:aws:iam::000000000000:role/NonExistentRole")
        .build()
        .unwrap();

    let response = provider.make_request_raw(&query).await;
    assert_eq!(response.status(), 403);

    let body = response.text().await.expect("Failed to read response body");
    assert!(body.contains("AccessDenied"));
}

#[tokio::test]
async fn test_role_chaining_with_refresh_now() {
    let helper = RoleChainingHelper::new().await;
    let role_arn = helper.get_role_arn(ROLE_CHAINING_ROLE_NAME).await;
    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(&SecretType::Basic);

    let provider = ProviderProcess::start().await;

    // First request with roleArn — populate cache with original value
    let query = ProviderQueryBuilder::default()
        .secret_id(&secret_name)
        .role_arn(&role_arn)
        .build()
        .unwrap();
    let response1 = provider.make_request(&query).await;
    let json1: serde_json::Value = serde_json::from_str(&response1).unwrap();
    let original_secret = json1["SecretString"].as_str().unwrap();
    assert!(original_secret.contains("testuser"));

    // Update the secret directly via SDK (using default credentials)
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

    // Allow time for update to propagate
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Second request without refreshNow — should return stale cached value
    let response2 = provider.make_request(&query).await;
    let json2: serde_json::Value = serde_json::from_str(&response2).unwrap();
    assert!(json2["SecretString"].as_str().unwrap().contains("testuser"));

    // Third request with refreshNow=true — should get fresh value via assumed role
    let refresh_query = ProviderQueryBuilder::default()
        .secret_id(&secret_name)
        .role_arn(&role_arn)
        .refresh_now(true)
        .build()
        .unwrap();
    let response3 = provider.make_request(&refresh_query).await;
    let json3: serde_json::Value = serde_json::from_str(&response3).unwrap();

    assert_eq!(json3["VersionId"].as_str().unwrap(), new_version_id);
    assert!(json3["SecretString"]
        .as_str()
        .unwrap()
        .contains("rotateduser"));
}

#[tokio::test]
async fn test_role_chaining_no_access_role_denied() {
    let helper = RoleChainingHelper::new().await;
    let role_arn = helper.get_role_arn(NO_ACCESS_ROLE_NAME).await;
    let target_role_arn = helper.get_role_arn(ROLE_CHAINING_ROLE_NAME).await;

    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(&SecretType::Basic);

    let provider = ProviderProcess::start().await;

    // Fetch with the target role — should succeed
    let query_ok = ProviderQueryBuilder::default()
        .secret_id(&secret_name)
        .role_arn(&target_role_arn)
        .build()
        .unwrap();
    let response_ok = provider.make_request_raw(&query_ok).await;
    assert_eq!(response_ok.status(), 200);

    // Fetch the same secret with the no-access role — should fail
    let query_denied = ProviderQueryBuilder::default()
        .secret_id(&secret_name)
        .role_arn(&role_arn)
        .build()
        .unwrap();
    let response_denied = provider.make_request_raw(&query_denied).await;
    assert_eq!(response_denied.status(), 400);

    let body = response_denied
        .text()
        .await
        .expect("Failed to read response body");
    assert!(
        body.contains("AccessDeniedException") || body.contains("AccessDenied"),
        "Expected access denied error, got: {body}"
    );
}

#[tokio::test]
async fn test_role_chaining_separate_caches_per_role() {
    let helper = RoleChainingHelper::new().await;
    let role_arn = helper.get_role_arn(ROLE_CHAINING_ROLE_NAME).await;

    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(&SecretType::Basic);

    let provider = ProviderProcess::start().await;

    // Fetch with default provider role (no roleArn) — caches the original value
    let query_default = ProviderQueryBuilder::default()
        .secret_id(&secret_name)
        .build()
        .unwrap();
    let response_default = provider.make_request(&query_default).await;
    let json_default: serde_json::Value = serde_json::from_str(&response_default).unwrap();
    assert!(json_default["SecretString"]
        .as_str()
        .unwrap()
        .contains("testuser"));

    // Update the secret directly
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let client = aws_sdk_secretsmanager::Client::new(&config);
    client
        .update_secret()
        .secret_id(&secret_name)
        .secret_string(r#"{"username":"updateduser","password":"updatedpass"}"#)
        .send()
        .await
        .expect("Failed to update secret");

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Fetch with default role again — should still return stale cached value
    let response_default2 = provider.make_request(&query_default).await;
    let json_default2: serde_json::Value = serde_json::from_str(&response_default2).unwrap();
    assert!(
        json_default2["SecretString"]
            .as_str()
            .unwrap()
            .contains("testuser"),
        "Default role should return stale cached value"
    );

    // Fetch with target role — cache miss on its own cache, should get the updated value
    let query_role = ProviderQueryBuilder::default()
        .secret_id(&secret_name)
        .role_arn(&role_arn)
        .build()
        .unwrap();
    let response_role = provider.make_request(&query_role).await;
    let json_role: serde_json::Value = serde_json::from_str(&response_role).unwrap();
    assert!(
        json_role["SecretString"]
            .as_str()
            .unwrap()
            .contains("updateduser"),
        "Target role should get fresh value from its own separate cache"
    );
}
