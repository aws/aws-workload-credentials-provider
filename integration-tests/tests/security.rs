//! # Security Integration Tests
//!
//! This module contains integration tests for AWS Secrets Manager Agent's security features.
//! These tests verify SSRF protection, token validation, and other security mechanisms
//! to ensure the agent properly rejects unauthorized requests in production environments.

mod common;

use common::*;

#[tokio::test]
async fn test_ssrf_token_validation() {
    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(&SecretType::Basic);

    let agent = AgentProcess::start().await;

    let query = AgentQueryBuilder::default()
        .secret_id(&secret_name)
        .build()
        .unwrap();

    // Test 1: Request without SSRF token should be rejected
    let response_no_token = agent.make_request_without_token(&query).await;
    assert_eq!(response_no_token.status(), 403);

    // Test 2: Request with invalid SSRF token should be rejected
    let response_invalid_token = agent.make_request_with_invalid_token(&query).await;
    assert_eq!(response_invalid_token.status(), 403);

    // Test 3: Request with valid SSRF token should succeed
    let response_valid = agent.make_request_raw(&query).await;
    assert_eq!(response_valid.status(), 200);

    let body_valid = response_valid
        .text()
        .await
        .expect("Failed to read response body");
    let json: serde_json::Value = serde_json::from_str(&body_valid).unwrap();
    assert!(json["SecretString"].as_str().unwrap().contains("testuser"));

    // Test 4: Verify token validation works with refreshNow parameter
    let refresh_query = AgentQueryBuilder::default()
        .secret_id(&secret_name)
        .refresh_now(true)
        .build()
        .unwrap();

    let response_refresh_no_token = agent.make_request_without_token(&refresh_query).await;
    assert_eq!(response_refresh_no_token.status(), 403);

    let response_refresh_valid = agent.make_request_raw(&refresh_query).await;
    assert_eq!(response_refresh_valid.status(), 200);
}
#[tokio::test]
async fn test_x_forwarded_for_rejection() {
    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(&SecretType::Basic);

    let agent = AgentProcess::start().await;

    let query = AgentQueryBuilder::default()
        .secret_id(&secret_name)
        .build()
        .unwrap();

    // Test that request with X-Forwarded-For header is rejected
    let response_with_xff = agent.make_request_with_x_forwarded_for(&query).await;
    assert_eq!(response_with_xff.status(), 400);

    // Test that normal request without X-Forwarded-For succeeds
    let response_normal = agent.make_request_raw(&query).await;
    assert_eq!(response_normal.status(), 200);

    let body_normal = response_normal
        .text()
        .await
        .expect("Failed to read response body");
    let json: serde_json::Value = serde_json::from_str(&body_normal).unwrap();
    assert!(json["SecretString"].as_str().unwrap().contains("testuser"));
}
