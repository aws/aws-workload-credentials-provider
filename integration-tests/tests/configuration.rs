//! # Configuration Integration Tests
//!
//! This module contains integration tests for AWS Secrets Manager Agent's configuration features.
//! These tests verify that configuration options work correctly and affect agent behavior as expected,
//! including health check endpoints and path-based request handling.

mod common;

use common::*;

#[tokio::test]
async fn test_ping_endpoint_health_check() {
    let agent = AgentProcess::start().await;

    // Test 1: Ping endpoint should work without token
    let response_no_token = agent.make_ping_request().await;
    assert_eq!(response_no_token.status(), 200);

    let body_no_token = response_no_token
        .text()
        .await
        .expect("Failed to read response body");
    assert_eq!(body_no_token, "healthy");

    // Test 2: Ping endpoint should also work with token (token not required for ping)
    let response_with_token = agent.make_ping_request_with_token().await;
    assert_eq!(response_with_token.status(), 200);

    let body_with_token = response_with_token
        .text()
        .await
        .expect("Failed to read response body");
    assert_eq!(body_with_token, "healthy");
}
#[tokio::test]
async fn test_path_based_requests() {
    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(&SecretType::Basic);

    let agent = AgentProcess::start().await;

    // Test path-based request using default path_prefix "/v1/"
    let response_path = agent.make_path_based_request(&secret_name).await;
    assert_eq!(response_path.status(), 200);

    let body_path = response_path
        .text()
        .await
        .expect("Failed to read response body");
    let json_path: serde_json::Value = serde_json::from_str(&body_path).unwrap();
    assert!(json_path["SecretString"]
        .as_str()
        .unwrap()
        .contains("testuser"));
    assert_eq!(json_path["Name"].as_str().unwrap(), secret_name);

    // Compare with regular query-based request to ensure same result
    let query = AgentQueryBuilder::default()
        .secret_id(&secret_name)
        .build()
        .unwrap();
    let response_query = agent.make_request_raw(&query).await;
    assert_eq!(response_query.status(), 200);

    let body_query = response_query
        .text()
        .await
        .expect("Failed to read response body");
    let json_query: serde_json::Value = serde_json::from_str(&body_query).unwrap();

    // Both methods should return identical secret data
    assert_eq!(json_path["SecretString"], json_query["SecretString"]);
    assert_eq!(json_path["VersionId"], json_query["VersionId"]);
}
