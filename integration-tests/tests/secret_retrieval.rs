//! # Secret Retrieval Integration Tests
//!
//! This module contains integration tests for AWS Secrets Manager Agent's core secret retrieval functionality.
//! These tests verify that the agent can correctly fetch different types of secrets using various
//! identification methods and handle different secret formats.

mod common;

use common::*;

#[tokio::test]
async fn test_secret_retrieval_by_name() {
    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(&SecretType::Basic);

    let agent = AgentProcess::start().await;

    let query = AgentQueryBuilder::default()
        .secret_id(&secret_name)
        .build()
        .unwrap();
    let response = agent.make_request(&query).await;
    let json: serde_json::Value = serde_json::from_str(&response).unwrap();

    assert_eq!(json["Name"], secret_name);
    assert!(json["SecretString"].as_str().unwrap().contains("testuser"));
    assert!(json["VersionId"].is_string());
}

#[tokio::test]
async fn test_secret_retrieval_by_arn() {
    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(&SecretType::Basic);

    // Get the ARN using AWS SDK
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let client = aws_sdk_secretsmanager::Client::new(&config);

    let describe_response = client
        .describe_secret()
        .secret_id(&secret_name)
        .send()
        .await
        .expect("Failed to describe secret");

    let arn = describe_response.arn().expect("Secret ARN not found");

    let agent = AgentProcess::start().await;

    let query = AgentQueryBuilder::default().secret_id(arn).build().unwrap();
    let response = agent.make_request(&query).await;
    let json: serde_json::Value = serde_json::from_str(&response).unwrap();

    assert_eq!(json["ARN"], arn);
    assert!(json["SecretString"].as_str().unwrap().contains("testuser"));
}

#[tokio::test]
async fn test_binary_secret_retrieval() {
    let secrets = TestSecrets::setup_binary().await;
    let secret_name = secrets.secret_name(&SecretType::Binary);

    let agent = AgentProcess::start().await;

    let query = AgentQueryBuilder::default()
        .secret_id(&secret_name)
        .build()
        .unwrap();
    let response = agent.make_request(&query).await;
    let json: serde_json::Value = serde_json::from_str(&response).unwrap();

    assert_eq!(json["Name"], secret_name);
    assert!(json["SecretBinary"].is_string());
    assert!(json["SecretString"].is_null());
}

#[tokio::test]
async fn test_version_stage_retrieval() {
    let secrets = TestSecrets::setup_versioned().await;
    let secret_name = secrets.secret_name(&SecretType::Versioned);

    // Wait for AWSPENDING version to be available
    let _ = secrets
        .wait_for_pending_version(&SecretType::Versioned)
        .await;

    let agent = AgentProcess::start().await;

    // Test AWSCURRENT stage (latest version)
    let current_query = AgentQueryBuilder::default()
        .secret_id(&secret_name)
        .version_stage("AWSCURRENT")
        .build()
        .unwrap();
    let current_response = agent.make_request(&current_query).await;
    let current_json: serde_json::Value = serde_json::from_str(&current_response).unwrap();

    assert_eq!(current_json["Name"], secret_name);
    assert!(current_json["SecretString"]
        .as_str()
        .unwrap()
        .contains("currentuser"));
    assert!(current_json["VersionStages"]
        .as_array()
        .unwrap()
        .contains(&serde_json::Value::String("AWSCURRENT".to_string())));

    // Test AWSPENDING stage (previous version)
    let pending_query = AgentQueryBuilder::default()
        .secret_id(&secret_name)
        .version_stage("AWSPENDING")
        .build()
        .unwrap();
    let pending_response = agent.make_request(&pending_query).await;
    let pending_json: serde_json::Value = serde_json::from_str(&pending_response).unwrap();

    assert_eq!(pending_json["Name"], secret_name);
    assert!(pending_json["SecretString"]
        .as_str()
        .unwrap()
        .contains("pendinguser"));
    assert!(pending_json["VersionStages"]
        .as_array()
        .unwrap()
        .contains(&serde_json::Value::String("AWSPENDING".to_string())));
}

#[tokio::test]
async fn test_version_id_retrieval() {
    let secrets = TestSecrets::setup_versioned().await;
    let secret_name = secrets.secret_name(&SecretType::Versioned);

    // Wait for AWSPENDING version to be available
    let _ = secrets
        .wait_for_pending_version(&SecretType::Versioned)
        .await;

    // Get the version IDs for both stages
    let (current_version_id, pending_version_id) =
        secrets.get_version_ids(&SecretType::Versioned).await;

    let agent = AgentProcess::start().await;

    // Test retrieval by AWSCURRENT version ID
    let current_query = AgentQueryBuilder::default()
        .secret_id(&secret_name)
        .version_id(&current_version_id)
        .build()
        .unwrap();
    let current_response = agent.make_request(&current_query).await;
    let current_json: serde_json::Value = serde_json::from_str(&current_response).unwrap();

    assert_eq!(current_json["Name"], secret_name);
    assert_eq!(current_json["VersionId"], current_version_id);
    assert!(current_json["SecretString"]
        .as_str()
        .unwrap()
        .contains("currentuser"));

    // Test retrieval by AWSPENDING version ID
    let pending_query = AgentQueryBuilder::default()
        .secret_id(&secret_name)
        .version_id(&pending_version_id)
        .build()
        .unwrap();
    let pending_response = agent.make_request(&pending_query).await;
    let pending_json: serde_json::Value = serde_json::from_str(&pending_response).unwrap();

    assert_eq!(pending_json["Name"], secret_name);
    assert_eq!(pending_json["VersionId"], pending_version_id);
    assert!(pending_json["SecretString"]
        .as_str()
        .unwrap()
        .contains("pendinguser"));
}

#[tokio::test]
async fn test_large_secret_retrieval() {
    let secrets = TestSecrets::setup_large().await;
    let secret_name = secrets.secret_name(&SecretType::Large);

    let agent = AgentProcess::start().await;

    let query = AgentQueryBuilder::default()
        .secret_id(&secret_name)
        .build()
        .unwrap();
    let response = agent.make_request(&query).await;
    let json: serde_json::Value = serde_json::from_str(&response).unwrap();

    assert_eq!(json["Name"], secret_name);
    let secret_string = json["SecretString"].as_str().unwrap();
    let secret_data: serde_json::Value = serde_json::from_str(secret_string).unwrap();

    // Verify the large data is present and correct size
    assert_eq!(secret_data["size"], "60KB");
    assert_eq!(secret_data["data"].as_str().unwrap().len(), 60000);
    assert!(secret_data["data"]
        .as_str()
        .unwrap()
        .chars()
        .all(|c| c == 'x'));
}

#[tokio::test]
async fn test_real_nonexistent_secret() {
    let agent = AgentProcess::start().await;

    // Generate a guaranteed non-existent secret name
    let nonexistent_secret = format!(
        "nonexistent-secret-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    let query = AgentQueryBuilder::default()
        .secret_id(&nonexistent_secret)
        .build()
        .unwrap();

    // Request non-existent secret - should return proper error response
    let response = agent.make_request_raw(&query).await;

    // Should return 400 status for ResourceNotFoundException
    assert_eq!(response.status(), 400);

    let body = response.text().await.expect("Failed to read response body");

    // For a 400 status with non-existent secret, any non-empty response is acceptable
    // The specific error format may vary between environments
    assert!(
        !body.is_empty(),
        "Expected error response body to be non-empty"
    );

    // Test with refreshNow=true - should also fail consistently
    let refresh_query = AgentQueryBuilder::default()
        .secret_id(&nonexistent_secret)
        .refresh_now(true)
        .build()
        .unwrap();

    let refresh_response = agent.make_request_raw(&refresh_query).await;
    assert_eq!(refresh_response.status(), 400);

    let refresh_body = refresh_response
        .text()
        .await
        .expect("Failed to read refresh response body");

    // For a 400 status with non-existent secret, any non-empty response is acceptable
    assert!(
        !refresh_body.is_empty(),
        "Expected refresh error response body to be non-empty"
    );
}
