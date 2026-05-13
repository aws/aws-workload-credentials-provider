//! # Version Management Integration Tests
//!
//! This module contains integration tests for AWS Secrets Manager Agent's version management capabilities.
//! These tests verify that the agent correctly handles secret version stages (AWSCURRENT, AWSPENDING)
//! and version transitions during secret rotation scenarios.

mod common;

use common::*;

#[tokio::test]
async fn test_version_stage_transitions() {
    let secrets = TestSecrets::setup_versioned().await;
    let secret_name = secrets.secret_name(&SecretType::Versioned);

    let agent = AgentProcess::start().await;

    // Wait for AWSPENDING version to be available
    let _ = secrets
        .wait_for_pending_version(&SecretType::Versioned)
        .await;

    // Get the version IDs for both stages
    let (current_version_id, pending_version_id) =
        secrets.get_version_ids(&SecretType::Versioned).await;

    // Test AWSPENDING stage before promotion
    let pending_query = AgentQueryBuilder::default()
        .secret_id(&secret_name)
        .version_stage("AWSPENDING")
        .build()
        .unwrap();
    let pending_response = agent.make_request(&pending_query).await;
    let pending_json: serde_json::Value = serde_json::from_str(&pending_response).unwrap();

    assert_eq!(pending_json["VersionId"], pending_version_id);
    assert!(pending_json["SecretString"]
        .as_str()
        .unwrap()
        .contains("pendinguser"));

    // Test AWSCURRENT stage before promotion
    let current_query = AgentQueryBuilder::default()
        .secret_id(&secret_name)
        .version_stage("AWSCURRENT")
        .build()
        .unwrap();
    let current_response = agent.make_request(&current_query).await;
    let current_json: serde_json::Value = serde_json::from_str(&current_response).unwrap();

    assert_eq!(current_json["VersionId"], current_version_id);
    assert!(current_json["SecretString"]
        .as_str()
        .unwrap()
        .contains("currentuser"));

    // Promote AWSPENDING to AWSCURRENT using update_secret_version_stage
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let client = aws_sdk_secretsmanager::Client::new(&config);

    client
        .update_secret_version_stage()
        .secret_id(&secret_name)
        .version_stage("AWSCURRENT")
        .move_to_version_id(&pending_version_id)
        .remove_from_version_id(&current_version_id)
        .send()
        .await
        .expect("Failed to promote version stage");

    // Wait for promotion to be reflected in agent with retry logic
    // This handles both AWS propagation and agent cache refresh
    let mut promoted_json = None;
    for attempt in 0..10 {
        let promoted_query = AgentQueryBuilder::default()
            .secret_id(&secret_name)
            .version_stage("AWSCURRENT")
            .refresh_now(true)
            .build()
            .unwrap();
        let promoted_response = agent.make_request(&promoted_query).await;
        let json: serde_json::Value = serde_json::from_str(&promoted_response).unwrap();

        if json["VersionId"].as_str().unwrap() == pending_version_id {
            promoted_json = Some(json);
            break;
        }

        if attempt < 9 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }

    let promoted_json =
        promoted_json.expect("Version promotion not reflected in agent after retries");

    // After promotion, AWSCURRENT should now have the pending version ID and content
    assert_eq!(promoted_json["VersionId"], pending_version_id);
    assert!(promoted_json["SecretString"]
        .as_str()
        .unwrap()
        .contains("pendinguser"));
    assert!(promoted_json["VersionStages"]
        .as_array()
        .unwrap()
        .contains(&serde_json::Value::String("AWSCURRENT".to_string())));

    // Verify the old current version is no longer AWSCURRENT
    let old_current_query = AgentQueryBuilder::default()
        .secret_id(&secret_name)
        .version_id(&current_version_id)
        .refresh_now(true)
        .build()
        .unwrap();
    let old_current_response = agent.make_request(&old_current_query).await;
    let old_current_json: serde_json::Value = serde_json::from_str(&old_current_response).unwrap();

    // The old version should still exist but not have AWSCURRENT stage
    assert_eq!(old_current_json["VersionId"], current_version_id);
    assert!(old_current_json["SecretString"]
        .as_str()
        .unwrap()
        .contains("currentuser"));
    assert!(!old_current_json["VersionStages"]
        .as_array()
        .unwrap()
        .contains(&serde_json::Value::String("AWSCURRENT".to_string())));
}
