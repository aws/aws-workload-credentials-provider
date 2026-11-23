//! # Role Credential Failover Integration Tests
//!
//! Tests that `roleArn` requests fail over to STS in `default_failover_region`
//! when STS in the primary region is down.
//!
//! Strategy: the provider runs with `AWS_REGION` set to `FAKE_REGION`, a region
//! that doesn't exist, so every primary call (STS `AssumeRole` and
//! `GetCallerIdentity`, and Secrets Manager) fails its DNS lookup, while the
//! failover calls reach real AWS in the failover region. Each test checks the
//! response and the provider's `failover=true` log lines.
//!
//! STS 5xx, throttling and hanging primaries are covered by the unit tests in
//! `failover_credentials_provider.rs`.
//!
//! Required roles: `asm-role-chaining-role` and `provider-no-access-role`, the
//! same as the role chaining tests.

mod common;

use common::*;
use tempfile::NamedTempFile;

/// The whole primary region is down: role credentials and the secret both come
/// from the failover region.
#[tokio::test]
async fn test_role_failover_primary_region_down() {
    let helper = RoleChainingHelper::new().await;
    let role_arn = helper.get_role_arn(ROLE_CHAINING_ROLE_NAME).await;
    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(&SecretType::Basic);
    let real_region = real_region().await;
    let (provider, logs) = ProviderProcess::start_with_failover_config(
        2900,
        &format!("default_failover_region = \"{real_region}\""),
        &[("AWS_REGION", FAKE_REGION)],
    )
    .await;

    let query = ProviderQueryBuilder::default()
        .secret_id(&secret_name)
        .role_arn(&role_arn)
        .build()
        .unwrap();
    let response = provider.make_request(&query).await;
    let json: serde_json::Value = serde_json::from_str(&response).unwrap();

    assert_eq!(json["Name"], secret_name);
    assert!(json["SecretString"].as_str().unwrap().contains("testuser"));
    logs.assert_failed_over("AssumeRole").await;
    logs.assert_failed_over("GetCallerIdentity").await;
    logs.assert_failed_over("GetSecretValue").await;
}

/// The primary and failover regions are both down: the STS failover is
/// attempted and fails. The request fails at STS, so no secret is needed.
#[tokio::test]
async fn test_role_failover_all_sts_down() {
    let helper = RoleChainingHelper::new().await;
    let role_arn = helper.get_role_arn(ROLE_CHAINING_ROLE_NAME).await;
    let (provider, logs) = ProviderProcess::start_with_failover_config(
        2901,
        &format!("default_failover_region = \"{FAKE_FAILOVER_REGION}\""),
        &[("AWS_REGION", FAKE_REGION)],
    )
    .await;

    let query = ProviderQueryBuilder::default()
        .secret_id("any-secret")
        .role_arn(&role_arn)
        .build()
        .unwrap();
    let response = provider.make_request_raw(&query).await;
    assert_eq!(response.status(), 403);
    logs.assert_failover_errored("AssumeRole").await;
}

/// The primary region is down with no failover region: the request fails at
/// STS, so no secret is needed.
#[tokio::test]
async fn test_role_failover_not_configured() {
    let helper = RoleChainingHelper::new().await;
    let role_arn = helper.get_role_arn(ROLE_CHAINING_ROLE_NAME).await;
    let (provider, logs) =
        ProviderProcess::start_with_failover_config(2902, "", &[("AWS_REGION", FAKE_REGION)]).await;

    let query = ProviderQueryBuilder::default()
        .secret_id("any-secret")
        .role_arn(&role_arn)
        .build()
        .unwrap();
    let response = provider.make_request_raw(&query).await;

    assert_eq!(response.status(), 403);
    // Every role client failure is a 403, so check that STS was called in the down region
    let lines = logs.wait_for("Failed to create role client").await;
    assert!(
        lines.iter().any(|line| line.contains("dns error")),
        "Expected STS in {FAKE_REGION} to fail its DNS lookup: {lines:?}"
    );
    assert!(logs.wait_for("failover=true").await.is_empty());
}

/// A role that can't be assumed: access denied isn't an outage, so no failover.
#[tokio::test]
async fn test_role_failover_not_on_access_denied() {
    let failover_region = other_region().await;
    let (provider, logs) = ProviderProcess::start_with_failover_config(
        2903,
        // The primary AssumeRole gets 5s, so a slow cold STS call isn't read as an outage
        &format!(
            "default_failover_region = \"{failover_region}\"\n\
             operation_timeout_ms = 10000"
        ),
        &[],
    )
    .await;

    let query = ProviderQueryBuilder::default()
        .secret_id("any-secret")
        .role_arn("arn:aws:iam::000000000000:role/NonExistentRole")
        .build()
        .unwrap();
    let response = provider.make_request_raw(&query).await;
    assert_eq!(response.status(), 403);

    // Every role client failure is a 403, so check that STS denied the role
    let lines = logs.wait_for("Failed to create role client").await;
    assert!(
        lines.iter().any(|line| line.contains("AccessDenied")),
        "Expected STS to deny the role: {lines:?}"
    );
    assert!(logs.wait_for("failover=true").await.is_empty());
}

/// The agent's only credentials are a `credentials_file_path` file, as on a host
/// outside AWS: the failover AssumeRole uses the file's credentials too.
#[tokio::test]
async fn test_role_failover_with_credentials_file() {
    let helper = RoleChainingHelper::new().await;
    let role_arn = helper.get_role_arn(ROLE_CHAINING_ROLE_NAME).await;
    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(&SecretType::Basic);
    let real_region = real_region().await;
    let mut credentials_file = NamedTempFile::new().unwrap();
    write_real_credentials(&mut credentials_file).await;
    let config_content = format!(
        r#"
[logging]
log_level = "info"
log_to_file = false

[capabilities.secrets_manager]
http_port = 2904
validate_credentials = false
credentials_file_path = "{}"

[capabilities.secrets_manager.failover]
default_failover_region = "{real_region}"
"#,
        credentials_file.path().display()
    );
    // No other credentials source: no environment keys, web identity, container
    // credentials, shared config files or IMDS.
    let (provider, logs) = ProviderProcess::start_provider_with_captured_logs(
        2904,
        &config_content,
        &[
            ("AWS_REGION", FAKE_REGION),
            ("AWS_ACCESS_KEY_ID", ""),
            ("AWS_SECRET_ACCESS_KEY", ""),
            ("AWS_SESSION_TOKEN", ""),
            ("AWS_WEB_IDENTITY_TOKEN_FILE", ""),
            ("AWS_ROLE_ARN", ""),
            ("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", ""),
            ("AWS_CONTAINER_CREDENTIALS_FULL_URI", ""),
            ("AWS_CONFIG_FILE", "/nonexistent"),
            ("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent"),
            ("AWS_EC2_METADATA_DISABLED", "true"),
        ],
    )
    .await;

    let query = ProviderQueryBuilder::default()
        .secret_id(&secret_name)
        .role_arn(&role_arn)
        .build()
        .unwrap();
    let response = provider.make_request(&query).await;
    let json: serde_json::Value = serde_json::from_str(&response).unwrap();

    assert_eq!(json["Name"], secret_name);
    logs.assert_failed_over("AssumeRole").await;
    logs.assert_failed_over("GetCallerIdentity").await;
}

/// The primary region is up: the request is served from it and the failover
/// region, which has no endpoints, is never called.
#[tokio::test]
async fn test_role_failover_not_on_healthy_primary() {
    let helper = RoleChainingHelper::new().await;
    let role_arn = helper.get_role_arn(ROLE_CHAINING_ROLE_NAME).await;
    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(&SecretType::Basic);
    let (provider, logs) = ProviderProcess::start_with_failover_config(
        2905,
        // The primary AssumeRole gets 5s, so a slow cold STS call isn't read as an outage
        &format!(
            "default_failover_region = \"{FAKE_FAILOVER_REGION}\"\n\
             operation_timeout_ms = 10000"
        ),
        &[],
    )
    .await;

    let query = ProviderQueryBuilder::default()
        .secret_id(&secret_name)
        .role_arn(&role_arn)
        .build()
        .unwrap();
    let response = provider.make_request(&query).await;
    let json: serde_json::Value = serde_json::from_str(&response).unwrap();

    assert_eq!(json["Name"], secret_name);
    assert!(logs.wait_for("failover=true").await.is_empty());
}

/// The primary region is down and the role can't read the secret: the role's
/// credentials fail over, the failover region denies the role's read, and the
/// primary's connection error is returned.
#[tokio::test]
async fn test_role_failover_secret_access_denied() {
    let helper = RoleChainingHelper::new().await;
    let role_arn = helper.get_role_arn(NO_ACCESS_ROLE_NAME).await;
    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(&SecretType::Basic);
    let real_region = real_region().await;
    let (provider, logs) = ProviderProcess::start_with_failover_config(
        2906,
        // Room for the primary's retries, so its connection error isn't cut into a 504
        &format!(
            "default_failover_region = \"{real_region}\"\n\
             operation_timeout_ms = 10000"
        ),
        &[("AWS_REGION", FAKE_REGION)],
    )
    .await;

    let query = ProviderQueryBuilder::default()
        .secret_id(&secret_name)
        .role_arn(&role_arn)
        .build()
        .unwrap();
    let response = provider.make_request_raw(&query).await;
    assert_eq!(response.status(), 502);

    logs.assert_failed_over("AssumeRole").await;
    logs.assert_failed_over("GetCallerIdentity").await;
    let line = logs.assert_failover_errored("GetSecretValue").await;
    assert!(
        line.contains("assumed-role/provider-no-access-role"),
        "Failover wasn't denied for the role: {line}"
    );
}

/// The primary region is set by the config file's `region`, not the SDK: with
/// that region down, AssumeRole is pinned to it and fails over, rather than
/// going to the SDK's region.
#[tokio::test]
async fn test_role_failover_configured_region() {
    let helper = RoleChainingHelper::new().await;
    let role_arn = helper.get_role_arn(ROLE_CHAINING_ROLE_NAME).await;
    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(&SecretType::Basic);
    let real_region = real_region().await;
    let config_content = format!(
        r#"
[logging]
log_level = "info"
log_to_file = false

[capabilities.secrets_manager]
http_port = 2907
validate_credentials = false
region = "{FAKE_REGION}"

[capabilities.secrets_manager.failover]
default_failover_region = "{real_region}"
"#
    );
    let (provider, logs) =
        ProviderProcess::start_provider_with_captured_logs(2907, &config_content, &[]).await;

    let query = ProviderQueryBuilder::default()
        .secret_id(&secret_name)
        .role_arn(&role_arn)
        .build()
        .unwrap();
    let response = provider.make_request(&query).await;
    let json: serde_json::Value = serde_json::from_str(&response).unwrap();

    assert_eq!(json["Name"], secret_name);
    logs.assert_failed_over("AssumeRole").await;
    logs.assert_failed_over("GetCallerIdentity").await;
    logs.assert_failed_over("GetSecretValue").await;
}

/// The primary region is down and the failover region comes only from the
/// `failoverRegion` query parameter: role credentials fail over only with
/// `default_failover_region`, so the request fails at STS.
#[tokio::test]
async fn test_role_failover_not_on_query_parameter_only() {
    let helper = RoleChainingHelper::new().await;
    let role_arn = helper.get_role_arn(ROLE_CHAINING_ROLE_NAME).await;
    let real_region = real_region().await;
    let (provider, logs) =
        ProviderProcess::start_with_failover_config(2908, "", &[("AWS_REGION", FAKE_REGION)]).await;

    let query = ProviderQueryBuilder::default()
        .secret_id("any-secret")
        .role_arn(&role_arn)
        .failover_region(&real_region)
        .build()
        .unwrap();
    let response = provider.make_request_raw(&query).await;

    assert_eq!(response.status(), 403);
    // Every role client failure is a 403, so check that STS was called in the down region
    let lines = logs.wait_for("Failed to create role client").await;
    assert!(
        lines.iter().any(|line| line.contains("dns error")),
        "Expected STS in {FAKE_REGION} to fail its DNS lookup: {lines:?}"
    );
    assert!(logs.wait_for("failover=true").await.is_empty());
}

/// A role request by the secret's ARN in the primary region, as for a replicated
/// secret: the role's credentials fail over, and the failover call rewrites the
/// ARN to the failover region.
#[tokio::test]
async fn test_role_failover_retargets_arn() {
    let helper = RoleChainingHelper::new().await;
    let role_arn = helper.get_role_arn(ROLE_CHAINING_ROLE_NAME).await;
    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(&SecretType::Basic);
    let real_region = real_region().await;
    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let secret_arn = aws_sdk_secretsmanager::Client::new(&sdk_config)
        .describe_secret()
        .secret_id(&secret_name)
        .send()
        .await
        .expect("Failed to describe secret")
        .arn()
        .expect("Secret ARN not found")
        .to_string();
    // The same secret's ARN in the primary region, which is down
    let primary_arn = secret_arn.replace(
        &format!(":secretsmanager:{real_region}:"),
        &format!(":secretsmanager:{FAKE_REGION}:"),
    );
    assert_ne!(primary_arn, secret_arn);
    let (provider, logs) = ProviderProcess::start_with_failover_config(
        2909,
        &format!("default_failover_region = \"{real_region}\""),
        &[("AWS_REGION", FAKE_REGION)],
    )
    .await;

    let query = ProviderQueryBuilder::default()
        .secret_id(&primary_arn)
        .role_arn(&role_arn)
        .build()
        .unwrap();
    let response = provider.make_request(&query).await;
    let json: serde_json::Value = serde_json::from_str(&response).unwrap();

    assert_eq!(json["ARN"], secret_arn);
    logs.assert_failed_over("AssumeRole").await;
    logs.assert_failed_over("GetCallerIdentity").await;
    logs.assert_failed_over("GetSecretValue").await;
}

/// The cached value expires while Secrets Manager is down in both regions: the
/// role's credentials are still cached, the freshness check (DescribeSecret)
/// fails in both regions, and the cached value is served.
#[tokio::test]
async fn test_role_failover_all_down_serves_cached_value() {
    let helper = RoleChainingHelper::new().await;
    let role_arn = helper.get_role_arn(ROLE_CHAINING_ROLE_NAME).await;
    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(&SecretType::Basic);
    let real_region = real_region().await;
    let ttl_seconds = 2;
    let (provider, logs) = ProviderProcess::start_with_failover_config(
        2919,
        &format!(
            "default_failover_region = \"{real_region}\"\n\
             [capabilities.secrets_manager.cache]\n\
             ttl_seconds = {ttl_seconds}"
        ),
        &[("AWS_REGION", FAKE_REGION)],
    )
    .await;

    let query = ProviderQueryBuilder::default()
        .secret_id(&secret_name)
        .role_arn(&role_arn)
        .build()
        .unwrap();
    let response1 = provider.make_request(&query).await;
    let json1: serde_json::Value = serde_json::from_str(&response1).unwrap();

    // Wait for the cache entry to expire
    tokio::time::sleep(std::time::Duration::from_secs(ttl_seconds)).await;

    // The `failoverRegion` query parameter points Secrets Manager at a region that's down too
    let down_query = ProviderQueryBuilder::default()
        .secret_id(&secret_name)
        .role_arn(&role_arn)
        .failover_region(FAKE_FAILOVER_REGION)
        .build()
        .unwrap();
    let response2 = provider.make_request(&down_query).await;
    let json2: serde_json::Value = serde_json::from_str(&response2).unwrap();

    assert_eq!(json2["VersionId"], json1["VersionId"]);
    // One AssumeRole, from the first request: the role's credentials were reused
    logs.assert_failed_over("AssumeRole").await;
    let line = logs.assert_failover_errored("DescribeSecret").await;
    assert!(
        line.contains(&format!("failover_region={FAKE_FAILOVER_REGION} ")),
        "Failover wasn't to {FAKE_FAILOVER_REGION}: {line}"
    );
}

/// The primary region is down and the failover region comes only from
/// `secret_to_region_map`: role credentials fail over only with
/// `default_failover_region`, so the request fails at STS.
#[tokio::test]
async fn test_role_failover_not_on_secret_to_region_map_only() {
    let helper = RoleChainingHelper::new().await;
    let role_arn = helper.get_role_arn(ROLE_CHAINING_ROLE_NAME).await;
    let real_region = real_region().await;
    // The request fails at STS, so the secret doesn't need to exist
    let secret_arn = format!(
        "arn:aws:secretsmanager:{FAKE_REGION}:{}:secret:any-secret-AbCdEf",
        helper.account_id
    );
    let (provider, logs) = ProviderProcess::start_with_failover_config(
        2925,
        &format!(
            "[capabilities.secrets_manager.failover.secret_to_region_map]\n\
             \"{secret_arn}\" = \"{real_region}\""
        ),
        &[("AWS_REGION", FAKE_REGION)],
    )
    .await;

    let query = ProviderQueryBuilder::default()
        .secret_id(&secret_arn)
        .role_arn(&role_arn)
        .build()
        .unwrap();
    let response = provider.make_request_raw(&query).await;

    assert_eq!(response.status(), 403);
    // Every role client failure is a 403, so check that STS was called in the down region
    let lines = logs.wait_for("Failed to create role client").await;
    assert!(
        lines.iter().any(|line| line.contains("dns error")),
        "Expected STS in {FAKE_REGION} to fail its DNS lookup: {lines:?}"
    );
    assert!(logs.wait_for("failover=true").await.is_empty());
}
