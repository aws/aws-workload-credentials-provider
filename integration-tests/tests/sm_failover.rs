//! # Secrets Manager Failover Integration Tests
//!
//! Tests that secret requests fail over to Secrets Manager in the failover region
//! when Secrets Manager in the primary region is down.
//!
//! Strategy: the same as the role failover tests. The provider runs with
//! `AWS_REGION` set to `FAKE_REGION`, so every primary call fails its DNS
//! lookup, while the failover calls reach real Secrets Manager in the test's own
//! region, where the secret is. Each test checks the response and the
//! provider's `failover=true` log lines.
//!
//! Throttling, 5xx and hanging primaries, and the ARN rewrite for a request by
//! ARN, are covered by the unit tests in `aws_secretsmanager_caching` and
//! `aws_secretsmanager_provider`.

mod common;

use aws_credential_types::provider::ProvideCredentials;
use common::*;
use std::io::Write;
use tempfile::NamedTempFile;

/// An AWS config file whose `awcp-own-role` profile assumes `role_arn` with the
/// test's own credentials, so the provider's own credentials come from STS, as
/// on an EC2 or on-premises host with a `role_arn` profile.
async fn own_credentials_profile(role_arn: &str) -> NamedTempFile {
    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let test_credentials = sdk_config
        .credentials_provider()
        .expect("No credentials provider")
        .provide_credentials()
        .await
        .expect("Failed to resolve credentials");
    let mut content = format!(
        "[profile awcp-source]\naws_access_key_id={}\naws_secret_access_key={}\n",
        test_credentials.access_key_id(),
        test_credentials.secret_access_key()
    );
    if let Some(token) = test_credentials.session_token() {
        content.push_str(&format!("aws_session_token={token}\n"));
    }
    content.push_str(&format!(
        "\n[profile awcp-own-role]\nrole_arn={role_arn}\nsource_profile=awcp-source\n"
    ));
    let mut aws_config_file = NamedTempFile::new().unwrap();
    aws_config_file.write_all(content.as_bytes()).unwrap();
    aws_config_file.flush().unwrap();
    aws_config_file
}

/// An AWS config file whose `awcp-slow-process` profile hands out the test's own
/// credentials through a `credential_process` that takes 2s, longer than the
/// 1.5s primary cut, as a slow IAM Roles Anywhere helper on an on-premises host
/// might. Each run appends a line to the returned runs file.
async fn slow_credential_process_profile() -> (NamedTempFile, NamedTempFile) {
    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let test_credentials = sdk_config
        .credentials_provider()
        .expect("No credentials provider")
        .provide_credentials()
        .await
        .expect("Failed to resolve credentials");
    let process_output = serde_json::json!({
        "Version": 1,
        "AccessKeyId": test_credentials.access_key_id(),
        "SecretAccessKey": test_credentials.secret_access_key(),
        "SessionToken": test_credentials.session_token(),
    });
    let runs_file = NamedTempFile::new().unwrap();
    let content = format!(
        // `&&` rather than `;`, which the profile parser treats as a comment after a space.
        "[profile awcp-slow-process]\ncredential_process = echo run >> {} && sleep 2 && echo '{process_output}'\n",
        runs_file.path().display()
    );
    let mut aws_config_file = NamedTempFile::new().unwrap();
    aws_config_file.write_all(content.as_bytes()).unwrap();
    aws_config_file.flush().unwrap();
    (aws_config_file, runs_file)
}

/// The primary region is down: the secret is read from the failover region.
#[tokio::test]
async fn test_sm_failover_primary_region_down() {
    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(&SecretType::Basic);
    let real_region = real_region().await;
    let (provider, logs) = ProviderProcess::start_with_failover_config(
        2910,
        &format!("default_failover_region = \"{real_region}\""),
        &[("AWS_REGION", FAKE_REGION)],
    )
    .await;

    let query = ProviderQueryBuilder::default()
        .secret_id(&secret_name)
        .build()
        .unwrap();
    let response = provider.make_request(&query).await;
    let json: serde_json::Value = serde_json::from_str(&response).unwrap();

    assert_eq!(json["Name"], secret_name);
    assert!(json["SecretString"].as_str().unwrap().contains("testuser"));
    logs.assert_failed_over("GetSecretValue").await;
}

/// The cached value expires while the primary is down: the freshness check
/// (DescribeSecret) fails over and the cached value is served.
#[tokio::test]
async fn test_sm_failover_on_cache_refresh() {
    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(&SecretType::Basic);
    let real_region = real_region().await;
    let ttl_seconds = 2;
    let (provider, logs) = ProviderProcess::start_with_failover_config(
        2911,
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
        .build()
        .unwrap();
    let response1 = provider.make_request(&query).await;
    let json1: serde_json::Value = serde_json::from_str(&response1).unwrap();

    // Wait for the cache entry to expire
    tokio::time::sleep(std::time::Duration::from_secs(ttl_seconds + 1)).await;

    let response2 = provider.make_request(&query).await;
    let json2: serde_json::Value = serde_json::from_str(&response2).unwrap();

    assert_eq!(json2["VersionId"], json1["VersionId"]);
    logs.assert_failed_over("DescribeSecret").await;
    // The secret was current, so it wasn't fetched again
    logs.assert_failed_over("GetSecretValue").await;
}

/// `refreshNow=true` with a version stage skips the cache: the fetch fails over
/// again, with the version stage passed to the failover region.
#[tokio::test]
async fn test_sm_failover_refresh_now() {
    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(&SecretType::Basic);
    let real_region = real_region().await;
    let (provider, logs) = ProviderProcess::start_with_failover_config(
        2912,
        &format!("default_failover_region = \"{real_region}\""),
        &[("AWS_REGION", FAKE_REGION)],
    )
    .await;

    let query = ProviderQueryBuilder::default()
        .secret_id(&secret_name)
        .version_stage("AWSCURRENT")
        .build()
        .unwrap();
    let response1 = provider.make_request(&query).await;
    let json1: serde_json::Value = serde_json::from_str(&response1).unwrap();

    let refresh_query = ProviderQueryBuilder::default()
        .secret_id(&secret_name)
        .version_stage("AWSCURRENT")
        .refresh_now(true)
        .build()
        .unwrap();
    let response2 = provider.make_request(&refresh_query).await;
    let json2: serde_json::Value = serde_json::from_str(&response2).unwrap();

    assert_eq!(json2["VersionId"], json1["VersionId"]);
    assert!(json2["VersionStages"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("AWSCURRENT")));

    let lines = logs
        .wait_for_count("failover=true operation=GetSecretValue ", 2)
        .await;
    assert_eq!(
        lines.len(),
        2,
        "Expected two GetSecretValue failovers, got {lines:?}"
    );
    assert!(
        lines.iter().all(|l| l.contains("result=ok")),
        "Failover didn't succeed: {lines:?}"
    );
}

/// The `failoverRegion` query parameter sets the failover region, over the
/// config's `default_failover_region`, which points at a region without the secret.
#[tokio::test]
async fn test_sm_failover_query_parameter() {
    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(&SecretType::Basic);
    let real_region = real_region().await;
    let (provider, logs) = ProviderProcess::start_with_failover_config(
        2913,
        &format!("default_failover_region = \"{}\"", other_region().await),
        &[("AWS_REGION", FAKE_REGION)],
    )
    .await;

    let query = ProviderQueryBuilder::default()
        .secret_id(&secret_name)
        .failover_region(&real_region)
        .build()
        .unwrap();
    let response = provider.make_request(&query).await;
    let json: serde_json::Value = serde_json::from_str(&response).unwrap();

    assert_eq!(json["Name"], secret_name);
    logs.assert_failed_over("GetSecretValue").await;
}

/// A malformed `failoverRegion` query parameter is rejected before any AWS call.
#[tokio::test]
async fn test_sm_failover_invalid_query_parameter() {
    let (provider, _logs) = ProviderProcess::start_with_failover_config(2914, "", &[]).await;

    let query = ProviderQueryBuilder::default()
        .secret_id("any-secret")
        .failover_region("not.a.region")
        .build()
        .unwrap();
    let response = provider.make_request_raw(&query).await;
    assert_eq!(response.status(), 400);

    let body = response.text().await.expect("Failed to read response body");
    assert!(body.contains("invalid failoverRegion format"));
}

/// No default failover region: `secret_to_region_map`, keyed by the secret's
/// ARN, sets the failover region for a request by that ARN.
#[tokio::test]
async fn test_sm_failover_secret_to_region_map() {
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
    let (provider, logs) = ProviderProcess::start_with_failover_config(
        2915,
        &format!(
            "[capabilities.secrets_manager.failover.secret_to_region_map]\n\
             \"{secret_arn}\" = \"{real_region}\""
        ),
        &[("AWS_REGION", FAKE_REGION)],
    )
    .await;

    let query = ProviderQueryBuilder::default()
        .secret_id(&secret_arn)
        .build()
        .unwrap();
    let response = provider.make_request(&query).await;
    let json: serde_json::Value = serde_json::from_str(&response).unwrap();

    assert_eq!(json["Name"], secret_name);
    logs.assert_failed_over("GetSecretValue").await;

    // A secret that isn't in the map has no failover region
    let other_query = ProviderQueryBuilder::default()
        .secret_id("any-secret")
        .build()
        .unwrap();
    let other_response = provider.make_request_raw(&other_query).await;
    assert_eq!(other_response.status(), 502);
}

/// The primary region is down with no failover region: the request fails with
/// a connection error.
#[tokio::test]
async fn test_sm_failover_not_configured() {
    let (provider, logs) =
        ProviderProcess::start_with_failover_config(2916, "", &[("AWS_REGION", FAKE_REGION)]).await;

    let query = ProviderQueryBuilder::default()
        .secret_id("any-secret")
        .build()
        .unwrap();
    let response = provider.make_request_raw(&query).await;

    assert_eq!(response.status(), 502);
    assert!(logs.wait_for("failover=true").await.is_empty());
}

/// The primary and failover regions are both down: the failover is attempted
/// and fails.
#[tokio::test]
async fn test_sm_failover_all_down() {
    let (provider, logs) = ProviderProcess::start_with_failover_config(
        2917,
        // Room for the primary's retries, so its connection error isn't cut into a 504
        &format!(
            "default_failover_region = \"{FAKE_FAILOVER_REGION}\"\n\
             operation_timeout_ms = 10000"
        ),
        &[("AWS_REGION", FAKE_REGION)],
    )
    .await;

    let query = ProviderQueryBuilder::default()
        .secret_id("any-secret")
        .build()
        .unwrap();
    let response = provider.make_request_raw(&query).await;
    assert_eq!(response.status(), 502);
    logs.assert_failover_errored("GetSecretValue").await;
}

/// A secret that doesn't exist: not found isn't an outage, so no failover.
#[tokio::test]
async fn test_sm_failover_not_on_not_found() {
    let failover_region = other_region().await;
    let (provider, logs) = ProviderProcess::start_with_failover_config(
        2918,
        &format!("default_failover_region = \"{failover_region}\""),
        &[],
    )
    .await;

    let query = ProviderQueryBuilder::default()
        .secret_id("aws-workload-credentials-provider-test-does-not-exist")
        .build()
        .unwrap();
    let response = provider.make_request_raw(&query).await;

    // Should return 400 status for ResourceNotFoundException
    assert_eq!(response.status(), 400);
    assert!(logs.wait_for("failover=true").await.is_empty());
}

/// The provider's own credentials come from STS (a `role_arn` profile) and the
/// whole primary region is down: its own credentials, the startup credential
/// check and the secret request each fail over once.
#[tokio::test]
async fn test_sm_failover_own_credentials_from_sts() {
    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(&SecretType::Basic);
    let real_region = real_region().await;
    let role_arn = RoleChainingHelper::new()
        .await
        .get_role_arn(ROLE_CHAINING_ROLE_NAME)
        .await;
    let aws_config_file = own_credentials_profile(&role_arn).await;
    let config_content = format!(
        r#"
[logging]
log_level = "info"
log_to_file = false

[capabilities.secrets_manager]
http_port = 2920
validate_credentials = true

[capabilities.secrets_manager.failover]
default_failover_region = "{real_region}"
"#
    );
    let (provider, logs) = ProviderProcess::start_provider_with_captured_logs(
        2920,
        &config_content,
        &[
            ("AWS_REGION", FAKE_REGION),
            ("AWS_CONFIG_FILE", aws_config_file.path().to_str().unwrap()),
            ("AWS_PROFILE", "awcp-own-role"),
            // Blank, so the default chain skips any environment credentials and
            // uses the profile.
            ("AWS_ACCESS_KEY_ID", ""),
            ("AWS_SECRET_ACCESS_KEY", ""),
            ("AWS_SESSION_TOKEN", ""),
        ],
    )
    .await;

    let query = ProviderQueryBuilder::default()
        .secret_id(&secret_name)
        .build()
        .unwrap();
    let response = provider.make_request(&query).await;
    let json: serde_json::Value = serde_json::from_str(&response).unwrap();

    assert_eq!(json["Name"], secret_name);
    logs.assert_failed_over("OwnCredentials").await;
    logs.assert_failed_over("GetCallerIdentity").await;
    logs.assert_failed_over("GetSecretValue").await;
}

/// The provider's own credentials come from a slow but healthy
/// `credential_process`, which doesn't call STS, with a failover region set and
/// the primary region up: they aren't cut off at the primary timeout or loaded
/// again in the failover region, so nothing fails over and the process runs once.
#[tokio::test]
async fn test_sm_failover_slow_credential_process_not_failed_over() {
    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(&SecretType::Basic);
    let failover_region = other_region().await;
    let (aws_config_file, runs_file) = slow_credential_process_profile().await;
    let config_content = format!(
        r#"
[logging]
log_level = "info"
log_to_file = false

[capabilities.secrets_manager]
http_port = 2921
validate_credentials = true

[capabilities.secrets_manager.failover]
default_failover_region = "{failover_region}"
"#
    );
    let (provider, logs) = ProviderProcess::start_provider_with_captured_logs(
        2921,
        &config_content,
        &[
            ("AWS_CONFIG_FILE", aws_config_file.path().to_str().unwrap()),
            ("AWS_PROFILE", "awcp-slow-process"),
            // Blank, so the default chain skips any environment credentials and
            // uses the profile.
            ("AWS_ACCESS_KEY_ID", ""),
            ("AWS_SECRET_ACCESS_KEY", ""),
            ("AWS_SESSION_TOKEN", ""),
        ],
    )
    .await;

    let query = ProviderQueryBuilder::default()
        .secret_id(&secret_name)
        .build()
        .unwrap();
    let response = provider.make_request(&query).await;
    let json: serde_json::Value = serde_json::from_str(&response).unwrap();

    assert_eq!(json["Name"], secret_name);
    assert!(logs.wait_for("failover=true").await.is_empty());
    let runs = std::fs::read_to_string(runs_file.path()).unwrap();
    assert_eq!(runs.lines().count(), 1, "credential_process runs: {runs:?}");
}

/// `refreshNow=true` while both regions are down: the cache is skipped, so the
/// primary's connection error is returned even though a value is cached.
#[tokio::test]
async fn test_sm_failover_all_down_refresh_now() {
    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(&SecretType::Basic);
    let real_region = real_region().await;
    let (provider, logs) = ProviderProcess::start_with_failover_config(
        2922,
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
        .build()
        .unwrap();
    let response1 = provider.make_request(&query).await;
    let json1: serde_json::Value = serde_json::from_str(&response1).unwrap();

    // The `failoverRegion` query parameter points the failover at a region that's down too
    let refresh_query = ProviderQueryBuilder::default()
        .secret_id(&secret_name)
        .refresh_now(true)
        .failover_region(FAKE_FAILOVER_REGION)
        .build()
        .unwrap();
    let response2 = provider.make_request_raw(&refresh_query).await;
    assert_eq!(response2.status(), 502);

    // Without refreshNow the cached value is still served
    let cached_query = ProviderQueryBuilder::default()
        .secret_id(&secret_name)
        .failover_region(FAKE_FAILOVER_REGION)
        .build()
        .unwrap();
    let response3 = provider.make_request(&cached_query).await;
    let json3: serde_json::Value = serde_json::from_str(&response3).unwrap();
    assert_eq!(json3["VersionId"], json1["VersionId"]);

    // A duplicate failover line can arrive after the response; wait before counting.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let lines = logs
        .wait_for_count("failover=true operation=GetSecretValue ", 2)
        .await;
    assert_eq!(
        lines.len(),
        2,
        "Expected two GetSecretValue failover lines, got {lines:?}"
    );
    assert!(
        lines[1].contains(&format!(
            "failover_region={FAKE_FAILOVER_REGION} result=error"
        )),
        "The refresh's failover didn't fail: {}",
        lines[1]
    );
}

/// The agent starts with prefetch while the primary region is down: prefetch
/// doesn't fail over, so the first request fetches the secret through failover.
#[tokio::test]
async fn test_sm_failover_prefetch_primary_region_down() {
    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(&SecretType::Basic);
    let real_region = real_region().await;
    let (provider, logs) = ProviderProcess::start_with_failover_config(
        2923,
        &format!(
            "default_failover_region = \"{real_region}\"\n\
             [[capabilities.secrets_manager.prefetch.secrets]]\n\
             secret_id = \"{secret_name}\""
        ),
        &[("AWS_REGION", FAKE_REGION)],
    )
    .await;

    // Prefetch's BatchGetSecretValue retries in the down region for up to about 3s
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    assert!(
        !logs
            .wait_for("Pre-fetch: BatchGetSecretValue failed with a transient error")
            .await
            .is_empty(),
        "Expected prefetch to fail in the primary region"
    );

    let query = ProviderQueryBuilder::default()
        .secret_id(&secret_name)
        .build()
        .unwrap();
    let response = provider.make_request(&query).await;
    let json: serde_json::Value = serde_json::from_str(&response).unwrap();

    assert_eq!(json["Name"], secret_name);
    logs.assert_failed_over("GetSecretValue").await;
}
