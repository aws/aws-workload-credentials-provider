use crate::cache_manager::CacheManager;
use aws_sdk_secretsmanager::types::{Filter, FilterNameStringType};
use aws_workload_credentials_provider_common::config::types::{
    SecretPrefetchConfig, SecretsManagerConfig, TagFilter,
};
use log::{debug, error, info, warn};
use rand::RngExt;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

/// Maximum number of secrets per BatchGetSecretValue call.
const BATCH_SIZE: usize = 20;

/// Rate limiting delay between batch calls (~30 TPS).
const BATCH_DELAY_MS: u64 = 34;

/// Format role ARN for log messages. Shows "default credentials" for None.
fn role_display(role_arn: Option<&str>) -> &str {
    role_arn.unwrap_or("default credentials")
}

/// Tracks success and failure counts across the prefetch operation.
#[derive(Debug, Default)]
struct PrefetchStats {
    success: usize,
    failed: usize,
}

/// Spawn the prefetch background task.
///
/// Adds random jitter (0 to max_jitter_seconds) to prevent fleet-wide synchronized
/// API calls, then runs the prefetch logic. Default jitter is 0 (no delay).
///
/// # Arguments
///
/// * `cache_manager` - Shared reference to the cache manager (same instance the server uses).
/// * `config` - Provider configuration containing prefetch settings and cache size.
pub fn start_prefetch_task(cache_manager: Arc<CacheManager>, config: SecretsManagerConfig) {
    tokio::spawn(async move {
        let max_jitter = config.prefetch.max_jitter_seconds;
        if max_jitter > 0 {
            let jitter = rand::rng().random_range(0.0..max_jitter as f64);
            sleep(Duration::from_secs_f64(jitter)).await;
        }

        let mut stats = PrefetchStats::default();
        run_prefetch(&cache_manager, &config, &mut stats).await;

        info!(
            "Pre-fetch complete: success={}, failed={}",
            stats.success, stats.failed
        );
    });
}

/// Run the prefetch logic: resolve secrets from config, group by role, and fetch.
///
/// Two independent paths are executed:
/// 1. Explicit secrets from `prefetch.secrets` — fetched via BatchGetSecretValue with SecretIdList.
/// 2. Tag-based secrets from `prefetch.filter_tags` — fetched via BatchGetSecretValue with Filters.
///
/// # Arguments
///
/// * `cm` - The cache manager providing per-role caching clients.
/// * `config` - Provider configuration with prefetch settings and cache size.
/// * `stats` - Mutable stats tracker updated throughout the operation.
async fn run_prefetch(cm: &CacheManager, config: &SecretsManagerConfig, stats: &mut PrefetchStats) {
    let cache_size: usize = config.cache.cache_size.get();
    let warmup_limit = ((cache_size as f32 * config.prefetch.cache_buffer_ratio) as usize).max(1);
    let prefetch = &config.prefetch;

    // Track remaining capacity per role across both paths to prevent
    // exceeding cache_buffer_ratio when the same role appears in both
    // prefetch.secrets and prefetch.filter_tags.
    let mut remaining_by_role: HashMap<Option<String>, usize> = HashMap::new();

    // Path 1: Explicit secrets grouped by role_arn
    if !prefetch.secrets.is_empty() {
        let grouped = group_secrets_by_role(&prefetch.secrets);
        for (role_arn, secret_ids) in &grouped {
            let remaining = remaining_by_role
                .entry(role_arn.clone())
                .or_insert(warmup_limit);
            fetch_secret_id_group(cm, role_arn.as_deref(), secret_ids, remaining, stats).await;
        }
    }

    // Path 2: Tag-based filtering grouped by role_arn
    if !prefetch.filter_tags.is_empty() {
        let grouped = group_tags_by_role(&prefetch.filter_tags);
        for (role_arn, keys) in &grouped {
            let remaining = remaining_by_role
                .entry(role_arn.clone())
                .or_insert(warmup_limit);
            if *remaining == 0 {
                continue;
            }
            fetch_tag_group(cm, role_arn.as_deref(), keys, remaining, stats).await;
        }
    }
}

/// Group explicit secrets by role_arn for batching.
///
/// Secrets without a role_arn are grouped under `None` (default credentials).
/// Secrets sharing the same role_arn are batched together so they use the
/// same caching client.
///
/// # Arguments
///
/// * `secrets` - The list of secret configurations from the prefetch config.
///
/// # Returns
///
/// * `HashMap<Option<String>, Vec<String>>` - Secret IDs grouped by role ARN.
fn group_secrets_by_role(secrets: &[SecretPrefetchConfig]) -> HashMap<Option<String>, Vec<String>> {
    let mut grouped: HashMap<Option<String>, Vec<String>> = HashMap::new();
    for s in secrets {
        grouped
            .entry(s.role_arn.clone())
            .or_default()
            .push(s.secret_id.clone());
    }
    grouped
}

/// Group tag filters by role_arn for batching.
///
/// Tags without a role_arn are grouped under `None` (default credentials).
/// Tags sharing the same role_arn are combined into a single
/// BatchGetSecretValue call with multiple Filters.
///
/// # Arguments
///
/// * `tags` - The list of tag filter configurations from the prefetch config.
///
/// # Returns
///
/// * `HashMap<Option<String>, Vec<String>>` - Tag keys grouped by role ARN.
fn group_tags_by_role(tags: &[TagFilter]) -> HashMap<Option<String>, Vec<String>> {
    let mut grouped: HashMap<Option<String>, Vec<String>> = HashMap::new();
    for t in tags {
        grouped
            .entry(t.role_arn.clone())
            .or_default()
            .push(t.key.clone());
    }
    grouped
}

/// Fetch explicit secrets using BatchGetSecretValue with SecretIdList.
///
/// Obtains the appropriate caching client for the role (or default), chunks
/// the secret IDs into batches of 20, and calls BatchGetSecretValue for each
/// chunk. Respects the warmup_limit to avoid filling the cache beyond the
/// configured buffer ratio.
///
/// # Arguments
///
/// * `cm` - The cache manager providing per-role caching clients.
/// * `role_arn` - Optional IAM role ARN. `None` uses default credentials.
/// * `secret_ids` - The secret IDs to fetch.
/// * `remaining` - Mutable remaining capacity for this role group (shared across paths).
/// * `stats` - Mutable stats tracker.
async fn fetch_secret_id_group(
    cm: &CacheManager,
    role_arn: Option<&str>,
    secret_ids: &[String],
    remaining: &mut usize,
    stats: &mut PrefetchStats,
) {
    let client = match cm.get_client(role_arn).await {
        Ok(c) => c,
        Err(e) => {
            error!(
                "Pre-fetch: failed to get client for {}: {}",
                role_display(role_arn),
                e.1
            );
            stats.failed += secret_ids.len();
            return;
        }
    };

    let total = secret_ids.len();
    let mut processed = 0;

    for chunk in secret_ids.chunks(BATCH_SIZE) {
        if *remaining == 0 {
            warn!(
                "Pre-fetch: cache buffer limit reached for {}, {} secret(s) not fetched",
                role_display(role_arn),
                total - processed
            );
            break;
        }

        let truncated = chunk.len() > *remaining;
        let batch_size = chunk.len().min(*remaining);
        if truncated {
            warn!(
                "Pre-fetch: cache buffer limit reached for {}, {} secret(s) not fetched",
                role_display(role_arn),
                total - processed - batch_size
            );
        }
        let batch: Vec<String> = chunk[..batch_size].to_vec();
        let batch_len = batch.len();

        match client
            .batch_get_secret_value(Some(batch), None, None, None)
            .await
        {
            Ok(Some(resp)) => {
                let fetched = resp.secret_values().len();
                stats.success += fetched;
                stats.failed += resp.errors().len();
                *remaining = remaining.saturating_sub(fetched);
                for err in resp.errors() {
                    debug!(
                        "Pre-fetch: failed to fetch {}: {}",
                        err.secret_id().unwrap_or("unknown"),
                        err.error_code().unwrap_or("unknown")
                    );
                }
            }
            Ok(None) => {
                stats.failed += batch_len;
            }
            Err(e) => {
                error!("Pre-fetch: BatchGetSecretValue failed: {}", e);
                stats.failed += batch_len;
            }
        }

        processed += batch_len;

        if truncated {
            break;
        }

        if *remaining > 0 {
            sleep(Duration::from_millis(BATCH_DELAY_MS)).await;
        }
    }
}

/// Fetch tag-based secrets using BatchGetSecretValue with Filters.
///
/// Obtains the appropriate caching client for the role (or default), builds
/// tag key filters, and calls BatchGetSecretValue with pagination. Each page
/// discovers and caches secrets matching the tag keys. Respects the
/// warmup_limit to avoid filling the cache beyond the configured buffer ratio.
///
/// # Arguments
///
/// * `cm` - The cache manager providing per-role caching clients.
/// * `role_arn` - Optional IAM role ARN. `None` uses default credentials.
/// * `keys` - The tag keys to filter by.
/// * `remaining` - Mutable remaining capacity for this role group (shared across paths).
/// * `stats` - Mutable stats tracker.
async fn fetch_tag_group(
    cm: &CacheManager,
    role_arn: Option<&str>,
    keys: &[String],
    remaining: &mut usize,
    stats: &mut PrefetchStats,
) {
    let client = match cm.get_client(role_arn).await {
        Ok(c) => c,
        Err(e) => {
            error!(
                "Pre-fetch: failed to get client for {}: {}",
                role_display(role_arn),
                e.1
            );
            return;
        }
    };

    let filters: Vec<Filter> = keys
        .iter()
        .map(|k| {
            Filter::builder()
                .key(FilterNameStringType::TagKey)
                .values(k)
                .build()
        })
        .collect();

    let mut next_token: Option<String> = None;

    loop {
        if *remaining == 0 {
            warn!(
                "Pre-fetch: cache buffer limit reached for {}",
                role_display(role_arn)
            );
            break;
        }

        let max_results = (*remaining as i32).min(BATCH_SIZE as i32);

        match client
            .batch_get_secret_value(None, Some(filters.clone()), Some(max_results), next_token)
            .await
        {
            Ok(Some(resp)) => {
                let fetched = resp.secret_values().len();
                stats.success += fetched;
                stats.failed += resp.errors().len();
                *remaining = remaining.saturating_sub(fetched);

                for err in resp.errors() {
                    debug!(
                        "Pre-fetch: failed to fetch {}: {}",
                        err.secret_id().unwrap_or("unknown"),
                        err.error_code().unwrap_or("unknown")
                    );
                }

                if fetched == 0 && resp.errors().is_empty() {
                    warn!("Pre-fetch: no secrets found for tag filters {:?}", keys);
                }

                next_token = resp.next_token().map(String::from);
            }
            Ok(None) => break,
            Err(e) => {
                error!("Pre-fetch: BatchGetSecretValue with filters failed: {}", e);
                break;
            }
        }

        if next_token.is_none() {
            break;
        }
        sleep(Duration::from_millis(BATCH_DELAY_MS)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_workload_credentials_provider_common::config::types::PrefetchConfig;

    async fn test_cache_manager(config: &SecretsManagerConfig) -> Arc<CacheManager> {
        Arc::new(
            CacheManager::new(config)
                .await
                .expect("cache manager failed"),
        )
    }

    #[test]
    fn test_group_secrets_no_roles() {
        let secrets = vec![
            SecretPrefetchConfig {
                secret_id: "s1".into(),
                role_arn: None,
            },
            SecretPrefetchConfig {
                secret_id: "s2".into(),
                role_arn: None,
            },
        ];
        let grouped = group_secrets_by_role(&secrets);
        assert_eq!(grouped.len(), 1);
        assert_eq!(grouped[&None].len(), 2);
    }

    #[test]
    fn test_group_secrets_mixed_roles() {
        let secrets = vec![
            SecretPrefetchConfig {
                secret_id: "s1".into(),
                role_arn: None,
            },
            SecretPrefetchConfig {
                secret_id: "s2".into(),
                role_arn: Some("arn:aws:iam::111:role/A".into()),
            },
            SecretPrefetchConfig {
                secret_id: "s3".into(),
                role_arn: Some("arn:aws:iam::111:role/A".into()),
            },
            SecretPrefetchConfig {
                secret_id: "s4".into(),
                role_arn: Some("arn:aws:iam::222:role/B".into()),
            },
        ];
        let grouped = group_secrets_by_role(&secrets);
        assert_eq!(grouped.len(), 3);
        assert_eq!(grouped[&None].len(), 1);
        assert_eq!(grouped[&Some("arn:aws:iam::111:role/A".into())].len(), 2);
        assert_eq!(grouped[&Some("arn:aws:iam::222:role/B".into())].len(), 1);
    }

    #[test]
    fn test_group_tags_no_roles() {
        let tags = vec![
            TagFilter {
                key: "Env".into(),
                role_arn: None,
            },
            TagFilter {
                key: "Team".into(),
                role_arn: None,
            },
        ];
        let grouped = group_tags_by_role(&tags);
        assert_eq!(grouped.len(), 1);
        assert_eq!(grouped[&None].len(), 2);
    }

    #[test]
    fn test_group_tags_mixed_roles() {
        let tags = vec![
            TagFilter {
                key: "Env".into(),
                role_arn: None,
            },
            TagFilter {
                key: "Team".into(),
                role_arn: Some("arn:aws:iam::111:role/A".into()),
            },
            TagFilter {
                key: "App".into(),
                role_arn: Some("arn:aws:iam::111:role/A".into()),
            },
        ];
        let grouped = group_tags_by_role(&tags);
        assert_eq!(grouped.len(), 2);
        assert_eq!(grouped[&None].len(), 1);
        assert_eq!(grouped[&Some("arn:aws:iam::111:role/A".into())].len(), 2);
    }

    // Verify prefetch with explicit secrets populates the cache.
    #[tokio::test]
    async fn test_fetch_secret_id_group_success() {
        let config = SecretsManagerConfig::default();
        let cache_manager = test_cache_manager(&config).await;
        let mut stats = PrefetchStats::default();

        fetch_secret_id_group(
            &cache_manager,
            None,
            &["MyTest".to_string()],
            &mut 100,
            &mut stats,
        )
        .await;

        assert_eq!(stats.success, 1);
        assert_eq!(stats.failed, 0);

        // Verify the secret is actually in the cache (not a fetch-on-miss)
        let client = cache_manager.get_client(None).await.unwrap();
        assert!(client.cache_contains("MyTest").await);
    }

    // Verify prefetch with a role_arn creates a role client and caches the secret.
    #[tokio::test]
    async fn test_fetch_secret_id_group_with_role() {
        let config = SecretsManagerConfig::default();
        let cache_manager = test_cache_manager(&config).await;
        let mut stats = PrefetchStats::default();
        let role = "arn:aws:iam::123456789012:role/TestRole";

        fetch_secret_id_group(
            &cache_manager,
            Some(role),
            &["MyTest".to_string()],
            &mut 100,
            &mut stats,
        )
        .await;

        assert_eq!(stats.success, 1);
        assert_eq!(stats.failed, 0);

        // Verify the secret is in the role client's cache
        let client = cache_manager.get_client(Some(role)).await.unwrap();
        assert!(client.cache_contains("MyTest").await);
    }

    // Verify prefetch stops when warmup_limit is zero.
    #[tokio::test]
    async fn test_fetch_secret_id_group_buffer_limit() {
        let config = SecretsManagerConfig::default();
        let cache_manager = test_cache_manager(&config).await;
        let mut stats = PrefetchStats::default();

        fetch_secret_id_group(
            &cache_manager,
            None,
            &["MyTest".to_string(), "MyTest2".to_string()],
            &mut 0,
            &mut stats,
        )
        .await;

        assert_eq!(stats.success, 0);
    }

    // Verify run_prefetch orchestrates correctly with a secrets config.
    #[tokio::test]
    async fn test_run_prefetch_with_secrets() {
        let config = SecretsManagerConfig {
            prefetch: PrefetchConfig {
                secrets: vec![SecretPrefetchConfig {
                    secret_id: "MyTest".into(),
                    role_arn: None,
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        let cache_manager = test_cache_manager(&config).await;
        let mut stats = PrefetchStats::default();

        run_prefetch(&cache_manager, &config, &mut stats).await;

        assert_eq!(stats.success, 1);
        assert_eq!(stats.failed, 0);
    }

    // Verify run_prefetch is a no-op with empty config.
    #[tokio::test]
    async fn test_run_prefetch_empty_config() {
        let config = SecretsManagerConfig::default();
        let cache_manager = test_cache_manager(&config).await;
        let mut stats = PrefetchStats::default();

        run_prefetch(&cache_manager, &config, &mut stats).await;

        assert_eq!(stats.success, 0);
        assert_eq!(stats.failed, 0);
    }

    // Verify API-level batch error is handled gracefully.
    #[tokio::test]
    async fn test_fetch_secret_id_group_api_error() {
        let config = SecretsManagerConfig::default();
        let cache_manager = test_cache_manager(&config).await;
        let mut stats = PrefetchStats::default();

        fetch_secret_id_group(
            &cache_manager,
            None,
            &["BATCHAPIERROR_secret".to_string()],
            &mut 100,
            &mut stats,
        )
        .await;

        assert_eq!(stats.success, 0);
        assert_eq!(stats.failed, 1);
    }

    // Verify partial batch failure: some secrets succeed, some fail.
    #[tokio::test]
    async fn test_fetch_secret_id_group_partial_failure() {
        let config = SecretsManagerConfig::default();
        let cache_manager = test_cache_manager(&config).await;
        let mut stats = PrefetchStats::default();

        fetch_secret_id_group(
            &cache_manager,
            None,
            &["NOTFOUNDsecret".to_string(), "ValidSecret".to_string()],
            &mut 100,
            &mut stats,
        )
        .await;

        assert_eq!(stats.success, 1);
        assert_eq!(stats.failed, 1);
    }

    // Verify tag-based prefetch discovers and caches secrets.
    #[tokio::test]
    async fn test_fetch_tag_group_success() {
        let config = SecretsManagerConfig::default();
        let cache_manager = test_cache_manager(&config).await;
        let mut stats = PrefetchStats::default();

        fetch_tag_group(
            &cache_manager,
            None,
            &["Environment".to_string()],
            &mut 100,
            &mut stats,
        )
        .await;

        assert_eq!(stats.success, 1);
        assert_eq!(stats.failed, 0);

        // Verify the tagged secret is in the cache
        let client = cache_manager.get_client(None).await.unwrap();
        assert!(client.cache_contains("TaggedSecret").await);
    }

    // Verify total = success + failed when get_client() fails (max_roles exceeded).
    #[tokio::test]
    async fn test_fetch_secret_id_group_client_failure_counts_total() {
        let config = SecretsManagerConfig {
            max_roles: 2,
            ..Default::default()
        };
        let cache_manager = test_cache_manager(&config).await;
        let mut stats = PrefetchStats::default();

        // Fill both role slots
        fetch_secret_id_group(
            &cache_manager,
            Some("arn:aws:iam::111111111111:role/Role1"),
            &["MyTest".to_string()],
            &mut 100,
            &mut stats,
        )
        .await;
        fetch_secret_id_group(
            &cache_manager,
            Some("arn:aws:iam::222222222222:role/Role2"),
            &["MyTest".to_string()],
            &mut 100,
            &mut stats,
        )
        .await;

        // Third role exceeds max_roles — get_client() returns Err
        let mut stats3 = PrefetchStats::default();
        fetch_secret_id_group(
            &cache_manager,
            Some("arn:aws:iam::333333333333:role/Role3"),
            &["MyTest".to_string(), "MyTest2".to_string()],
            &mut 100,
            &mut stats3,
        )
        .await;

        // Both secrets should be counted in total and failed
        assert_eq!(stats3.failed, 2);
        assert_eq!(stats3.success, 0);
    }

    // Verify tag-based prefetch respects buffer limit.
    #[tokio::test]
    async fn test_fetch_tag_group_buffer_limit() {
        let config = SecretsManagerConfig::default();
        let cache_manager = test_cache_manager(&config).await;
        let mut stats = PrefetchStats::default();

        fetch_tag_group(
            &cache_manager,
            None,
            &["Env".to_string()],
            &mut 0,
            &mut stats,
        )
        .await;

        assert_eq!(stats.success, 0);
    }
}
