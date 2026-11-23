// #![warn(missing_docs)]
#![warn(
    missing_debug_implementations,
    missing_docs,
    rustdoc::missing_crate_level_docs
)]

//! AWS Secrets Manager Caching Library

/// Error types
pub mod error;
/// Output of secret store
pub mod output;
/// Manages the lifecycle of cached secrets
pub mod secret_store;
mod utils;

use aws_config::BehaviorVersion;
use aws_sdk_secretsmanager::config::{retry::RetryPartition, Builder as ConfigBuilder, Region};
use aws_sdk_secretsmanager::operation::batch_get_secret_value::BatchGetSecretValueOutput;
use aws_sdk_secretsmanager::types::Filter;
use aws_sdk_secretsmanager::Client as SecretsManagerClient;
use aws_smithy_types::timeout::TimeoutConfig;
use error::is_transient_error;
#[cfg(debug_assertions)]
use log::{info, warn};
use output::{BlobDef, GetSecretValueOutputDef};
use secret_store::{MemoryStore, SecretStore, SecretStoreError};
#[cfg(debug_assertions)]
use std::sync::atomic::{AtomicU32, Ordering};
use std::{error::Error, fmt::Display, num::NonZeroUsize, time::Duration};
use tokio::sync::RwLock;
use utils::{error_chain, retarget_arn, CachingLibraryInterceptor};

/// AWS Secrets Manager Caching client
#[derive(Debug)]
pub struct SecretsManagerCachingClient {
    /// Secrets Manager client to retrieve secrets.
    asm_client: SecretsManagerClient,
    /// A store used to cache secrets.
    store: RwLock<Box<dyn SecretStore>>,
    ignore_transient_errors: bool,
    /// Bound on each primary-region call that has a failover region, retries
    /// included, so a hanging primary fails over in time. `None` leaves primary
    /// calls unbounded.
    primary_timeout: Option<Duration>,
    #[cfg(debug_assertions)]
    metrics: CacheMetrics,
}

#[derive(Debug)]
#[cfg(debug_assertions)]
struct CacheMetrics {
    hits: AtomicU32,
    misses: AtomicU32,
    refreshes: AtomicU32,
}

impl SecretsManagerCachingClient {
    /// Create a new caching client with in-memory store
    ///
    /// # Arguments
    ///
    /// * `asm_client` - Initialized AWS SDK Secrets Manager client instance
    /// * `max_size` - Maximum size of the store.
    /// * `ttl` - Time-to-live of the secrets in the store.
    /// * `ignore_transient_errors` - Whether the client should serve cached data on transient refresh errors
    /// ```rust
    /// use aws_sdk_secretsmanager::Client as SecretsManagerClient;
    /// use aws_sdk_secretsmanager::{config::Region, Config};
    /// use aws_secretsmanager_caching::SecretsManagerCachingClient;
    /// use std::num::NonZeroUsize;
    /// use std::time::Duration;
    ///
    /// let asm_client = SecretsManagerClient::from_conf(
    /// Config::builder()
    ///     .behavior_version_latest()
    ///     .build(),
    /// );
    /// let client = SecretsManagerCachingClient::new(
    ///     asm_client,
    ///     NonZeroUsize::new(1000).unwrap(),
    ///     Duration::from_secs(300),
    ///     false,
    /// );
    /// ```
    pub fn new(
        asm_client: SecretsManagerClient,
        max_size: NonZeroUsize,
        ttl: Duration,
        ignore_transient_errors: bool,
    ) -> Result<Self, SecretStoreError> {
        Ok(Self {
            asm_client,
            store: RwLock::new(Box::new(MemoryStore::new(max_size, ttl))),
            ignore_transient_errors,
            primary_timeout: None,
            #[cfg(debug_assertions)]
            metrics: CacheMetrics {
                hits: AtomicU32::new(0),
                misses: AtomicU32::new(0),
                refreshes: AtomicU32::new(0),
            },
        })
    }

    /// Create a new caching client with in-memory store and the default AWS SDK client configuration
    ///
    /// # Arguments
    ///
    /// * `max_size` - Maximum size of the store.
    /// * `ttl` - Time-to-live of the secrets in the store.
    /// ```rust
    /// tokio_test::block_on(async {
    /// use aws_secretsmanager_caching::SecretsManagerCachingClient;
    /// use std::num::NonZeroUsize;
    /// use std::time::Duration;
    ///
    /// let client = SecretsManagerCachingClient::default(
    /// NonZeroUsize::new(1000).unwrap(),
    /// Duration::from_secs(300),
    /// ).await.unwrap();
    /// })
    /// ```
    pub async fn default(max_size: NonZeroUsize, ttl: Duration) -> Result<Self, SecretStoreError> {
        let default_config = &aws_config::load_defaults(BehaviorVersion::latest()).await;
        let asm_builder = aws_sdk_secretsmanager::config::Builder::from(default_config)
            .interceptor(CachingLibraryInterceptor);

        let asm_client = SecretsManagerClient::from_conf(asm_builder.build());
        Self::new(asm_client, max_size, ttl, false)
    }

    /// Create a new caching client with in-memory store from an AWS SDK client builder
    ///
    /// # Arguments
    ///
    /// * `asm_builder` - AWS Secrets Manager SDK client builder.
    /// * `max_size` - Maximum size of the store.
    /// * `ttl` - Time-to-live of the secrets in the store.
    ///
    /// ```rust
    /// tokio_test::block_on(async {
    /// use aws_secretsmanager_caching::SecretsManagerCachingClient;
    /// use std::num::NonZeroUsize;
    /// use std::time::Duration;
    /// use aws_config::{BehaviorVersion, Region};
    ///
    /// let config = aws_config::load_defaults(BehaviorVersion::latest())
    /// .await
    /// .into_builder()
    /// .region(Region::from_static("us-west-2"))
    /// .build();
    ///
    /// let asm_builder = aws_sdk_secretsmanager::config::Builder::from(&config);
    ///
    /// let client = SecretsManagerCachingClient::from_builder(
    /// asm_builder,
    /// NonZeroUsize::new(1000).unwrap(),
    /// Duration::from_secs(300),
    /// false,
    /// )
    /// .await.unwrap();
    /// })
    /// ```
    pub async fn from_builder(
        asm_builder: aws_sdk_secretsmanager::config::Builder,
        max_size: NonZeroUsize,
        ttl: Duration,
        ignore_transient_errors: bool,
    ) -> Result<Self, SecretStoreError> {
        let asm_client = SecretsManagerClient::from_conf(
            asm_builder.interceptor(CachingLibraryInterceptor).build(),
        );
        Self::new(asm_client, max_size, ttl, ignore_transient_errors)
    }

    /// Set the primary timeout (`operation_timeout_ms`). Failover calls aren't bounded by it.
    pub fn with_primary_timeout(mut self, timeout: Duration) -> Self {
        self.primary_timeout = Some(timeout);
        self
    }

    /// Retrieves the value of the secret from the specified version.
    ///
    /// # Arguments
    ///
    /// * `secret_id` - The ARN or name of the secret to retrieve.
    /// * `version_id` - The version id of the secret version to retrieve.
    /// * `version_stage` - The staging label of the version of the secret to retrieve.
    /// * `refresh_now` - Whether to serve from the cache or fetch from ASM.
    /// * `failover_region` - Region to repeat a call in when the primary region fails
    ///   with a transient error. Ignored when it is the client's own region.
    pub async fn get_secret_value(
        &self,
        secret_id: &str,
        version_id: Option<&str>,
        version_stage: Option<&str>,
        refresh_now: bool,
        failover_region: Option<&str>,
    ) -> Result<GetSecretValueOutputDef, Box<dyn Error>> {
        // Failing over to the primary itself would only repeat the failed call.
        let primary_region = self.asm_client.config().region().map(|r| r.as_ref());
        let failover_region = failover_region.filter(|r| Some(*r) != primary_region);

        if refresh_now {
            #[cfg(debug_assertions)]
            {
                self.increment_counter(&self.metrics.refreshes);

                let (hit_rate, miss_rate) = self.get_cache_rates();

                info!(
                    "METRICS: Bypassing cache. Refreshing secret '{}' immediately. \
                    Total hits: {}. Total misses: {}. Total refreshes: {}. Hit rate: {:.2}%. Miss rate: {:.2}%",
                    secret_id,
                    self.get_counter_value(&self.metrics.hits),
                    self.get_counter_value(&self.metrics.misses),
                    self.get_counter_value(&self.metrics.refreshes),
                    hit_rate,
                    miss_rate
                );
            }

            return self
                .refresh_secret_value(secret_id, version_id, version_stage, None, failover_region)
                .await;
        }

        let read_lock = self.store.read().await;

        match read_lock.get_secret_value(secret_id, version_id, version_stage) {
            Ok(r) => {
                #[cfg(debug_assertions)]
                {
                    self.increment_counter(&self.metrics.hits);

                    let (hit_rate, miss_rate) = self.get_cache_rates();

                    info!(
                        "METRICS: Cache HIT for secret '{}'. Total hits: {}. Total misses: {}. \
                        Hit rate: {:.2}%. Miss rate: {:.2}%.",
                        secret_id,
                        self.get_counter_value(&self.metrics.hits),
                        self.get_counter_value(&self.metrics.misses),
                        hit_rate,
                        miss_rate
                    );
                }

                Ok(r)
            }
            Err(SecretStoreError::ResourceNotFound) => {
                #[cfg(debug_assertions)]
                {
                    self.increment_counter(&self.metrics.misses);

                    let (hit_rate, miss_rate) = self.get_cache_rates();

                    info!(
                        "METRICS: Cache MISS for secret '{}'. Total hits: {}. Total misses: {}. \
                        Hit rate: {:.2}%. Miss rate: {:.2}%.",
                        secret_id,
                        self.get_counter_value(&self.metrics.hits),
                        self.get_counter_value(&self.metrics.misses),
                        hit_rate,
                        miss_rate
                    );
                }

                drop(read_lock);
                Ok(self
                    .refresh_secret_value(
                        secret_id,
                        version_id,
                        version_stage,
                        None,
                        failover_region,
                    )
                    .await?)
            }
            Err(SecretStoreError::CacheExpired(cached_value)) => {
                #[cfg(debug_assertions)]
                {
                    self.increment_counter(&self.metrics.misses);

                    let (hit_rate, miss_rate) = self.get_cache_rates();

                    info!(
                        "METRICS: Cache entry expired for secret '{}'. Total hits: {}. Total \
                        misses: {}. Total refreshes: {}. Hit rate: {:.2}%. Miss rate: {:.2}%.",
                        secret_id,
                        self.get_counter_value(&self.metrics.hits),
                        self.get_counter_value(&self.metrics.misses),
                        self.get_counter_value(&self.metrics.refreshes),
                        hit_rate,
                        miss_rate
                    );
                }

                drop(read_lock);
                Ok(self
                    .refresh_secret_value(
                        secret_id,
                        version_id,
                        version_stage,
                        Some(cached_value),
                        failover_region,
                    )
                    .await?)
            }
            Err(e) => Err(Box::new(e)),
        }
    }

    /// Batch fetch secrets from Secrets Manager and write them to the cache.
    ///
    /// Calls the BatchGetSecretValue API, converts successful results to
    /// `GetSecretValueOutputDef`, and writes them to the internal store under
    /// a single write lock. Per-secret errors are logged as warnings but do
    /// not stop the operation.
    ///
    /// # Arguments
    ///
    /// * `secret_id_list` - Secret ARNs or names to retrieve. Mutually exclusive with `filters`.
    /// * `filters` - Tag-based filters for discovery. Mutually exclusive with `secret_id_list`.
    /// * `max_results` - Maximum number of results per page (up to 20).
    /// * `next_token` - Pagination token from a previous call.
    ///
    /// # Returns
    ///
    /// * `Ok(Some(output))` - The raw SDK response for the caller to inspect (next_token, errors).
    /// * `Ok(None)` - A transient error was suppressed (when `ignore_transient_errors` is true).
    /// * `Err(...)` - A non-transient SDK error.
    pub async fn batch_get_secret_value(
        &self,
        secret_id_list: Option<Vec<String>>,
        filters: Option<Vec<Filter>>,
        max_results: Option<i32>,
        next_token: Option<String>,
    ) -> Result<Option<BatchGetSecretValueOutput>, Box<dyn Error>> {
        let response = match self
            .asm_client
            .batch_get_secret_value()
            .set_secret_id_list(secret_id_list)
            .set_filters(filters)
            .set_max_results(max_results)
            .set_next_token(next_token)
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(e) if self.ignore_transient_errors && is_transient_error(&e) => {
                return Ok(None);
            }
            Err(e) => return Err(Box::new(e)),
        };

        // Convert SecretValueEntry → GetSecretValueOutputDef
        let mut to_cache: Vec<(String, GetSecretValueOutputDef)> = Vec::new();
        for entry in response.secret_values() {
            if let Some(name) = entry.name() {
                to_cache.push((
                    name.to_owned(),
                    GetSecretValueOutputDef {
                        arn: entry.arn().map(String::from),
                        name: Some(name.to_owned()),
                        version_id: entry.version_id().map(String::from),
                        secret_string: entry.secret_string().map(String::from),
                        secret_binary: entry
                            .secret_binary()
                            .map(|b| BlobDef::new(b.clone().into_inner())),
                        version_stages: Some(entry.version_stages().to_vec()),
                        created_date: entry
                            .created_date()
                            .copied()
                            .and_then(|dt| std::time::SystemTime::try_from(dt).ok()),
                    },
                ));
            }
        }

        // Log per-secret errors
        #[cfg(debug_assertions)]
        {
            for err in response.errors() {
                warn!(
                    "BatchGetSecretValue failed for {}: {}",
                    err.secret_id().unwrap_or("unknown"),
                    err.error_code().unwrap_or("unknown")
                );
            }
        }

        // Write all secrets under a single lock acquisition
        let mut store = self.store.write().await;
        for (name, secret) in to_cache {
            store.write_secret_value(name, None, None, secret)?;
        }
        drop(store);

        Ok(Some(response))
    }

    /// Refreshes the secret value through a GetSecretValue call to ASM
    ///
    /// # Arguments
    /// * `secret_id` - The ARN or name of the secret to retrieve.
    /// * `version_id` - The version id of the secret version to retrieve.
    /// * `version_stage` - The staging label of the version of the secret to retrieve.
    /// * `cached_value` - The value currently in the cache.
    /// * `failover_region` - Region to repeat a call in after a transient primary error.
    async fn refresh_secret_value(
        &self,
        secret_id: &str,
        version_id: Option<&str>,
        version_stage: Option<&str>,
        cached_value: Option<Box<GetSecretValueOutputDef>>,
        failover_region: Option<&str>,
    ) -> Result<GetSecretValueOutputDef, Box<dyn Error>> {
        if let Some(ref cached_value) = cached_value {
            // The cache already had a value in it, we can quick-refresh it if the value is still current.
            if self
                .is_current(
                    secret_id,
                    version_id,
                    version_stage,
                    cached_value.clone(),
                    failover_region,
                )
                .await?
            {
                // Re-up the entry freshness (TTL, cache rank) by writing the same data back to the cache.
                self.store.write().await.write_secret_value(
                    secret_id.to_owned(),
                    version_id.map(String::from),
                    version_stage.map(String::from),
                    *cached_value.clone(),
                )?;
                // Serve the cached value
                return Ok(*cached_value.clone());
            }
        }

        let request = self
            .asm_client
            .get_secret_value()
            .secret_id(secret_id)
            .set_version_id(version_id.map(String::from))
            .set_version_stage(version_stage.map(String::from));

        let primary = request
            .clone()
            .customize()
            .config_override(self.primary_overrides(failover_region))
            .send()
            .await;

        let response = match (primary, failover_region) {
            // Try the failover region before falling back to a stale value.
            (Err(e), Some(region)) if is_transient_error(&e) => {
                let failover = request
                    .secret_id(retarget_arn(secret_id, region))
                    .customize()
                    .config_override(Self::failover_overrides(region))
                    .send()
                    .await;
                let outcome = match &failover {
                    Ok(r) => format!("ok version_id={}", r.version_id().unwrap_or("none")),
                    Err(f) => format!("error \"{}\"", error_chain(f)),
                };
                self.warn_failover(
                    "GetSecretValue",
                    secret_id,
                    error_chain(&e),
                    region,
                    outcome,
                );
                // If the failover fails too, it's handled as the primary's transient error.
                failover.or(Err(e))
            }
            (primary, _) => primary,
        };
        let result: GetSecretValueOutputDef = match response {
            Ok(r) => r.into(),
            Err(e)
                if self.ignore_transient_errors
                    && is_transient_error(&e)
                    && cached_value.is_some() =>
            {
                *cached_value.unwrap()
            }
            Err(e) => Err(e)?,
        };

        // Cached under the caller's identifier, whichever region served it.
        self.store.write().await.write_secret_value(
            secret_id.to_owned(),
            version_id.map(String::from),
            version_stage.map(String::from),
            result.clone(),
        )?;

        Ok(result)
    }

    /// Check if the value in the cache is still fresh enough to be served again
    ///
    /// # Arguments
    /// * `secret_id` - The ARN or name the caller asked for. The cached value's own ARN names
    ///   whichever region served it, so it is not used here.
    /// * `version_id` - The version id of the secret version to retrieve.
    /// * `version_stage` - The staging label of the version of the secret to retrieve. Defaults to AWSCURRENT
    /// * `cached_value` - The value currently in the cache.
    /// * `failover_region` - Region to repeat the call in after a transient primary error.
    ///
    /// # Returns
    /// * true if value can be reused, false if not
    async fn is_current(
        &self,
        secret_id: &str,
        version_id: Option<&str>,
        version_stage: Option<&str>,
        cached_value: Box<GetSecretValueOutputDef>,
        failover_region: Option<&str>,
    ) -> Result<bool, Box<dyn Error>> {
        let request = self.asm_client.describe_secret().secret_id(secret_id);
        let primary = request
            .clone()
            .customize()
            .config_override(self.primary_overrides(failover_region))
            .send()
            .await;
        let response = match (primary, failover_region) {
            // Try the failover region before falling back to the cached value.
            (Err(e), Some(region)) if is_transient_error(&e) => {
                let failover = request
                    .secret_id(retarget_arn(secret_id, region))
                    .customize()
                    .config_override(Self::failover_overrides(region))
                    .send()
                    .await;
                let outcome = match &failover {
                    Ok(_) => "ok".to_string(),
                    Err(f) => format!("error \"{}\"", error_chain(f)),
                };
                self.warn_failover(
                    "DescribeSecret",
                    secret_id,
                    error_chain(&e),
                    region,
                    outcome,
                );
                // If the failover fails too, it's handled as the primary's transient error.
                failover.or(Err(e))
            }
            (primary, _) => primary,
        };
        let describe = match response {
            Ok(r) => r,
            Err(e) if self.ignore_transient_errors && is_transient_error(&e) => return Ok(true),
            Err(e) => Err(e)?,
        };

        let real_vids_to_stages = match describe.version_ids_to_stages() {
            Some(vids_to_stages) => vids_to_stages,
            // Secret has no version Ids
            None => return Ok(false),
        };

        #[allow(clippy::unnecessary_unwrap)]
        // Only version id is given, then check if the version id still exists
        if version_id.is_some() && version_stage.is_none() {
            return Ok(real_vids_to_stages
                .iter()
                .any(|(k, _)| k.eq(version_id.unwrap())));
        }

        // If no version id is given, use the cached version id
        let version_id = match version_id {
            Some(id) => id.to_owned(),
            None => cached_value.version_id.clone().unwrap(),
        };

        // If no version stage was passed, check AWSCURRENT
        let version_stage = match version_stage {
            Some(v) => v.to_owned(),
            None => "AWSCURRENT".to_owned(),
        };

        // True if the version id and version stage match real_vids_to_stages in AWS Secrets Manager
        Ok(real_vids_to_stages
            .iter()
            .any(|(k, v)| k.eq(&version_id) && v.contains(&version_stage)))
    }

    /// Settings for a primary call, layered over the client's own: the primary
    /// timeout, only when there is a failover region to move to. Otherwise the
    /// settings are empty and the call runs as the client would.
    fn primary_overrides(&self, failover_region: Option<&str>) -> ConfigBuilder {
        match (failover_region, self.primary_timeout) {
            (Some(_), Some(timeout)) => ConfigBuilder::default()
                .timeout_config(TimeoutConfig::builder().operation_timeout(timeout).build()),
            _ => ConfigBuilder::default(),
        }
    }

    /// Settings for a failover call: the failover region, with its own retry
    /// partition so a failing primary can't drain the retry tokens it needs. It
    /// carries no credentials and isn't built from the client's config, which would
    /// duplicate interceptors.
    fn failover_overrides(region: &str) -> ConfigBuilder {
        ConfigBuilder::default()
            .region(Region::new(region.to_string()))
            .retry_partition(RetryPartition::new(format!("secretsmanager-{region}")))
    }

    /// WARN on every failover, with the fields operators alert and build metrics on.
    /// Logged in release builds too, unlike the cache metrics above.
    fn warn_failover(
        &self,
        operation: &str,
        secret_id: &str,
        primary_error: impl Display,
        failover_region: &str,
        outcome: impl Display,
    ) {
        log::warn!(
            "failover=true operation={operation} secret_id={secret_id} primary_region={} \
             primary_error=\"{primary_error}\" failover_region={failover_region} result={outcome}",
            self.asm_client
                .config()
                .region()
                .map_or("unknown", |r| r.as_ref()),
        );
    }

    #[cfg(debug_assertions)]
    fn get_cache_rates(&self) -> (f64, f64) {
        let hits = self.metrics.hits.load(Ordering::Relaxed);
        let misses = self.metrics.misses.load(Ordering::Relaxed);
        let total = hits + misses;

        if total == 0 {
            return (0.0, 0.0);
        }

        let hit_rate = (hits as f64 / total as f64) * 100.0;

        (hit_rate, 100.0 - hit_rate)
    }

    #[cfg(debug_assertions)]
    fn increment_counter(&self, counter: &AtomicU32) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(debug_assertions)]
    fn get_counter_value(&self, counter: &AtomicU32) -> u32 {
        counter.load(Ordering::Relaxed)
    }

    /// Check if a secret exists in the cache
    ///
    /// Reads directly from the store — returns true if the key is present and
    /// not expired, false otherwise. Only available in test builds.
    #[cfg(any(test, feature = "test-util"))]
    pub async fn cache_contains(&self, secret_id: &str) -> bool {
        let store = self.store.read().await;
        store.get_secret_value(secret_id, None, None).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use tokio::time::sleep;

    use super::*;

    use aws_smithy_runtime_api::client::http::SharedHttpClient;

    fn fake_client(
        ttl: Option<Duration>,
        ignore_transient_errors: bool,
        http_client: Option<SharedHttpClient>,
        endpoint_url: Option<String>,
    ) -> SecretsManagerCachingClient {
        SecretsManagerCachingClient::new(
            asm_mock::def_fake_client(http_client, endpoint_url),
            NonZeroUsize::new(1000).unwrap(),
            match ttl {
                Some(ttl) => ttl,
                None => Duration::from_secs(1000),
            },
            ignore_transient_errors,
        )
        .expect("client should create")
    }

    #[tokio::test]
    async fn test_get_secret_value() {
        let client = fake_client(None, false, None, None);
        let secret_id = "test_secret";

        let response = client
            .get_secret_value(secret_id, None, None, false, None)
            .await
            .unwrap();

        assert_eq!(response.name, Some(secret_id.to_string()));
        assert_eq!(response.secret_string, Some("hunter2".to_string()));
        assert_eq!(
            response.arn,
            Some(
                asm_mock::FAKE_ARN
                    .replace("{{name}}", secret_id)
                    .to_string()
            )
        );
        assert_eq!(
            response.version_stages,
            Some(vec!["AWSCURRENT".to_string()])
        );
    }

    #[tokio::test]
    async fn test_get_secret_value_version_id() {
        let client = fake_client(None, false, None, None);
        let secret_id = "test_secret";
        let version_id = "test_version";

        let response = client
            .get_secret_value(secret_id, Some(version_id), None, false, None)
            .await
            .unwrap();

        assert_eq!(response.name, Some(secret_id.to_string()));
        assert_eq!(response.secret_string, Some("hunter2".to_string()));
        assert_eq!(response.version_id, Some(version_id.to_string()));
        assert_eq!(
            response.arn,
            Some(
                asm_mock::FAKE_ARN
                    .replace("{{name}}", secret_id)
                    .to_string()
            )
        );
        assert_eq!(
            response.version_stages,
            Some(vec!["AWSCURRENT".to_string()])
        );
    }

    #[tokio::test]
    async fn test_get_secret_value_version_stage() {
        let client = fake_client(None, false, None, None);
        let secret_id = "test_secret";
        let stage_label = "STAGEHERE";

        let response = client
            .get_secret_value(secret_id, None, Some(stage_label), false, None)
            .await
            .unwrap();

        assert_eq!(response.name, Some(secret_id.to_string()));
        assert_eq!(response.secret_string, Some("hunter2".to_string()));
        assert_eq!(
            response.arn,
            Some(
                asm_mock::FAKE_ARN
                    .replace("{{name}}", secret_id)
                    .to_string()
            )
        );
        assert_eq!(response.version_stages, Some(vec![stage_label.to_string()]));
    }

    #[tokio::test]
    async fn test_get_secret_value_version_id_and_stage() {
        let client = fake_client(None, false, None, None);
        let secret_id = "test_secret";
        let version_id = "test_version";
        let stage_label = "STAGEHERE";

        let response = client
            .get_secret_value(secret_id, Some(version_id), Some(stage_label), false, None)
            .await
            .unwrap();

        assert_eq!(response.name, Some(secret_id.to_string()));
        assert_eq!(response.secret_string, Some("hunter2".to_string()));
        assert_eq!(response.version_id, Some(version_id.to_string()));
        assert_eq!(
            response.arn,
            Some(
                asm_mock::FAKE_ARN
                    .replace("{{name}}", secret_id)
                    .to_string()
            )
        );
        assert_eq!(response.version_stages, Some(vec![stage_label.to_string()]));
    }

    #[tokio::test]
    async fn test_get_cache_expired() {
        let client = fake_client(Some(Duration::from_secs(0)), false, None, None);
        let secret_id = "test_secret";

        // Run through this twice to test the cache expiration
        for i in 0..2 {
            let response = client
                .get_secret_value(secret_id, None, None, false, None)
                .await
                .unwrap();

            assert_eq!(response.name, Some(secret_id.to_string()));
            assert_eq!(response.secret_string, Some("hunter2".to_string()));
            assert_eq!(
                response.arn,
                Some(
                    asm_mock::FAKE_ARN
                        .replace("{{name}}", secret_id)
                        .to_string()
                )
            );
            assert_eq!(
                response.version_stages,
                Some(vec!["AWSCURRENT".to_string()])
            );
            // let the entry expire
            if i == 0 {
                sleep(Duration::from_millis(50)).await;
            }
        }
    }

    #[tokio::test]
    #[should_panic]
    async fn test_get_secret_value_kms_access_denied() {
        let client = fake_client(None, false, None, None);
        let secret_id = "KMSACCESSDENIEDabcdef";

        client
            .get_secret_value(secret_id, None, None, false, None)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic]
    async fn test_get_secret_value_resource_not_found() {
        let client = fake_client(None, false, None, None);
        let secret_id = "NOTFOUNDfasefasef";

        client
            .get_secret_value(secret_id, None, None, false, None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_get_secret_value_throttling_cold_cache_fails() {
        let client = fake_client(None, true, None, None);
        let secret_id = "THROTTLINGabcdef";

        assert!(client
            .get_secret_value(secret_id, None, None, false, None)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_is_current_default_succeeds() {
        let client = fake_client(Some(Duration::from_secs(0)), false, None, None);
        let secret_id = "test_secret";

        let res1 = client
            .get_secret_value(secret_id, None, None, false, None)
            .await
            .unwrap();

        let res2 = client
            .get_secret_value(secret_id, None, None, false, None)
            .await
            .unwrap();

        assert_eq!(res1, res2)
    }

    #[tokio::test]
    async fn test_is_current_version_id_succeeds() {
        let client = fake_client(Some(Duration::from_secs(0)), false, None, None);
        let secret_id = "test_secret";
        let version_id = Some("test_version");

        let res1 = client
            .get_secret_value(secret_id, version_id, None, false, None)
            .await
            .unwrap();

        let res2 = client
            .get_secret_value(secret_id, version_id, None, false, None)
            .await
            .unwrap();

        assert_eq!(res1, res2)
    }

    #[tokio::test]
    async fn test_is_current_version_stage_succeeds() {
        let client = fake_client(Some(Duration::from_secs(0)), false, None, None);
        let secret_id = "test_secret";
        let version_stage = Some("VERSIONSTAGE");

        let res1 = client
            .get_secret_value(secret_id, None, version_stage, false, None)
            .await
            .unwrap();

        let res2 = client
            .get_secret_value(secret_id, None, version_stage, false, None)
            .await
            .unwrap();

        assert_eq!(res1, res2)
    }

    #[tokio::test]
    async fn test_is_current_both_version_id_and_version_stage_succeeds() {
        let client = fake_client(Some(Duration::from_secs(0)), false, None, None);
        let secret_id = "test_secret";
        let version_id = Some("test_version");
        let version_stage = Some("VERSIONSTAGE");

        let res1 = client
            .get_secret_value(secret_id, version_id, version_stage, false, None)
            .await
            .unwrap();

        let res2 = client
            .get_secret_value(secret_id, version_id, version_stage, false, None)
            .await
            .unwrap();

        assert_eq!(res1, res2)
    }

    #[tokio::test]
    async fn test_is_current_describe_access_denied_fails() {
        let client = fake_client(Some(Duration::from_secs(0)), false, None, None);
        let secret_id = "DESCRIBEACCESSDENIED_test_secret";
        let version_id = Some("test_version");

        client
            .get_secret_value(secret_id, version_id, None, false, None)
            .await
            .unwrap();

        if (client
            .get_secret_value(secret_id, version_id, None, false, None)
            .await)
            .is_ok()
        {
            panic!("Expected failure")
        }
    }

    #[tokio::test]
    async fn test_is_current_describe_timeout_error_succeeds() {
        use asm_mock::GSV_BODY;
        use aws_smithy_runtime::client::http::test_util::wire::{ReplayedEvent, WireMockServer};

        let mock = WireMockServer::start(vec![
            ReplayedEvent::with_body(GSV_BODY),
            ReplayedEvent::Timeout,
        ])
        .await;
        let client = fake_client(
            Some(Duration::from_secs(0)),
            true,
            Some(mock.http_client()),
            Some(mock.endpoint_url()),
        );
        let secret_id = "DESCRIBETIMEOUT_test_secret";
        let version_id = Some("test_version");

        let res1 = client
            .get_secret_value(secret_id, version_id, None, false, None)
            .await
            .unwrap();

        let res2 = client
            .get_secret_value(secret_id, version_id, None, false, None)
            .await
            .unwrap();

        mock.shutdown();

        assert_eq!(res1, res2)
    }

    #[tokio::test]
    async fn test_is_current_describe_throttling_wire_mock_succeeds() {
        use asm_mock::GSV_BODY;
        use asm_mock::THROTTLING_EXCEPTION_BODY;
        use aws_smithy_runtime::client::http::test_util::wire::{ReplayedEvent, WireMockServer};

        let mock = WireMockServer::start(vec![
            ReplayedEvent::with_body(GSV_BODY),
            ReplayedEvent::HttpResponse {
                status: 400,
                body: THROTTLING_EXCEPTION_BODY.into(),
            },
        ])
        .await;
        let client = fake_client(
            Some(Duration::from_secs(0)),
            true,
            Some(mock.http_client()),
            Some(mock.endpoint_url()),
        );
        let secret_id = "WIRETHROTTLING_test_secret";
        let version_id = Some("test_version");

        let res1 = client
            .get_secret_value(secret_id, version_id, None, false, None)
            .await
            .unwrap();

        let res2 = client
            .get_secret_value(secret_id, version_id, None, false, None)
            .await
            .unwrap();

        mock.shutdown();

        assert_eq!(res1, res2)
    }

    #[tokio::test]
    async fn test_is_current_describe_service_error_succeeds() {
        let client = fake_client(Some(Duration::from_secs(0)), true, None, None);
        let secret_id = "DESCRIBESERVICEERROR_test_secret";
        let version_id = Some("test_version");
        let version_stage = Some("VERSIONSTAGE");

        let res1 = client
            .get_secret_value(secret_id, version_id, version_stage, false, None)
            .await
            .unwrap();

        let res2 = client
            .get_secret_value(secret_id, version_id, version_stage, false, None)
            .await
            .unwrap();

        assert_eq!(res1, res2)
    }

    #[tokio::test]
    async fn test_is_current_describe_throttling_error_succeeds() {
        let client = fake_client(Some(Duration::from_secs(0)), true, None, None);
        let secret_id = "DESCRIBETHROTTLING_test_secret";
        let version_id = Some("test_version");
        let version_stage = Some("VERSIONSTAGE");

        let res1 = client
            .get_secret_value(secret_id, version_id, version_stage, false, None)
            .await
            .unwrap();

        let res2 = client
            .get_secret_value(secret_id, version_id, version_stage, false, None)
            .await
            .unwrap();

        assert_eq!(res1, res2)
    }

    #[tokio::test]
    async fn test_is_current_gsv_timeout_error_succeeds() {
        use asm_mock::DESC_BODY;
        use asm_mock::GSV_BODY;
        use aws_smithy_runtime::client::http::test_util::wire::{ReplayedEvent, WireMockServer};

        let mock = WireMockServer::start(vec![
            ReplayedEvent::with_body(
                GSV_BODY
                    .replace("{{version}}", "old_version")
                    .replace("{{label}}", "AWSCURRENT"),
            ),
            ReplayedEvent::with_body(
                DESC_BODY
                    .replace("{{version}}", "new_version")
                    .replace("{{label}}", "AWSCURRENT"),
            ),
            ReplayedEvent::Timeout,
        ])
        .await;
        let client = fake_client(
            Some(Duration::from_secs(0)),
            true,
            Some(mock.http_client()),
            Some(mock.endpoint_url()),
        );
        let secret_id = "GSVTIMEOUT_test_secret";

        let res1 = client
            .get_secret_value(secret_id, None, None, false, None)
            .await
            .unwrap();

        let res2 = client
            .get_secret_value(secret_id, None, None, false, None)
            .await
            .unwrap();

        mock.shutdown();

        assert_eq!(res1, res2)
    }

    #[tokio::test]
    async fn test_get_secret_value_refresh_now_true() {
        let client = fake_client(Some(Duration::from_secs(30)), false, None, None);
        let secret_id = "REFRESHNOW_test_secret";

        let response1 = client
            .get_secret_value(secret_id, None, None, false, None)
            .await
            .unwrap();

        assert_eq!(response1.name, Some(secret_id.to_string()));
        assert_eq!(
            response1.arn,
            Some(
                asm_mock::FAKE_ARN
                    .replace("{{name}}", secret_id)
                    .to_string()
            )
        );
        assert_eq!(
            response1.version_stages,
            Some(vec!["AWSCURRENT".to_string()])
        );

        sleep(Duration::from_millis(1)).await;

        let response2 = client
            .get_secret_value(secret_id, None, None, true, None)
            .await
            .unwrap();

        assert_ne!(response1.secret_string, response2.secret_string);
        assert_eq!(response1.arn, response2.arn);
        assert_eq!(response1.version_stages, response2.version_stages);
    }

    #[tokio::test]
    async fn test_get_secret_value_refresh_now_false() {
        let client = fake_client(Some(Duration::from_secs(30)), false, None, None);
        let secret_id = "REFRESHNOW_test_secret";

        let response1 = client
            .get_secret_value(secret_id, None, None, false, None)
            .await
            .unwrap();

        assert_eq!(response1.name, Some(secret_id.to_string()));
        assert_eq!(
            response1.arn,
            Some(
                asm_mock::FAKE_ARN
                    .replace("{{name}}", secret_id)
                    .to_string()
            )
        );
        assert_eq!(
            response1.version_stages,
            Some(vec!["AWSCURRENT".to_string()])
        );

        sleep(Duration::from_millis(1)).await;

        let response2 = client
            .get_secret_value(secret_id, None, None, false, None)
            .await
            .unwrap();

        assert_eq!(response1, response2);
    }

    #[tokio::test]
    async fn test_get_secret_value_version_id_and_stage_refresh_now() {
        let client = fake_client(Some(Duration::from_secs(30)), false, None, None);
        let secret_id = "REFRESHNOW_test_secret";
        let version_id = "test_version";
        let stage_label = "STAGEHERE";

        let response1 = client
            .get_secret_value(secret_id, Some(version_id), Some(stage_label), false, None)
            .await
            .unwrap();

        sleep(Duration::from_millis(1)).await;

        let response2 = client
            .get_secret_value(secret_id, Some(version_id), Some(stage_label), true, None)
            .await
            .unwrap();

        assert_ne!(response1.secret_string, response2.secret_string);
        assert_eq!(response1.arn, response2.arn);
        assert_eq!(response1.version_stages, response2.version_stages);
    }

    #[tokio::test]
    async fn test_batch_get_secret_value_success() {
        let client = fake_client(None, false, None, None);

        // Mock returns one secret per batch call (keyed on first ID)
        let result = client
            .batch_get_secret_value(Some(vec!["MyTest".to_string()]), None, None, None)
            .await;

        assert!(result.is_ok());
        let resp = result.unwrap().unwrap();
        assert_eq!(resp.secret_values().len(), 1);
        assert!(resp.errors().is_empty());

        // Verify the secret was written to the cache (cache hit, no network call)
        let cached = client
            .get_secret_value("MyTest", None, None, false, None)
            .await;
        assert!(cached.is_ok());
        assert_eq!(cached.unwrap().secret_string, Some("hunter2".to_string()));
    }

    #[tokio::test]
    async fn test_batch_get_secret_value_partial_failure() {
        let client = fake_client(None, false, None, None);

        let result = client
            .batch_get_secret_value(
                Some(vec![
                    "NOTFOUNDsecret".to_string(),
                    "ValidSecret".to_string(),
                ]),
                None,
                None,
                None,
            )
            .await;

        assert!(result.is_ok());
        let resp = result.unwrap().unwrap();
        // One secret succeeded, one errored
        assert_eq!(resp.secret_values().len(), 1);
        assert_eq!(resp.errors().len(), 1);

        // Valid secret should be cached
        let cached = client
            .get_secret_value("ValidSecret", None, None, false, None)
            .await;
        assert!(cached.is_ok());
    }

    #[tokio::test]
    async fn test_batch_get_secret_value_api_error() {
        let client = fake_client(None, false, None, None);

        let result = client
            .batch_get_secret_value(
                Some(vec!["BATCHAPIERROR_secret".to_string()]),
                None,
                None,
                None,
            )
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_batch_get_secret_value_transient_suppressed() {
        use aws_smithy_runtime::client::http::test_util::wire::{ReplayedEvent, WireMockServer};

        let mock = WireMockServer::start(vec![ReplayedEvent::Timeout]).await;
        let client = fake_client(
            None,
            true, // ignore_transient_errors = true
            Some(mock.http_client()),
            Some(mock.endpoint_url()),
        );

        let result = client
            .batch_get_secret_value(Some(vec!["MyTest".to_string()]), None, None, None)
            .await;

        mock.shutdown();

        // Transient error should be suppressed → Ok(None)
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    // Failover tests. The fake routes each request by the region in its endpoint,
    // so the primary (the fake client's us-west-2) and the failover region can
    // each be up, down, or denied independently.
    mod failover {
        use super::asm_mock::{format_rsp, DEFAULT_SECRET_STRING, FAKE_ARN};
        use super::*;
        use aws_sdk_secretsmanager::error::SdkError;
        use aws_sdk_secretsmanager::operation::describe_secret::DescribeSecretError;
        use aws_sdk_secretsmanager::operation::get_secret_value::GetSecretValueError;
        use aws_smithy_runtime::client::http::test_util::{infallible_client_fn, NeverClient};
        use aws_smithy_runtime_api::client::orchestrator::HttpResponse;
        use aws_smithy_types::body::SdkBody;
        use std::sync::{Arc, Mutex};

        const PRIMARY: &str = "us-west-2";
        const FAILOVER: &str = "us-east-1";
        const SERVER_ERROR: &str = r#"{"__type":"InternalServiceError","Message":"down"}"#;
        const DENIED: &str = r#"{"__type":"AccessDeniedException","Message":"denied"}"#;

        // How a region answers.
        #[derive(Clone, Copy)]
        enum Mode {
            Ok,
            Down,
            Denied,
        }

        struct Fake {
            primary: Mode,
            failover: Mode,
            // "Operation@region" for each call, in order.
            calls: Vec<String>,
            // The SecretId sent with each call.
            ids: Vec<String>,
        }

        type Shared = Arc<Mutex<Fake>>;

        fn client(ignore_transient_errors: bool) -> (SecretsManagerCachingClient, Shared) {
            let fake = Arc::new(Mutex::new(Fake {
                primary: Mode::Ok,
                failover: Mode::Ok,
                calls: vec![],
                ids: vec![],
            }));
            let state = fake.clone();
            let http = infallible_client_fn(move |req| {
                let region = if req.uri().to_string().contains(FAILOVER) {
                    FAILOVER
                } else {
                    PRIMARY
                };
                let op = req.headers()["x-amz-target"]
                    .to_str()
                    .unwrap()
                    .trim_start_matches("secretsmanager.")
                    .to_string();
                let body: serde_json::Value =
                    serde_json::from_slice(req.body().bytes().unwrap()).unwrap();
                let mode = {
                    let mut f = state.lock().unwrap();
                    f.calls.push(format!("{op}@{region}"));
                    f.ids.push(body["SecretId"].as_str().unwrap().to_string());
                    if region == FAILOVER {
                        f.failover
                    } else {
                        f.primary
                    }
                };
                let (code, rsp) = match (mode, op.as_str()) {
                    (Mode::Ok, _) => format_rsp(req),
                    (Mode::Down, _) => (500, SERVER_ERROR.to_string()),
                    (Mode::Denied, _) => (400, DENIED.to_string()),
                };
                http::Response::builder()
                    .status(code)
                    .body(SdkBody::from(rsp))
                    .unwrap()
            });
            let client = fake_client(
                Some(Duration::from_millis(50)),
                ignore_transient_errors,
                Some(http),
                None,
            );
            (client, fake)
        }

        // Set how each region answers, and clear the call log.
        fn set(fake: &Shared, primary: Mode, failover: Mode) {
            let mut f = fake.lock().unwrap();
            f.primary = primary;
            f.failover = failover;
            f.calls.clear();
            f.ids.clear();
        }

        fn calls(fake: &Shared) -> Vec<String> {
            std::mem::take(&mut fake.lock().unwrap().calls)
        }

        // Cache the secret while both regions are healthy, then let it expire.
        async fn cache_then_expire(client: &SecretsManagerCachingClient) {
            get(client, "prod-db", false, Some(FAILOVER)).await.unwrap();
            sleep(Duration::from_millis(80)).await;
        }

        async fn get(
            client: &SecretsManagerCachingClient,
            secret_id: &str,
            refresh_now: bool,
            failover_region: Option<&str>,
        ) -> Result<String, Box<dyn Error>> {
            client
                .get_secret_value(secret_id, None, None, refresh_now, failover_region)
                .await
                .map(|v| v.secret_string.unwrap())
        }

        // The HTTP status of the error, whichever operation returned it.
        fn status(err: &(dyn Error + 'static)) -> u16 {
            let raw = match err.downcast_ref::<SdkError<GetSecretValueError, HttpResponse>>() {
                Some(e) => e.raw_response(),
                None => err
                    .downcast_ref::<SdkError<DescribeSecretError, HttpResponse>>()
                    .and_then(|e| e.raw_response()),
            };
            raw.map(|r| r.status().as_u16()).unwrap_or_default()
        }

        // The version check fails over, and the cached value is confirmed current.
        // ignore_transient_errors is off, so the value can only come from the failover answer.
        #[tokio::test]
        async fn test_failover_confirms_cached_value() {
            let (client, fake) = client(false);
            cache_then_expire(&client).await;
            set(&fake, Mode::Down, Mode::Ok);

            let value = get(&client, "prod-db", false, Some(FAILOVER))
                .await
                .unwrap();
            assert_eq!(value, DEFAULT_SECRET_STRING);
            assert_eq!(
                calls(&fake),
                ["DescribeSecret@us-west-2", "DescribeSecret@us-east-1"]
            );
        }

        // Any failover error falls back to the stale value, not only a transient one.
        #[tokio::test]
        async fn test_failover_access_denied_serves_stale_value() {
            let (client, fake) = client(true);
            cache_then_expire(&client).await;
            set(&fake, Mode::Down, Mode::Denied);

            let value = get(&client, "prod-db", false, Some(FAILOVER))
                .await
                .unwrap();
            assert_eq!(value, DEFAULT_SECRET_STRING);
            assert_eq!(
                calls(&fake),
                ["DescribeSecret@us-west-2", "DescribeSecret@us-east-1"]
            );
        }

        // Without ignore_transient_errors, a failed failover returns the primary's
        // error (500), not the failover's (400).
        #[tokio::test]
        async fn test_failed_failover_returns_primary_error() {
            let (client, fake) = client(false);
            cache_then_expire(&client).await;
            set(&fake, Mode::Down, Mode::Denied);

            let err = get(&client, "prod-db", false, Some(FAILOVER))
                .await
                .expect_err("both regions failed");
            assert_eq!(status(err.as_ref()), 500);
            assert_eq!(
                calls(&fake),
                ["DescribeSecret@us-west-2", "DescribeSecret@us-east-1"]
            );
        }

        // With nothing cached, a failed failover returns the primary's error even
        // with ignore_transient_errors on.
        #[tokio::test]
        async fn test_failed_failover_on_cold_cache_returns_primary_error() {
            let (client, fake) = client(true);
            set(&fake, Mode::Down, Mode::Denied);

            let err = get(&client, "prod-db", false, Some(FAILOVER))
                .await
                .expect_err("both regions failed");
            assert_eq!(status(err.as_ref()), 500);
            assert_eq!(
                calls(&fake),
                ["GetSecretValue@us-west-2", "GetSecretValue@us-east-1"]
            );
        }

        // Both failover calls rewrite the ARN, and the version check sends the caller's ARN.
        #[tokio::test]
        async fn test_failover_retargets_arn() {
            let (client, fake) = client(true);
            set(&fake, Mode::Down, Mode::Ok);
            let arn = FAKE_ARN.replace("{{name}}", "prod-db");
            let replica_arn = arn.replace(":us-west-2:", ":us-east-1:");

            get(&client, &arn, true, Some(FAILOVER)).await.unwrap();
            sleep(Duration::from_millis(80)).await;
            get(&client, &arn, false, Some(FAILOVER)).await.unwrap();
            assert_eq!(
                calls(&fake),
                [
                    "GetSecretValue@us-west-2",
                    "GetSecretValue@us-east-1",
                    "DescribeSecret@us-west-2",
                    "DescribeSecret@us-east-1"
                ]
            );
            assert_eq!(
                fake.lock().unwrap().ids,
                [arn.clone(), replica_arn.clone(), arn, replica_arn]
            );
        }

        // A non-transient primary error is returned without failing over.
        #[tokio::test]
        async fn test_no_failover_on_non_transient_error() {
            let (client, fake) = client(true);
            set(&fake, Mode::Denied, Mode::Ok);
            let err = get(&client, "prod-db", false, Some(FAILOVER))
                .await
                .expect_err("primary denied");
            assert_eq!(status(err.as_ref()), 400);
            assert_eq!(calls(&fake), ["GetSecretValue@us-west-2"]);

            set(&fake, Mode::Ok, Mode::Ok);
            cache_then_expire(&client).await;
            set(&fake, Mode::Denied, Mode::Ok);
            let err = get(&client, "prod-db", false, Some(FAILOVER))
                .await
                .expect_err("primary denied");
            assert_eq!(status(err.as_ref()), 400);
            assert_eq!(calls(&fake), ["DescribeSecret@us-west-2"]);
        }

        // A failover region equal to the primary is ignored, so the call isn't repeated.
        #[tokio::test]
        async fn test_failover_region_equal_to_primary_is_ignored() {
            let (client, fake) = client(true);
            set(&fake, Mode::Down, Mode::Ok);

            let err = get(&client, "prod-db", false, Some(PRIMARY))
                .await
                .expect_err("primary down, no failover");
            assert_eq!(status(err.as_ref()), 500);
            assert_eq!(calls(&fake), ["GetSecretValue@us-west-2"]);
        }

        // When both regions hang, the primary call is cut off at the primary timeout
        // (10 ms), not the fake client's 100 ms attempt timeout, and the failover call
        // isn't bounded by it. Without a failover region, the primary timeout doesn't
        // apply. The clock is paused, so the elapsed times are exact.
        #[tokio::test(start_paused = true)]
        async fn test_primary_timeout_applies_only_with_failover_region() {
            let hang = SharedHttpClient::new(NeverClient::new());
            let client = fake_client(None, false, Some(hang), None)
                .with_primary_timeout(Duration::from_millis(10));

            let start = tokio::time::Instant::now();
            get(&client, "prod-db", false, Some(FAILOVER))
                .await
                .expect_err("both regions hang");
            assert_eq!(start.elapsed(), Duration::from_millis(110));

            let start = tokio::time::Instant::now();
            get(&client, "prod-db", false, None)
                .await
                .expect_err("primary hangs");
            assert_eq!(start.elapsed(), Duration::from_millis(100));
        }
    }

    mod asm_mock {
        use aws_sdk_secretsmanager as secretsmanager;
        use aws_smithy_runtime::client::http::test_util::infallible_client_fn;
        use aws_smithy_runtime_api::client::http::SharedHttpClient;
        use aws_smithy_types::body::SdkBody;
        use aws_smithy_types::timeout::TimeoutConfig;
        use http::{Request, Response};
        use secretsmanager::config::BehaviorVersion;
        use serde_json::Value;
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        pub const FAKE_ARN: &str =
            "arn:aws:secretsmanager:us-west-2:123456789012:secret:{{name}}-NhBWsc";
        pub const DEFAULT_VERSION: &str = "5767290c-d089-49ed-b97c-17086f8c9d79";
        pub const DEFAULT_LABEL: &str = "AWSCURRENT";
        pub const DEFAULT_SECRET_STRING: &str = "hunter2";

        // Template GetSecretValue responses for testing
        pub const GSV_BODY: &str = r###"{
        "ARN": "{{arn}}",
        "Name": "{{name}}",
        "VersionId": "{{version}}",
        "SecretString": "{{secret}}",
        "VersionStages": [
            "{{label}}"
        ],
        "CreatedDate": 1569534789.046
        }"###;

        // Template DescribeSecret responses for testing
        pub const DESC_BODY: &str = r###"{
          "ARN": "{{arn}}",
          "Name": "{{name}}",
          "Description": "My test secret",
          "KmsKeyId": "arn:aws:kms:us-west-2:123456789012:key/exampled-90ab-cdef-fedc-bbd6-7e6f303ac933",
          "LastChangedDate": 1523477145.729,
          "LastAccessedDate": 1524572133.25,
          "VersionIdsToStages": {
              "{{version}}": [
                  "{{label}}"
              ]
          },
          "CreatedDate": 1569534789.046
        }"###;

        // Template for access denied testing
        const KMS_ACCESS_DENIED_BODY: &str = r###"{
        "__type":"AccessDeniedException",
        "Message":"Access to KMS is not allowed"
        }"###;

        // Template for testing resource not found with DescribeSecret
        const NOT_FOUND_EXCEPTION_BODY: &str = r###"{
        "__type":"ResourceNotFoundException",
        "message":"Secrets Manager can't find the specified secret."
        }"###;

        const SECRETSMANAGER_ACCESS_DENIED_BODY: &str = r###"{
        "__type:"AccessDeniedException",
        "Message": "is not authorized to perform: secretsmanager:DescribeSecret on resource: XXXXXXXX"
        }"###;

        const SECRETSMANAGER_INTERNAL_SERVICE_ERROR_BODY: &str = r###"{
        "__type:"InternalServiceError",
        "Message": "Internal service error"
        }"###;

        pub const THROTTLING_EXCEPTION_BODY: &str = r###"{
        "__type":"ThrottlingException",
        "message":"Rate exceeded"
        }"###;

        // Template BatchGetSecretValue response for testing
        const BATCH_GSV_BODY: &str = r###"{
            "SecretValues": [
                {
                    "ARN": "{{arn}}",
                    "Name": "{{name}}",
                    "VersionId": "{{version}}",
                    "SecretString": "{{secret}}",
                    "VersionStages": ["{{label}}"],
                    "CreatedDate": 1569534789.046
                }
            ],
            "Errors": []
        }"###;

        // Template BatchGetSecretValue response with per-secret errors
        const BATCH_WITH_ERRORS_BODY: &str = r###"{
            "SecretValues": [
                {
                    "ARN": "{{arn}}",
                    "Name": "{{valid_name}}",
                    "VersionId": "{{version}}",
                    "SecretString": "{{secret}}",
                    "VersionStages": ["{{label}}"],
                    "CreatedDate": 1569534789.046
                }
            ],
            "Errors": [
                {
                    "SecretId": "{{err_name}}",
                    "ErrorCode": "ResourceNotFoundException",
                    "Message": "Secrets Manager can't find the specified secret."
                }
            ]
        }"###;

        // Template for BatchGetSecretValue API-level error
        const BATCH_INVALID_PARAMETER_BODY: &str = r###"{
            "__type":"InvalidParameterException",
            "message":"The parameter SecretIdList contains invalid values"
        }"###;

        // Helper to look at the request and provide the correct response.
        pub fn format_rsp(req: Request<SdkBody>) -> (u16, String) {
            let (parts, body) = req.into_parts();
            let target = parts.headers["x-amz-target"].to_str().unwrap();

            let req_map: serde_json::Map<String, Value> =
                serde_json::from_slice(body.bytes().unwrap()).unwrap();

            // Handle BatchGetSecretValue requests
            if target == "secretsmanager.BatchGetSecretValue" {
                let secret_ids = req_map
                    .get("SecretIdList")
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
                    .unwrap_or_default();
                let has_filters = req_map.get("Filters").is_some();

                if secret_ids.iter().any(|s| s.starts_with("BATCHAPIERROR")) {
                    return (400, BATCH_INVALID_PARAMETER_BODY.to_string());
                }

                if secret_ids.iter().any(|s| s.starts_with("NOTFOUND")) {
                    let valid_name = secret_ids
                        .iter()
                        .find(|s| !s.starts_with("NOTFOUND"))
                        .unwrap_or(&"Valid");
                    let err_name = secret_ids
                        .iter()
                        .find(|s| s.starts_with("NOTFOUND"))
                        .unwrap_or(&"NOTFOUND");
                    let rsp = BATCH_WITH_ERRORS_BODY
                        .replace("{{arn}}", &FAKE_ARN.replace("{{name}}", valid_name))
                        .replace("{{valid_name}}", valid_name)
                        .replace("{{err_name}}", err_name)
                        .replace("{{version}}", DEFAULT_VERSION)
                        .replace("{{secret}}", DEFAULT_SECRET_STRING)
                        .replace("{{label}}", DEFAULT_LABEL);
                    return (200, rsp);
                }

                // For filter-based requests return "TaggedSecret"; for SecretIdList use first ID
                let name = if has_filters {
                    "TaggedSecret"
                } else {
                    secret_ids.first().unwrap_or(&"MyTest")
                };
                let rsp = BATCH_GSV_BODY
                    .replace("{{arn}}", &FAKE_ARN.replace("{{name}}", name))
                    .replace("{{name}}", name)
                    .replace("{{version}}", DEFAULT_VERSION)
                    .replace("{{secret}}", DEFAULT_SECRET_STRING)
                    .replace("{{label}}", DEFAULT_LABEL);
                return (200, rsp);
            }

            // Existing single-request handling
            let version = req_map
                .get("VersionId")
                .map_or(DEFAULT_VERSION, |x| x.as_str().unwrap());
            let label = req_map
                .get("VersionStage")
                .map_or(DEFAULT_LABEL, |x| x.as_str().unwrap());
            let name = req_map.get("SecretId").unwrap().as_str().unwrap(); // Does not handle full ARN case.

            let secret_string = match name {
                secret if secret.starts_with("REFRESHNOW") => SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis()
                    .to_string(),
                _ => DEFAULT_SECRET_STRING.to_string(),
            };

            let (code, template) = match target {
                "secretsmanager.GetSecretValue" if name.starts_with("KMSACCESSDENIED") => {
                    (400, KMS_ACCESS_DENIED_BODY)
                }
                "secretsmanager.GetSecretValue" if name.starts_with("NOTFOUND") => {
                    (400, NOT_FOUND_EXCEPTION_BODY)
                }
                "secretsmanager.GetSecretValue" if name.starts_with("THROTTLING") => {
                    (400, THROTTLING_EXCEPTION_BODY)
                }
                "secretsmanager.GetSecretValue" => (200, GSV_BODY),
                "secretsmanager.DescribeSecret" if name.contains("DESCRIBEACCESSDENIED") => {
                    (400, SECRETSMANAGER_ACCESS_DENIED_BODY)
                }
                "secretsmanager.DescribeSecret" if name.contains("DESCRIBESERVICEERROR") => {
                    (500, SECRETSMANAGER_INTERNAL_SERVICE_ERROR_BODY)
                }
                "secretsmanager.DescribeSecret" if name.contains("DESCRIBETHROTTLING") => {
                    (400, THROTTLING_EXCEPTION_BODY)
                }
                "secretsmanager.DescribeSecret" => (200, DESC_BODY),
                _ => panic!("Unknown operation"),
            };

            // Fill in the template and return the response.
            let rsp = template
                .replace("{{arn}}", FAKE_ARN)
                .replace("{{name}}", name)
                .replace("{{version}}", version)
                .replace("{{secret}}", &secret_string)
                .replace("{{label}}", label);
            (code, rsp)
        }

        // Test client that stubs off network call and provides a canned response.
        pub fn def_fake_client(
            http_client: Option<SharedHttpClient>,
            endpoint_url: Option<String>,
        ) -> secretsmanager::Client {
            use aws_smithy_types::retry::RetryConfig;

            let fake_creds = secretsmanager::config::Credentials::new(
                "AKIDTESTKEY",
                "astestsecretkey",
                Some("atestsessiontoken".to_string()),
                None,
                "",
            );

            let mut config_builder = secretsmanager::Config::builder()
                .behavior_version(BehaviorVersion::latest())
                .credentials_provider(fake_creds)
                .region(secretsmanager::config::Region::new("us-west-2"))
                .timeout_config(
                    TimeoutConfig::builder()
                        .operation_attempt_timeout(Duration::from_millis(100))
                        .build(),
                )
                .retry_config(RetryConfig::disabled())
                .http_client(match http_client {
                    Some(custom_client) => custom_client,
                    None => infallible_client_fn(|_req| {
                        let (code, rsp) = format_rsp(_req);
                        Response::builder()
                            .status(code)
                            .body(SdkBody::from(rsp))
                            .unwrap()
                    }),
                });
            config_builder = match endpoint_url {
                Some(endpoint_url) => config_builder.endpoint_url(endpoint_url),
                None => config_builder,
            };

            secretsmanager::Client::from_conf(config_builder.build())
        }
    }
}
