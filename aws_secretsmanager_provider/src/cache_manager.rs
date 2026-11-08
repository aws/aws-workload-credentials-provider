use crate::error::HttpError;
use crate::utils::err_response;
use aws_sdk_secretsmanager::error::ProvideErrorMetadata;
use aws_sdk_secretsmanager::operation::describe_secret::DescribeSecretError;
use aws_sdk_secretsmanager::operation::get_secret_value::GetSecretValueError;
use aws_secretsmanager_caching::SecretsManagerCachingClient;
use aws_smithy_runtime_api::client::orchestrator::HttpResponse;
use aws_smithy_runtime_api::client::result::SdkError;
use aws_workload_credentials_provider_common::config::types::SecretsManagerConfig;
use log::{error, info, warn};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Wrapper around the caching library
///
/// Routes requests to the appropriate caching client based on role ARN.
/// The default client uses the provider's own credentials. Role clients
/// use AssumeRole credentials and are created lazily on first request.
#[derive(Debug)]
pub struct CacheManager {
    default_client: Arc<SecretsManagerCachingClient>,
    role_clients: RwLock<HashMap<String, Arc<SecretsManagerCachingClient>>>,
    config: SecretsManagerConfig,
    #[cfg(not(test))]
    base_sdk_config: aws_config::SdkConfig,
}

// Use either the real Secrets Manager client or the stub for testing
#[doc(hidden)]
#[cfg(not(test))]
use crate::utils::validate_and_create_asm_client as asm_client;
#[cfg(test)]
use tests::init_client as asm_client;

#[cfg(not(test))]
use crate::utils::create_role_asm_client;

/// Wrapper around the caching library
///
/// Used to cache and retrieve secrets.
impl CacheManager {
    /// Create a new CacheManager.
    pub async fn new(cfg: &SecretsManagerConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let (client, sdk_config) = asm_client(cfg).await?;
        let default_client = Arc::new(caching_client(client, cfg)?);

        Ok(Self {
            default_client,
            role_clients: RwLock::new(HashMap::new()),
            config: cfg.clone(),
            #[cfg(not(test))]
            base_sdk_config: sdk_config,
        })
    }

    /// Test helper: a CacheManager that uses `default_client` as is, for tests
    /// that need different timeouts than `caching_client` sets.
    #[cfg(test)]
    pub(crate) fn with_default_client(
        cfg: &SecretsManagerConfig,
        default_client: SecretsManagerCachingClient,
    ) -> Self {
        Self {
            default_client: Arc::new(default_client),
            role_clients: RwLock::new(HashMap::new()),
            config: cfg.clone(),
        }
    }

    /// Fetch a secret from the cache, routing to the appropriate client based on role ARN.
    ///
    /// # Arguments
    ///
    /// * `secret_id` - The name of the secret to fetch.
    /// * `version` - The version of the secret to fetch.
    /// * `label` - The label of the secret to fetch.
    /// * `refresh_now` - Whether to serve from the cache or fetch from ASM.
    /// * `role_arn` - Optional IAM role ARN for cross-account access via AssumeRole.
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - The value of the secret.
    /// * `Err((u16, String))` - The error code and message.
    ///
    /// # Errors
    ///
    /// * `SerializationError` - The error returned from the serde_json::to_string method.
    /// * `HttpError(400, ...)` - Max roles exceeded.
    /// * `HttpError(403, ...)` - For credential or access denied errors (e.g. failed AssumeRole).
    /// * `HttpError(504, ...)` - A timeout, including one while creating a role client
    ///   or loading credentials.
    ///
    /// # Example
    ///
    ///
    /// let cache_manager = CacheManager::new().await.unwrap();
    /// let value = cache_manager.fetch("my-secret", None, None).unwrap();
    ///
    pub async fn fetch(
        &self,
        secret_id: &str,
        version: Option<&str>,
        label: Option<&str>,
        refresh_now: bool,
        role_arn: Option<&str>,
    ) -> Result<String, HttpError> {
        let client = self.get_client(role_arn).await?;

        // Read the secret from the cache or fetch it over the network.
        let found = match client
            .get_secret_value(secret_id, version, label, refresh_now)
            .await
        {
            Ok(value) => value,
            Err(e) if e.is::<SdkError<GetSecretValueError, HttpResponse>>() => {
                let (code, msg, status) = svc_err::<GetSecretValueError>(e)?;
                return Err(HttpError(status, err_response(&code, &msg)));
            }
            Err(e) if e.is::<SdkError<DescribeSecretError, HttpResponse>>() => {
                let (code, msg, status) = svc_err::<DescribeSecretError>(e)?;
                return Err(HttpError(status, err_response(&code, &msg)));
            }
            Err(e) => {
                error!("Internal error for {secret_id} - {:?}", e);
                return Err(int_err());
            }
        };

        // Serialize and return the value
        match serde_json::to_string(&found) {
            Ok(value) => Ok(value),
            _ => {
                error!("Serialization error for {secret_id}");
                Err(int_err())?
            }
        }
    }

    /// Checks whether the number of cached role clients has reached the configured max_roles limit.
    ///
    /// Called under both read and write locks to prevent concurrent requests from
    /// exceeding the limit.
    ///
    /// # Arguments
    ///
    /// * `current` - The current number of cached role clients.
    /// * `role_arn` - The IAM role ARN being requested
    ///
    /// # Errors
    ///
    /// * `HttpError(400, ...)` - If the `max_roles` limit has been reached.
    fn check_max_roles(&self, current: usize, role_arn: &str) -> Result<(), HttpError> {
        if current >= self.config.max_roles {
            error!(
                "Max roles limit ({}) reached, rejecting role assumption request for {}",
                self.config.max_roles, role_arn
            );
            return Err(HttpError(
                400,
                err_response(
                    "MaxRolesExceeded",
                    &format!(
                        "The maximum number of assumed roles ({}) has been reached. Unable to assume the following role to create a client: {}",
                        self.config.max_roles,
                        role_arn
                    ),
                ),
            ));
        }
        Ok(())
    }

    /// Get the appropriate caching client for the request.
    ///
    /// Returns the default client when no role ARN is provided. For role-based
    /// requests, looks up an existing client or lazily creates one using
    /// AssumeRole credentials. Uses double-check locking to avoid duplicate
    /// client creation under concurrent requests.
    ///
    /// # Arguments
    ///
    /// * `role_arn` - Optional IAM role ARN. `None` returns the default client.
    ///
    /// # Returns
    ///
    /// * `Ok(Arc<SecretsManagerCachingClient>)` - The caching client for the request.
    ///
    /// # Errors
    ///
    /// * `HttpError(400, ...)` - If the `max_roles` limit has been reached.
    /// * `HttpError(403, ...)` - If role client creation fails (e.g. STS AssumeRole denied).
    /// * `HttpError(504, ...)` - If role client creation times out.
    pub(crate) async fn get_client(
        &self,
        role_arn: Option<&str>,
    ) -> Result<Arc<SecretsManagerCachingClient>, HttpError> {
        let arn = match role_arn {
            None => return Ok(self.default_client.clone()),
            Some(arn) => arn,
        };
        // Check if client already exists
        {
            let clients = self.role_clients.read().await;
            if let Some(client) = clients.get(arn) {
                return Ok(client.clone());
            }
            self.check_max_roles(clients.len(), arn)?;
        }

        // Create the role client
        let role_client = self
            .create_role_client(arn)
            .await
            .map_err(|e| role_client_err(arn, e.as_ref()))?;

        // Write lock: insert after double-checking the map and checking max_roles validation
        let (client, count) = {
            let mut clients = self.role_clients.write().await;
            if let Some(client) = clients.get(arn) {
                return Ok(client.clone());
            }
            self.check_max_roles(clients.len(), arn)?;

            let client = Arc::new(role_client);
            clients.insert(arn.to_string(), client.clone());
            (client, clients.len())
        };

        info!(
            "Created new role client ({}/{})",
            count, self.config.max_roles,
        );

        Ok(client)
    }

    /// Create a new SecretsManagerCachingClient for the given role ARN.
    ///
    /// Builds an SDK client with AssumeRole credentials using the stored base
    /// SDK config, then wraps it in a caching client with the provider's configured
    /// cache size, TTL, and transient error settings.
    ///
    /// # Arguments
    ///
    /// * `role_arn` - The IAM role ARN to assume.
    ///
    /// # Returns
    ///
    /// * `Ok(SecretsManagerCachingClient)` - A caching client with AssumeRole credentials.
    ///
    /// # Errors
    ///
    /// * `Box<dyn std::error::Error>` - If the AssumeRoleProvider or caching client creation fails.
    #[cfg(not(test))]
    async fn create_role_client(
        &self,
        role_arn: &str,
    ) -> Result<SecretsManagerCachingClient, Box<dyn std::error::Error>> {
        let asm_client =
            create_role_asm_client(&self.config, &self.base_sdk_config, role_arn).await?;

        Ok(caching_client(asm_client, &self.config)?)
    }

    /// Test stub for creating role clients — uses the same fake client as default.
    #[cfg(test)]
    async fn create_role_client(
        &self,
        _role_arn: &str,
    ) -> Result<SecretsManagerCachingClient, Box<dyn std::error::Error>> {
        let (client, _) = asm_client(&self.config).await?;
        Ok(caching_client(client, &self.config)?)
    }
}

/// Wraps an SDK client in a caching client with the provider's cache size,
/// TTL and transient error settings. Prefetch batch calls get their own,
/// longer per-attempt timeout.
///
/// # Arguments
///
/// * `asm_client` - The Secrets Manager SDK client to wrap.
/// * `cfg` - The provider's Secrets Manager settings.
fn caching_client(
    asm_client: aws_sdk_secretsmanager::Client,
    cfg: &SecretsManagerConfig,
) -> Result<SecretsManagerCachingClient, aws_secretsmanager_caching::secret_store::SecretStoreError>
{
    Ok(SecretsManagerCachingClient::new(
        asm_client,
        cfg.cache.cache_size,
        Duration::from_secs(cfg.cache.ttl_seconds as u64),
        cfg.ignore_transient_errors,
    )?
    .with_batch_attempt_timeout(crate::constants::PREFETCH_BATCH_ATTEMPT_TIMEOUT))
}

/// Private helper to format in internal service error response.
#[doc(hidden)]
fn int_err() -> HttpError {
    HttpError(500, err_response("InternalFailure", ""))
}

/// Private helper to log a role client creation failure and map it to an HTTP error.
///
/// A timeout while setting up the role's credentials (the per-attempt SDK
/// operation timeout, or a connector-level timeout) returns 504, the same as a
/// timed-out fetch, so a slow call isn't reported as a permissions problem.
/// Any other failure (e.g. AssumeRole denied) returns 403.
///
/// # Arguments
///
/// * `role_arn` - The IAM role ARN the client was being created for.
/// * `err` - The error returned while creating the role client.
#[doc(hidden)]
fn role_client_err(role_arn: &str, err: &(dyn std::error::Error + 'static)) -> HttpError {
    if is_timeout_in_chain(err) {
        warn!(
            "Setting up credentials for role {} timed out (the {}s per-attempt SDK operation \
             timeout or a connector-level timeout); returning 504: {:?}",
            role_arn,
            crate::constants::SDK_OP_ATTEMPT_TIMEOUT.as_secs(),
            err
        );
        return HttpError(
            504,
            err_response(
                "TimeoutError",
                &format!("Timed out creating caching client from role: {role_arn}"),
            ),
        );
    }
    error!("Failed to create role client for {}: {:?}", role_arn, err);
    HttpError(
        403,
        err_response(
            "AccessDeniedException",
            &format!("Failed to create caching client from role: {role_arn}"),
        ),
    )
}

/// Private helper to check whether an SDK error has a timeout anywhere in it.
///
/// The SDK loads credentials inside each call's attempt, e.g. AssumeRole
/// inside the eager GetCallerIdentity when creating a role client, or a
/// credential refresh inside GetSecretValue. A hung credential call usually
/// ends as the outer call's own timeout. But if the credential call's timeout
/// fires first (both have the same attempt timeout), the SDK wraps it in a
/// credentials error inside a non-timeout DispatchFailure. So this walks the
/// whole `source()` chain, not just the top error.
///
/// The identity cache's own load timeout (5s by default) uses a private error
/// type and isn't detected here. It can't fire first while the per-attempt
/// timeout is shorter than that.
#[doc(hidden)]
fn is_timeout_in_chain(err: &(dyn std::error::Error + 'static)) -> bool {
    use aws_sdk_sts::operation::assume_role::AssumeRoleError;
    use aws_sdk_sts::operation::get_caller_identity::GetCallerIdentityError;
    use aws_smithy_runtime_api::client::result::ConnectorError;

    std::iter::successors(Some(err), |e| e.source()).any(|e| {
        // A connector-level timeout is a ConnectorError at some layer; a
        // per-attempt timeout is an SdkError::TimeoutError on either call.
        e.downcast_ref::<ConnectorError>()
            .is_some_and(ConnectorError::is_timeout)
            || matches!(
                e.downcast_ref::<SdkError<GetCallerIdentityError, HttpResponse>>(),
                Some(SdkError::TimeoutError(_))
            )
            || matches!(
                e.downcast_ref::<SdkError<AssumeRoleError, HttpResponse>>(),
                Some(SdkError::TimeoutError(_))
            )
    })
}

/// Private helper to extract the error code, message, and status code from an SDK exception.
///
/// Downcasts the exception into the specific SDK exception type and retrieves
/// the exception code (e.g. ResourceNotFoundException), error message, and http
/// status code or returns an error if the fields are not present. Timeout and
/// network errors are also translated to appropriate error codes.
///
/// # Returns
///
/// * `Ok((code, msg, status))` - A tuple of error code, error message, and http status code.
/// * `Err((500, InternalFailureString))` - An internal service error.
#[doc(hidden)]
fn svc_err<S>(err: Box<dyn std::error::Error>) -> Result<(String, String, u16), HttpError>
where
    S: ProvideErrorMetadata + std::error::Error + 'static,
{
    let sdk_err = err
        .downcast_ref::<SdkError<S, HttpResponse>>()
        .ok_or(int_err())?;

    // Get the error metadata and translate timeouts to 504 and network errors to 502
    let err_meta = match sdk_err {
        SdkError::ServiceError(serr) => serr.err().meta(),
        SdkError::DispatchFailure(derr) if derr.is_timeout() => {
            // Connector-level timeout (connect / TLS / read). The per-attempt
            // operation timeout surfaces as SdkError::TimeoutError below.
            warn!("Secrets Manager request failed with a connector-level timeout (connect/TLS/read); returning 504");
            return Ok(("TimeoutError".into(), "Timeout".into(), 504));
        }
        SdkError::TimeoutError(_) => {
            // Print the bound so on-call can see which timeout fired.
            warn!(
                "Secrets Manager request exceeded the {}s per-attempt SDK operation \
                 timeout; returning 504",
                crate::constants::SDK_OP_ATTEMPT_TIMEOUT.as_secs()
            );
            return Ok(("TimeoutError".into(), "Timeout".into(), 504));
        }
        SdkError::DispatchFailure(derr) if derr.is_io() => {
            return Ok(("ConnectionError".into(), "Read Error".into(), 502));
        }
        // The AWS SDK wraps credential-refresh failures (e.g. a
        // revoked AssumeRole trust relationship) as DispatchFailure with
        // kind=Other. There is no typed error variant or metadata accessor on
        // DispatchFailure for credential errors — the inner STS error is buried
        // inside Box<dyn Error> layers (ConnectorError -> ProviderError ->
        // ServiceError -> Unhandled). For now, using string matching.
        SdkError::DispatchFailure(derr) if derr.is_other() => {
            // A credential load or refresh that timed out first is wrapped here.
            if is_timeout_in_chain(err.as_ref()) {
                warn!(
                    "Loading credentials for a Secrets Manager request timed out (the {}s \
                     per-attempt SDK operation timeout or a connector-level timeout); \
                     returning 504: {:?}",
                    crate::constants::SDK_OP_ATTEMPT_TIMEOUT.as_secs(),
                    derr
                );
                return Ok(("TimeoutError".into(), "Timeout".into(), 504));
            }
            let msg = format!("{:?}", derr);
            if msg.contains("AccessDenied") {
                return Ok(("AccessDeniedException".into(), msg, 403));
            }
            return Err(int_err());
        }
        SdkError::ResponseError(_) => {
            return Ok(("ConnectionError".into(), "Response Error".into(), 502));
        }
        _ => return Err(int_err()),
    };

    let code = err_meta.code().ok_or(int_err())?;
    let msg = err_meta.message().ok_or(int_err())?;
    let status = sdk_err.raw_response().ok_or(int_err())?.status().as_u16();

    Ok((code.into(), msg.into(), status))
}

#[cfg(test)]
pub mod tests {
    use crate::cache_manager::CacheManager;
    use crate::utils::AgentModifierInterceptor;
    use aws_config::BehaviorVersion;
    use aws_sdk_secretsmanager as secretsmanager;
    use aws_smithy_runtime::client::http::test_util::{infallible_client_fn, NeverClient};
    use aws_smithy_types::body::SdkBody;
    use aws_workload_credentials_provider_common::config::types::SecretsManagerConfig;
    use aws_workload_credentials_provider_common::constants::PROVIDER_NAME;
    use http::{Request, Response};
    use serde_json::Value;
    use std::cell::RefCell;
    use std::sync::Arc;
    use std::thread::sleep;
    use std::thread_local;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    pub const FAKE_ARN: &str =
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:{{name}}-NhBWsc";
    pub const DEFAULT_VERSION: &str = "5767290c-d089-49ed-b97c-17086f8c9d79";
    pub const DEFAULT_LABEL: &str = "AWSCURRENT";
    pub const DEFAULT_SECRET_STRING: &str = "hunter2";

    // Template GetSecretValue responses for testing
    const GSV_BODY: &str = r###"{
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
    const DESC_BODY: &str = r###"{
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

    // Template for testing other errors (bad creds in this case)
    const OTHER_EXCEPTION_BODY: &str = r###"{
        "__type":"InvalidSignatureException",
        "message":"The request signature we calculated does not match ..."
    }"###;

    // Template for testing resource not found with DescribeSecret
    const NOT_FOUND_EXCEPTION_BODY: &str = r###"{
        "__type":"ResourceNotFoundException",
        "message":"Secrets Manager can't find the specified secret."
    }"###;

    // Used to inject a test client to stub off Secrets Manager network calls.
    thread_local! {
        static CLIENT: RefCell<secretsmanager::Client> = RefCell::new(def_fake_client());
    }

    // Test interface to override the default client used.
    pub fn set_client(client: secretsmanager::Client) {
        CLIENT.set(client);
    }

    // Used to replace the real client with the stub client.
    pub async fn init_client(
        _cfg: &SecretsManagerConfig,
    ) -> Result<(secretsmanager::Client, ()), Box<dyn std::error::Error>> {
        Ok((CLIENT.with_borrow(|v| v.clone()), ()))
    }

    // Private helper to look at the request and provide the correct response.
    fn format_rsp(req: Request<SdkBody>) -> (u16, String) {
        let (parts, body) = req.into_parts();
        assert!(parts.headers["user-agent"]
            .to_str()
            .unwrap()
            .contains(PROVIDER_NAME)); // validate user-agent

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
                return (
                    400,
                    r#"{"__type":"InvalidParameterException","message":"invalid"}"#.to_string(),
                );
            }

            if secret_ids.iter().any(|s| s.starts_with("NOTFOUND")) {
                let valid = secret_ids
                    .iter()
                    .find(|s| !s.starts_with("NOTFOUND"))
                    .unwrap_or(&"Valid");
                let err = secret_ids
                    .iter()
                    .find(|s| s.starts_with("NOTFOUND"))
                    .unwrap_or(&"NOTFOUND");
                return (
                    200,
                    format!(
                        r#"{{"SecretValues":[{{"ARN":"{}","Name":"{}","VersionId":"{}","SecretString":"{}","VersionStages":["{}"],"CreatedDate":1569534789.046}}],"Errors":[{{"SecretId":"{}","ErrorCode":"ResourceNotFoundException","Message":"not found"}}]}}"#,
                        FAKE_ARN.replace("{{name}}", valid),
                        valid,
                        DEFAULT_VERSION,
                        DEFAULT_SECRET_STRING,
                        DEFAULT_LABEL,
                        err
                    ),
                );
            }

            // For filter-based requests or secret ID list requests, return a single secret
            let name = if has_filters {
                "TaggedSecret"
            } else {
                secret_ids.first().unwrap_or(&"MyTest")
            };
            return (
                200,
                format!(
                    r#"{{"SecretValues":[{{"ARN":"{}","Name":"{}","VersionId":"{}","SecretString":"{}","VersionStages":["{}"],"CreatedDate":1569534789.046}}],"Errors":[]}}"#,
                    FAKE_ARN.replace("{{name}}", name),
                    name,
                    DEFAULT_VERSION,
                    DEFAULT_SECRET_STRING,
                    DEFAULT_LABEL
                ),
            );
        }

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
            "secretsmanager.GetSecretValue" if name.starts_with("OTHERERROR") => {
                (400, OTHER_EXCEPTION_BODY)
            }
            "secretsmanager.DescribeSecret" if name.starts_with("NOTFOUND") => {
                (400, NOT_FOUND_EXCEPTION_BODY)
            }
            "secretsmanager.GetSecretValue" => (200, GSV_BODY),
            "secretsmanager.DescribeSecret" => (200, DESC_BODY),
            _ => panic!("Unknown operation"),
        };

        // Implement a sleep for testing. We can not do an async sleep here so
        // timeout tests should use the timeout_client instead.
        if let Some(sleep_val) = name.strip_prefix("SleepyTest_") {
            if let Ok(sleep_num) = sleep_val.parse::<u64>() {
                sleep(Duration::from_secs(sleep_num));
            }
        }

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
    pub fn def_fake_client() -> secretsmanager::Client {
        let fake_creds = secretsmanager::config::Credentials::new(
            "AKIDTESTKEY",
            "astestsecretkey",
            Some("atestsessiontoken".to_string()),
            None,
            "",
        );
        let http_client = infallible_client_fn(|_req| {
            let (code, rsp) = format_rsp(_req);
            Response::builder()
                .status(code)
                .body(SdkBody::from(rsp))
                .unwrap()
        });

        secretsmanager::Client::from_conf(
            secretsmanager::Config::builder()
                .behavior_version(BehaviorVersion::latest())
                .credentials_provider(fake_creds)
                .interceptor(AgentModifierInterceptor)
                .region(secretsmanager::config::Region::new("us-west-2"))
                .http_client(http_client)
                .build(),
        )
    }

    // Test client that makes all Secrets Manager calls hang. Sets NO SDK
    // timeout, so `timeout_test` still exercises the inbound-server deadline in
    // `server.rs`.
    pub fn timeout_client() -> secretsmanager::Client {
        let fake_creds = secretsmanager::config::Credentials::new(
            "AKIDTESTKEY",
            "astestsecretkey",
            Some("atestsessiontoken".to_string()),
            None,
            "",
        );

        secretsmanager::Client::from_conf(
            secretsmanager::Config::builder()
                .behavior_version(BehaviorVersion::latest())
                .credentials_provider(fake_creds)
                .region(secretsmanager::config::Region::new("us-west-2"))
                .http_client(NeverClient::new())
                .build(),
        )
    }

    // Like `timeout_client()`, but calls abort at `attempt_timeout`. Retries are
    // disabled so it stops after a single attempt.
    pub fn op_timeout_test_client(attempt_timeout: Duration) -> secretsmanager::Client {
        use aws_smithy_types::retry::RetryConfig;
        use aws_smithy_types::timeout::TimeoutConfig;

        let fake_creds = secretsmanager::config::Credentials::new(
            "AKIDTESTKEY",
            "astestsecretkey",
            Some("atestsessiontoken".to_string()),
            None,
            "",
        );

        secretsmanager::Client::from_conf(
            secretsmanager::Config::builder()
                .behavior_version(BehaviorVersion::latest())
                .credentials_provider(fake_creds)
                .region(secretsmanager::config::Region::new("us-west-2"))
                .timeout_config(
                    TimeoutConfig::builder()
                        .operation_attempt_timeout(attempt_timeout)
                        .build(),
                )
                .retry_config(RetryConfig::disabled())
                .http_client(NeverClient::new())
                .build(),
        )
    }

    // Helper to create a CacheManager with a specific config.
    async fn cache_manager_with_config(config: &SecretsManagerConfig) -> CacheManager {
        CacheManager::new(config)
            .await
            .expect("cache manager failed")
    }

    // Verify fetch without role_arn uses the default client (backward compat).
    #[tokio::test]
    async fn test_fetch_without_role_arn() {
        let config = SecretsManagerConfig::default();
        let cm = cache_manager_with_config(&config).await;
        let result = cm.fetch("MySecret", None, None, false, None).await;
        assert!(result.is_ok());
        let body: Value = serde_json::from_str(&result.unwrap()).unwrap();
        assert_eq!(body["SecretString"], DEFAULT_SECRET_STRING);

        // Verify no role clients were created
        let clients = cm.role_clients.read().await;
        assert_eq!(clients.len(), 0);
    }

    // Verify a hung Secrets Manager response is bounded by the per-attempt SDK
    // timeout. Asserts on timing, because the inbound-server deadline also
    // returns 504, so the status alone can't show which timeout fired.
    #[tokio::test]
    async fn test_fetch_bounded_by_op_timeout() {
        // RAII guard: restore the default client even if an assertion below
        // panics, so this test never leaves the NeverClient installed.
        struct ClientGuard;
        impl Drop for ClientGuard {
            fn drop(&mut self) {
                set_client(def_fake_client());
            }
        }
        let _guard = ClientGuard;

        // Use the real production per-attempt value.
        let attempt_timeout = crate::constants::SDK_OP_ATTEMPT_TIMEOUT;
        set_client(op_timeout_test_client(attempt_timeout));
        let config = SecretsManagerConfig::default();
        let cm = cache_manager_with_config(&config).await;

        let start = std::time::Instant::now();
        let result = cm.fetch("MySecret", None, None, false, None).await;
        let elapsed = start.elapsed();

        let err = result.expect_err("expected a timeout error");
        assert_eq!(err.0, 504, "timeout should surface as HTTP 504");
        let body: Value = serde_json::from_str(&err.1).unwrap();
        assert_eq!(body["__type"], "TimeoutError");

        // The per-attempt timeout (retries disabled) fires at
        // SDK_OP_ATTEMPT_TIMEOUT (2s), far under the 10s inbound-server
        // deadline. Generous upper bound to avoid CI flakiness.
        assert!(
            elapsed < Duration::from_secs(5),
            "fetch should abort at the op timeout, took {elapsed:?}"
        );
    }

    // Verify the role client is cached and reused on subsequent requests.
    #[tokio::test]
    async fn test_role_client_cached() {
        let config = SecretsManagerConfig::default();
        let cm = cache_manager_with_config(&config).await;
        let role = "arn:aws:iam::123456789012:role/CachedRole";

        let r1 = cm.fetch("MySecret", None, None, false, Some(role)).await;
        assert!(r1.is_ok());
        let r2 = cm.fetch("MySecret", None, None, false, Some(role)).await;
        assert!(r2.is_ok());

        // Verify only one client was created
        let clients = cm.role_clients.read().await;
        assert_eq!(clients.len(), 1);
    }

    // Prefetch batch calls get the longer prefetch bound on both the default
    // and role clients.
    #[tokio::test]
    async fn test_caching_clients_use_prefetch_batch_timeout() {
        let config = SecretsManagerConfig::default();
        let cm = cache_manager_with_config(&config).await;
        let expected = Some(crate::constants::PREFETCH_BATCH_ATTEMPT_TIMEOUT);

        let default_client = cm.get_client(None).await.expect("default client");
        assert_eq!(default_client.batch_attempt_timeout(), expected);

        let role_client = cm
            .get_client(Some("arn:aws:iam::123456789012:role/PrefetchRole"))
            .await
            .expect("role client");
        assert_eq!(role_client.batch_attempt_timeout(), expected);
    }

    // Verify max_roles limit is enforced.
    #[tokio::test]
    async fn test_max_roles_limit_enforced() {
        let config = SecretsManagerConfig {
            max_roles: 2,
            ..Default::default()
        };
        let cm = cache_manager_with_config(&config).await;

        // Fill up to the limit (max_roles = 2)
        let r1 = cm
            .fetch(
                "MySecret",
                None,
                None,
                false,
                Some("arn:aws:iam::111111111111:role/Role1"),
            )
            .await;
        assert!(r1.is_ok());

        let r2 = cm
            .fetch(
                "MySecret",
                None,
                None,
                false,
                Some("arn:aws:iam::222222222222:role/Role2"),
            )
            .await;
        assert!(r2.is_ok());

        // Verify 2 clients were created
        {
            let clients = cm.role_clients.read().await;
            assert_eq!(clients.len(), 2);
        }

        // Third role should be rejected
        let r3 = cm
            .fetch(
                "MySecret",
                None,
                None,
                false,
                Some("arn:aws:iam::333333333333:role/Role3"),
            )
            .await;
        assert!(r3.is_err());
        let err = r3.unwrap_err();
        assert_eq!(err.0, 400);
        assert!(err.1.contains("MaxRolesExceeded"));

        // server continues to serve after max role limit
        let r2 = cm
            .fetch(
                "MySecret",
                None,
                None,
                false,
                Some("arn:aws:iam::222222222222:role/Role2"),
            )
            .await;
        assert!(r2.is_ok());
    }

    // Verify concurrent requests for the same role don't create duplicate clients.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_same_role_no_duplicates() {
        let config = SecretsManagerConfig::default();
        let cm = Arc::new(cache_manager_with_config(&config).await);
        let role = "arn:aws:iam::123456789012:role/ConcurrentRole";

        let mut handles = vec![];
        for _ in 0..5 {
            let cm = cm.clone();
            let role = role.to_string();
            handles.push(tokio::spawn(async move {
                cm.fetch("MySecret", None, None, false, Some(&role)).await
            }));
        }

        for h in handles {
            assert!(h.await.unwrap().is_ok());
        }

        // Only one client should exist despite 5 concurrent requests along 4 threads
        let clients = cm.role_clients.read().await;
        assert_eq!(clients.len(), 1);
    }

    // Verify multiple distinct roles each get their own cached client.
    #[tokio::test]
    async fn test_multiple_role_clients_stored() {
        let config = SecretsManagerConfig::default();
        let cm = cache_manager_with_config(&config).await;

        let roles = [
            "arn:aws:iam::111111111111:role/RoleA",
            "arn:aws:iam::222222222222:role/RoleB",
            "arn:aws:iam::333333333333:role/RoleC",
        ];

        for role in &roles {
            cm.fetch("MySecret", None, None, false, Some(role))
                .await
                .unwrap();
        }

        let clients = cm.role_clients.read().await;
        assert_eq!(clients.len(), roles.len());
        for role in &roles {
            assert!(clients.contains_key(*role), "missing client for {role}");
        }
    }

    // Verify a timeout while creating a role client returns 504, not 403.
    #[test]
    fn test_role_client_err_timeout_is_504() {
        use aws_sdk_sts::operation::get_caller_identity::GetCallerIdentityError;
        use aws_smithy_runtime_api::client::orchestrator::HttpResponse;
        use aws_smithy_runtime_api::client::result::{ConnectorError, SdkError};

        use aws_credential_types::provider::error::CredentialsError;
        use aws_sdk_sts::operation::assume_role::AssumeRoleError;

        let role = "arn:aws:iam::123456789012:role/SlowRole";
        let attempt: SdkError<GetCallerIdentityError, HttpResponse> =
            SdkError::timeout_error("attempt timed out");
        let connector: SdkError<GetCallerIdentityError, HttpResponse> =
            SdkError::dispatch_failure(ConnectorError::timeout("connect timed out".into()));
        // AssumeRole's own timeout, wrapped the way the SDK wraps it.
        let inner: SdkError<AssumeRoleError, HttpResponse> =
            SdkError::timeout_error("attempt timed out");
        let nested: SdkError<GetCallerIdentityError, HttpResponse> = SdkError::dispatch_failure(
            ConnectorError::other(Box::new(CredentialsError::provider_error(inner)), None),
        );

        for e in [attempt, connector, nested] {
            let e: Box<dyn std::error::Error> = Box::new(e);
            let err = super::role_client_err(role, e.as_ref());
            assert_eq!(err.0, 504);
            let body: Value = serde_json::from_str(&err.1).unwrap();
            assert_eq!(body["__type"], "TimeoutError");
            assert_eq!(
                body["message"],
                format!("Timed out creating caching client from role: {role}")
            );
        }
    }

    // Verify any other role client failure still returns 403. A denied
    // AssumeRole reaches GetCallerIdentity as a non-timeout DispatchFailure.
    #[test]
    fn test_role_client_err_other_is_403() {
        use aws_sdk_sts::operation::get_caller_identity::GetCallerIdentityError;
        use aws_smithy_runtime_api::client::orchestrator::HttpResponse;
        use aws_smithy_runtime_api::client::result::{ConnectorError, SdkError};

        use aws_credential_types::provider::error::CredentialsError;

        let role = "arn:aws:iam::123456789012:role/DeniedRole";
        let denied: SdkError<GetCallerIdentityError, HttpResponse> =
            SdkError::dispatch_failure(ConnectorError::other(
                Box::new(CredentialsError::provider_error("AccessDenied")),
                None,
            ));
        let denied: Box<dyn std::error::Error> = Box::new(denied);
        let not_sdk: Box<dyn std::error::Error> = "invalid cache config".into();

        for e in [denied, not_sdk] {
            let err = super::role_client_err(role, e.as_ref());
            assert_eq!(err.0, 403);
            let body: Value = serde_json::from_str(&err.1).unwrap();
            assert_eq!(body["__type"], "AccessDeniedException");
            assert_eq!(
                body["message"],
                format!("Failed to create caching client from role: {role}")
            );
        }
    }

    // Verify that on the fetch path a wrapped credential timeout returns 504,
    // a wrapped AccessDenied still returns 403, and anything else 500.
    #[test]
    fn test_svc_err_wrapped_credential_errors() {
        use aws_credential_types::provider::error::CredentialsError;
        use aws_sdk_secretsmanager::operation::get_secret_value::GetSecretValueError;
        use aws_sdk_sts::operation::assume_role::AssumeRoleError;
        use aws_smithy_runtime_api::client::orchestrator::HttpResponse;
        use aws_smithy_runtime_api::client::result::{ConnectorError, SdkError};

        fn wrapped(inner: CredentialsError) -> Box<dyn std::error::Error> {
            let e: SdkError<GetSecretValueError, HttpResponse> =
                SdkError::dispatch_failure(ConnectorError::other(Box::new(inner), None));
            Box::new(e)
        }

        let timeout: SdkError<AssumeRoleError, HttpResponse> =
            SdkError::timeout_error("attempt timed out");
        let (code, msg, status) = super::svc_err::<GetSecretValueError>(wrapped(
            CredentialsError::provider_error(timeout),
        ))
        .unwrap();
        assert_eq!(
            (code.as_str(), msg.as_str(), status),
            ("TimeoutError", "Timeout", 504)
        );

        let (code, _, status) = super::svc_err::<GetSecretValueError>(wrapped(
            CredentialsError::provider_error("AccessDenied"),
        ))
        .unwrap();
        assert_eq!((code.as_str(), status), ("AccessDeniedException", 403));

        // Neither a timeout nor AccessDenied: still an internal error.
        let err = super::svc_err::<GetSecretValueError>(wrapped(CredentialsError::provider_error(
            "no credentials found",
        )))
        .unwrap_err();
        assert_eq!(err.0, 500);
    }

    const HUNG_ROLE: &str = "arn:aws:iam::123456789012:role/HungRole";

    // Build a base config where every call hangs, and an AssumeRole
    // credentials provider over it, as `create_role_asm_client` does. `inner`
    // is the AssumeRole client's attempt timeout. Retries are off.
    async fn hung_assume_role(
        inner: Option<Duration>,
    ) -> (
        aws_config::SdkConfig,
        aws_credential_types::provider::SharedCredentialsProvider,
    ) {
        use aws_config::sts::AssumeRoleProvider;
        use aws_credential_types::provider::SharedCredentialsProvider;
        use aws_smithy_types::retry::RetryConfig;
        use aws_smithy_types::timeout::TimeoutConfig;

        // `empty_test_environment` keeps host env vars out of the config.
        let mut loader = aws_config::defaults(BehaviorVersion::latest())
            .empty_test_environment()
            .test_credentials()
            .region(aws_config::Region::new("us-west-2"))
            .http_client(NeverClient::new())
            .retry_config(RetryConfig::disabled());
        if let Some(inner) = inner {
            loader = loader.timeout_config(
                TimeoutConfig::builder()
                    .operation_attempt_timeout(inner)
                    .build(),
            );
        }
        let base_config = loader.load().await;

        // Like production, the AssumeRole client copies the base config.
        let provider = AssumeRoleProvider::builder(HUNG_ROLE)
            .configure(&base_config)
            .session_name("secrets-manager-provider")
            .build()
            .await;
        (base_config, SharedCredentialsProvider::new(provider))
    }

    // Run the eager GetCallerIdentity `create_role_asm_client` makes, with the
    // hung AssumeRole inside it, and map the error. `outer` is the
    // GetCallerIdentity attempt timeout. `wrapped` is whether the SDK error is
    // expected to be the wrapped DispatchFailure rather than a TimeoutError, so
    // the test fails if the SDK changes how it reports the timeout.
    async fn hung_role_client_err(
        inner: Option<Duration>,
        outer: Duration,
        wrapped: bool,
    ) -> crate::error::HttpError {
        use aws_smithy_runtime_api::client::result::SdkError;
        use aws_smithy_types::timeout::TimeoutConfig;

        let (base_config, provider) = hung_assume_role(inner).await;
        let sts_client = aws_sdk_sts::Client::from_conf(
            aws_sdk_sts::config::Builder::from(&base_config)
                .credentials_provider(provider)
                .timeout_config(
                    TimeoutConfig::builder()
                        .operation_attempt_timeout(outer)
                        .build(),
                )
                .build(),
        );

        let e = sts_client.get_caller_identity().send().await.unwrap_err();
        if wrapped {
            assert!(matches!(e, SdkError::DispatchFailure(_)), "{e:?}");
        } else {
            assert!(matches!(e, SdkError::TimeoutError(_)), "{e:?}");
        }
        let e: Box<dyn std::error::Error> = Box::new(e);
        super::role_client_err(HUNG_ROLE, e.as_ref())
    }

    // Verify, against the real SDK, that a role client's credential refresh
    // timing out during a fetch returns 504, not 500. The AssumeRole timeout
    // fires first and is wrapped inside a non-timeout DispatchFailure on
    // GetSecretValue.
    #[tokio::test]
    async fn test_fetch_hung_credential_refresh_maps_to_504() {
        use aws_sdk_secretsmanager::operation::get_secret_value::GetSecretValueError;
        use aws_smithy_runtime_api::client::result::SdkError;
        use aws_smithy_types::timeout::TimeoutConfig;

        let (base_config, provider) = hung_assume_role(Some(Duration::from_millis(50))).await;
        let asm_client = secretsmanager::Client::from_conf(
            secretsmanager::config::Builder::from(&base_config)
                .credentials_provider(provider)
                .timeout_config(
                    TimeoutConfig::builder()
                        .operation_attempt_timeout(Duration::from_millis(1000))
                        .build(),
                )
                .build(),
        );

        let e = asm_client
            .get_secret_value()
            .secret_id("MyTest")
            .send()
            .await
            .unwrap_err();
        // Make sure this is the wrapped shape, not a plain TimeoutError.
        assert!(matches!(e, SdkError::DispatchFailure(_)), "{e:?}");
        let (code, _, status) = super::svc_err::<GetSecretValueError>(Box::new(e)).unwrap();
        assert_eq!(status, 504);
        assert_eq!(code, "TimeoutError");
    }

    // Verify, against the real SDK, that a hung AssumeRole ends as 504 when
    // GetCallerIdentity's attempt timeout fires first.
    #[tokio::test]
    async fn test_hung_assume_role_maps_to_504() {
        let err = hung_role_client_err(None, Duration::from_millis(100), false).await;
        assert_eq!(err.0, 504);
    }

    // Verify a hung AssumeRole also ends as 504 when its own attempt timeout
    // fires first. The SDK then wraps that timeout in a credentials error
    // inside a non-timeout DispatchFailure on GetCallerIdentity.
    #[tokio::test]
    async fn test_hung_assume_role_inner_timeout_maps_to_504() {
        let err = hung_role_client_err(
            Some(Duration::from_millis(50)),
            Duration::from_millis(1000),
            true,
        )
        .await;
        assert_eq!(err.0, 504);
    }
}
