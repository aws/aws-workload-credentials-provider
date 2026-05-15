use crate::error::HttpError;
use crate::utils::err_response;
use aws_sdk_secretsmanager::error::ProvideErrorMetadata;
use aws_sdk_secretsmanager::operation::describe_secret::DescribeSecretError;
use aws_sdk_secretsmanager::operation::get_secret_value::GetSecretValueError;
use aws_secretsmanager_caching::SecretsManagerCachingClient;
use aws_smithy_runtime_api::client::orchestrator::HttpResponse;
use aws_smithy_runtime_api::client::result::SdkError;
use log::{error, info};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::Config;

/// Wrapper around the caching library
///
/// Routes requests to the appropriate caching client based on role ARN.
/// The default client uses the agent's own credentials. Role clients
/// use AssumeRole credentials and are created lazily on first request.
#[derive(Debug)]
pub struct CacheManager {
    default_client: Arc<SecretsManagerCachingClient>,
    role_clients: RwLock<HashMap<String, Arc<SecretsManagerCachingClient>>>,
    config: Config,
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
    pub async fn new(cfg: &Config) -> Result<Self, Box<dyn std::error::Error>> {
        let default_client = Arc::new(SecretsManagerCachingClient::new(
            asm_client(cfg).await?,
            cfg.cache_size(),
            cfg.ttl(),
            cfg.ignore_transient_errors(),
        )?);

        Ok(Self {
            default_client,
            role_clients: RwLock::new(HashMap::new()),
            config: cfg.clone(),
            #[cfg(not(test))]
            base_sdk_config: aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await,
        })
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
    ///
    /// # Example
    ///
    /// ```
    /// let cache_manager = CacheManager::new().await.unwrap();
    /// let value = cache_manager.fetch("my-secret", None, None).unwrap();
    /// ```
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
        if current >= self.config.max_roles() {
            error!(
                "Max roles limit ({}) reached, rejecting role assumption request for {}",
                self.config.max_roles(),
                role_arn
            );
            return Err(HttpError(
                400,
                err_response(
                    "MaxRolesExceeded",
                    &format!(
                        "The maximum number of assumed roles ({}) has been reached. Unable to assume the following role to create a client: {}",
                        self.config.max_roles(),
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
        let role_client = self.create_role_client(arn).await.map_err(|e| {
            error!("Failed to create role client for {}: {:?}", arn, e);
            HttpError(
                403,
                err_response(
                    "AccessDeniedException",
                    &format!("Failed to create caching client from role: {arn}"),
                ),
            )
        })?;

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
            count,
            self.config.max_roles()
        );

        Ok(client)
    }

    /// Create a new SecretsManagerCachingClient for the given role ARN.
    ///
    /// Builds an SDK client with AssumeRole credentials using the stored base
    /// SDK config, then wraps it in a caching client with the agent's configured
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

        Ok(SecretsManagerCachingClient::new(
            asm_client,
            self.config.cache_size(),
            self.config.ttl(),
            self.config.ignore_transient_errors(),
        )?)
    }

    /// Test stub for creating role clients — uses the same fake client as default.
    #[cfg(test)]
    async fn create_role_client(
        &self,
        _role_arn: &str,
    ) -> Result<SecretsManagerCachingClient, Box<dyn std::error::Error>> {
        Ok(SecretsManagerCachingClient::new(
            asm_client(&self.config).await?,
            self.config.cache_size(),
            self.config.ttl(),
            self.config.ignore_transient_errors(),
        )?)
    }
}

/// Private helper to format in internal service error response.
#[doc(hidden)]
fn int_err() -> HttpError {
    HttpError(500, err_response("InternalFailure", ""))
}

/// Private helper to extract the error code, message, and status code from an SDK exception.
///
/// Downcasts the exception into the specific SDK exception type and retrieves
/// the excpetion code (e.g. ResourceNotFoundException), error message, and http
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
            return Ok(("TimeoutError".into(), "Timeout".into(), 504));
        }
        SdkError::TimeoutError(_) => {
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
    use super::*;
    use crate::constants::APPNAME;
    use crate::utils::AgentModifierInterceptor;
    use aws_config::BehaviorVersion;
    use aws_sdk_secretsmanager as secretsmanager;
    use aws_smithy_runtime::client::http::test_util::{infallible_client_fn, NeverClient};
    use aws_smithy_types::body::SdkBody;
    use http::{Request, Response};
    use serde_json::Value;
    use std::thread::sleep;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use std::cell::RefCell;
    use std::thread_local;

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
        _cfg: &Config,
    ) -> Result<secretsmanager::Client, Box<dyn std::error::Error>> {
        Ok(CLIENT.with_borrow(|v| v.clone()))
    }

    // Private helper to look at the request and provide the correct reponse.
    fn format_rsp(req: Request<SdkBody>) -> (u16, String) {
        let (parts, body) = req.into_parts();
        assert!(parts.headers["user-agent"]
            .to_str()
            .unwrap()
            .contains(APPNAME)); // validate user-agent

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
    fn def_fake_client() -> secretsmanager::Client {
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

    // Test client that makes all Secrets Manager calls time out.
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

    // Helper to create a CacheManager with a specific config file.
    async fn cache_manager_with_config(config_path: &str) -> CacheManager {
        let cfg = Config::new(Some(config_path)).expect("config failed");
        CacheManager::new(&cfg).await.expect("cache manager failed")
    }

    // Verify fetch without role_arn uses the default client (backward compat).
    #[tokio::test]
    async fn test_fetch_without_role_arn() {
        let cm =
            cache_manager_with_config("tests/resources/configs/config_file_anyport.toml").await;
        let result = cm.fetch("MySecret", None, None, false, None).await;
        assert!(result.is_ok());
        let body: Value = serde_json::from_str(&result.unwrap()).unwrap();
        assert_eq!(body["SecretString"], DEFAULT_SECRET_STRING);

        // Verify no role clients were created
        let clients = cm.role_clients.read().await;
        assert_eq!(clients.len(), 0);
    }

    // Verify the role client is cached and reused on subsequent requests.
    #[tokio::test]
    async fn test_role_client_cached() {
        let cm =
            cache_manager_with_config("tests/resources/configs/config_file_anyport.toml").await;
        let role = "arn:aws:iam::123456789012:role/CachedRole";

        let r1 = cm.fetch("MySecret", None, None, false, Some(role)).await;
        assert!(r1.is_ok());
        let r2 = cm.fetch("MySecret", None, None, false, Some(role)).await;
        assert!(r2.is_ok());

        // Verify only one client was created
        let clients = cm.role_clients.read().await;
        assert_eq!(clients.len(), 1);
    }

    // Verify max_roles limit is enforced.
    #[tokio::test]
    async fn test_max_roles_limit_enforced() {
        let cm =
            cache_manager_with_config("tests/resources/configs/config_file_max_roles_2.toml").await;

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
        let cm = Arc::new(
            cache_manager_with_config("tests/resources/configs/config_file_anyport.toml").await,
        );
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
        let cm =
            cache_manager_with_config("tests/resources/configs/config_file_anyport.toml").await;

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
}
