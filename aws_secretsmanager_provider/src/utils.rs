use crate::constants::{MAX_REQ_TIME_SEC, VERSION};
use crate::failover_credentials_provider::{warn_failover, FailoverCredentialsProvider};
use aws_sdk_secretsmanager::config::interceptors::BeforeTransmitInterceptorContextMut;
use aws_sdk_secretsmanager::config::SharedCredentialsProvider;
use aws_sdk_secretsmanager::config::{ConfigBag, Intercept, RuntimeComponents};
use aws_sdk_secretsmanager::Client as SecretsManagerClient;
use aws_sdk_sts::config::{
    retry::{RetryConfig, RetryPartition},
    Region,
};
use aws_sdk_sts::error::ProvideErrorMetadata;
use aws_secretsmanager_caching::error::is_transient_error;
use aws_types::os_shim_internal::{Env, Fs};
use aws_workload_credentials_provider_common::config::types::SecretsManagerConfig;
use std::env::VarError;
use std::fs;
use std::time::Duration;

#[cfg(not(test))]
use std::env::var; // Use the real std::env::var
#[cfg(test)]
use tests::var_test as var;

/// Helper to format error response body in JSON 1.1 format.
///
/// Callers need to pass in the error code (e.g.  InternalFailure,
/// InvalidParameterException, ect.) and the error message. This function will
/// then format a response body in JSON 1.1 format. All values are properly
/// JSON-escaped via serde_json to prevent injection attacks.
///
/// # Arguments
///
/// * `err_code` - The modeled exception name or InternalFailure for 500s.
/// * `msg` - The optional error message or "" for InternalFailure.
///
/// # Returns
///
/// * `String` - The JSON 1.1 response body.
///
/// # Example
///
///
/// assert_eq!(err_response("InternalFailure", ""), "{\"__type\":\"InternalFailure\"}");
/// assert_eq!(
///     err_response("ResourceNotFoundException", "Secrets Manager can't find the specified secret."),
///     "{\"__type\":\"ResourceNotFoundException\",\"message\":\"Secrets Manager can't find the specified secret.\"}"
/// );
///
#[doc(hidden)]
pub fn err_response(err_code: &str, msg: &str) -> String {
    if msg.is_empty() || err_code == "InternalFailure" {
        return String::from("{\"__type\":\"InternalFailure\"}");
    }
    serde_json::json!({
        "__type": err_code,
        "message": msg
    })
    .to_string()
}

/// Helper function to get the SSRF token value.
///
/// Reads the SSRF token from the configured env variable. If the env variable
/// is a reference to a file (namely file://FILENAME), the data is read in from
/// that file.
///
/// # Arguments
///
/// * `ssrf_env_variables` - The list of environment variable names to check for the SSRF token.
///
/// # Returns
///
/// * `Ok(String)` - The SSRF token value.
/// * `Err(Error)` - Error indicating that the variable is not set or could not be read.
#[doc(hidden)]
pub fn get_token(ssrf_env_variables: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    // Iterate through the env name list looking for the first variable set
    #[allow(clippy::redundant_closure)]
    let found = ssrf_env_variables
        .iter()
        .map(|n| var(n))
        .filter_map(|r| r.ok())
        .next();
    if found.is_none() {
        return Err(Box::new(VarError::NotPresent));
    }
    let val = found.unwrap();

    // If the variable is not a reference to a file, just return the value.
    if !val.starts_with("file://") {
        return Ok(val);
    }

    // Read and return the contents of the file.
    let file = val.strip_prefix("file://").unwrap();
    Ok(fs::read_to_string(file)?.trim().to_string())
}

#[doc(hidden)]
#[cfg(not(test))]
pub use time_out_impl as time_out;
#[cfg(test)]
pub use time_out_test as time_out;

/// Helper function to get the time out setting for request processing.
///
/// # Returns
///
/// * `Duration` - How long to wait before canceling the operation.
#[doc(hidden)]
pub fn time_out_impl() -> Duration {
    Duration::from_secs(MAX_REQ_TIME_SEC)
}
#[cfg(test)]
pub fn time_out_test() -> Duration {
    Duration::from_secs(10) // Timeout in 10 seconds for testing.
}

/// Validates the provided configuration and creates an AWS Secrets Manager client
/// from the latest default AWS configuration.
///
/// # Arguments
///
/// * `config` - A reference to a `SecretsManagerConfig` object containing the necessary configuration
///   parameters for creating the AWS Secrets Manager client.
///
/// # Returns
///
/// * `Ok(SecretsManagerClient)` - An AWS Secrets Manager client if the credentials are valid.
/// * `Err(Box<dyn std::error::Error>)` if there is an error creating the Secrets Manager client
///   or validating the AWS credentials.
#[doc(hidden)]
#[cfg(not(test))]
pub async fn validate_and_create_asm_client(
    config: &SecretsManagerConfig,
) -> Result<(SecretsManagerClient, aws_config::SdkConfig), Box<dyn std::error::Error>> {
    use aws_config::BehaviorVersion;
    use aws_sdk_sts::error::SdkError;
    use aws_sdk_sts::operation::get_caller_identity::GetCallerIdentityError;

    use crate::credentials_file_provider::FileBasedCredentialsProvider;

    let mut sdk_config = aws_config::load_defaults(BehaviorVersion::latest()).await;

    // Use file-based credentials if configured.
    let has_file_provider = if let Some(path) = discover_credentials_file(config) {
        log::info!("Using file-based credentials from: {}", path.display());
        let provider = FileBasedCredentialsProvider::new(&path).await;
        sdk_config = sdk_config
            .into_builder()
            .credentials_provider(
                aws_sdk_secretsmanager::config::SharedCredentialsProvider::new(provider),
            )
            .build();
        true
    } else {
        log::info!("No credentials file found, using default SDK credential chain");
        false
    };

    let mut asm_builder = aws_sdk_secretsmanager::config::Builder::from(&sdk_config)
        .interceptor(AgentModifierInterceptor);
    let mut sts_builder = aws_sdk_sts::config::Builder::from(&sdk_config);
    // For the startup check: the region to retry it in, and the role for its log.
    let mut validation_failover = None;

    // Without a failover region there's nothing to wrap, so skip the check.
    let sts_role_arn = if config.failover.default_failover_region.is_some() {
        own_credentials_role(config, &Env::real(), &Fs::real()).await
    } else {
        None
    };
    if let Some(own_credentials_provider) =
        default_client_credentials(config, &sdk_config, sts_role_arn).await
    {
        validation_failover = Some((
            own_credentials_provider.failover_region.clone(),
            own_credentials_provider.role_arn.clone(),
        ));
        // Set up like a role client, so the STS validation fails over too and
        // Secrets Manager reuses its credentials.
        let (sts_config, asm_config) = role_client_configs(
            &sdk_config,
            config.region.as_deref(),
            SharedCredentialsProvider::new(own_credentials_provider),
            true,
        );
        sts_builder = sts_config.to_builder();
        asm_builder = asm_config.to_builder();
    }

    #[cfg(debug_assertions)]
    if std::env::var("SMA_DISABLE_IDENTITY_CACHE").is_ok() {
        log::info!("Identity caching disabled via SMA_DISABLE_IDENTITY_CACHE");
        asm_builder =
            asm_builder.identity_cache(aws_sdk_secretsmanager::config::IdentityCache::no_cache());
    }

    if let Some(ref region) = config.region {
        asm_builder.set_region(Some(Region::new(region.clone())));
    }

    if config.validate_credentials && !has_file_provider {
        if let Some(ref region) = config.region {
            sts_builder.set_region(Some(Region::new(region.clone())));
        }

        let sts_client = aws_sdk_sts::Client::from_conf(sts_builder.build());
        let (failover_region, role_arn) = validation_failover.unzip();
        let role_arn = role_arn.unwrap_or_else(|| "unknown".into());
        match validate_role_credentials(&sts_client, &role_arn, failover_region.as_deref()).await {
            Ok(()) => (),
            Err(e)
                if config.ignore_transient_errors
                    && e.downcast_ref::<SdkError<GetCallerIdentityError>>()
                        .is_some_and(is_transient_error) => {}
            Err(e) => Err(e)?,
        };
    } else if has_file_provider {
        log::info!("Skipping STS credential validation for file-based credentials");
    }

    Ok((
        aws_sdk_secretsmanager::Client::from_conf(asm_builder.build()),
        sdk_config,
    ))
}

/// The role the agent's own credentials come from through STS: the EKS IRSA
/// role, or a profile's role_arn. A credentials file replaces the default
/// chain; otherwise the sources are checked in the chain's order: environment
/// keys, the selected profile, then the IRSA variables.
///
/// # Returns
///
/// * `Some(role_arn)` - The own credentials come from STS, as this role.
/// * `None` - They don't call STS (a credentials file, static keys,
///   credential_process, SSO, `aws login`, container credentials or IMDS), so
///   a failover-region copy of them can't help.
async fn own_credentials_role(config: &SecretsManagerConfig, env: &Env, fs: &Fs) -> Option<String> {
    if config.credentials_file_path.is_some() {
        return None;
    }
    // The chain treats a blank variable as not set, and reads the secret from
    // SECRET_ACCESS_KEY when AWS_SECRET_ACCESS_KEY isn't set.
    let value = |name: &str| env.get(name).ok().filter(|value| !value.trim().is_empty());
    let secret = value("AWS_SECRET_ACCESS_KEY").or_else(|| value("SECRET_ACCESS_KEY"));
    if value("AWS_ACCESS_KEY_ID").is_some() && secret.is_some() {
        return None;
    }
    let profiles = aws_config::profile::load(fs, env, &Default::default(), None).await;
    let selected_profile = profiles
        .as_ref()
        .ok()
        .and_then(|profiles| profiles.get_profile(profiles.selected_profile()));
    if let Some(profile) = selected_profile {
        // web_identity_token_file needs role_arn too.
        if let Some(role_arn) = profile.get("role_arn") {
            return Some(role_arn.to_owned());
        }
        let local_credentials = [
            "aws_access_key_id",
            "credential_process",
            "sso_session",
            "sso_start_url",
            "login_session",
        ];
        if local_credentials
            .iter()
            .any(|key| profile.get(key).is_some())
        {
            return None;
        }
    }
    value("AWS_WEB_IDENTITY_TOKEN_FILE").and(value("AWS_ROLE_ARN"))
}

/// The default client's own credentials with failover. With a failover region
/// and own credentials from STS, the default chain is retried in the failover
/// region when its STS endpoint looks down (EKS IRSA, or a profile with role_arn).
///
/// # Returns
///
/// * `Some(provider)` - The default chain wrapped with its failover-region copy.
/// * `None` - No failover region, the failover region is the SDK's region, own
///   credentials not from STS (no `sts_role_arn`), or no credentials provider.
async fn default_client_credentials(
    config: &SecretsManagerConfig,
    sdk_config: &aws_config::SdkConfig,
    sts_role_arn: Option<String>,
) -> Option<FailoverCredentialsProvider<SharedCredentialsProvider>> {
    use crate::failover_credentials_provider::primary_attempt_timeout;
    use aws_config::default_provider::credentials::DefaultCredentialsChain;

    let role_arn = sts_role_arn?;
    // The default chain calls STS in the SDK's region, not the configured one.
    let primary_region = sdk_config.region().map(|region| region.to_string());
    let failover_region = config
        .failover
        .default_failover_region
        .as_deref()
        .filter(|region| Some(*region) != primary_region.as_deref())?;
    let primary_provider = sdk_config.credentials_provider()?;
    let failover_provider = DefaultCredentialsChain::builder()
        .configure(own_credentials_config(sdk_config))
        .region(Region::new(failover_region.to_owned()))
        .build()
        .await;
    Some(FailoverCredentialsProvider {
        primary: primary_provider,
        failover: SharedCredentialsProvider::new(failover_provider),
        // The IRSA role or the profile's role_arn, for the failover log only.
        role_arn,
        primary_region: primary_region.unwrap_or_else(|| "unknown".into()),
        failover_region: failover_region.to_owned(),
        primary_timeout: primary_attempt_timeout(Duration::from_millis(
            config.failover.operation_timeout_ms,
        )),
        primary_down_at: Default::default(),
        operation: "OwnCredentials",
    })
}

/// Discover a credentials file from explicit config.
///
/// Returns the configured credentials file path, if set.
/// If the configured path does not exist yet, it is still returned — the provider
/// will start with an empty cache and the background reload will pick up the file
/// when it appears.
#[cfg(not(test))]
fn discover_credentials_file(config: &SecretsManagerConfig) -> Option<std::path::PathBuf> {
    if let Some(path) = &config.credentials_file_path {
        if !path.is_file() {
            log::warn!(
                "Configured credentials_file_path does not exist yet: {}. \
                 The agent will watch for it to appear.",
                path.display()
            );
        }
        return Some(path.clone());
    }

    None
}

/// SDK interceptor to append the agent name and version to the User-Agent header for CloudTrail records.
#[doc(hidden)]
#[derive(Debug)]
pub struct AgentModifierInterceptor;

/// Creates a Secrets Manager client that uses AssumeRole credentials for cross-account access.
///
/// Builds an `AssumeRoleProvider` that handles automatic STS credential refresh,
/// then configures a Secrets Manager SDK client with those credentials. The
/// `AgentModifierInterceptor` is attached for CloudTrail user-agent tracking.
/// With a default failover region, AssumeRole falls back to that region's STS
/// endpoint when the primary region's fails.
///
/// # Arguments
///
/// * `config` - The agent configuration, used for optional region override.
/// * `base_config` - The base AWS SDK config providing default credentials (for the
///   AssumeRole call itself), HTTP client, retry config, and region.
/// * `role_arn` - The ARN of the IAM role to assume (e.g. `arn:aws:iam::123456789012:role/MyRole`).
///
/// # Returns
///
/// * `Ok(SecretsManagerClient)` - A Secrets Manager client configured with AssumeRole credentials.
///
/// # Errors
///
/// * `Box<dyn std::error::Error>` - If the `AssumeRoleProvider` fails to build or the
///   SDK client configuration is invalid.
#[doc(hidden)]
pub async fn create_role_asm_client(
    config: &SecretsManagerConfig,
    base_config: &aws_config::SdkConfig,
    role_arn: &str,
) -> Result<SecretsManagerClient, Box<dyn std::error::Error>> {
    use crate::failover_credentials_provider::primary_attempt_timeout;
    use aws_config::default_provider::credentials::DefaultCredentialsChain;

    let assume_role = |region: Option<&str>| {
        let mut builder = aws_config::sts::AssumeRoleProvider::builder(role_arn)
            .configure(base_config)
            .session_name("secrets-manager-provider");
        if let Some(region) = region {
            builder = builder.region(Region::new(region.to_owned()));
        }
        builder
    };
    let (primary_region, failover_region, pinned_region) = role_regions(config, base_config);
    let primary = assume_role(pinned_region).build().await;
    let shared_provider = match failover_region {
        None => SharedCredentialsProvider::new(primary),
        Some(region) => SharedCredentialsProvider::new(FailoverCredentialsProvider {
            primary,
            // When the agent's own credentials come from STS (EKS IRSA, or a profile
            // with role_arn), resolve them in the failover region too. A credentials
            // file is local, so it's kept.
            failover: if config.credentials_file_path.is_some() {
                assume_role(Some(region)).build().await
            } else {
                let own_credentials = DefaultCredentialsChain::builder()
                    .configure(own_credentials_config(base_config))
                    .region(Region::new(region.to_owned()))
                    .build()
                    .await;
                assume_role(Some(region))
                    .build_from_provider(own_credentials)
                    .await
            },
            role_arn: role_arn.to_owned(),
            // For the failover log only.
            primary_region: primary_region.unwrap_or_else(|| "unknown".into()),
            failover_region: region.to_owned(),
            primary_timeout: primary_attempt_timeout(Duration::from_millis(
                config.failover.operation_timeout_ms,
            )),
            primary_down_at: Default::default(),
            operation: "AssumeRole",
        }),
    };
    let (sts_config, asm_config) = role_client_configs(
        base_config,
        config.region.as_deref(),
        shared_provider,
        failover_region.is_some(),
    );

    // Eagerly validate the assumed role credentials with a GetCallerIdentity call.
    // The AssumeRoleProvider is lazy — without this, STS errors would only surface
    // on the first Secrets Manager request, returning a generic InternalFailure.
    let sts_client = aws_sdk_sts::Client::from_conf(sts_config);

    // if failure, let error propagate to cache manager
    validate_role_credentials(&sts_client, role_arn, failover_region).await?;

    Ok(SecretsManagerClient::from_conf(asm_config))
}

/// Chooses the regions for a role client's AssumeRole calls.
///
/// # Returns
///
/// * `(primary, failover, pinned)` - The primary region, for the failover log;
///   the failover region, if it differs from the primary; and the region
///   AssumeRole is pinned to.
fn role_regions<'a>(
    config: &'a SecretsManagerConfig,
    base_config: &aws_config::SdkConfig,
) -> (Option<String>, Option<&'a str>, Option<&'a str>) {
    let primary_region = config
        .region
        .clone()
        .or_else(|| base_config.region().map(|r| r.to_string()));

    // Credentials from either region are valid in every region. A failover region
    // equal to the primary would only retry the same endpoint.
    let failover_region = config
        .failover
        .default_failover_region
        .as_deref()
        .filter(|r| Some(*r) != primary_region.as_deref());
    // Pinned to the configured region only with failover, so without it AssumeRole
    // keeps using the SDK's region as before.
    let pinned_region = failover_region.and(config.region.as_deref());
    (primary_region, failover_region, pinned_region)
}

/// Provider config for the agent's own credentials in the failover region, with
/// the base config's FIPS and dual-stack settings and HTTP client.
/// `ProviderConfig::default()` doesn't load them, so without this the failover
/// STS calls skip FIPS endpoints.
fn own_credentials_config(
    base_config: &aws_config::SdkConfig,
) -> aws_config::provider_config::ProviderConfig {
    let provider_config = aws_config::provider_config::ProviderConfig::default()
        .with_use_fips(base_config.use_fips())
        .with_use_dual_stack(base_config.use_dual_stack());
    match base_config.http_client() {
        Some(http_client) => provider_config.with_http_client(http_client),
        None => provider_config,
    }
}

/// Builds the STS and Secrets Manager configs for a role client. Both share one
/// credentials provider and, with failover, an identity cache whose load timeout
/// leaves room for the failover attempt.
///
/// # Arguments
///
/// * `base_config` - The base AWS SDK config.
/// * `configured_region` - The region from the config file, if set.
/// * `shared_provider` - The role's credentials provider.
/// * `failover_enabled` - Whether a failover region is configured.
///
/// # Returns
///
/// * `(aws_sdk_sts::Config, aws_sdk_secretsmanager::Config)` - The STS config for
///   validation and the Secrets Manager config.
fn role_client_configs(
    base_config: &aws_config::SdkConfig,
    configured_region: Option<&str>,
    shared_provider: aws_sdk_secretsmanager::config::SharedCredentialsProvider,
    failover_enabled: bool,
) -> (aws_sdk_sts::Config, aws_sdk_secretsmanager::Config) {
    use crate::failover_credentials_provider::{ATTEMPT_TIMEOUT, LOAD_TIMEOUT};
    use aws_sdk_secretsmanager::config::IdentityCache;
    use aws_sdk_sts::config::timeout::TimeoutConfig;

    // The default 5s load timeout would expire before the failover attempt runs.
    let identity_cache =
        failover_enabled.then(|| IdentityCache::lazy().load_timeout(LOAD_TIMEOUT).build());

    let mut sts_builder = aws_sdk_sts::config::Builder::from(base_config);
    // Set directly: credentials_provider() would wrap it again in a new cache partition.
    sts_builder.set_credentials_provider(Some(shared_provider.clone()));
    if let Some(cache) = &identity_cache {
        sts_builder = sts_builder.identity_cache(cache.clone());
        // Without a read timeout, a primary STS that accepts connections but never
        // answers holds the call until the request times out, so failover never runs.
        let timeouts = base_config
            .timeout_config()
            .map_or_else(TimeoutConfig::builder, TimeoutConfig::to_builder)
            .read_timeout(ATTEMPT_TIMEOUT)
            .build();
        sts_builder.set_timeout_config(Some(timeouts));
    }

    let mut asm_builder = aws_sdk_secretsmanager::config::Builder::from(base_config)
        .interceptor(AgentModifierInterceptor);
    // Same partition as the STS client, so the validated credentials are reused.
    asm_builder.set_credentials_provider(Some(shared_provider));
    if let Some(cache) = identity_cache {
        asm_builder = asm_builder.identity_cache(cache);
    }

    if let Some(region) = configured_region {
        sts_builder.set_region(Some(Region::new(region.to_owned())));
        asm_builder.set_region(Some(Region::new(region.to_owned())));
    }

    (sts_builder.build(), asm_builder.build())
}

/// Validates assumed role credentials with a GetCallerIdentity call.
///
/// After a transient error from the primary region's STS endpoint, retries the
/// call in the failover region, so a role first seen during a primary outage
/// can still be used. The failover call has its own retry partition, so a
/// failing primary can't drain the retry tokens it needs. With a failover
/// region, the primary call gets one attempt, so a hanging primary fails over
/// sooner. A throttled primary is retried with the SDK's retries instead.
///
/// # Arguments
///
/// * `sts_client` - An STS client that uses the role's credentials.
/// * `role_arn` - The role ARN, for the failover log.
/// * `failover_region` - Region to retry in, or `None` to not retry.
///
/// # Errors
///
/// * `Box<dyn std::error::Error>` - The primary's `SdkError`, if it isn't
///   retried or the failover fails too.
#[doc(hidden)]
pub async fn validate_role_credentials(
    sts_client: &aws_sdk_sts::Client,
    role_arn: &str,
    failover_region: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut primary = sts_client.get_caller_identity().customize();
    if failover_region.is_some() {
        primary = primary.config_override(
            aws_sdk_sts::config::Builder::default()
                .retry_config(RetryConfig::standard().with_max_attempts(1)),
        );
    }
    match (primary.send().await, failover_region) {
        (Err(e), Some(region)) if is_transient_error(&e) => {
            let failover = sts_client
                .get_caller_identity()
                .customize()
                .config_override(
                    aws_sdk_sts::config::Builder::default()
                        .region(Region::new(region.to_owned()))
                        .retry_partition(RetryPartition::new(format!("sts-{region}"))),
                )
                .send()
                .await;
            warn_failover(
                "GetCallerIdentity",
                role_arn,
                sts_client
                    .config()
                    .region()
                    .map_or("unknown", |r| r.as_ref()),
                &e,
                region,
                &failover,
            );
            // If the failover fails too, return the primary's error.
            failover.map(|_| ()).or(Err(e.into()))
        }
        // Throttling isn't an outage, so it isn't failed over, but it gets the
        // rest of the SDK's 3 attempts, as without a failover region.
        (Err(e), Some(_)) if e.code() == Some("Throttling") => {
            sts_client
                .get_caller_identity()
                .customize()
                .config_override(
                    aws_sdk_sts::config::Builder::default()
                        .retry_config(RetryConfig::standard().with_max_attempts(2)),
                )
                .send()
                .await?;
            Ok(())
        }
        (primary, _) => {
            primary?;
            Ok(())
        }
    }
}

/// SDK interceptor to append the agent name and version to the User-Agent header for CloudTrail records.
///
/// This interceptor adds the agent name and version to the User-Agent header
/// of outbound Secrets Manager SDK requests.
#[doc(hidden)]
impl Intercept for AgentModifierInterceptor {
    fn name(&self) -> &'static str {
        "AgentModifierInterceptor"
    }

    fn modify_before_signing(
        &self,
        context: &mut BeforeTransmitInterceptorContextMut<'_>,
        _runtime_components: &RuntimeComponents,
        _cfg: &mut ConfigBag,
    ) -> Result<(), aws_sdk_secretsmanager::error::BoxError> {
        let request = context.request_mut();
        let agent = request.headers().get("user-agent").unwrap_or_default(); // Get current agent
        let full_agent = format!(
            "{agent} {}/{}",
            aws_workload_credentials_provider_common::constants::PROVIDER_NAME,
            VERSION.unwrap_or("0.0.0")
        );
        request.headers_mut().insert("user-agent", full_agent); // Overwrite header.

        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use aws_workload_credentials_provider_common::config::validator::ConfigValidator;
    use std::cell::RefCell;
    use std::env::temp_dir;
    use std::thread_local;
    use std::time::{SystemTime, UNIX_EPOCH};

    // Used to cleanup resources after test completion.
    pub struct CleanUp<'a> {
        pub file: Option<&'a str>,
    }

    impl Drop for CleanUp<'_> {
        fn drop(&mut self) {
            // Clear env var injections.
            ENVVAR.set(None);

            // Cleanup temp files.
            if let Some(name) = self.file {
                let _ = std::fs::remove_file(name);
            }
        }
    }

    // Create a temp file name for a test.
    pub fn tmpfile_name(suffix: &str) -> String {
        format!(
            "{}/{}_{:?}_{suffix}",
            temp_dir().display(),
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
        )
    }

    // Used to inject env variable values for testing. Uses thread local data since
    // multi-threaded tests setting process wide env variables can collide.
    thread_local! {
        static ENVVAR: RefCell<Option<Vec<(&'static str, &'static str)>>> = const { RefCell::new(None) };
    }
    pub fn set_test_var(key: &'static str, val: &'static str) {
        ENVVAR.set(Some(vec![(key, val)]));
    }
    pub fn set_test_vars(vars: Vec<(&'static str, &'static str)>) {
        ENVVAR.set(Some(vars));
    }

    // Stub std::env::var that reads injected variables from thread_local
    pub fn var_test(key: &str) -> Result<String, VarError> {
        // Shortcut key to force failure.
        if key == "FAIL_TOKEN" {
            return Err(VarError::NotPresent);
        }
        if let Some(varvec) = ENVVAR.with_borrow(|v| v.clone()) {
            let found = varvec.iter().find(|keyval| keyval.0 == key);
            if let Some(some_found) = found {
                return Ok(some_found.1.to_string());
            }
        } else {
            // Return a default value if no value is injected.
            return Ok("xyzzy".to_string()); // Poof!
        }

        Err(VarError::NotPresent) // A fake value was injected but not for this key.
    }

    // Verify we can read the default config variable.
    #[test]
    fn test_env_set() {
        let _cleanup = CleanUp { file: None };
        set_test_var("AWS_TOKEN", "abc123");
        let cfg = ConfigValidator::new()
            .validate(None)
            .expect("config failed");
        assert_eq!(
            get_token(&cfg.secrets_manager.security.ssrf_env_variables).expect("token fail"),
            "abc123"
        );
    }

    // Verify we can use the second variable in the list
    #[test]
    fn test_alt_env_set() {
        let _cleanup = CleanUp { file: None };
        set_test_var("AWS_SESSION_TOKEN", "123abc");
        let cfg = ConfigValidator::new()
            .validate(None)
            .expect("config failed");
        assert_eq!(
            get_token(&cfg.secrets_manager.security.ssrf_env_variables).expect("token fail"),
            "123abc"
        );
    }

    // Verify the variable can point to a file and we use the file contents.
    #[test]
    fn test_file_token() {
        let token = "4 chosen by fair dice roll, guaranteed to be random";
        let tmpfile = tmpfile_name("test_file_token");
        let _cleanup = CleanUp {
            file: Some(&tmpfile),
        };
        std::fs::write(&tmpfile, token).expect("could not write");
        let file = Box::new(format!("file://{tmpfile}"));
        set_test_var("AWS_TOKEN", Box::leak(file));
        let cfg = ConfigValidator::new()
            .validate(None)
            .expect("config failed");
        assert_eq!(
            get_token(&cfg.secrets_manager.security.ssrf_env_variables).expect("token fail"),
            token
        );
    }

    // Verify we correctly handle a missing file.
    #[test]
    fn test_file_token_missing() {
        #[cfg(unix)]
        const NO_SUCH_FILE_ERROR_MSG: &str = "No such file or directory (os error 2)";
        #[cfg(windows)]
        const NO_SUCH_FILE_ERROR_MSG: &str =
            "The system cannot find the file specified. (os error 2)";

        let _cleanup = CleanUp { file: None };
        set_test_var("AWS_TOKEN", "file:///NoSuchFile");
        let cfg = ConfigValidator::new()
            .validate(None)
            .expect("config failed");
        assert_eq!(
            get_token(&cfg.secrets_manager.security.ssrf_env_variables)
                .err()
                .unwrap()
                .to_string(),
            NO_SUCH_FILE_ERROR_MSG
        );
    }

    // Verify the first variable in the list takes precedence
    #[test]
    fn two_tokens() {
        let _cleanup = CleanUp { file: None };
        set_test_vars(vec![
            ("AWS_TOKEN", "yzzyx"),
            ("AWS_SESSION_TOKEN", "CTAtoken"),
        ]); // Good token, unusable token.
        let cfg = ConfigValidator::new()
            .validate(None)
            .expect("config failed");
        assert_eq!(
            get_token(&cfg.secrets_manager.security.ssrf_env_variables).expect("token fail"),
            "yzzyx"
        );
    }

    // Verify we return the correct error when a variable is not set.
    #[test]
    fn test_env_fail() {
        let _cleanup = CleanUp { file: None };
        set_test_var("", "");
        let env_vars = vec!["NOSUCHENV".to_string()];
        assert!(get_token(&env_vars)
            .err()
            .unwrap()
            .downcast_ref::<VarError>()
            .unwrap()
            .eq(&VarError::NotPresent));
    }

    // Make sure the timeout functon returns the correct value.
    #[test]
    fn test_time_out() {
        assert_eq!(time_out_impl(), Duration::from_secs(MAX_REQ_TIME_SEC));
    }

    // A failover region equal to the primary is ignored, and AssumeRole is pinned
    // to the configured region only with failover.
    #[test]
    fn test_role_regions() {
        let base_config = aws_config::SdkConfig::builder()
            .region(Region::new("us-east-1"))
            .build();
        let mut config = SecretsManagerConfig::default();
        let east = Some("us-east-1".to_string());
        assert_eq!(
            role_regions(&config, &base_config),
            (east.clone(), None, None)
        );

        config.failover.default_failover_region = Some("us-east-1".into());
        assert_eq!(
            role_regions(&config, &base_config),
            (east.clone(), None, None)
        );

        config.failover.default_failover_region = Some("us-west-2".into());
        assert_eq!(
            role_regions(&config, &base_config),
            (east, Some("us-west-2"), None)
        );

        config.region = Some("eu-west-1".into());
        assert_eq!(
            role_regions(&config, &base_config),
            (
                Some("eu-west-1".into()),
                Some("us-west-2"),
                Some("eu-west-1")
            )
        );
    }

    // The default client's own credentials get a failover-region copy only with a
    // failover region other than the SDK's region and own credentials from STS.
    #[tokio::test]
    async fn test_default_client_credentials() {
        let sdk_config = aws_config::SdkConfig::builder()
            .region(Region::new("us-east-1"))
            .credentials_provider(SharedCredentialsProvider::new(
                aws_credential_types::Credentials::new("akid", "secret", None, None, "test"),
            ))
            .build();
        let mut secrets_manager_config = SecretsManagerConfig {
            // Own credentials call STS in the SDK's region, not the configured one.
            region: Some("us-west-2".into()),
            ..Default::default()
        };
        let sts_role_arn = || Some("arn:aws:iam::123456789012:role/Own".to_string());
        assert!(
            default_client_credentials(&secrets_manager_config, &sdk_config, sts_role_arn())
                .await
                .is_none()
        );

        secrets_manager_config.failover.default_failover_region = Some("us-west-2".into());
        assert!(
            default_client_credentials(&secrets_manager_config, &sdk_config, None)
                .await
                .is_none()
        );

        let own_credentials_provider =
            default_client_credentials(&secrets_manager_config, &sdk_config, sts_role_arn())
                .await
                .expect("failover provider");
        assert_eq!(own_credentials_provider.operation, "OwnCredentials");
        assert_eq!(
            own_credentials_provider.role_arn,
            "arn:aws:iam::123456789012:role/Own"
        );
        assert_eq!(own_credentials_provider.primary_region, "us-east-1");
        assert_eq!(own_credentials_provider.failover_region, "us-west-2");
        assert_eq!(
            own_credentials_provider.primary_timeout,
            Duration::from_millis(1500)
        );

        // A failover region equal to the SDK's region gets no failover copy as it would retry the same STS endpoint
        secrets_manager_config.failover.default_failover_region = Some("us-east-1".into());
        assert!(
            default_client_credentials(&secrets_manager_config, &sdk_config, sts_role_arn())
                .await
                .is_none()
        );
    }

    // Only own credentials from STS get the failover-region copy, logged with their
    // role. The sources are checked in the default chain's order.
    #[tokio::test]
    async fn test_own_credentials_role() {
        // (case, environment, config file, the role if from STS)
        type Case<'a> = (&'a str, &'a [(&'a str, &'a str)], &'a str, Option<&'a str>);
        let irsa_role = "arn:aws:iam::123456789012:role/Irsa";
        let profile_role = "arn:aws:iam::123456789012:role/Profile";
        let irsa = [
            ("AWS_WEB_IDENTITY_TOKEN_FILE", "/token"),
            ("AWS_ROLE_ARN", irsa_role),
        ];
        // Each profile that doesn't call STS is checked with the IRSA variables set
        // too, so it only passes if the profile is recognized.
        let cases: [Case; 15] = [
            ("EKS IRSA", &irsa, "", Some(irsa_role)),
            ("a token file without AWS_ROLE_ARN isn't IRSA", &[irsa[0]], "", None),
            ("AWS_ROLE_ARN without a token file isn't IRSA", &[irsa[1]], "", None),
            ("blank environment keys are skipped", &[("AWS_ACCESS_KEY_ID", " "), ("AWS_SECRET_ACCESS_KEY", ""), irsa[0], irsa[1]], "", Some(irsa_role)),
            ("an access key ID without a secret is skipped", &[("AWS_ACCESS_KEY_ID", "a"), irsa[0], irsa[1]], "", Some(irsa_role)),
            ("environment keys with SECRET_ACCESS_KEY come before IRSA", &[("AWS_ACCESS_KEY_ID", "a"), ("SECRET_ACCESS_KEY", "s"), irsa[0], irsa[1]], "", None),
            ("profile with role_arn comes before IRSA", &irsa, "[default]\nrole_arn = arn:aws:iam::123456789012:role/Profile\nsource_profile = base\n[profile base]\naws_access_key_id = a\naws_secret_access_key = s\n", Some(profile_role)),
            ("AWS_PROFILE selects a role_arn profile", &[("AWS_PROFILE", "other")], "[default]\naws_access_key_id = a\naws_secret_access_key = s\n[profile other]\nrole_arn = arn:aws:iam::123456789012:role/Profile\ncredential_source = Environment\n", Some(profile_role)),
            ("environment keys come before IRSA", &[("AWS_ACCESS_KEY_ID", "a"), ("AWS_SECRET_ACCESS_KEY", "s"), irsa[0], irsa[1]], "", None),
            ("static profile comes before IRSA", &irsa, "[default]\naws_access_key_id = a\naws_secret_access_key = s\n", None),
            ("credential_process comes before IRSA", &irsa, "[default]\ncredential_process = /bin/creds\n", None),
            ("sso_session comes before IRSA", &irsa, "[default]\nsso_session = s\n", None),
            ("sso_start_url comes before IRSA", &irsa, "[default]\nsso_start_url = https://example.awsapps.com/start\n", None),
            ("login_session comes before IRSA", &irsa, "[default]\nlogin_session = arn:aws:iam::123456789012:user/Admin\n", None),
            ("nothing set (container credentials, IMDS)", &[], "", None),
        ];
        for (case, environment, config_file, role) in cases {
            let mut variables = vec![("AWS_CONFIG_FILE", "/aws/config")];
            variables.extend_from_slice(environment);
            let env = Env::from_slice(&variables);
            let fs = Fs::from_slice(&[("/aws/config", config_file)]);
            assert_eq!(
                own_credentials_role(&SecretsManagerConfig::default(), &env, &fs)
                    .await
                    .as_deref(),
                role,
                "{case}"
            );
        }

        // A credentials file replaces the default chain, so even IRSA isn't wrapped.
        let file_config = SecretsManagerConfig {
            credentials_file_path: Some("/creds".into()),
            ..Default::default()
        };
        let env = Env::from_slice(&irsa);
        assert_eq!(
            own_credentials_role(&file_config, &env, &Fs::from_slice(&[])).await,
            None
        );
    }

    // The agent's own credentials in the failover region keep the base config's
    // FIPS and dual-stack settings. `ProviderConfig` has no public getters, so its
    // Debug output is checked.
    #[test]
    fn test_own_credentials_config_keeps_fips_and_dual_stack() {
        let base_config = aws_config::SdkConfig::builder()
            .use_fips(true)
            .use_dual_stack(true)
            .build();
        let provider_config = format!("{:?}", own_credentials_config(&base_config));
        assert!(provider_config.contains("use_fips: Some(true)"));
        assert!(provider_config.contains("use_dual_stack: Some(true)"));
    }

    mod role_validation {
        use super::super::validate_role_credentials;
        use aws_config::BehaviorVersion;
        use aws_credential_types::Credentials;
        use aws_sdk_sts::config::{retry::RetryConfig, Region};
        use aws_smithy_runtime::client::http::test_util::infallible_client_fn;
        use aws_smithy_runtime_api::client::http::{
            http_client_fn, HttpConnector, HttpConnectorFuture, SharedHttpConnector,
        };
        use aws_smithy_runtime_api::client::orchestrator::{HttpRequest, HttpResponse};
        use aws_smithy_types::body::SdkBody;
        use std::sync::{Arc, Mutex};

        const ROLE_ARN: &str = "arn:aws:iam::123456789012:role/MyRole";

        const GCI_BODY: &str = "<GetCallerIdentityResponse><GetCallerIdentityResult>\
            <Arn>arn:aws:sts::123456789012:assumed-role/MyRole/s</Arn><UserId>AROAEXAMPLE:s</UserId>\
            <Account>123456789012</Account></GetCallerIdentityResult></GetCallerIdentityResponse>";

        const ASSUME_ROLE_BODY: &str = "<AssumeRoleResponse><AssumeRoleResult><Credentials>\
            <AccessKeyId>role-akid</AccessKeyId><SecretAccessKey>s</SecretAccessKey>\
            <SessionToken>t</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration>\
            </Credentials></AssumeRoleResult></AssumeRoleResponse>";

        const ERROR_BODY: &str = "<ErrorResponse><Error><Type>Sender</Type>\
            <Code>TestError</Code><Message>test error</Message></Error></ErrorResponse>";

        const THROTTLING_BODY: &str = "<ErrorResponse><Error><Type>Sender</Type>\
            <Code>Throttling</Code><Message>Rate exceeded</Message></Error></ErrorResponse>";

        /// An STS client in us-east-1 that answers with `primary_status` and
        /// `primary_body` there and 200 in any other region, and records each
        /// request's host.
        fn fake_sts(
            primary_status: u16,
            primary_body: &'static str,
        ) -> (aws_sdk_sts::Client, Arc<Mutex<Vec<String>>>) {
            let hosts = Arc::new(Mutex::new(Vec::new()));
            let seen = hosts.clone();
            let http_client = infallible_client_fn(move |req| {
                let host = req.uri().host().unwrap_or_default().to_string();
                let status = if host.contains("us-east-1") {
                    primary_status
                } else {
                    200
                };
                seen.lock().unwrap().push(host);
                let body = if status == 200 {
                    GCI_BODY
                } else {
                    primary_body
                };
                http::Response::builder()
                    .status(status)
                    .body(SdkBody::from(body))
                    .unwrap()
            });
            let client = aws_sdk_sts::Client::from_conf(
                aws_sdk_sts::Config::builder()
                    .behavior_version(BehaviorVersion::latest())
                    .region(Region::new("us-east-1"))
                    .credentials_provider(Credentials::new("akid", "secret", None, None, "test"))
                    .retry_config(RetryConfig::standard())
                    .http_client(http_client)
                    .build(),
            );
            (client, hosts)
        }

        // A transient primary error is retried once, against the failover region's endpoint.
        #[tokio::test(start_paused = true)]
        async fn test_transient_error_fails_over() {
            let (sts, hosts) = fake_sts(500, ERROR_BODY);
            validate_role_credentials(&sts, ROLE_ARN, Some("us-west-2"))
                .await
                .expect("failover succeeds");
            assert_eq!(
                *hosts.lock().unwrap(),
                ["sts.us-east-1.amazonaws.com", "sts.us-west-2.amazonaws.com"]
            );
        }

        // A client error fails the same way in any region, so it isn't retried.
        #[tokio::test]
        async fn test_client_error_does_not_fail_over() {
            let (sts, hosts) = fake_sts(403, ERROR_BODY);
            validate_role_credentials(&sts, ROLE_ARN, Some("us-west-2"))
                .await
                .expect_err("client error");
            assert_eq!(hosts.lock().unwrap().len(), 1);
        }

        // Throttling isn't failed over, and it keeps the SDK's 3 attempts.
        #[tokio::test(start_paused = true)]
        async fn test_throttling_is_retried_not_failed_over() {
            let (sts, hosts) = fake_sts(400, THROTTLING_BODY);
            validate_role_credentials(&sts, ROLE_ARN, Some("us-west-2"))
                .await
                .expect_err("throttled");
            assert_eq!(*hosts.lock().unwrap(), ["sts.us-east-1.amazonaws.com"; 3]);
        }

        // Without a failover region, a transient error gets the SDK's retries as before.
        #[tokio::test(start_paused = true)]
        async fn test_no_failover_region_returns_error() {
            let (sts, hosts) = fake_sts(500, ERROR_BODY);
            validate_role_credentials(&sts, ROLE_ARN, None)
                .await
                .expect_err("transient error");
            assert_eq!(hosts.lock().unwrap().len(), 3);
        }

        // A hanging primary fails over within one identity load, and Secrets Manager
        // reuses the credentials the STS client loaded.
        #[tokio::test(start_paused = true)]
        async fn test_role_client_configs_fail_over_within_one_load() {
            use super::super::role_client_configs;
            use crate::failover_credentials_provider::tests::{provider, Fake};
            use aws_credential_types::provider::SharedCredentialsProvider;
            use std::time::Duration;
            use tokio::time::Instant;

            let http_client = infallible_client_fn(|request| {
                let response_body = if request.uri().host().unwrap_or_default().starts_with("sts.")
                {
                    GCI_BODY
                } else {
                    r#"{"Name":"s","SecretString":"v"}"#
                };
                http::Response::builder()
                    .status(200)
                    .body(SdkBody::from(response_body))
                    .unwrap()
            });
            let base_config = aws_config::SdkConfig::builder()
                .behavior_version(BehaviorVersion::latest())
                .http_client(http_client)
                .build();
            let failover_provider = provider(Fake::Hang, Fake::Slow("failover"));
            let (sts_config, asm_config) = role_client_configs(
                &base_config,
                Some("us-east-1"),
                SharedCredentialsProvider::new(failover_provider),
                true,
            );

            aws_sdk_sts::Client::from_conf(sts_config)
                .get_caller_identity()
                .send()
                .await
                .expect("failover credentials");
            let secret_fetch_start = Instant::now();
            aws_sdk_secretsmanager::Client::from_conf(asm_config)
                .get_secret_value()
                .secret_id("s")
                .send()
                .await
                .expect("cached credentials");
            assert_eq!(secret_fetch_start.elapsed(), Duration::ZERO);
        }

        /// STS that's down in us-east-1: AssumeRole never answers and
        /// GetCallerIdentity gets a 500. Every other region answers, and each
        /// request's URI is recorded.
        #[derive(Clone, Debug)]
        struct PrimaryStsDown {
            request_uris: Arc<Mutex<Vec<String>>>,
        }

        impl HttpConnector for PrimaryStsDown {
            fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
                let assume_role =
                    String::from_utf8_lossy(request.body().bytes().unwrap_or_default())
                        .contains("Action=AssumeRole");
                let primary = request.uri().contains("sts.us-east-1.");
                self.request_uris
                    .lock()
                    .unwrap()
                    .push(request.uri().to_string());
                let hang = assume_role && primary;
                let (status, response_body) = if assume_role {
                    (200, ASSUME_ROLE_BODY)
                } else if primary {
                    (500, ERROR_BODY)
                } else {
                    (200, GCI_BODY)
                };
                HttpConnectorFuture::new(async move {
                    if hang {
                        std::future::pending::<()>().await;
                    }
                    Ok(HttpResponse::new(
                        status.try_into().unwrap(),
                        SdkBody::from(response_body),
                    ))
                })
            }
        }

        // A role client's primary AssumeRole goes to the configured region with the
        // base config's credentials, so a hanging primary is cut at primary_timeout,
        // and AssumeRole and GetCallerIdentity each fail over to us-west-2.
        #[tokio::test(start_paused = true)]
        async fn test_create_role_asm_client_fails_over_hanging_primary() {
            use super::super::{create_role_asm_client, SecretsManagerConfig};
            use crate::failover_credentials_provider::primary_attempt_timeout;
            use aws_credential_types::provider::SharedCredentialsProvider;
            use aws_workload_credentials_provider_common::config::types::FailoverConfig;
            use std::time::Duration;
            use tokio::time::Instant;

            // load() supplies the time source AssumeRoleProvider needs. The base region
            // isn't the configured one, so an AssumeRole that isn't pinned doesn't hang.
            let request_uris = Arc::new(Mutex::new(Vec::new()));
            let fake_sts = PrimaryStsDown {
                request_uris: request_uris.clone(),
            };
            let base_config = aws_config::defaults(BehaviorVersion::latest())
                .empty_test_environment()
                .region(Region::new("eu-west-1"))
                .credentials_provider(SharedCredentialsProvider::new(Credentials::new(
                    "akid", "secret", None, None, "test",
                )))
                .http_client(http_client_fn(move |_, _| {
                    SharedHttpConnector::new(fake_sts.clone())
                }))
                .load()
                .await;
            let config = SecretsManagerConfig {
                region: Some("us-east-1".into()),
                // Keeps the failover AssumeRole on the base config's credentials.
                credentials_file_path: Some("/unused".into()),
                failover: FailoverConfig {
                    default_failover_region: Some("us-west-2".into()),
                    ..Default::default()
                },
                ..Default::default()
            };

            let start = Instant::now();
            create_role_asm_client(&config, &base_config, ROLE_ARN)
                .await
                .expect("fails over");
            assert_eq!(
                start.elapsed(),
                primary_attempt_timeout(Duration::from_millis(
                    config.failover.operation_timeout_ms
                ))
            );
            // AssumeRole, then GetCallerIdentity, each in us-east-1 and then us-west-2.
            assert_eq!(
                *request_uris.lock().unwrap(),
                [
                    "https://sts.us-east-1.amazonaws.com/",
                    "https://sts.us-west-2.amazonaws.com/",
                    "https://sts.us-east-1.amazonaws.com/",
                    "https://sts.us-west-2.amazonaws.com/",
                ]
            );
        }

        const WEB_IDENTITY_BODY: &str = "<AssumeRoleWithWebIdentityResponse>\
            <AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>irsa-akid</AccessKeyId>\
            <SecretAccessKey>s</SecretAccessKey><SessionToken>t</SessionToken>\
            <Expiration>2099-01-01T00:00:00Z</Expiration></Credentials>\
            </AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>";

        /// STS for an agent on EKS IRSA, down in us-east-1: AssumeRoleWithWebIdentity
        /// and AssumeRole never answer there and GetCallerIdentity gets a 500. Every
        /// other region answers, and each request's action and URI is recorded.
        #[derive(Clone, Debug)]
        struct IrsaSts {
            requests: Arc<Mutex<Vec<String>>>,
            /// Every other region answers every call with a 503 instead.
            failover_down: bool,
        }

        impl HttpConnector for IrsaSts {
            fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
                let request_body =
                    String::from_utf8_lossy(request.body().bytes().unwrap_or_default()).to_string();
                let action = if request_body.contains("Action=AssumeRoleWithWebIdentity") {
                    "AssumeRoleWithWebIdentity"
                } else if request_body.contains("Action=AssumeRole") {
                    "AssumeRole"
                } else {
                    "GetCallerIdentity"
                };
                self.requests
                    .lock()
                    .unwrap()
                    .push(format!("{action} {}", request.uri()));
                let primary = request.uri().contains("us-east-1");
                let hang = primary && action != "GetCallerIdentity";
                let (status, response_body) = match action {
                    _ if self.failover_down && !primary => (503, ERROR_BODY),
                    "GetCallerIdentity" if primary => (500, ERROR_BODY),
                    "AssumeRoleWithWebIdentity" => (200, WEB_IDENTITY_BODY),
                    "AssumeRole" => (200, ASSUME_ROLE_BODY),
                    _ => (200, GCI_BODY),
                };
                HttpConnectorFuture::new(async move {
                    if hang {
                        std::future::pending::<()>().await;
                    }
                    Ok(HttpResponse::new(
                        status.try_into().unwrap(),
                        SdkBody::from(response_body),
                    ))
                })
            }
        }

        // On EKS IRSA, each region gets the agent's own credentials with
        // AssumeRoleWithWebIdentity, then the role's with AssumeRole. With STS down
        // in the primary region, both calls are made in the failover region, with
        // the base config's FIPS and dual-stack settings. The IRSA environment
        // variables are set only in a child process running the test below, so
        // other tests don't see them.
        #[test]
        fn test_create_role_asm_client_fails_over_irsa_credentials() {
            run_in_irsa_child_process("irsa_failover_in_child_process");
        }

        // On EKS IRSA without a roleArn, the default client's only credentials come
        // from AssumeRoleWithWebIdentity. With STS down in the primary region, they
        // and the startup GetCallerIdentity come from the failover region. With STS
        // down in both regions there are no credentials, so no secret can be read.
        #[test]
        fn test_default_client_fails_over_irsa_credentials() {
            run_in_irsa_child_process("irsa_default_client_in_child_process");
        }

        /// Runs `child_test` in a child process whose only AWS credentials are the
        /// IRSA environment variables, as on an EKS pod, so other tests don't see them.
        fn run_in_irsa_child_process(child_test: &str) {
            let token_file = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(token_file.path(), "web-identity-token").unwrap();
            let child_test = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    &format!("utils::tests::role_validation::{child_test}"),
                    "--ignored",
                    "--nocapture",
                ])
                .env("IRSA_FAILOVER_CHILD_PROCESS", "1")
                .env("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/IrsaRole")
                .env("AWS_WEB_IDENTITY_TOKEN_FILE", token_file.path())
                .env("AWS_CONFIG_FILE", "/nonexistent")
                .env("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent")
                .env_remove("AWS_ACCESS_KEY_ID")
                .env_remove("AWS_SECRET_ACCESS_KEY")
                .env_remove("AWS_SESSION_TOKEN")
                .env_remove("AWS_PROFILE")
                .env_remove("AWS_ENDPOINT_URL")
                .env_remove("AWS_ENDPOINT_URL_STS")
                .output()
                .unwrap();
            // The child's panic text goes to stderr, so show both streams.
            let child_output = format!(
                "{}{}",
                String::from_utf8_lossy(&child_test.stdout),
                String::from_utf8_lossy(&child_test.stderr)
            );
            assert!(child_test.status.success(), "{child_output}");
            assert!(child_output.contains("1 passed"), "{child_output}");
        }

        // Run by the test above, in a child process with the IRSA environment variables.
        #[tokio::test]
        #[ignore = "run in a child process by test_create_role_asm_client_fails_over_irsa_credentials"]
        async fn irsa_failover_in_child_process() {
            use super::super::{create_role_asm_client, SecretsManagerConfig};
            use aws_workload_credentials_provider_common::config::types::FailoverConfig;

            if std::env::var("IRSA_FAILOVER_CHILD_PROCESS").is_err() {
                return;
            }
            let requests = Arc::new(Mutex::new(Vec::new()));
            let fake_sts = IrsaSts {
                requests: requests.clone(),
                failover_down: false,
            };
            // The agent's own credentials come from the default chain, as on a pod,
            // which finds the IRSA environment variables.
            let base_config = aws_config::defaults(BehaviorVersion::latest())
                .region(Region::new("us-east-1"))
                .use_fips(true)
                .use_dual_stack(true)
                .http_client(http_client_fn(move |_, _| {
                    SharedHttpConnector::new(fake_sts.clone())
                }))
                .load()
                .await;
            let config = SecretsManagerConfig {
                region: Some("us-east-1".into()),
                failover: FailoverConfig {
                    default_failover_region: Some("us-west-2".into()),
                    ..Default::default()
                },
                ..Default::default()
            };

            create_role_asm_client(&config, &base_config, ROLE_ARN)
                .await
                .expect("fails over");
            assert_eq!(
                *requests.lock().unwrap(),
                [
                    // The agent's own credentials in us-east-1: hangs, cut at primary_timeout.
                    "AssumeRoleWithWebIdentity https://sts-fips.us-east-1.api.aws/",
                    // The agent's own credentials, then the role's, in us-west-2.
                    "AssumeRoleWithWebIdentity https://sts-fips.us-west-2.api.aws/",
                    "AssumeRole https://sts-fips.us-west-2.api.aws/",
                    // The validation call: a 500 in us-east-1, then us-west-2.
                    "GetCallerIdentity https://sts-fips.us-east-1.api.aws/",
                    "GetCallerIdentity https://sts-fips.us-west-2.api.aws/",
                ]
            );
        }

        // Run by test_default_client_fails_over_irsa_credentials, in a child process
        // with the IRSA environment variables.
        #[tokio::test]
        #[ignore = "run in a child process by test_default_client_fails_over_irsa_credentials"]
        async fn irsa_default_client_in_child_process() {
            use super::super::{
                default_client_credentials, own_credentials_role, role_client_configs,
                SecretsManagerConfig,
            };
            use aws_sdk_secretsmanager::config::SharedCredentialsProvider;
            use aws_types::os_shim_internal::{Env, Fs};
            use aws_workload_credentials_provider_common::config::types::FailoverConfig;

            if std::env::var("IRSA_FAILOVER_CHILD_PROCESS").is_err() {
                return;
            }
            let config = SecretsManagerConfig {
                region: Some("us-east-1".into()),
                failover: FailoverConfig {
                    default_failover_region: Some("us-west-2".into()),
                    ..Default::default()
                },
                ..Default::default()
            };
            for failover_down in [false, true] {
                let requests = Arc::new(Mutex::new(Vec::new()));
                let fake_sts = IrsaSts {
                    requests: requests.clone(),
                    failover_down,
                };
                // The default client's own credentials come from the default chain,
                // which finds only the IRSA environment variables.
                let sdk_config = aws_config::defaults(BehaviorVersion::latest())
                    .region(Region::new("us-east-1"))
                    .http_client(http_client_fn(move |_, _| {
                        SharedHttpConnector::new(fake_sts.clone())
                    }))
                    .load()
                    .await;
                // Set up as validate_and_create_asm_client does.
                let sts_role_arn = own_credentials_role(&config, &Env::real(), &Fs::real()).await;
                assert_eq!(
                    sts_role_arn.as_deref(),
                    Some("arn:aws:iam::123456789012:role/IrsaRole")
                );
                let own_credentials_provider =
                    default_client_credentials(&config, &sdk_config, sts_role_arn)
                        .await
                        .expect("failover provider");
                let (sts_config, secrets_manager_config) = role_client_configs(
                    &sdk_config,
                    config.region.as_deref(),
                    SharedCredentialsProvider::new(own_credentials_provider),
                    true,
                );
                let sts_client = aws_sdk_sts::Client::from_conf(sts_config);
                let validation =
                    validate_role_credentials(&sts_client, "unknown", Some("us-west-2")).await;

                if !failover_down {
                    validation.expect("fails over");
                    assert_eq!(
                        *requests.lock().unwrap(),
                        [
                            // Own credentials in us-east-1: hangs, cut at primary_timeout.
                            "AssumeRoleWithWebIdentity https://sts.us-east-1.amazonaws.com/",
                            "AssumeRoleWithWebIdentity https://sts.us-west-2.amazonaws.com/",
                            // The startup check: a 500 in us-east-1, then us-west-2.
                            "GetCallerIdentity https://sts.us-east-1.amazonaws.com/",
                            "GetCallerIdentity https://sts.us-west-2.amazonaws.com/",
                        ]
                    );
                    continue;
                }
                // No credentials in either region: the startup check fails, and a
                // secret request is never sent.
                validation.expect_err("no credentials");
                let secrets_manager_client =
                    aws_sdk_secretsmanager::Client::from_conf(secrets_manager_config);
                secrets_manager_client
                    .get_secret_value()
                    .secret_id("my-secret")
                    .send()
                    .await
                    .expect_err("no credentials");
                let requests = requests.lock().unwrap();
                assert!(
                    requests
                        .iter()
                        .all(|request| request.starts_with("AssumeRoleWithWebIdentity ")),
                    "{requests:?}"
                );
            }
        }
    }
}
