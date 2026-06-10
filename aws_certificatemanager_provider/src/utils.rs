//! Shared utilities for the ACM provider crate.

use aws_config::sts::AssumeRoleProvider;
use aws_credential_types::provider::SharedCredentialsProvider;
use aws_sdk_acm::config::interceptors::BeforeTransmitInterceptorContextMut;
use aws_sdk_acm::config::{ConfigBag, Intercept, RuntimeComponents};

const SESSION_NAME: &str = "certificate-manager-provider";

/// SDK interceptor to append the provider name and version to the User-Agent header
/// of outbound ACM SDK requests for CloudTrail records.
#[derive(Debug)]
pub(crate) struct AcmUserAgentInterceptor;

impl Intercept for AcmUserAgentInterceptor {
    fn name(&self) -> &'static str {
        "AcmUserAgentInterceptor"
    }

    fn modify_before_signing(
        &self,
        context: &mut BeforeTransmitInterceptorContextMut<'_>,
        _runtime_components: &RuntimeComponents,
        _cfg: &mut ConfigBag,
    ) -> Result<(), aws_sdk_acm::error::BoxError> {
        let request = context.request_mut();
        let agent = request.headers().get("user-agent").unwrap_or_default();
        let full_agent = format!(
            "{agent} {}/{}",
            aws_workload_credentials_provider_common::constants::PROVIDER_NAME,
            option_env!("CARGO_PKG_VERSION").unwrap_or("0.0.0")
        );
        request.headers_mut().insert("user-agent", full_agent);
        Ok(())
    }
}

/// Builds an `AssumeRoleProvider` for the given role ARN and returns a
/// `SharedCredentialsProvider`.
///
/// The provider is lazy — credentials are not resolved until the first
/// API call. This lets transient STS failures surface through the normal
/// error classification path rather than failing permanently at startup.
///
/// # Arguments
///
/// * `base_config` - The base AWS SDK config providing default credentials,
///   HTTP client, retry config, and region.
/// * `role_arn` - The ARN of the IAM role to assume.
pub(crate) async fn build_credentials_provider(
    base_config: &aws_config::SdkConfig,
    role_arn: &str,
) -> SharedCredentialsProvider {
    let provider = AssumeRoleProvider::builder(role_arn)
        .configure(base_config)
        .session_name(SESSION_NAME)
        .build()
        .await;

    SharedCredentialsProvider::new(provider)
}

/// Generates a random duration between 0 and `max` seconds.
/// Returns `Duration::ZERO` if `max` is zero or random generation fails.
pub(crate) fn random_jitter(max: std::time::Duration) -> std::time::Duration {
    if max.is_zero() {
        return std::time::Duration::ZERO;
    }
    let mut buf = [0u8; 8];
    match aws_lc_rs::rand::fill(&mut buf) {
        Ok(()) => {
            let random_secs = u64::from_ne_bytes(buf) % max.as_secs().max(1);
            std::time::Duration::from_secs(random_secs)
        }
        Err(_) => std::time::Duration::ZERO,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn random_jitter_zero_max_returns_zero() {
        assert_eq!(random_jitter(Duration::ZERO), Duration::ZERO);
    }

    #[test]
    fn random_jitter_within_bounds() {
        let max = Duration::from_secs(60);
        let jitter = random_jitter(max);
        assert!(jitter < max);
    }

    #[test]
    fn random_jitter_one_second_max() {
        let jitter = random_jitter(Duration::from_secs(1));
        assert_eq!(jitter, Duration::ZERO);
    }

    #[test]
    fn interceptor_name() {
        assert_eq!(AcmUserAgentInterceptor.name(), "AcmUserAgentInterceptor");
    }

    /// Verifies that AcmUserAgentInterceptor appends the provider name and version
    /// to the user-agent header of outbound ACM SDK requests.
    ///
    /// Uses a fake HTTP client to capture the outgoing request headers after the
    /// full SDK middleware pipeline (serialization, interceptors, signing) runs.
    #[tokio::test]
    async fn interceptor_appends_user_agent() {
        use aws_sdk_acm::config::{BehaviorVersion, Credentials, Region};
        use aws_smithy_runtime::client::http::test_util::infallible_client_fn;
        use aws_smithy_types::body::SdkBody;
        use std::sync::{Arc, Mutex};

        // Shared state to capture the user-agent header from the outgoing request
        let captured_ua = Arc::new(Mutex::new(String::new()));
        let captured_ua_clone = captured_ua.clone();

        // Fake HTTP client that captures the user-agent header and returns a stub response
        let http_client = infallible_client_fn(move |req| {
            let ua = req
                .headers()
                .get("user-agent")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            *captured_ua_clone.lock().unwrap() = ua;
            http::Response::builder()
                .status(200)
                .body(SdkBody::from(
                    r#"{"Certificate":"c","CertificateChain":"ch","PrivateKey":"k"}"#,
                ))
                .unwrap()
        });

        // Build an ACM client with our interceptor wired in
        let fake_creds = Credentials::new("AKID", "secret", Some("token".into()), None, "test");
        let client = aws_sdk_acm::Client::from_conf(
            aws_sdk_acm::Config::builder()
                .behavior_version(BehaviorVersion::latest())
                .credentials_provider(fake_creds)
                .region(Region::new("us-west-2"))
                .http_client(http_client)
                .interceptor(AcmUserAgentInterceptor)
                .build(),
        );

        // Make an SDK call to trigger the interceptor pipeline
        let _ = client
            .export_certificate()
            .certificate_arn("arn:aws:acm:us-west-2:123456789012:certificate/test")
            .passphrase(aws_smithy_types::Blob::new(b"pass"))
            .send()
            .await;

        // Verify the user-agent header contains our provider name and version
        let ua = captured_ua.lock().unwrap();
        let expected = format!(
            "{}/{}",
            aws_workload_credentials_provider_common::constants::PROVIDER_NAME,
            option_env!("CARGO_PKG_VERSION").unwrap_or("0.0.0")
        );
        assert!(
            ua.contains(&expected),
            "user-agent '{ua}' should contain '{expected}'"
        );
    }
}
