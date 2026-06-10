use aws_sdk_secretsmanager::config::{
    interceptors::BeforeTransmitInterceptorContextMut, Intercept, RuntimeComponents,
};
use aws_smithy_types::config_bag::ConfigBag;

/// SDK interceptor to append the provider name and version to the User-Agent header for CloudTrail records.
#[derive(Debug)]
pub(crate) struct CachingLibraryInterceptor;

/// SDK interceptor to append the provider name and version to the User-Agent header for CloudTrail records.
///
/// This interceptor adds the provider name and version to the User-Agent header
/// of outbound Secrets Manager SDK requests.
impl Intercept for CachingLibraryInterceptor {
    fn name(&self) -> &'static str {
        "CachingLibraryInterceptor"
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
            "{agent} AWSSecretsManagerCachingRust/{}",
            option_env!("CARGO_PKG_VERSION").unwrap_or("0.0.0")
        );
        request.headers_mut().insert("user-agent", full_agent); // Overwrite header.

        Ok(())
    }
}
