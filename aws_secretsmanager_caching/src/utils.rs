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

/// Point a Secrets Manager ARN at `region`, for a call sent to that region.
///
/// A regional endpoint returns `ResourceNotFoundException` for an ARN that names
/// another region, and a replica's ARN differs from the primary's only in the
/// region field. Friendly names can't contain `:`, so they never match and pass
/// through unchanged, as does anything else that isn't a Secrets Manager ARN.
pub(crate) fn retarget_arn(secret_id: &str, region: &str) -> String {
    match secret_id.splitn(5, ':').collect::<Vec<_>>().as_slice() {
        ["arn", partition, "secretsmanager", _, rest] => {
            format!("arn:{partition}:secretsmanager:{region}:{rest}")
        }
        _ => secret_id.to_string(),
    }
}

/// An error's message followed by each cause's, joined with `": "`, for logs.
/// Unlike `DisplayErrorContext`, it leaves out the error's `Debug` form, which
/// holds the raw HTTP response, so the response itself never reaches the log. A
/// parse error's message can still quote a few characters of a malformed
/// response, such as an invalid JSON `\u` escape or an unknown XML entity.
pub(crate) fn error_chain(error: &dyn std::error::Error) -> String {
    let mut chain = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        chain.push_str(": ");
        chain.push_str(&cause.to_string());
        source = cause.source();
    }
    chain
}

#[cfg(test)]
mod tests {
    use super::*;

    // A friendly name passes through. In an ARN only the region changes: the
    // partition, the account, the name (case and slashes included) and the
    // 6-character suffix are copied as is.
    #[test]
    fn test_retarget_arn() {
        assert_eq!(
            retarget_arn("prod/my-app/db", "eu-west-1"),
            "prod/my-app/db"
        );

        let arn = "arn:aws:secretsmanager:us-west-2:123456789012:secret:Prod/MyApp/Db-AbCdEf";
        assert_eq!(
            retarget_arn(arn, "eu-west-1"),
            "arn:aws:secretsmanager:eu-west-1:123456789012:secret:Prod/MyApp/Db-AbCdEf"
        );

        let gov = "arn:aws-us-gov:secretsmanager:us-gov-west-1:123456789012:secret:Db-AbCdEf";
        assert_eq!(
            retarget_arn(gov, "us-gov-east-1"),
            "arn:aws-us-gov:secretsmanager:us-gov-east-1:123456789012:secret:Db-AbCdEf"
        );

        // A partial ARN has no random suffix and is rewritten the same way.
        let partial = "arn:aws:secretsmanager:us-west-2:123456789012:secret:Prod/MyApp/Db";
        assert_eq!(
            retarget_arn(partial, "eu-west-1"),
            "arn:aws:secretsmanager:eu-west-1:123456789012:secret:Prod/MyApp/Db"
        );
    }

    // A 200 whose body can't be parsed keeps the secret in the error's raw response.
    // The chain keeps the parse message for the log but not the secret.
    #[tokio::test]
    async fn test_error_chain_leaves_out_response_body() {
        use aws_smithy_mocks::{mock, mock_client, RuleMode};
        use aws_smithy_runtime_api::client::orchestrator::HttpResponse;
        use aws_smithy_runtime_api::http::StatusCode;
        use aws_smithy_types::body::SdkBody;

        let rule =
            mock!(aws_sdk_secretsmanager::Client::get_secret_value).then_http_response(|| {
                HttpResponse::new(
                    StatusCode::try_from(200).unwrap(),
                    SdkBody::from(r#"{"Name":"s","SecretString":"hunter2","CreatedDate":"oops"}"#),
                )
            });
        let asm = mock_client!(aws_sdk_secretsmanager, RuleMode::MatchAny, [&rule]);

        let unparseable = asm
            .get_secret_value()
            .secret_id("secretid")
            .send()
            .await
            .expect_err("mocked unparseable body");
        let chain = error_chain(&unparseable);
        assert!(!chain.contains("hunter2"));
        assert!(chain.contains("failed to parse JSON"));
    }
}
