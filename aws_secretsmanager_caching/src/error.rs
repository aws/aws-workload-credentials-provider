use aws_smithy_runtime_api::client::{orchestrator::HttpResponse, result::SdkError};
use aws_smithy_types::error::metadata::ProvideErrorMetadata;

/// Helper function to determine transient errors. Transient errors include any timeout error,
/// unparseable response error, dispatch error due to timeout or IO, 5xx server-side error, and
/// throttling error for ASM API, which reflects per-region capacity rather than a problem with
/// the request.
///
/// # Arguments
/// * `e` - An SDK error
///
/// # Returns
/// * true if transient error, false if not
pub fn is_transient_error<S>(e: &SdkError<S, HttpResponse>) -> bool
where
    S: ProvideErrorMetadata + std::error::Error + 'static,
{
    match e {
        SdkError::TimeoutError(_) => true,
        SdkError::ResponseError(_) => true,
        SdkError::DispatchFailure(derr) if derr.is_timeout() || derr.is_io() => true,
        SdkError::ServiceError(serr) => {
            serr.raw().status().is_server_error()
                || serr.err().code() == Some("ThrottlingException")
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_smithy_mocks::{mock, mock_client, RuleMode};
    use aws_smithy_runtime_api::http::StatusCode;
    use aws_smithy_types::body::SdkBody;

    fn throttling_response() -> HttpResponse {
        HttpResponse::new(
            StatusCode::try_from(400).unwrap(),
            SdkBody::from(r#"{"__type":"ThrottlingException","message":"Rate exceeded"}"#),
        )
    }

    /// Secrets Manager returns throttling with a 400 status, so it has to be recognized by error
    /// code rather than by status. Responses are served through a mocked client so the errors are
    /// produced by the SDK's deserializer rather than constructed by hand.
    #[tokio::test]
    async fn test_throttling_is_transient_despite_client_status() {
        let get_rule = mock!(aws_sdk_secretsmanager::Client::get_secret_value)
            .then_http_response(throttling_response);
        let describe_rule = mock!(aws_sdk_secretsmanager::Client::describe_secret)
            .then_http_response(throttling_response);
        let asm = mock_client!(
            aws_sdk_secretsmanager,
            RuleMode::MatchAny,
            [&get_rule, &describe_rule],
            |c| c.retry_config(aws_smithy_types::retry::RetryConfig::disabled())
        );

        let throttled = asm
            .get_secret_value()
            .secret_id("secretid")
            .send()
            .await
            .expect_err("mocked throttling error");
        assert!(is_transient_error(&throttled));

        let throttled = asm
            .describe_secret()
            .secret_id("secretid")
            .send()
            .await
            .expect_err("mocked throttling error");
        assert!(is_transient_error(&throttled));
    }

    fn not_found_response() -> HttpResponse {
        HttpResponse::new(
            StatusCode::try_from(400).unwrap(),
            SdkBody::from(r#"{"__type":"ResourceNotFoundException","message":"Not found"}"#),
        )
    }

    /// Other client errors fail the same way in any region, so they are not transient. This pins
    /// the throttling arm to the throttling code rather than to any code at a 400 status.
    #[tokio::test]
    async fn test_other_client_error_is_not_transient() {
        let rule = mock!(aws_sdk_secretsmanager::Client::get_secret_value)
            .then_http_response(not_found_response);
        let asm = mock_client!(aws_sdk_secretsmanager, RuleMode::MatchAny, [&rule]);

        let not_found = asm
            .get_secret_value()
            .secret_id("secretid")
            .send()
            .await
            .expect_err("mocked not-found error");
        assert!(!is_transient_error(&not_found));
    }
}
