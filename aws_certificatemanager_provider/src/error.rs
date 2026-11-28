//! Error classification for the ACM certificate provider crate.

use aws_sdk_acm::operation::export_certificate::ExportCertificateError;
use aws_smithy_runtime_api::client::{orchestrator::HttpResponse, result::SdkError};
use thiserror::Error;

use crate::telemetry::FailureCode;

/// Errors that can occur during ACM Manager operations.
///
/// Callers decide retry behavior based on the variant:
/// - `Transient` → retry with backoff
/// - `NonTransient` → do not retry, log and notify
/// - `InternalFailure` → bug or unexpected response, alert
#[derive(Debug, Error)]
pub enum AcmManagerError {
    /// Retryable: server errors, timeouts, throttling, request-in-progress.
    #[error("{0}")]
    Transient(SdkFailure),
    /// Not retryable: bad ARN, resource not found, validation failure.
    #[error("{0}")]
    NonTransient(SdkFailure),
    /// Bug in our code or unexpected API response.
    #[error("InternalFailure: {0}")]
    InternalFailure(String),
}

/// A classified SDK failure: a closed error code plus a summary for logs.
#[derive(Debug)]
pub struct SdkFailure {
    code: FailureCode,
    summary: String,
}

impl std::fmt::Display for SdkFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.summary)
    }
}

impl AcmManagerError {
    /// Returns true if this error is transient and the operation should be retried.
    pub fn is_transient(&self) -> bool {
        matches!(self, AcmManagerError::Transient(_))
    }

    /// Error code for telemetry. It never carries the summary text.
    pub fn telemetry_code(&self) -> FailureCode {
        match self {
            AcmManagerError::Transient(failure) | AcmManagerError::NonTransient(failure) => {
                failure.code
            }
            AcmManagerError::InternalFailure(_) => FailureCode::AgentInternal,
        }
    }
}

/// Classifies an `ExportCertificate` SDK error into the appropriate `AcmManagerError` variant.
pub(crate) fn classify_export_error(
    e: SdkError<ExportCertificateError, HttpResponse>,
) -> AcmManagerError {
    let failure = SdkFailure {
        code: sdk_error_code(&e),
        summary: summarize_sdk_error(&e),
    };
    if is_transient_error(&e)
        || matches!(
            e.as_service_error(),
            Some(ExportCertificateError::RequestInProgressException(_))
        )
    {
        AcmManagerError::Transient(failure)
    } else {
        AcmManagerError::NonTransient(failure)
    }
}

/// The service code (e.g. `AccessDeniedException`), or a fixed token for a transport failure.
fn sdk_error_code(e: &SdkError<ExportCertificateError, HttpResponse>) -> FailureCode {
    match e {
        SdkError::ServiceError(service_error) => {
            FailureCode::from_sdk_code(service_error.err().meta().code().unwrap_or_default())
        }
        SdkError::TimeoutError(_) => FailureCode::TimeoutError,
        SdkError::DispatchFailure(failure) if failure.is_timeout() => FailureCode::TimeoutError,
        SdkError::DispatchFailure(failure) if failure.is_io() => FailureCode::ConnectionError,
        SdkError::DispatchFailure(_) => FailureCode::DispatchFailure,
        SdkError::ResponseError(_) => FailureCode::ConnectionError,
        _ => FailureCode::Other,
    }
}

/// Extracts a concise human-readable description from an SdkError.
fn summarize_sdk_error(e: &SdkError<ExportCertificateError, HttpResponse>) -> String {
    match e {
        SdkError::ServiceError(service_error) => {
            let code = service_error.err().meta().code().unwrap_or("Unknown");
            let msg = service_error.err().meta().message().unwrap_or("no message");
            format!(
                "{} (HTTP {}): {}",
                code,
                service_error.raw().status().as_u16(),
                msg
            )
        }
        SdkError::TimeoutError(_) => "Timeout".to_string(),
        SdkError::DispatchFailure(e) => {
            let detail = e
                .as_connector_error()
                .map(|c| error_chain_message(c))
                .unwrap_or_else(|| "unknown".to_string());
            format!("DispatchFailure: {}", detail)
        }
        SdkError::ResponseError(e) => {
            format!("ResponseError (HTTP {})", e.raw().status().as_u16())
        }
        _ => e.to_string(),
    }
}

/// Walks the error source  and returns the deepest message (root cause).
fn error_chain_message(e: &dyn std::error::Error) -> String {
    let mut msg = e.to_string();
    let mut current = e.source();
    while let Some(src) = current {
        msg = src.to_string();
        current = src.source();
    }
    msg
}

/// Helper function to determine transient errors. Transient errors include any timeout error,
/// unparseable response error, dispatch error due to timeout or IO, and 5xx server-side error.
fn is_transient_error<S>(e: &SdkError<S, HttpResponse>) -> bool
where
    S: std::error::Error + 'static,
{
    match e {
        SdkError::TimeoutError(_) => true,
        SdkError::ResponseError(_) => true,
        SdkError::DispatchFailure(dispatch_error)
            if dispatch_error.is_timeout()
                || dispatch_error.is_io()
                || dispatch_error.as_other().is_some() =>
        {
            true
        }
        SdkError::ServiceError(service_error)
            if service_error.raw().status().is_server_error()
                || service_error.raw().status().as_u16() == 429 =>
        {
            true
        }
        _ => false,
    }
}

/// A watcher outcome that fails a certificate refresh without timing out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum WatcherFailureOutcome {
    #[error("failure")]
    Failure,
    #[error("not_found")]
    NotFound,
    #[error("superseded")]
    Superseded,
}

/// Errors from certificate refresh operations.
#[derive(Debug, Error)]
pub enum RefreshError {
    /// Certificate export from ACM failed.
    #[error("Certificate export failed for {certificate_arn}: {source}")]
    ExportFailed {
        certificate_arn: String,
        #[source]
        source: AcmManagerError,
    },

    /// Certificate file write failed.
    #[error("Certificate file write failed for {certificate_arn}: {source}")]
    WriteFailed {
        certificate_arn: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Post-renewal refresh command failed.
    #[error("Refresh command failed for {certificate_arn}: {source}")]
    CommandFailed {
        certificate_arn: String,
        /// New certificate files were written before the command ran.
        files_changed: bool,
        #[source]
        source: std::io::Error,
    },

    /// The watcher reported a non-timeout command failure.
    #[error("Watcher refresh command failed for {certificate_arn}: {outcome}")]
    WatcherFailed {
        certificate_arn: String,
        files_changed: bool,
        outcome: WatcherFailureOutcome,
    },

    /// The watcher reported that the refresh command ran out its time.
    #[error("Watcher refresh command timed out for {certificate_arn}")]
    WatcherTimeout {
        certificate_arn: String,
        files_changed: bool,
    },

    /// No watcher status arrived before the provider's response deadline.
    #[error("No watcher status for {certificate_arn} before the response deadline")]
    WatcherNoStatus {
        certificate_arn: String,
        files_changed: bool,
    },

    /// Writing the refresh request to the certificate's watcher failed.
    #[error("Refresh request to watcher {watcher_id} failed for {certificate_arn}: {source}")]
    RequestFailed {
        certificate_arn: String,
        watcher_id: String,
        /// New certificate files were written before the request was queued.
        files_changed: bool,
        #[source]
        source: std::io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_acm::types::error::{RequestInProgressException, ResourceNotFoundException};
    use aws_sdk_acm::Client;
    use aws_smithy_mocks::{mock, mock_client};
    use aws_smithy_runtime_api::http::StatusCode;
    use aws_smithy_types::body::SdkBody;

    async fn make_error(rule: aws_smithy_mocks::Rule) -> AcmManagerError {
        let client = mock_client!(aws_sdk_acm, [&rule]);
        let err = client
            .export_certificate()
            .certificate_arn("arn:aws:acm:us-west-2:123456789012:certificate/test")
            .passphrase(aws_smithy_types::Blob::new(vec![0u8; 32]))
            .send()
            .await
            .expect_err("expected error");
        classify_export_error(err)
    }

    #[tokio::test]
    async fn server_error_is_transient() {
        let rule = mock!(Client::export_certificate).then_http_response(|| {
            aws_smithy_runtime_api::http::Response::new(
                StatusCode::try_from(500).unwrap(),
                SdkBody::from("internal server error"),
            )
        });
        let err = make_error(rule).await;
        assert!(err.is_transient());
    }

    #[tokio::test]
    async fn resource_not_found_is_not_transient() {
        let rule = mock!(Client::export_certificate).then_error(|| {
            ExportCertificateError::ResourceNotFoundException(
                ResourceNotFoundException::builder().build(),
            )
        });
        let err = make_error(rule).await;
        assert!(!err.is_transient());
    }

    #[test]
    fn internal_failure_is_not_transient() {
        let err = AcmManagerError::InternalFailure("missing field".into());
        assert!(!err.is_transient());
    }

    #[tokio::test]
    async fn request_in_progress_is_transient() {
        let rule = mock!(Client::export_certificate).then_error(|| {
            ExportCertificateError::RequestInProgressException(
                RequestInProgressException::builder().build(),
            )
        });
        let err = make_error(rule).await;
        assert!(err.is_transient());
    }

    #[tokio::test]
    async fn throttling_429_is_transient() {
        let rule = mock!(Client::export_certificate).then_http_response(|| {
            aws_smithy_runtime_api::http::Response::new(
                StatusCode::try_from(429).unwrap(),
                SdkBody::from("too many requests"),
            )
        });
        let err = make_error(rule).await;
        assert!(err.is_transient());
    }

    // -- summarize_sdk_error tests --

    #[tokio::test]
    async fn summary_includes_status_code_and_message_for_service_error() {
        let rule = mock!(Client::export_certificate).then_http_response(|| {
            aws_smithy_runtime_api::http::Response::new(
                StatusCode::try_from(404).unwrap(),
                SdkBody::from("not found"),
            )
        });
        let err = make_error(rule).await;
        assert_eq!(err.to_string(), "Unknown (HTTP 404): no message");
    }

    // -- summarize_sdk_error: non-ServiceError branches --

    #[test]
    fn summary_timeout_error() {
        let err: SdkError<ExportCertificateError, HttpResponse> =
            SdkError::timeout_error("request timed out");
        let summary = summarize_sdk_error(&err);
        assert_eq!(summary, "Timeout");
    }

    #[test]
    fn summary_dispatch_failure() {
        use aws_smithy_runtime_api::client::result::ConnectorError;
        let connector_err = ConnectorError::other("connection reset".into(), None);
        let err: SdkError<ExportCertificateError, HttpResponse> =
            SdkError::dispatch_failure(connector_err);
        assert_eq!(
            summarize_sdk_error(&err),
            "DispatchFailure: connection reset"
        );
    }

    #[test]
    fn summary_response_error() {
        let raw = HttpResponse::new(
            StatusCode::try_from(502).unwrap(),
            SdkBody::from("bad gateway"),
        );
        let err: SdkError<ExportCertificateError, HttpResponse> =
            SdkError::response_error("parse failed", raw);
        assert_eq!(summarize_sdk_error(&err), "ResponseError (HTTP 502)");
    }

    // -- telemetry_code tests --

    #[tokio::test]
    async fn telemetry_code_is_service_code() {
        let rule = mock!(Client::export_certificate).then_http_response(|| {
            aws_smithy_runtime_api::http::Response::new(
                StatusCode::try_from(403).unwrap(),
                SdkBody::from(r#"{"__type":"AccessDeniedException","message":"denied for arn:aws:iam::111122223333:role/x"}"#),
            )
        });
        let err = make_error(rule).await;
        assert_eq!(err.telemetry_code(), FailureCode::AccessDeniedException);
        // Only the log summary keeps the message text.
        assert!(err.to_string().contains("denied for"));
    }

    #[tokio::test]
    async fn telemetry_code_is_other_without_service_code() {
        let rule = mock!(Client::export_certificate).then_http_response(|| {
            aws_smithy_runtime_api::http::Response::new(
                StatusCode::try_from(404).unwrap(),
                SdkBody::from("not found"),
            )
        });
        assert_eq!(make_error(rule).await.telemetry_code(), FailureCode::Other);
    }

    #[test]
    fn telemetry_code_tokens_for_transport_failures() {
        use aws_smithy_runtime_api::client::result::ConnectorError;
        use aws_smithy_types::retry::ErrorKind;
        let raw = HttpResponse::new(StatusCode::try_from(502).unwrap(), SdkBody::from(""));
        let cases: Vec<(SdkError<ExportCertificateError, HttpResponse>, FailureCode)> = vec![
            (
                SdkError::timeout_error("timed out"),
                FailureCode::TimeoutError,
            ),
            (
                SdkError::dispatch_failure(ConnectorError::timeout("connect".into())),
                FailureCode::TimeoutError,
            ),
            (
                SdkError::dispatch_failure(ConnectorError::io("reset".into())),
                FailureCode::ConnectionError,
            ),
            (
                SdkError::dispatch_failure(ConnectorError::other(
                    "other".into(),
                    Some(ErrorKind::TransientError),
                )),
                FailureCode::DispatchFailure,
            ),
            (
                SdkError::response_error("parse", raw),
                FailureCode::ConnectionError,
            ),
        ];
        for (err, expected) in cases {
            assert_eq!(sdk_error_code(&err), expected);
        }
    }

    #[test]
    fn telemetry_code_for_internal_failure_is_agent_internal() {
        let err =
            AcmManagerError::InternalFailure("no client for role arn:aws:iam::1:role/x".into());
        assert_eq!(err.telemetry_code(), FailureCode::AgentInternal);
    }

    // -- is_transient_error: non-ServiceError branches --

    #[test]
    fn timeout_error_is_transient() {
        let err: SdkError<ExportCertificateError, HttpResponse> =
            SdkError::timeout_error("timed out");
        assert!(is_transient_error(&err));
    }

    #[test]
    fn response_error_is_transient() {
        let raw = HttpResponse::new(StatusCode::try_from(200).unwrap(), SdkBody::from(""));
        let err: SdkError<ExportCertificateError, HttpResponse> =
            SdkError::response_error("incomplete", raw);
        assert!(is_transient_error(&err));
    }

    #[test]
    fn dispatch_failure_io_is_transient() {
        use aws_smithy_runtime_api::client::result::ConnectorError;
        let connector_err = ConnectorError::io("socket hangup".into());
        let err: SdkError<ExportCertificateError, HttpResponse> =
            SdkError::dispatch_failure(connector_err);
        assert!(is_transient_error(&err));
    }

    #[test]
    fn dispatch_failure_timeout_is_transient() {
        use aws_smithy_runtime_api::client::result::ConnectorError;
        let connector_err = ConnectorError::timeout("connect timeout".into());
        let err: SdkError<ExportCertificateError, HttpResponse> =
            SdkError::dispatch_failure(connector_err);
        assert!(is_transient_error(&err));
    }

    #[test]
    fn dispatch_failure_other_is_transient() {
        use aws_smithy_runtime_api::client::result::ConnectorError;
        use aws_smithy_types::retry::ErrorKind;
        let connector_err =
            ConnectorError::other("something else".into(), Some(ErrorKind::TransientError));
        let err: SdkError<ExportCertificateError, HttpResponse> =
            SdkError::dispatch_failure(connector_err);
        assert!(is_transient_error(&err));
    }

    // -- error_chain_message tests --

    #[test]
    fn error_chain_message_returns_leaf() {
        // Build a chain: outer -> inner
        #[derive(Debug)]
        struct Inner;
        impl std::fmt::Display for Inner {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "root cause")
            }
        }
        impl std::error::Error for Inner {}

        #[derive(Debug)]
        struct Outer(Inner);
        impl std::fmt::Display for Outer {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "outer wrapper")
            }
        }
        impl std::error::Error for Outer {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }

        let err = Outer(Inner);
        assert_eq!(error_chain_message(&err), "root cause");
    }

    #[test]
    fn error_chain_message_single_error_returns_own_message() {
        #[derive(Debug)]
        struct Simple;
        impl std::fmt::Display for Simple {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "simple error")
            }
        }
        impl std::error::Error for Simple {}

        assert_eq!(error_chain_message(&Simple), "simple error");
    }
}
