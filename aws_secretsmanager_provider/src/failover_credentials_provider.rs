use std::sync::Mutex;
use std::time::Duration;

use aws_credential_types::provider::{self, error::CredentialsError, future, ProvideCredentials};
use aws_sdk_sts::error::SdkError;
use aws_sdk_sts::operation::assume_role::AssumeRoleError;
use aws_sdk_sts::operation::assume_role_with_web_identity::AssumeRoleWithWebIdentityError;
use aws_secretsmanager_caching::error::is_transient_error;
use tokio::time::Instant;

/// Bound on the failover attempt, and the most the primary attempt gets. Matches
/// the SDK's default identity load timeout.
pub(crate) const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);

/// Bound on the primary attempt: half of `operation_timeout_ms`, at most
/// `ATTEMPT_TIMEOUT`. A Secrets Manager call that refreshes credentials runs
/// inside `operation_timeout_ms`, so the primary attempt and the failover
/// attempt after it have to fit in that budget, or the call is cut off and
/// fails over to the failover region's Secrets Manager with no outage.
pub(crate) fn primary_attempt_timeout(operation_timeout: Duration) -> Duration {
    (operation_timeout / 2).min(ATTEMPT_TIMEOUT)
}

/// Identity cache load timeout for a client using this provider. The default
/// would expire during the primary attempt, before the failover provider runs.
pub(crate) const LOAD_TIMEOUT: Duration = Duration::from_secs(2 * ATTEMPT_TIMEOUT.as_secs() + 1);

/// How long loads skip the primary after it looks down. A load that the Secrets
/// Manager call's timeout cuts during the failover attempt is dropped, and the
/// failover-region call's load starts within this long.
const SKIP_PRIMARY_FOR: Duration = ATTEMPT_TIMEOUT;

/// A credentials provider that tries a primary provider, then a failover
/// provider if the primary region looks down. `CredentialsProviderChain` can't be used as
/// it moves on only after `CredentialsNotLoaded`.
#[derive(Debug)]
pub(crate) struct FailoverCredentialsProvider<P> {
    pub(crate) primary: P,
    pub(crate) failover: P,
    pub(crate) role_arn: String,
    pub(crate) primary_region: String,
    pub(crate) failover_region: String,
    /// Bound on the primary attempt, from `primary_attempt_timeout`.
    pub(crate) primary_timeout: Duration,
    /// When the primary last looked down, so loads right after skip it.
    pub(crate) primary_down_at: Mutex<Option<Instant>>,
    /// The operation in the failover log: `AssumeRole` for a role, or
    /// `OwnCredentials` for the agent's own credentials (the default client).
    pub(crate) operation: &'static str,
}

impl<P: ProvideCredentials> ProvideCredentials for FailoverCredentialsProvider<P> {
    fn provide_credentials<'a>(&'a self) -> future::ProvideCredentials<'a>
    where
        Self: 'a,
    {
        future::ProvideCredentials::new(async {
            let primary_down_at = *self.primary_down_at.lock().unwrap();
            if primary_down_at.is_some_and(|at| at.elapsed() < SKIP_PRIMARY_FOR) {
                let failover = attempt(&self.failover, ATTEMPT_TIMEOUT).await;
                if failover.is_ok() {
                    warn_failover(
                        self.operation,
                        &self.role_arn,
                        &self.primary_region,
                        &CredentialsError::provider_error(
                            "skipped, it looked down on a recent load",
                        ),
                        &self.failover_region,
                        &failover,
                    );
                    return failover;
                }
                // The failover failed too, so the primary may be back: try it once.
                // The WARN waits for this attempt, so it shows how the load ended.
                let primary_result = attempt(&self.primary, self.primary_timeout).await;
                match &primary_result {
                    // It's back, so the load didn't fail over, and the next load
                    // tries it first again.
                    Ok(_) => *self.primary_down_at.lock().unwrap() = None,
                    Err(primary_error) => warn_failover(
                        self.operation,
                        &self.role_arn,
                        &self.primary_region,
                        primary_error,
                        &self.failover_region,
                        &failover,
                    ),
                }
                return primary_result;
            }
            let primary_result = attempt(&self.primary, self.primary_timeout).await;
            let primary_error = match primary_result {
                Ok(creds) => return Ok(creds),
                Err(e) if !is_region_down(&e) => return Err(e),
                Err(e) => e,
            };
            *self.primary_down_at.lock().unwrap() = Some(Instant::now());
            let failover = attempt(&self.failover, ATTEMPT_TIMEOUT).await;
            warn_failover(
                self.operation,
                &self.role_arn,
                &self.primary_region,
                &primary_error,
                &self.failover_region,
                &failover,
            );
            // If the failover fails too, return the primary's error.
            failover.or(Err(primary_error))
        })
    }
}

/// One provider attempt, cut off at `timeout` so a hanging primary leaves the
/// failover provider time to run.
async fn attempt(provider: &impl ProvideCredentials, timeout: Duration) -> provider::Result {
    tokio::time::timeout(timeout, provider.provide_credentials())
        .await
        .unwrap_or_else(|_| Err(CredentialsError::provider_timed_out(timeout)))
}

/// Whether a primary error points at the region rather than the request: a
/// timeout, or a transient error from the STS call that failed, whether that's
/// AssumeRole or the call behind the agent's own credentials (EKS IRSA, or a
/// profile with role_arn). Anything else fails the same way in every region:
/// AccessDenied, a throttling error that comes back before the primary attempt
/// is cut off, or a local fault in the agent's own credentials (no credentials,
/// a missing token file, a bad profile). A throttled primary that the SDK is
/// still retrying at the cutoff fails over as a timeout and starts the 5s skip
/// window. A higher `operation_timeout_ms` makes that less likely.
fn is_region_down(primary_error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(primary_error);
    while let Some(error) = current {
        if let Some(CredentialsError::ProviderTimedOut(_)) =
            error.downcast_ref::<CredentialsError>()
        {
            return true;
        }
        if let Some(sts_error) = error.downcast_ref::<SdkError<AssumeRoleWithWebIdentityError>>() {
            return is_transient_error(sts_error);
        }
        if let Some(sts_error) = error.downcast_ref::<SdkError<AssumeRoleError>>() {
            match sts_error {
                // AssumeRole never sent: the agent's own credentials failed, and
                // the error further down says why.
                SdkError::DispatchFailure(dispatch) if dispatch.is_other() => {}
                sts_error => return is_transient_error(sts_error),
            }
        }
        current = error.source();
    }
    false
}

/// WARN on every role credential failover, in the same format as Secrets
/// Manager failover so the same alerts and metrics pick it up.
pub(crate) fn warn_failover(
    operation: &str,
    role_arn: &str,
    primary_region: &str,
    primary_error: &(impl std::error::Error + 'static),
    failover_region: &str,
    failover_result: &Result<impl Sized, impl std::error::Error + 'static>,
) {
    let outcome = match failover_result {
        Ok(_) => "ok".to_string(),
        Err(f) => format!("error \"{}\"", error_chain(f)),
    };
    log::warn!(
        "failover=true operation={operation} role_arn={role_arn} primary_region={primary_region} \
         primary_error=\"{}\" failover_region={failover_region} result={outcome}",
        error_chain(primary_error)
    );
}

/// An error's message followed by each cause's, joined with `": "`, for logs.
/// Unlike `DisplayErrorContext`, it leaves out the error's `Debug` form, which
/// holds the raw HTTP response, so the response itself never reaches the log. A
/// parse error's message can still quote a few characters of a malformed
/// response, such as an invalid JSON `\u` escape or an unknown XML entity.
fn error_chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut chain = error_message(error);
    let mut source = error.source();
    while let Some(cause) = source {
        chain.push_str(": ");
        chain.push_str(&error_message(cause));
        source = cause.source();
    }
    chain
}

/// An error's message. A credentials timeout gets its exact duration: the SDK's
/// message rounds it down to whole seconds, so a 1.5s cutoff reads "1 seconds".
fn error_message(error: &(dyn std::error::Error + 'static)) -> String {
    match error.downcast_ref::<CredentialsError>() {
        Some(CredentialsError::ProviderTimedOut(timed_out)) => format!(
            "credentials provider timed out after {:?}",
            timed_out.timeout_duration()
        ),
        _ => error.to_string(),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use aws_credential_types::Credentials;
    use aws_sdk_sts::error::DisplayErrorContext;
    use aws_sdk_sts::error::ErrorMetadata;
    use aws_smithy_runtime_api::client::orchestrator::HttpResponse;
    use aws_smithy_runtime_api::client::result::ConnectorError;
    use aws_smithy_types::body::SdkBody;

    #[derive(Debug)]
    pub(crate) enum Fake {
        Ok(&'static str),
        /// Credentials with this access key after 1s, like a real STS round trip.
        Slow(&'static str),
        Fail(&'static str),
        Hang,
        /// An STS error response with this HTTP status and error code, wrapped
        /// the way `AssumeRoleProvider` wraps it.
        Sts(u16, &'static str),
        /// The bare web identity error the default chain returns for EKS IRSA:
        /// STS answered AssumeRoleWithWebIdentity with this HTTP status and error code.
        WebIdentitySts(u16, &'static str),
        /// AssumeRole never sent: STS answered the agent's own credentials request
        /// (EKS IRSA) with this HTTP status and error code.
        NoOwnCredentials(u16, &'static str),
        /// AssumeRole never sent: the agent's own credentials failed with this
        /// error, before any call to STS.
        OwnCredentialsFault(fn() -> CredentialsError),
    }

    impl ProvideCredentials for Fake {
        fn provide_credentials<'a>(&'a self) -> future::ProvideCredentials<'a>
        where
            Self: 'a,
        {
            future::ProvideCredentials::new(async move {
                match self {
                    Fake::Ok(key) => Ok(Credentials::new(*key, "secret", None, None, "test")),
                    Fake::Slow(key) => {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        Ok(Credentials::new(*key, "secret", None, None, "test"))
                    }
                    Fake::Fail(msg) => Err(CredentialsError::provider_error(*msg)),
                    Fake::Hang => std::future::pending().await,
                    Fake::Sts(status, code) => {
                        Err(CredentialsError::provider_error(SdkError::service_error(
                            AssumeRoleError::generic(ErrorMetadata::builder().code(*code).build()),
                            HttpResponse::new((*status).try_into().unwrap(), SdkBody::empty()),
                        )))
                    }
                    Fake::WebIdentitySts(status, code) => {
                        Err(CredentialsError::provider_error(SdkError::service_error(
                            AssumeRoleWithWebIdentityError::generic(
                                ErrorMetadata::builder().code(*code).build(),
                            ),
                            HttpResponse::new((*status).try_into().unwrap(), SdkBody::empty()),
                        )))
                    }
                    Fake::NoOwnCredentials(status, code) => {
                        let own_credentials_error =
                            CredentialsError::provider_error(SdkError::service_error(
                                AssumeRoleWithWebIdentityError::generic(
                                    ErrorMetadata::builder().code(*code).build(),
                                ),
                                HttpResponse::new((*status).try_into().unwrap(), SdkBody::empty()),
                            ));
                        Err(CredentialsError::provider_error(
                            SdkError::<AssumeRoleError>::dispatch_failure(ConnectorError::other(
                                own_credentials_error.into(),
                                None,
                            )),
                        ))
                    }
                    Fake::OwnCredentialsFault(fault) => Err(CredentialsError::provider_error(
                        SdkError::<AssumeRoleError>::dispatch_failure(ConnectorError::other(
                            fault().into(),
                            None,
                        )),
                    )),
                }
            })
        }
    }

    pub(crate) fn provider(primary: Fake, failover: Fake) -> FailoverCredentialsProvider<Fake> {
        FailoverCredentialsProvider {
            primary,
            failover,
            role_arn: "arn:aws:iam::123456789012:role/MyRole".into(),
            primary_region: "us-east-1".into(),
            failover_region: "us-west-2".into(),
            primary_timeout: ATTEMPT_TIMEOUT,
            primary_down_at: Default::default(),
            operation: "AssumeRole",
        }
    }

    async fn access_key(provider: FailoverCredentialsProvider<Fake>) -> String {
        provider
            .provide_credentials()
            .await
            .expect("credentials")
            .access_key_id()
            .to_string()
    }

    #[tokio::test]
    async fn test_primary_credentials_are_used_first() {
        let provider = provider(Fake::Ok("primary"), Fake::Fail("failover down"));
        assert_eq!(access_key(provider).await, "primary");
    }

    // The primary attempt is cut off, and the failover attempt still fits in the
    // identity cache's load timeout after it.
    #[tokio::test(start_paused = true)]
    async fn test_hanging_primary_fails_over() {
        let start = tokio::time::Instant::now();
        let provider = provider(Fake::Hang, Fake::Ok("failover"));
        assert_eq!(access_key(provider).await, "failover");
        assert!(start.elapsed() + ATTEMPT_TIMEOUT < LOAD_TIMEOUT);
    }

    // The primary attempt gets half of operation_timeout_ms, at most ATTEMPT_TIMEOUT.
    #[test]
    fn test_primary_attempt_timeout() {
        let half = |ms| primary_attempt_timeout(Duration::from_millis(ms));
        assert_eq!(half(2000), Duration::from_millis(1000));
        assert_eq!(half(3000), Duration::from_millis(1500));
        assert_eq!(half(25000), ATTEMPT_TIMEOUT);
    }

    // With the default 3000 ms operation timeout, a hanging primary fails over
    // before the Secrets Manager call that triggered the refresh is cut off.
    #[tokio::test(start_paused = true)]
    async fn test_hanging_primary_fails_over_within_operation_timeout() {
        let operation_timeout = Duration::from_millis(3000);
        let mut provider = provider(Fake::Hang, Fake::Slow("failover"));
        provider.primary_timeout = primary_attempt_timeout(operation_timeout);
        let start = tokio::time::Instant::now();
        assert_eq!(access_key(provider).await, "failover");
        assert!(start.elapsed() < operation_timeout);
    }

    // The Secrets Manager call's timeout cuts the first load during the failover
    // attempt. The failover-region call's load right after skips the hanging
    // primary.
    #[tokio::test(start_paused = true)]
    async fn test_load_after_cut_load_skips_primary() {
        let mut provider = provider(Fake::Hang, Fake::Slow("failover"));
        provider.primary_timeout = Duration::from_millis(1500);
        let secrets_manager_timeout = Duration::from_millis(2000);
        let cut_load =
            tokio::time::timeout(secrets_manager_timeout, provider.provide_credentials()).await;
        assert!(cut_load.is_err());
        let start = Instant::now();
        assert_eq!(access_key(provider).await, "failover");
        // Only the 1 s failover attempt, not the 1.5 s primary attempt before it.
        assert!(start.elapsed() < Duration::from_millis(1500));
    }

    // Once SKIP_PRIMARY_FOR has passed, loads try the primary again.
    #[tokio::test(start_paused = true)]
    async fn test_primary_tried_again_after_skip_window() {
        let mut provider = provider(Fake::Sts(500, "InternalFailure"), Fake::Ok("failover"));
        provider.provide_credentials().await.expect("failover");
        provider.primary = Fake::Ok("primary");
        let creds = provider.provide_credentials().await.expect("failover");
        assert_eq!(creds.access_key_id(), "failover");
        tokio::time::advance(SKIP_PRIMARY_FOR).await;
        let creds = provider.provide_credentials().await.expect("primary");
        assert_eq!(creds.access_key_id(), "primary");
    }

    // Inside the skip window the failover fails, so the primary, which is back,
    // is tried once instead of the load failing.
    #[tokio::test]
    async fn test_skipped_primary_tried_when_failover_fails() {
        let mut failover_credentials_provider = provider(
            Fake::Sts(500, "InternalFailure"),
            Fake::Fail("failover down"),
        );
        failover_credentials_provider
            .provide_credentials()
            .await
            .expect_err("both down");
        failover_credentials_provider.primary = Fake::Ok("primary");
        assert_eq!(access_key(failover_credentials_provider).await, "primary");
    }

    // Inside the skip window the failover fails and the primary answers, so the
    // window ends: the next load tries the primary first, not the failover.
    #[tokio::test]
    async fn test_skip_window_ends_when_skipped_primary_answers() {
        let mut failover_credentials_provider = provider(
            Fake::Sts(500, "InternalFailure"),
            Fake::Fail("failover down"),
        );
        failover_credentials_provider
            .provide_credentials()
            .await
            .expect_err("both down");
        failover_credentials_provider.primary = Fake::Ok("primary");
        failover_credentials_provider
            .provide_credentials()
            .await
            .expect("primary");
        failover_credentials_provider.failover = Fake::Ok("failover");
        assert_eq!(access_key(failover_credentials_provider).await, "primary");
    }

    // Inside the skip window the WARN shows how the load ended: result=ok when the
    // failover answers, the retry's error when the retried primary fails too, and
    // no WARN when the retried primary answers.
    #[tokio::test]
    async fn test_skip_window_warns_after_primary_retry() {
        let mut failover_credentials_provider = provider(
            Fake::Sts(500, "InternalFailure"),
            Fake::Fail("failover down"),
        );
        failover_credentials_provider
            .provide_credentials()
            .await
            .expect_err("both down");
        // Records this thread's WARN lines; each #[tokio::test] runs on its own thread.
        struct WarningRecorder;
        thread_local! {
            static WARNINGS: std::cell::RefCell<Vec<String>> = Default::default();
        }
        impl log::Log for WarningRecorder {
            fn enabled(&self, _: &log::Metadata) -> bool {
                true
            }
            fn log(&self, record: &log::Record) {
                WARNINGS.with(|lines| lines.borrow_mut().push(record.args().to_string()));
            }
            fn flush(&self) {}
        }
        log::set_logger(&WarningRecorder).expect("no other logger in unit tests");
        log::set_max_level(log::LevelFilter::Warn);
        let take_warnings = || WARNINGS.with(|lines| std::mem::take(&mut *lines.borrow_mut()));
        failover_credentials_provider.failover = Fake::Ok("failover");
        failover_credentials_provider
            .provide_credentials()
            .await
            .expect("failover");
        let warnings = take_warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("skipped, it looked down on a recent load"));
        assert!(warnings[0].contains("result=ok"));
        failover_credentials_provider.failover = Fake::Fail("failover down");
        failover_credentials_provider.primary = Fake::Fail("primary still down");
        failover_credentials_provider
            .provide_credentials()
            .await
            .expect_err("both still down");
        let warnings = take_warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains(
            "primary_error=\"an error occurred while loading credentials: primary still down\""
        ));
        assert!(warnings[0].contains("result=error"));
        failover_credentials_provider.primary = Fake::Ok("primary");
        failover_credentials_provider
            .provide_credentials()
            .await
            .expect("primary");
        assert_eq!(take_warnings(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn test_transient_sts_error_fails_over() {
        let provider = provider(Fake::Sts(500, "InternalFailure"), Fake::Ok("failover"));
        assert_eq!(access_key(provider).await, "failover");
    }

    // The agent's own credentials failed (EKS IRSA with the primary STS down).
    #[tokio::test]
    async fn test_own_credentials_failure_fails_over() {
        let provider = provider(
            Fake::NoOwnCredentials(503, "ServiceUnavailable"),
            Fake::Ok("failover"),
        );
        assert_eq!(access_key(provider).await, "failover");
    }

    // STS refused the agent's own credentials (a wrong IRSA trust policy), so it doesn't fail over.
    #[tokio::test]
    async fn test_refused_own_credentials_do_not_fail_over() {
        let provider = provider(
            Fake::NoOwnCredentials(403, "AccessDenied"),
            Fake::Ok("failover"),
        );
        let err = provider.provide_credentials().await.expect_err("refused");
        assert!(DisplayErrorContext(&err)
            .to_string()
            .contains("AccessDenied"));
    }

    // The default client's own credentials on EKS IRSA: the default chain returns
    // the web identity error itself, not wrapped in an AssumeRole error.
    #[tokio::test]
    async fn test_web_identity_sts_error_fails_over() {
        let provider = provider(
            Fake::WebIdentitySts(503, "ServiceUnavailable"),
            Fake::Ok("failover"),
        );
        assert_eq!(access_key(provider).await, "failover");
    }

    #[tokio::test]
    async fn test_web_identity_access_denied_does_not_fail_over() {
        let provider = provider(
            Fake::WebIdentitySts(403, "AccessDenied"),
            Fake::Ok("failover"),
        );
        let err = provider.provide_credentials().await.expect_err("refused");
        assert!(DisplayErrorContext(&err)
            .to_string()
            .contains("AccessDenied"));
    }

    // The agent's own credentials timed out, as when their STS endpoint hangs.
    #[tokio::test]
    async fn test_own_credentials_timeout_fails_over() {
        let timeout = || CredentialsError::provider_timed_out(ATTEMPT_TIMEOUT);
        let provider = provider(Fake::OwnCredentialsFault(timeout), Fake::Ok("failover"));
        assert_eq!(access_key(provider).await, "failover");
    }

    // A local fault in the agent's own credentials (no credentials, a bad
    // profile, a missing token file) fails the same way in every region.
    #[tokio::test]
    async fn test_local_own_credentials_faults_do_not_fail_over() {
        let faults: [fn() -> CredentialsError; 3] = [
            || CredentialsError::not_loaded("no credentials"),
            || CredentialsError::invalid_configuration("bad profile"),
            || CredentialsError::provider_error(std::io::Error::from(std::io::ErrorKind::NotFound)),
        ];
        for fault in faults {
            let provider = provider(Fake::OwnCredentialsFault(fault), Fake::Ok("failover"));
            assert!(provider.provide_credentials().await.is_err());
        }
    }

    // A throttling error that comes back before the primary attempt is cut off
    // isn't a region outage, so the primary's error is returned. One the SDK is
    // still retrying at the cutoff fails over as a timeout (see is_region_down).
    #[tokio::test]
    async fn test_throttled_primary_does_not_fail_over() {
        let provider = provider(Fake::Sts(400, "Throttling"), Fake::Ok("failover"));
        let err = provider.provide_credentials().await.expect_err("throttled");
        assert!(DisplayErrorContext(&err).to_string().contains("Throttling"));
    }

    #[tokio::test]
    async fn test_failed_failover_returns_primary_error() {
        let provider = provider(
            Fake::Sts(500, "InternalFailure"),
            Fake::Fail("failover down"),
        );
        let err = provider.provide_credentials().await.expect_err("both fail");
        assert!(DisplayErrorContext(&err)
            .to_string()
            .contains("InternalFailure"));
    }

    // An AssumeRole 200 that can't be parsed keeps the role's credentials in the
    // error's raw response, wrapped the way AssumeRoleProvider wraps it. The chain
    // keeps the parse message for the failover log but not the credentials.
    #[test]
    fn test_error_chain_leaves_out_response_body() {
        let unparseable = CredentialsError::provider_error(SdkError::service_error(
            AssumeRoleError::unhandled("error parsing XML"),
            HttpResponse::new(
                200.try_into().unwrap(),
                SdkBody::from("<SecretAccessKey>role-secret-key</SecretAccessKey>"),
            ),
        ));
        let chain = error_chain(&unparseable);
        assert!(!chain.contains("role-secret-key"));
        assert!(chain.contains("error parsing XML"));
    }

    // The default primary cutoff is 1.5s, which the SDK's timeout message would
    // round down to "1 seconds".
    #[test]
    fn test_error_chain_keeps_exact_timeout() {
        let primary_cut = CredentialsError::provider_timed_out(Duration::from_millis(1500));
        assert_eq!(
            error_chain(&primary_cut),
            "credentials provider timed out after 1.5s"
        );
    }
}
