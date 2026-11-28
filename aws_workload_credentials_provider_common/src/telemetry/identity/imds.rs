//! IMDSv2 transport for EC2 detection: one GET of the instance identity
//! document. The SDK client does the token exchange, honors the
//! `AWS_EC2_METADATA_SERVICE_ENDPOINT*` overrides, and never falls back to
//! IMDSv1. It does not honor `AWS_EC2_METADATA_DISABLED`; that is checked here.

use std::time::Duration;

use aws_config::imds::Client;
use aws_config::provider_config::ProviderConfig;
use log::debug;

const DOCUMENT_PATH: &str = "/latest/dynamic/instance-identity/document";
const ATTEMPTS: u32 = 2;
const CONNECT_TIMEOUT: Duration = Duration::from_millis(500);
const READ_TIMEOUT: Duration = Duration::from_secs(1);
const DEADLINE: Duration = Duration::from_secs(3);

/// The document body, or `None` on any failure. The body is never logged.
pub(super) async fn instance_identity_document(
    env: &impl Fn(&str) -> Option<String>,
) -> Option<String> {
    if disabled(env) {
        return None;
    }
    get(&client(&ProviderConfig::default())).await
}

fn disabled(env: &impl Fn(&str) -> Option<String>) -> bool {
    env("AWS_EC2_METADATA_DISABLED").is_some_and(|value| value.eq_ignore_ascii_case("true"))
}

fn client(config: &ProviderConfig) -> Client {
    Client::builder()
        .max_attempts(ATTEMPTS)
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(READ_TIMEOUT)
        .configure(config)
        .build()
}

async fn get(client: &Client) -> Option<String> {
    match tokio::time::timeout(DEADLINE, client.get(DOCUMENT_PATH)).await {
        Ok(Ok(body)) => Some(body.into()),
        Ok(Err(error)) => {
            debug!("IMDS instance identity document: {error}");
            None
        }
        Err(_) => {
            debug!("IMDS instance identity document: no answer within {DEADLINE:?}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_smithy_http_client::test_util::{ReplayEvent, StaticReplayClient};
    use aws_smithy_types::body::SdkBody;

    const IMDS: &str = "http://169.254.169.254";
    const TOKEN_PATH: &str = "/latest/api/token";
    const TOKEN_TTL_HEADER: &str = "x-aws-ec2-metadata-token-ttl-seconds";

    fn env<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |key| {
            vars.iter()
                .find(|(name, _)| *name == key)
                .map(|(_, value)| value.to_string())
        }
    }

    fn request(method: &str, path: &str) -> http::Request<SdkBody> {
        http::Request::builder()
            .method(method)
            .uri(format!("{IMDS}{path}"))
            .body(SdkBody::empty())
            .unwrap()
    }

    fn response(status: u16, body: &'static str) -> http::Response<SdkBody> {
        http::Response::builder()
            .status(status)
            .body(SdkBody::from(body))
            .unwrap()
    }

    fn token_issued() -> ReplayEvent {
        let mut response = response(200, "token");
        response
            .headers_mut()
            .insert(TOKEN_TTL_HEADER, "21600".parse().unwrap());
        ReplayEvent::new(request("PUT", TOKEN_PATH), response)
    }

    fn document_answered(status: u16, body: &'static str) -> ReplayEvent {
        ReplayEvent::new(
            request("GET", "/latest/dynamic/instance-identity/document"),
            response(status, body),
        )
    }

    async fn get_replayed(events: Vec<ReplayEvent>) -> Option<String> {
        let replay = StaticReplayClient::new(events);
        let config = ProviderConfig::default().with_http_client(replay.clone());
        let body = get(&client(&config)).await;
        replay.assert_requests_match(&[]);
        body
    }

    #[test]
    fn disabled_only_when_env_is_true() {
        assert!(disabled(&env(&[("AWS_EC2_METADATA_DISABLED", "true")])));
        assert!(disabled(&env(&[("AWS_EC2_METADATA_DISABLED", "TRUE")])));
        assert!(!disabled(&env(&[("AWS_EC2_METADATA_DISABLED", "false")])));
        assert!(!disabled(&env(&[])));
    }

    #[tokio::test]
    async fn document_round_trip() {
        let body = r#"{"instanceId":"i-1234567890abcdef0","region":"us-west-2"}"#;
        assert_eq!(
            get_replayed(vec![token_issued(), document_answered(200, body)]).await,
            Some(body.to_string())
        );
    }

    #[tokio::test]
    async fn token_forbidden_is_none() {
        let token_refused = ReplayEvent::new(request("PUT", TOKEN_PATH), response(403, ""));
        assert_eq!(get_replayed(vec![token_refused]).await, None);
    }
}
