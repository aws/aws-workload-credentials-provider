//! Mock IMDS (Instance Metadata Service) server for integration tests.
//!
//! Provides a minimal IMDSv2-compatible HTTP server that the AWS SDK's
//! `imds::Client` can talk to when `AWS_EC2_METADATA_SERVICE_ENDPOINT`
//! points at it. This lets discovery integration tests run on any machine
//! — no real EC2 instance required.
//!
//! The mock handles the IMDSv2 token exchange:
//! - `PUT /latest/api/token` → returns a fixed token string
//! - `GET /latest/dynamic/instance-identity/document` → returns the
//!   configured instance identity JSON document (token validated)

use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// The instance identity document served by the mock.
pub struct MockImdsConfig {
    pub instance_id: String,
    pub account_id: String,
    pub region: String,
}

impl Default for MockImdsConfig {
    fn default() -> Self {
        Self {
            instance_id: "i-mocktest123456".to_string(),
            account_id: "999888777666".to_string(),
            region: "us-west-2".to_string(),
        }
    }
}

impl MockImdsConfig {
    /// Serializes the identity document the same way EC2 IMDS does.
    fn identity_document(&self) -> String {
        format!(
            r#"{{"instanceId":"{}","accountId":"{}","region":"{}","availabilityZone":"{}a","instanceType":"m5.xlarge","imageId":"ami-0123456789abcdef0","pendingTime":"2024-01-01T00:00:00Z","architecture":"x86_64","version":"2017-09-30"}}"#,
            self.instance_id, self.account_id, self.region, self.region
        )
    }
}

/// A running mock IMDS server. Dropping it aborts the accept loop.
pub struct MockImds {
    pub endpoint: String,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for MockImds {
    fn drop(&mut self) {
        // Dropping a JoinHandle only detaches the task; abort stops it.
        self.handle.abort();
    }
}

const IMDS_TOKEN: &str = "mock-imds-token-for-testing";

/// Starts a mock IMDS server on `127.0.0.1:0` (OS-assigned port).
///
/// The returned `MockImds` carries the port and the full endpoint URL
/// suitable for `AWS_EC2_METADATA_SERVICE_ENDPOINT`.
pub async fn start_mock_imds(config: MockImdsConfig) -> MockImds {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind mock IMDS listener");
    let addr = listener.local_addr().expect("failed to get local addr");
    let port = addr.port();
    let endpoint = format!("http://127.0.0.1:{port}");
    let document = config.identity_document();

    let handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let doc = document.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, &doc).await {
                            // Connection reset by peer is normal when the SDK
                            // client closes early; don't pollute test output.
                            if e.kind() != io::ErrorKind::ConnectionReset {
                                eprintln!("mock IMDS connection error: {e}");
                            }
                        }
                    });
                }
                Err(e) => {
                    eprintln!("mock IMDS accept error: {e}");
                    break;
                }
            }
        }
    });

    MockImds { endpoint, handle }
}

/// Handles one HTTP connection. Buffers bytes until a whole request (headers
/// plus any `content-length` body) has arrived, answers it, and keeps any
/// bytes of the next request, so split and pipelined requests both work.
/// Supports HTTP keep-alive by looping until the client closes.
async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    identity_document: &str,
) -> io::Result<()> {
    let mut pending = Vec::new();
    let mut buf = [0u8; 4096];

    loop {
        while let Some(len) = complete_request_len(&pending) {
            let request: Vec<u8> = pending.drain(..len).collect();
            let request = String::from_utf8_lossy(&request);
            let response = route_request(&request, identity_document);
            stream.write_all(response.as_bytes()).await?;
            stream.flush().await?;
        }

        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        pending.extend_from_slice(&buf[..n]);
    }
}

/// The length of the first complete request in `buf`, or `None` if its
/// headers or body haven't all arrived.
fn complete_request_len(buf: &[u8]) -> Option<usize> {
    let header_end = buf.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let headers = String::from_utf8_lossy(&buf[..header_end]);
    let body_len = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    (buf.len() >= header_end + body_len).then_some(header_end + body_len)
}

/// Routes an HTTP request to the appropriate mock handler.
fn route_request(request: &str, identity_document: &str) -> String {
    let first_line = request.lines().next().unwrap_or("");

    if first_line.starts_with("PUT /latest/api/token") {
        return http_response(
            200,
            IMDS_TOKEN,
            &[("x-aws-ec2-metadata-token-ttl-seconds", "21600")],
        );
    }

    if first_line.starts_with("GET /latest/dynamic/instance-identity/document") {
        // Validate the token header (case-insensitive search).
        let has_token = request.lines().any(|line| {
            let lower = line.to_ascii_lowercase();
            lower.starts_with("x-aws-ec2-metadata-token:") && line.contains(IMDS_TOKEN)
        });

        if !has_token {
            return http_response(401, "Unauthorized — missing or invalid token", &[]);
        }

        return http_response(
            200,
            identity_document,
            &[("content-type", "application/json")],
        );
    }

    // Catch-all for unexpected paths.
    http_response(404, "Not Found", &[])
}

/// Formats a minimal HTTP/1.1 response.
fn http_response(status: u16, body: &str, extra_headers: &[(&str, &str)]) -> String {
    let reason = match status {
        200 => "OK",
        401 => "Unauthorized",
        404 => "Not Found",
        _ => "Unknown",
    };
    let mut headers = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         content-length: {}\r\n",
        body.len()
    );
    for (key, value) in extra_headers {
        headers.push_str(&format!("{key}: {value}\r\n"));
    }
    headers.push_str("\r\n");
    headers.push_str(body);
    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_document_contains_required_fields() {
        let config = MockImdsConfig::default();
        let doc = config.identity_document();
        let parsed: serde_json::Value = serde_json::from_str(&doc).unwrap();
        assert_eq!(parsed["instanceId"], "i-mocktest123456");
        assert_eq!(parsed["accountId"], "999888777666");
        assert_eq!(parsed["region"], "us-west-2");
    }

    #[test]
    fn route_put_token_returns_200() {
        let response = route_request("PUT /latest/api/token HTTP/1.1\r\n\r\n", "{}");
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains(IMDS_TOKEN));
    }

    #[test]
    fn route_get_document_without_token_returns_401() {
        let response = route_request(
            "GET /latest/dynamic/instance-identity/document HTTP/1.1\r\n\r\n",
            "{}",
        );
        assert!(response.starts_with("HTTP/1.1 401"));
    }

    #[test]
    fn route_get_document_with_token_returns_200() {
        let doc = r#"{"instanceId":"i-test","region":"us-west-2"}"#;
        let request = format!(
            "GET /latest/dynamic/instance-identity/document HTTP/1.1\r\n\
             x-aws-ec2-metadata-token: {IMDS_TOKEN}\r\n\r\n"
        );
        let response = route_request(&request, doc);
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains(doc));
    }

    #[test]
    fn a_split_request_is_not_complete_until_its_headers_end() {
        assert_eq!(
            complete_request_len(b"PUT /latest/api/token HTTP/1.1\r\n"),
            None
        );
        let whole = b"PUT /latest/api/token HTTP/1.1\r\n\r\n";
        assert_eq!(complete_request_len(whole), Some(whole.len()));
    }

    #[test]
    fn a_body_is_waited_for_and_a_pipelined_request_is_left_over() {
        let first = b"PUT /x HTTP/1.1\r\ncontent-length: 2\r\n\r\nab";
        assert_eq!(complete_request_len(&first[..first.len() - 1]), None);
        let mut pipelined = first.to_vec();
        pipelined.extend_from_slice(b"GET /y HTTP/1.1\r\n\r\n");
        assert_eq!(complete_request_len(&pipelined), Some(first.len()));
    }

    #[test]
    fn route_unknown_path_returns_404() {
        let response = route_request("GET /foo HTTP/1.1\r\n\r\n", "{}");
        assert!(response.starts_with("HTTP/1.1 404"));
    }
}
