//! Task metadata transport for ECS detection: one GET of
//! `${ECS_CONTAINER_METADATA_URI_V4}/task` from the ECS agent. Only an
//! `http://169.254.170.2/v4/<id>` URI is fetched, and the agent is dialed at that
//! fixed address, so no DNS or proxy applies. The request is HTTP/1.0, so the
//! reply is never chunked and ends when the agent closes the connection.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use log::debug;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub(super) const URI_V4: &str = "ECS_CONTAINER_METADATA_URI_V4";
const ENDPOINT_PREFIX: &str = "http://169.254.170.2/v4/";
const AGENT: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 170, 2)), 80);
const MAX_RESPONSE: u64 = 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(2);

/// The `/task` body, or `None` on any failure. The body is never logged.
pub(super) async fn task(env: &impl Fn(&str) -> Option<String>) -> Option<String> {
    let Some(path) = env(URI_V4).as_deref().and_then(task_path) else {
        debug!("ECS task metadata: URI is not {ENDPOINT_PREFIX}<id>");
        return None;
    };
    get(AGENT, &path, DEADLINE).await
}

fn task_path(uri: &str) -> Option<String> {
    let id = uri.strip_prefix(ENDPOINT_PREFIX)?;
    let pinned = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'-';
    if id.is_empty() || !id.bytes().all(pinned) {
        return None;
    }
    Some(format!("/v4/{id}/task"))
}

async fn get(address: SocketAddr, path: &str, deadline: Duration) -> Option<String> {
    match tokio::time::timeout(deadline, request(address, path)).await {
        Ok(Ok(body)) => Some(body),
        Ok(Err(error)) => {
            debug!("ECS task metadata: {error}");
            None
        }
        Err(_) => {
            debug!("ECS task metadata: no answer within {deadline:?}");
            None
        }
    }
}

async fn request(address: SocketAddr, path: &str) -> io::Result<String> {
    let mut stream = TcpStream::connect(address).await?;
    let request = format!("GET {path} HTTP/1.0\r\nHost: 169.254.170.2\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    let mut capped = stream.take(MAX_RESPONSE + 1);
    capped.read_to_end(&mut response).await?;
    if response.len() as u64 > MAX_RESPONSE {
        return Err(io::Error::other("response too large"));
    }
    let response = String::from_utf8(response).map_err(io::Error::other)?;
    let (head, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| io::Error::other("response has no end of headers"))?;
    match head.split_whitespace().nth(1) {
        Some("200") => Ok(body.to_string()),
        status => Err(io::Error::other(format!("HTTP status {status:?}"))),
    }
}

#[cfg(test)]
mod tests {
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    use super::*;

    const PATH: &str = "/v4/abc/task";
    const TASK: &str = r#"{"TaskARN":"arn:aws:ecs:us-west-2:111122223333:task/MyCluster/1234567890abcdef1234567890abcdef"}"#;

    async fn serve(response: impl Into<Vec<u8>>) -> (SocketAddr, JoinHandle<String>) {
        let response = response.into();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(stream.read_u8().await.unwrap());
            }
            let _ = stream.write_all(&response).await;
            String::from_utf8(head).unwrap()
        });
        (address, server)
    }

    async fn get_reply(response: impl Into<Vec<u8>>) -> Option<String> {
        let (address, _server) = serve(response).await;
        get(address, PATH, DEADLINE).await
    }

    #[test]
    fn task_path_is_the_v4_uri_plus_task() {
        let uri = "http://169.254.170.2/v4/a1b2c3d4-5678-90ab-cdef-EXAMPLEaaaaa";
        assert_eq!(
            task_path(uri).as_deref(),
            Some("/v4/a1b2c3d4-5678-90ab-cdef-EXAMPLEaaaaa/task")
        );
    }

    #[test]
    fn task_path_rejects_unsafe_id() {
        let traversal = "http://169.254.170.2/v4/abc/../../v2/credentials/x";
        let injection = "http://169.254.170.2/v4/abc\r\nHost: example.com";
        assert_eq!(task_path(traversal), None);
        assert_eq!(task_path(injection), None);
    }

    #[tokio::test]
    async fn get_returns_body_on_200() {
        let reply = format!("HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{TASK}");
        assert_eq!(get_reply(reply).await.as_deref(), Some(TASK));
    }

    #[tokio::test]
    async fn get_sends_http_1_0_request() {
        let (address, server) = serve("HTTP/1.0 200 OK\r\n\r\n{}").await;
        get(address, PATH, DEADLINE).await;
        assert_eq!(
            server.await.unwrap(),
            "GET /v4/abc/task HTTP/1.0\r\nHost: 169.254.170.2\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn get_rejects_reply_over_cap() {
        let mut reply = b"HTTP/1.0 200 OK\r\n\r\n".to_vec();
        reply.resize(MAX_RESPONSE as usize + 1, b' ');
        assert_eq!(get_reply(reply).await, None);
    }

    #[tokio::test]
    async fn get_times_out_on_silent_agent() {
        let silent = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = silent.local_addr().unwrap();
        assert_eq!(get(address, PATH, Duration::from_millis(100)).await, None);
    }
}
