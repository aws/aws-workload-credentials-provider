//! AWS Secrets Manager Provider — library entry points for the unified
//! AWS Workload Credentials Provider binary.

mod cache_manager;
mod constants;
mod error;
mod parse;
mod prefetch;
mod server;
mod utils;

use std::net::SocketAddr;

use log::{error, info};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use aws_workload_credentials_provider_common::config::types::ValidatedConfig;
#[cfg(unix)]
use aws_workload_credentials_provider_common::shutdown_signal;
use constants::VERSION;
use server::Server;
use utils::get_token;

/// Runs the Secrets Manager HTTP server until `token` is cancelled.
///
/// This is the Windows/SCM entry point: the service runner owns the tokio
/// runtime and cancels `token` from the SCM Stop/Shutdown callback.
pub async fn sm_workload(
    config: ValidatedConfig,
    token: CancellationToken,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = init_listener(&config).await?;
    serve(listener, &config, token).await
}

/// Drives the HTTP server on `listener` until `token` is cancelled.
///
/// Split from `sm_workload` so tests can bind their own listener (port 0)
/// to discover the actual port before connecting clients.
async fn serve(
    listener: TcpListener,
    config: &ValidatedConfig,
    token: CancellationToken,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = listener.local_addr()?;
    let svr = Server::new(listener, config)
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { format!("{e}").into() })?;

    // Start prefetch background task if enabled
    if config.secrets_manager.prefetch.is_enabled() {
        info!("Pre-fetch enabled, starting background task");
        prefetch::start_prefetch_task(svr.cache_manager(), config.secrets_manager.clone());
    }

    let start_msg = format!(
        "Secrets Manager Provider/{} listening on http://{}",
        VERSION.unwrap_or("0.0.0"),
        addr
    );
    println!("{start_msg}");
    info!("{start_msg}");

    tokio::select! {
        _ = async {
            loop {
                if let Err(e) = svr.serve_request().await {
                    error!("Could not accept connection: {e:?}");
                }
            }
        } => {},
        _ = token.cancelled() => {
            info!("Secrets Manager workload shutting down");
        }
    }

    Ok(())
}

/// Runs the Secrets Manager HTTP server as a standalone process (Unix).
///
/// Creates a tokio runtime, sets up signal handling, and blocks until
/// SIGINT/SIGTERM.
#[cfg(unix)]
pub fn run_sm(config: ValidatedConfig) -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let cancel = CancellationToken::new();
        let token = cancel.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            token.cancel();
        });

        sm_workload(config, cancel)
            .await
            .map_err(|e| -> Box<dyn std::error::Error> { e })
    })
}

/// Validates the SSRF token and binds the TCP listener.
async fn init_listener(
    config: &ValidatedConfig,
) -> Result<TcpListener, Box<dyn std::error::Error + Send + Sync>> {
    if let Err(err) = get_token(&config.secrets_manager.security.ssrf_env_variables) {
        let msg = format!(
            "Could not read SSRF token variable(s) {:?}: {err}",
            config.secrets_manager.security.ssrf_env_variables
        );
        return Err(msg.into());
    }

    let addr: SocketAddr = ([127, 0, 0, 1], config.secrets_manager.http_port).into();
    let listener =
        TcpListener::bind(addr)
            .await
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                format!("Could not bind to {addr}: {e}").into()
            })?;

    Ok(listener)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_secretsmanager as secretsmanager;
    use aws_workload_credentials_provider_common::config::types::{
        LoggingConfig, SecretsManagerConfig, SecurityConfig,
    };
    use aws_workload_credentials_provider_common::config::validator::ConfigValidator;
    use bytes::Bytes;
    use cache_manager::tests::{
        set_client, timeout_client, DEFAULT_LABEL, DEFAULT_VERSION, FAKE_ARN,
    };
    use http_body_util::{BodyExt, Empty};
    use hyper::header::{HeaderName, HeaderValue};
    use hyper::{client, Request, StatusCode};
    use hyper_util::rt::TokioIo;
    use serde_json::Value;

    use std::net::SocketAddr;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{mpsc, Arc, Mutex};
    use std::time::Duration;
    use std::{fs, thread};

    use tokio::net::TcpStream;
    use tokio::task::JoinSet;

    #[cfg(unix)]
    // set_test_var does not work across threads (e.g. run_request)
    use utils::tests::set_test_var;
    use utils::tests::{tmpfile_name, CleanUp};

    // Helpers to run the server in the back ground and send it the given request(s).
    async fn run_request(req: &str) -> (StatusCode, Bytes) {
        run_requests_with_verb(vec![("GET", req)])
            .await
            .expect("request failed")
            .pop()
            .unwrap()
    }
    async fn run_requests_with_verb(
        req_vec: Vec<(&str, &str)>,
    ) -> Result<Vec<(StatusCode, Bytes)>, Box<dyn std::error::Error>> {
        run_requests_with_headers(req_vec, vec![("X-Aws-Parameters-Secrets-Token", "xyzzy")]).await
    }
    async fn run_requests_with_headers(
        req_vec: Vec<(&str, &str)>,
        headers: Vec<(&str, &str)>,
    ) -> Result<Vec<(StatusCode, Bytes)>, Box<dyn std::error::Error>> {
        run_requests_with_client(req_vec, headers, None).await
    }
    async fn run_timeout_request(req: &str) -> (StatusCode, Bytes) {
        run_requests_with_client(
            vec![("GET", req)],
            vec![("X-Aws-Parameters-Secrets-Token", "xyzzy")],
            Some(timeout_client()),
        )
        .await
        .expect("request failed")
        .pop()
        .unwrap()
    }
    async fn run_requests_with_client(
        req_vec: Vec<(&str, &str)>,
        headers: Vec<(&str, &str)>,
        opt_client: Option<secretsmanager::Client>,
    ) -> Result<Vec<(StatusCode, Bytes)>, Box<dyn std::error::Error>> {
        let cfg = ValidatedConfig {
            logging: LoggingConfig::default(),
            secrets_manager: SecretsManagerConfig {
                http_port: 0,
                max_conn: 1,
                ..Default::default()
            },
            acm: None,
        };
        let (tx_addr, rx_addr) = mpsc::channel(); // Open channel for server to report the port
        let token = CancellationToken::new();
        let token_for_thread = token.clone();

        // Run the http server in the background and find the port it is using
        let thr = thread::Builder::new().spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                if let Some(client) = opt_client {
                    set_client(client);
                }
                let listener = init_listener(&cfg).await.expect("could not bind listener");
                let addr = listener.local_addr().expect("could not get local addr");
                tx_addr.send(addr).expect("could not send address");
                serve(listener, &cfg, token_for_thread)
                    .await
                    .expect("could not run server");
            })
        })?;
        let addr = rx_addr.recv()?;

        // Run the series of requests and build up the responses.
        // Each request is run as an async task so they can overlap time wise.
        let mut join_set = JoinSet::new();
        let send_cnt = req_vec.len();
        let mut idx = 0;
        let responses = Arc::new(Mutex::new(Vec::new()));
        for (meth, query) in req_vec.clone() {
            // Setup the connection to the server
            let stream = TcpStream::connect(addr)
                .await
                .expect("could not setup client stream");
            let io = TokioIo::new(stream);
            let (mut sender, conn) = client::conn::http1::handshake(io)
                .await
                .expect("could not setup client");
            // spawn a task to poll the connection and drive the HTTP state
            tokio::spawn(async move {
                if let Err(e) = conn.await {
                    panic!("Error in connection: {}", e);
                }
            });

            // Format the request
            let mut req = Request::builder()
                .uri(query)
                .method(meth)
                .body(Empty::<Bytes>::new())
                .expect("could not build request");
            for (header, header_val) in headers.clone() {
                req.headers_mut().insert(
                    HeaderName::from_lowercase(header.to_lowercase().as_bytes())?,
                    HeaderValue::from_str(header_val)?,
                );
            }

            // Send the request and add the response to the list.
            let rsp_vec = responses.clone();
            join_set.spawn(async move {
                // Get the response, map IncompleteMessage error to timeout
                let rsp = match sender.send_request(req).await {
                    Ok(x) => x,
                    Err(h_err) if h_err.is_incomplete_message() => {
                        rsp_vec.lock().expect("lock poisoned").push((
                            idx,
                            StatusCode::GATEWAY_TIMEOUT,
                            Bytes::new(),
                        ));
                        return;
                    }
                    _ => panic!("unknown error sending request"),
                };

                // Return the status code and response data
                let status = rsp.status();
                let data = rsp
                    .into_body()
                    .collect()
                    .await
                    .expect("can not read body")
                    .to_bytes();

                rsp_vec
                    .lock()
                    .expect("lock poisoned")
                    .push((idx, status, data));
            });

            // Inject an inter message delay for all but the last request
            idx += 1;
            if idx < send_cnt {
                tokio::time::sleep(Duration::from_secs(4)).await;
            }
        }

        // Check for errors.
        while let Some(res) = join_set.join_next().await {
            res.expect("task failed");
        }

        // Make sure everything shutdown cleanly.
        token.cancel();
        if let Err(msg) = thr.join() {
            panic!("server failed: {:?}", msg);
        }

        // Return the responses in the original request order and strip out the index.
        let mut rsp_vec = responses.clone().lock().expect("lock poisoned").to_vec();
        rsp_vec.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
        Ok(rsp_vec
            .iter()
            .map(|x| (x.1, x.2.clone()))
            .collect::<Vec<_>>())
    }

    // Private helper to validate the response fields.
    fn validate_response(name: &str, body: Bytes) {
        validate_response_extra(name, DEFAULT_VERSION, vec![DEFAULT_LABEL], body);
    }

    // Private helper to validate the response fields.
    fn validate_response_extra(name: &str, version: &str, labels: Vec<&str>, body: Bytes) {
        let map: serde_json::Map<String, Value> = serde_json::from_slice(&body).unwrap();

        // Validate all the fields.
        let fake_arn = FAKE_ARN.replace("{{name}}", name);
        assert_eq!(map.get("Name").unwrap(), name);
        assert_eq!(map.get("ARN").unwrap(), &fake_arn);
        assert_eq!(map.get("VersionId").unwrap(), version);
        if !name.contains("REFRESHNOW") {
            assert_eq!(map.get("SecretString").unwrap(), "hunter2");
        }
        assert_eq!(map.get("CreatedDate").unwrap(), "1569534789.046");
        assert_eq!(
            map.get("VersionStages").unwrap().as_array().unwrap(),
            &labels
        );
    }

    // Private helper to validate an error response.
    fn validate_err(err_code: &str, msg: &str, body: Bytes) {
        let map: serde_json::Map<String, Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(map.get("__type").unwrap(), err_code);
        if !msg.is_empty() && err_code != "InternalFailure" {
            assert_eq!(map.get("message").unwrap(), msg);
        }
    }

    // Verify the correct error is returned when the token env var is not set.
    #[tokio::test]
    async fn no_token_env() {
        let cfg = ValidatedConfig {
            logging: LoggingConfig::default(),
            secrets_manager: SecretsManagerConfig {
                http_port: 0,
                security: SecurityConfig {
                    ssrf_env_variables: vec!["FAIL_TOKEN".to_string()],
                    ..Default::default()
                },
                ..Default::default()
            },
            acm: None,
        };

        let err = init_listener(&cfg)
            .await
            .expect_err("expected init_listener to fail");
        assert_eq!(
            err.to_string(),
            "Could not read SSRF token variable(s) [\"FAIL_TOKEN\"]: environment variable not found"
        );
    }

    // Verify the correct error is returned when a token file can not be read.
    #[cfg(unix)]
    #[tokio::test]
    async fn bad_token_file() {
        // Generate a temp file with the default token and take away read permissions.
        let tmpfile = tmpfile_name("bad_token_file.toml");
        let _cleanup = CleanUp {
            file: Some(&tmpfile),
        };
        fs::write(&tmpfile, "xyzzy").expect("could not write");
        fs::set_permissions(&tmpfile, fs::Permissions::from_mode(0o333))
            .expect("could not set perms"); // No read permissions
        let file = Box::new(format!("file://{tmpfile}"));
        set_test_var("AWS_TOKEN", Box::leak(file));

        let cfg = ConfigValidator::new()
            .validate(None)
            .expect("could not validate default config");
        let err = init_listener(&cfg)
            .await
            .expect_err("expected init_listener to fail");
        assert_eq!(
            err.to_string(),
            "Could not read SSRF token variable(s) [\"AWS_TOKEN\", \"AWS_SESSION_TOKEN\", \"AWS_CONTAINER_AUTHORIZATION_TOKEN\"]: Permission denied (os error 13)"
        );
    }

    // Verify we correctly handle port in use errors
    #[tokio::test]
    async fn port_in_use() {
        // Bind to an arbitrary port.
        let addr: SocketAddr = ([127, 0, 0, 1], 0).into();
        let listener: TcpListener = TcpListener::bind(addr)
            .await
            .expect("Could not bind to port");
        let port = listener.local_addr().expect("can not find port").port();

        let cfg = ValidatedConfig {
            logging: LoggingConfig::default(),
            secrets_manager: SecretsManagerConfig {
                http_port: port,
                ..Default::default()
            },
            acm: None,
        };

        let err = init_listener(&cfg)
            .await
            .expect_err("expected init_listener to fail");
        let msg = err.to_string();
        #[cfg(unix)]
        assert!(
            msg.contains("Address already in use"),
            "unexpected error: {msg}"
        );
        #[cfg(windows)]
        assert!(
            msg.contains(
                "Only one usage of each socket address (protocol/network address/port) is normally permitted."
            ),
            "unexpected error: {msg}"
        );
    }

    // Verify a basic ping request succeeds.
    #[tokio::test]
    async fn ping_req() {
        let (status, body) = run_request("/ping").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "healthy");
    }

    // Verify ping does not require a token
    #[tokio::test]
    async fn ping_no_token() {
        let (status, body) = run_requests_with_headers(vec![("GET", "/ping")], vec![])
            .await
            .expect("request failed")
            .pop()
            .unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "healthy");
    }

    // Verify unknown paths fail with 404
    #[tokio::test]
    async fn pong_req() {
        let (status, _) = run_request("/pong").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // Verify query requests return 400 when missing a secret id
    #[tokio::test]
    async fn missing_id() {
        let (status, _) = run_request("/secretsmanager/get").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // Verify path based requests return 400 when missing a secret id
    #[tokio::test]
    async fn missing_path_id() {
        let (status, _) = run_request("/v1/").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // Verify that query with parameter "abc" returns 400
    #[tokio::test]
    async fn bad_query_parameter() {
        let (status, _) = run_request(
            "/secretsmanager/get?secretId=MyTest&versionStage=AWSPENDING&abc=XXXXXXXXXXXX",
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // Verify that path query with parameter "abc" returns 400
    #[tokio::test]
    async fn path_bad_query_parameter() {
        let (status, _) = run_request("/v1/MyTest?versionStage=AWSPENDING&abc=XXXXXXXXXXXX").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    // Verify that path query with missing parameter "secretId" returns 400
    async fn missing_query_parameter() {
        let (status, _) = run_request("/secretsmanager/get?versionStage=AWSPENDING").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // Verify a basic query request succeeds
    #[tokio::test]
    async fn basic_success() {
        let (status, body) = run_request("/secretsmanager/get?secretId=MyTest").await;
        assert_eq!(status, StatusCode::OK);
        validate_response("MyTest", body);
    }

    // Verify a query using the refreshNow parameter
    #[tokio::test]
    async fn basic_refresh_success() {
        let (status, body) = run_request("/secretsmanager/get?secretId=MyTest&refreshNow=1").await;
        assert_eq!(status, StatusCode::OK);
        validate_response("MyTest", body);
    }

    // Verify a query using the pending label
    #[tokio::test]
    async fn pending_success() {
        let req = "/secretsmanager/get?secretId=MyTest&versionStage=AWSPENDING".to_string();
        let (status, body) = run_request(&req).await;
        assert_eq!(status, StatusCode::OK);
        validate_response_extra("MyTest", DEFAULT_VERSION, vec!["AWSPENDING"], body);
    }

    // Verify a query for a specific version.
    #[tokio::test]
    async fn version_success() {
        let ver = "11111";
        let req = format!("/secretsmanager/get?secretId=MyTest&versionId={ver}");
        let (status, body) = run_request(&req).await;
        assert_eq!(status, StatusCode::OK);
        validate_response_extra("MyTest", ver, vec![DEFAULT_LABEL], body);
    }

    // Verify a query request with all args.
    #[tokio::test]
    async fn all_args_success() {
        let ver = "000000000000";
        let req =
            format!("/secretsmanager/get?secretId=MyTest&versionStage=AWSPENDING&versionId={ver}&refreshNow=true");
        let (status, body) = run_request(&req).await;
        assert_eq!(status, StatusCode::OK);
        validate_response_extra("MyTest", ver, vec!["AWSPENDING"], body);
    }

    // Verify access denied errors
    #[tokio::test]
    async fn access_denied_test() {
        let (status, body) = run_request("/secretsmanager/get?secretId=KMSACCESSDENIEDTest").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        validate_err(
            "AccessDeniedException",
            "Access to KMS is not allowed",
            body,
        );
    }

    // Verify creds error
    #[tokio::test]
    async fn other_error_test() {
        let (status, body) = run_request("/secretsmanager/get?secretId=OTHERERRORTest").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        validate_err(
            "InvalidSignatureException",
            "The request signature we calculated does not match ...",
            body,
        );
    }

    // Verify refreshNow behavior
    #[tokio::test]
    async fn refresh_now_test() {
        let responses = run_requests_with_client(
            vec![
                ("GET", "/secretsmanager/get?secretId=REFRESHNOWtestsecret"),
                ("GET", "/secretsmanager/get?secretId=REFRESHNOWtestsecret"),
                (
                    "GET",
                    "/secretsmanager/get?secretId=REFRESHNOWtestsecret&refreshNow=true",
                ),
            ],
            vec![("X-Aws-Parameters-Secrets-Token", "xyzzy")],
            None,
        )
        .await
        .unwrap();

        let mut secret_strings = Vec::new();
        for (status, body) in responses {
            assert_eq!(status, StatusCode::OK);

            let map: serde_json::Map<String, Value> = serde_json::from_slice(&body).unwrap();
            let secret_string = map.get("SecretString").unwrap().to_string();

            secret_strings.insert(0, secret_string)
        }

        assert_ne!(secret_strings[1], secret_strings[2]);
        assert_eq!(secret_strings[0], secret_strings[1]);
    }

    // Verify a basic path based request with an alternate header succeeds
    #[tokio::test]
    async fn path_success() {
        let (status, body) = run_requests_with_headers(
            vec![("GET", "/v1/MyTest")],
            vec![("X-Vault-Token", "xyzzy")],
        )
        .await
        .expect("request failed")
        .pop()
        .unwrap();
        assert_eq!(status, StatusCode::OK);
        validate_response("MyTest", body);
    }

    // Verify a query using the pending label
    #[tokio::test]
    async fn path_pending_success() {
        let req = "/v1/My/Test?versionStage=AWSPENDING";
        let (status, body) = run_request(req).await;
        assert_eq!(status, StatusCode::OK);
        validate_response_extra("My/Test", DEFAULT_VERSION, vec!["AWSPENDING"], body);
    }

    // Verify a query using the refreshNow parameter
    #[tokio::test]
    async fn path_refresh_success() {
        let req = "/v1/My/Test?versionStage=AWSPENDING&refreshNow=0";
        let (status, body) = run_request(&req).await;
        assert_eq!(status, StatusCode::OK);
        validate_response_extra("My/Test", DEFAULT_VERSION, vec!["AWSPENDING"], body);
    }

    // Verify a query for a specific version.
    #[tokio::test]
    async fn path_version_success() {
        let ver = "11111";
        let req = format!("/v1/My/Test?versionId={ver}");
        let (status, body) = run_request(&req).await;
        assert_eq!(status, StatusCode::OK);
        validate_response_extra("My/Test", ver, vec![DEFAULT_LABEL], body);
    }

    // Verify a query request with all args.
    #[tokio::test]
    async fn path_all_args_success() {
        let ver = "000000000000";
        let req = format!("/v1/My/Test?versionStage=AWSPENDING&versionId={ver}&refreshNow=true");
        let (status, body) = run_request(&req).await;
        assert_eq!(status, StatusCode::OK);
        validate_response_extra("My/Test", ver, vec!["AWSPENDING"], body);
    }

    // Verify a query request fails if the SSRF token is not present
    #[tokio::test]
    async fn no_token_fail() {
        let (status, _) =
            run_requests_with_headers(vec![("GET", "/secretsmanager/get?secretId=MyTest")], vec![])
                .await
                .expect("request failed")
                .pop()
                .unwrap();
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    // Verify a path based request fails if the SSRF token is not present
    #[tokio::test]
    async fn path_no_token_fail() {
        let (status, _) = run_requests_with_headers(vec![("GET", "/v1/MyTest")], vec![])
            .await
            .expect("request failed")
            .pop()
            .unwrap();
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    // Verify failure if an incorrect token is passed.
    #[tokio::test]
    async fn bad_token() {
        let (status, _) = run_requests_with_headers(
            vec![("GET", "/secretsmanager/get?secretId=MyTest")],
            vec![("X-Vault-Token", "click slipers")],
        )
        .await
        .expect("request failed")
        .pop()
        .unwrap();
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    // Verify the X-Forwarded-For header is not allowed.
    #[tokio::test]
    async fn xff_fail() {
        let (status, _) = run_requests_with_headers(
            vec![("GET", "/secretsmanager/get?secretId=MyTest")],
            vec![
                ("X-Vault-Token", "xyzzy"),
                ("X-Forwarded-For", "54.239.28.85"),
            ],
        )
        .await
        .expect("request failed")
        .pop()
        .unwrap();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // Verify max conn is enforced (max conn set to 1 for testing)
    #[tokio::test]
    async fn max_conn_test() {
        /* Note that run_requests injects a 4 second inter-message delay and
         * responses are returned in the original request order, regardless
         * of timing. Also must not exceed the 10 second timeout for unit tests.
         */
        let reqs = vec![
            ("GET", "/secretsmanager/get?secretId=SleepyTest_6"), // req takes 6 seconds
            ("GET", "/secretsmanager/get?secretId=MyTest"),       // req sent after 4 seconds
            ("GET", "/secretsmanager/get?secretId=MyTest"),       // req sent after 8 seconds
        ];
        let mut rsp = run_requests_with_verb(reqs).await.expect("request failed");
        assert_eq!(rsp.len(), 3); // Verify 3 responses

        // Verify the first request (the delayed request) was successful.
        let (status, body) = rsp.pop().unwrap();
        assert_eq!(status, StatusCode::OK);
        validate_response("SleepyTest_6", body);

        // Make sure the second request failed (because the first was still in progress)
        let (status, _) = rsp.pop().unwrap();
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

        // Make sure the third request succeeded (because first already completed)
        let (status, body) = rsp.pop().unwrap();
        assert_eq!(status, StatusCode::OK);
        validate_response("MyTest", body);
    }

    // Verify health checks can exceed max conn
    #[tokio::test]
    async fn ping_max_conn() {
        let reqs = vec![
            ("GET", "/secretsmanager/get?secretId=SleepyTest_6"), // req takes 6 seconds
            ("GET", "/ping"),                                     // req sent after 4 seconds
        ];
        let mut rsp = run_requests_with_verb(reqs).await.expect("request failed");
        assert_eq!(rsp.len(), 2); // Verify 2 responses

        // Verify the first request (the delayed request) was successful.
        let (status, body) = rsp.pop().unwrap();
        assert_eq!(status, StatusCode::OK);
        validate_response("SleepyTest_6", body);

        // Make sure the ping was not blocked by the first request.
        let (status, body) = rsp.pop().unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "healthy");
    }

    // Verify requests time out correctly.
    #[tokio::test]
    async fn timeout_test() {
        /* Run a request that waits forever; run_request will map
         * IncompleteMessage (due to the server timeing out) to GATEWAY_TIMEOUT
         */
        let (status, _) = run_timeout_request(&format!(
            "/secretsmanager/get?secretId=SleepyTest_{}",
            u64::MAX
        ))
        .await;
        assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
    }

    // Verify requests using the wrong verbs fail with 405.
    #[tokio::test]
    async fn get_only() {
        for verb in [
            "POST", "PUT", "PATCH", "DELETE", "HEAD", "CONNECT", "OPTIONS", "TRACE",
        ] {
            let (status, _) =
                run_requests_with_verb(vec![(verb, "/secretsmanager/get?secretId=MyTest")])
                    .await
                    .expect("request failed")
                    .pop()
                    .unwrap();
            assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
            let (status, _) = run_requests_with_verb(vec![(verb, "/v1/MyTest")])
                .await
                .expect("request failed")
                .pop()
                .unwrap();
            assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
            let (status, _) = run_requests_with_verb(vec![(verb, "/ping")])
                .await
                .expect("request failed")
                .pop()
                .unwrap();
            assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        }
    }

    // Verify a query-style request with roleArn succeeds.
    #[tokio::test]
    async fn role_arn_query_success() {
        let role = "arn:aws:iam::123456789012:role/TestRole";
        let (status, body) = run_request(&format!(
            "/secretsmanager/get?secretId=MyTest&roleArn={role}"
        ))
        .await;
        assert_eq!(status, StatusCode::OK);
        validate_response("MyTest", body);
    }

    // Verify a path-style request with roleArn succeeds.
    #[tokio::test]
    async fn role_arn_path_success() {
        let role = "arn:aws:iam::123456789012:role/TestRole";
        let (status, body) = run_request(&format!("/v1/MyTest?roleArn={role}")).await;
        assert_eq!(status, StatusCode::OK);
        validate_response("MyTest", body);
    }

    // Verify an invalid roleArn returns 400.
    #[tokio::test]
    async fn role_arn_invalid() {
        let (status, body) =
            run_request("/secretsmanager/get?secretId=MyTest&roleArn=not-a-valid-arn").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body,
            "invalid roleArn format, expected arn:<partition>:iam::<account>:role/<name>"
        );
    }

    // Verify roleArn works alongside other parameters.
    #[tokio::test]
    async fn role_arn_with_all_params() {
        let role = "arn:aws:iam::123456789012:role/TestRole";
        let ver = "11111";
        let (status, body) = run_request(
            &format!("/secretsmanager/get?secretId=MyTest&versionId={ver}&versionStage=AWSPENDING&refreshNow=true&roleArn={role}"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        validate_response_extra("MyTest", ver, vec!["AWSPENDING"], body);
    }
}
