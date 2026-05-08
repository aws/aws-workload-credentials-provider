use log::{error, info};
use tokio::net::TcpListener;

use std::env;
use std::net::SocketAddr;
mod error;
mod parse;

mod cache_manager;
mod server;
use server::Server;
mod config;
mod constants;
mod logging;
mod utils;

use config::Config;
use constants::VERSION;
use logging::init_logger;
use utils::get_token;

/// Main entry point for the daemon.
///
/// # Returns
///
/// * `Ok(())` - Never retuned.
/// * `Box<dyn std::error::Error>>` - Retruned for errors initializing the agent.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    run(env::args(), &report, &forever).await
}

/// Private helper to report startup and the listener port.
///
/// The private helper just prints the startup info. In unit tests a different
/// helper is used to report back the server port.
///
/// # Arguments
///
/// * `addr` - The socket address on which the daemon is listening.
///
/// # Example
///
/// ```
/// use std::net::SocketAddr;
/// report( &SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 2773) );
/// ```
#[doc(hidden)]
fn report(addr: &SocketAddr) {
    let start_msg = format!(
        "Agent/{} listening on http://{}",
        VERSION.unwrap_or("0.0.0"),
        addr
    );
    println!("{start_msg}");
    info!("{start_msg}");
}

/// Private helper used to run the server fovever.
///
/// This helper is used when the server is started through the main entry point.
/// In unit tests a different helper is used to signal shutdown.
///
/// # Returns
///
/// * bool - Always returns false so the server never shuts down.
///
/// # Example
///
/// ```
/// assert_eq!(forever(), false);
/// ```
#[doc(hidden)]
fn forever() -> bool {
    false
}

/// Private helper do the main body of the server.
///
/// # Arguments
///
/// * `args` - The command line arguments.
/// * `report` - A call back used to report startup and the listener port.
/// * `end` - A call back used to signal shut down.
/// # Returns
///
/// * `Ok(())` - Never retuned when started by the main entry point.
/// * `Box<dyn std::error::Error>` - Retruned for errors initializing the agent.
#[doc(hidden)]
async fn run<S: FnMut(&SocketAddr), E: FnMut() -> bool>(
    args: impl IntoIterator<Item = String>,
    mut report: S,
    mut end: E,
) -> Result<(), Box<dyn std::error::Error>> {
    let (cfg, listener) = init(args).await;
    let addr = listener.local_addr()?;
    let svr = Server::new(listener, &cfg).await?;

    report(&addr); // Report the port used.

    // Spawn a handler for each incomming request.
    loop {
        // Report errors on accept.
        if let Err(msg) = svr.serve_request().await {
            error!("Could not accept connection: {:?}", msg);
        }

        // Check for end of test in unit tests.
        if end() {
            return Ok(());
        }
    }
}

/// Private helper to perform initialization.
///
/// # Arguments
///
/// * `args` - The command line args.
///
/// # Returns
///
/// * (Config, TcpListener) - The configuration info and the TCP listener.
///
/// ```
#[doc(hidden)]
async fn init(args: impl IntoIterator<Item = String>) -> (Config, TcpListener) {
    // Get the arg iterator and program name from arg 0.
    let mut args = args.into_iter();
    let usage = format!(
        "Usage: {} [--config <file>]",
        args.next().unwrap_or_default().as_str()
    );
    let usage = usage.as_str();
    let mut config_file = None;

    // Parse command line args and see if there is a config file.
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "--config" => {
                config_file = args.next().or_else(|| err_exit("Argument expected", usage))
            }
            "-h" | "--help" => err_exit("", usage),
            _ => err_exit(&format!("Unknown option {arg}"), usage),
        }
    }

    // Initialize the config options.
    let config = match Config::new(config_file.as_deref()) {
        Ok(conf) => conf,
        Err(msg) => err_exit(&msg.to_string(), ""),
    };

    // Initialize logging
    if let Err(msg) = init_logger(config.log_level(), config.log_to_file()) {
        err_exit(&msg.to_string(), "");
    }

    // Verify the SSRF token env variable is set
    if let Err(err) = get_token(&config) {
        let msg = format!(
            "Could not read SSRF token variable(s) {:?}: {err}",
            config.ssrf_env_variables()
        );
        error!("{msg}");
        err_exit(&msg, "");
    }

    // Bind the listener to the specified port
    let addr: SocketAddr = ([127, 0, 0, 1], config.http_port()).into();
    let listener: TcpListener = TcpListener::bind(addr).await.unwrap_or_else(|err| {
        let msg = format!("Could not bind to {addr}: {}", err);
        error!("{msg}");
        err_exit(&msg, "")
    });

    (config, listener)
}

/// Private helper print error messages and exit the process with an error.
///
/// # Arguments
///
/// * `msg` - An error message to print (or the empty string if none is to be printed).
/// * `usage` - A usage message to print (or the empty string if none is to be printed).
#[doc(hidden)]
#[cfg(not(test))]
fn err_exit(msg: &str, usage: &str) -> ! {
    if !msg.is_empty() {
        eprintln!("{msg}");
    }
    if !usage.is_empty() {
        eprintln!("{usage}");
    }
    std::process::exit(1);
}
#[cfg(test)] // Use panic for testing
fn err_exit(msg: &str, usage: &str) -> ! {
    if !msg.is_empty() {
        panic!("{msg} !!!"); // Suffix message with !!! so we can distinguish it in tests
    }
    if !usage.is_empty() {
        panic!("#{usage}"); // Preceed usage with # so we can distinguish it in tests.
    }
    panic!("Should not get here");
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_secretsmanager as secretsmanager;
    use bytes::Bytes;
    use cache_manager::tests::{
        set_client, timeout_client, DEFAULT_LABEL, DEFAULT_VERSION, FAKE_ARN,
    };
    use http_body_util::{BodyExt, Empty};
    use hyper::header::{HeaderName, HeaderValue};
    use hyper::{client, Request, StatusCode};
    use hyper_util::rt::TokioIo;
    use serde_json::Value;

    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{mpsc, Arc, Mutex};
    use std::time::Duration;
    use std::{fs, thread};

    use tokio::net::TcpStream;
    use tokio::task::JoinSet;
    use tokio::time::timeout;
    #[cfg(unix)]
    // set_test_var does not work across threads (e.g. run_request)
    use utils::tests::set_test_var;
    use utils::tests::{tmpfile_name, CleanUp};

    fn one_shot() -> bool {
        true // Tell the sever to quit
    }
    fn noop(_addr: &SocketAddr) {}

    // Run a timer for a test that is expected to panic.
    async fn panic_test(args: impl IntoIterator<Item = &str>) {
        let vargs: Vec<String> = args.into_iter().map(String::from).collect();
        let _ = timeout(Duration::from_secs(5), async {
            run(vargs, noop, one_shot).await
        })
        .await
        .expect("Timed out waiting for panic");
        panic!("Did not panic!");
    }

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
        // Run server on port 0 which tells the OS to find an open port.
        let args = vec![
            String::from("prog"),
            String::from("--config"),
            String::from("tests/resources/configs/config_file_anyport.toml"),
        ];
        let (tx_addr, rx_addr) = mpsc::channel(); // Open channel for server to report the port
        let (tx_lock, rx_lock) = mpsc::channel(); // Open channel to use as a sync primitive/lock

        let end = move || {
            rx_lock.recv().expect("no shutdown signal") // Wait for shutdown signal
        };
        let rpt = move |addr: &SocketAddr| {
            tx_addr.send(*addr).expect("could not send address");
        };

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
                run(args, rpt, end).await.expect("could not run server");
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
                tx_lock.send(false).expect("could not sync"); // Tell the server to continue for all but the last request.
                tokio::time::sleep(Duration::from_secs(4)).await;
            }
        }

        // Check for errors.
        while let Some(res) = join_set.join_next().await {
            res.expect("task failed");
        }

        // Make sure everything shutdown cleanly.
        tx_lock.send(true).expect("could not sync"); // Tell the server to shut down.
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

    // Verify the report and forever functions do not panic
    #[test]
    fn test_report() {
        report(&SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            2773,
        ));
        assert!(!forever());
    }

    // Verify the correct error message for unknown options
    #[tokio::test]
    #[should_panic(expected = "Unknown option -failure !!!")] // Failure is not an option.
    async fn unkown_arg() {
        panic_test(vec!["prog", "--config", "NoSuchFile", "-failure"]).await;
    }

    // Verify the correct error message when --config is specified with no argument
    #[tokio::test]
    #[should_panic(expected = "Argument expected !!!")]
    async fn missing_arg() {
        panic_test(vec!["prog", "--config"]).await;
    }

    // Verify the correct message for the --help option
    #[tokio::test]
    #[should_panic(expected = "#Usage: prog [--config <file>]")]
    async fn help_arg() {
        panic_test(vec!["prog", "--help"]).await;
    }

    // Verify the correct error is returned for non-existant config files.
    #[tokio::test]
    #[should_panic(expected = "configuration file \"NoSuchFile\" not found !!!")]
    async fn nofile_arg() {
        panic_test(vec!["prog", "-c", "NoSuchFile"]).await;
    }

    // Verify the correct error is returned when the token env var is not set.
    #[tokio::test]
    #[should_panic(
        expected = "Could not read SSRF token variable(s) [\"FAIL_TOKEN\"]: environment variable not found !!!"
    )]
    async fn no_token_env() {
        // Generate a temp config file that uses FAIL_TOKEN which forces the unset env var behavior in unit test.
        let tmpfile = tmpfile_name("no_token_env.toml");
        let _cleanup = CleanUp {
            file: Some(&tmpfile),
        };
        fs::write(&tmpfile, "ssrf_env_variables = [\"FAIL_TOKEN\"]").expect("could not write");

        panic_test(vec!["prog", "-c", &tmpfile]).await;
    }

    // Verify the correct error is returned when a token file can not be read.
    #[cfg(unix)]
    #[tokio::test]
    #[should_panic(
        expected = "Could not read SSRF token variable(s) [\"AWS_TOKEN\", \"AWS_SESSION_TOKEN\", \"AWS_CONTAINER_AUTHORIZATION_TOKEN\"]: Permission denied (os error 13) !!!"
    )]
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

        panic_test(vec!["prog"]).await;
    }

    // Verify we correctly handle port in use errors
    #[tokio::test]
    #[cfg_attr(unix, should_panic(expected = "Address already in use"))]
    #[cfg_attr(
        windows,
        should_panic(
            expected = "Only one usage of each socket address (protocol/network address/port) is normally permitted."
        )
    )]
    async fn port_in_use() {
        // Generate a temp file and auto-remove it at the end of test.
        let tmpfile = tmpfile_name("port_in_use.toml");
        let _cleanup = CleanUp {
            file: Some(&tmpfile),
        };

        // Bind to an arbitrary port.
        let addr: SocketAddr = ([127, 0, 0, 1], 0).into();
        let listener: TcpListener = TcpListener::bind(addr)
            .await
            .expect("Could not bind to port");
        let port = listener.local_addr().expect("can not find port").port();

        // Write out a temp config file with the port.
        fs::write(&tmpfile, format!("http_port = {port}")).expect("could not write");

        panic_test(vec!["prog", "-c", &tmpfile]).await;
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
         * responses are returned in the orginal request order, regarless
         * of timing. Also must not exceed the 10 second timeout for unit tests.
         */
        let reqs = vec![
            ("GET", "/secretsmanager/get?secretId=SleepyTest_6"), // req takes 6 seconds
            ("GET", "/secretsmanager/get?secretId=MyTest"),       // req sent after 4 seconds
            ("GET", "/secretsmanager/get?secretId=MyTest"),       // req sent after 8 seconds
        ];
        let mut rsp = run_requests_with_verb(reqs).await.expect("request failed");
        assert_eq!(rsp.len(), 3); // Verify 3 reponses

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
        assert_eq!(rsp.len(), 2); // Verify 2 reponses

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
}
