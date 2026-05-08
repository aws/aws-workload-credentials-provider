use crate::config::Config;
use crate::constants::{APPNAME, MAX_REQ_TIME_SEC, VERSION};
use aws_sdk_secretsmanager::config::interceptors::BeforeTransmitInterceptorContextMut;
use aws_sdk_secretsmanager::config::{ConfigBag, Intercept, RuntimeComponents};
#[cfg(not(test))]
use aws_sdk_secretsmanager::Client as SecretsManagerClient;
use std::env::VarError;
use std::fs;
use std::time::Duration;

#[cfg(not(test))]
use std::env::var; // Use the real std::env::var
#[cfg(test)]
use tests::var_test as var;

/// Helper to format error response body in Coral JSON 1.1 format.
///
/// Callers need to pass in the error code (e.g.  InternalFailure,
/// InvalidParameterException, ect.) and the error message. This function will
/// then format a response body in JSON 1.1 format.
///
/// # Arguments
///
/// * `err_code` - The modeled exception name or InternalFailure for 500s.
/// * `msg` - The optional error message or "" for InternalFailure.
///
/// # Returns
///
/// * `String` - The JSON 1.1 response body.
///
/// # Example
///
/// ```
/// assert_eq!(err_response("InternalFailure", ""), "{\"__type\":\"InternalFailure\"}");
/// assert_eq!(
///     err_response("ResourceNotFoundException", "Secrets Manager can't find the specified secret."),
///     "{\"__type\":\"ResourceNotFoundException\",\"message\":\"Secrets Manager can't find the specified secret.\"}"
/// );
/// ```
#[doc(hidden)]
pub fn err_response(err_code: &str, msg: &str) -> String {
    if msg.is_empty() || err_code == "InternalFailure" {
        return String::from("{\"__type\":\"InternalFailure\"}");
    }
    format!("{{\"__type\":\"{err_code}\", \"message\":\"{msg}\"}}")
}

/// Helper function to get the SSRF token value.
///
/// Reads the SSRF token from the configured env variable. If the env variable
/// is a reference to a file (namely file://FILENAME), the data is read in from
/// that file.
///
/// # Arguments
///
/// * `config` - The configuration options for the daemon.
///
/// # Returns
///
/// * `Ok(String)` - The SSRF token value.
/// * `Err(Error)` - Error indicating that the variable is not set or could not be read.
#[doc(hidden)]
pub fn get_token(config: &Config) -> Result<String, Box<dyn std::error::Error>> {
    // Iterate through the env name list looking for the first variable set
    #[allow(clippy::redundant_closure)]
    let found = config
        .ssrf_env_variables()
        .iter()
        .map(|n| var(n))
        .filter_map(|r| r.ok())
        .next();
    if found.is_none() {
        return Err(Box::new(VarError::NotPresent));
    }
    let val = found.unwrap();

    // If the variable is not a reference to a file, just return the value.
    if !val.starts_with("file://") {
        return Ok(val);
    }

    // Read and return the contents of the file.
    let file = val.strip_prefix("file://").unwrap();
    Ok(fs::read_to_string(file)?.trim().to_string())
}

#[doc(hidden)]
#[cfg(not(test))]
pub use time_out_impl as time_out;
#[cfg(test)]
pub use time_out_test as time_out;

/// Helper function to get the time out setting for request processing.
///
/// # Returns
///
/// * `Durration` - How long to wait before canceling the operation.
#[doc(hidden)]
pub fn time_out_impl() -> Duration {
    Duration::from_secs(MAX_REQ_TIME_SEC)
}
#[cfg(test)]
pub fn time_out_test() -> Duration {
    Duration::from_secs(10) // Timeout in 10 seconds for testing.
}

/// Validates the provided configuration and creates an AWS Secrets Manager client
/// from the latest default AWS configuration.
///
/// # Arguments
///
/// * `config` - A reference to a `Config` object containing the necessary configuration
///   parameters for creating the AWS Secrets Manager client.
///
/// # Returns
///
/// * `Ok(SecretsManagerClient)` - An AWS Secrets Manager client if the credentials are valid.
/// * `Err(Box<dyn std::error::Error>)` if there is an error creating the Secrets Manager client
///   or validating the AWS credentials.
#[doc(hidden)]
#[cfg(not(test))]
pub async fn validate_and_create_asm_client(
    config: &Config,
) -> Result<SecretsManagerClient, Box<dyn std::error::Error>> {
    use aws_config::{BehaviorVersion, Region};
    use aws_secretsmanager_caching::error::is_transient_error;
    let default_config = &aws_config::load_defaults(BehaviorVersion::latest()).await;
    let mut asm_builder = aws_sdk_secretsmanager::config::Builder::from(default_config)
        .interceptor(AgentModifierInterceptor);

    if let Some(region) = config.region() {
        asm_builder.set_region(Some(Region::new(region.clone())));
    }

    if config.validate_credentials() {
        let mut sts_builder = aws_sdk_sts::config::Builder::from(default_config);
        if let Some(region) = config.region() {
            sts_builder.set_region(Some(Region::new(region.clone())));
        }

        let sts_client = aws_sdk_sts::Client::from_conf(sts_builder.build());
        match sts_client.get_caller_identity().send().await {
            Ok(_) => (),
            Err(e) if config.ignore_transient_errors() && is_transient_error(&e) => (),
            Err(e) => Err(e)?,
        };
    }

    Ok(aws_sdk_secretsmanager::Client::from_conf(
        asm_builder.build(),
    ))
}

/// SDK interceptor to append the agent name and version to the User-Agent header for CloudTrail records.
#[doc(hidden)]
#[derive(Debug)]
pub struct AgentModifierInterceptor;

/// SDK interceptor to append the agent name and version to the User-Agent header for CloudTrail records.
///
/// This interceptor adds the agent name and version to the User-Agent header
/// of outbound Secrets Manager SDK requests.
#[doc(hidden)]
impl Intercept for AgentModifierInterceptor {
    fn name(&self) -> &'static str {
        "AgentModifierInterceptor"
    }

    fn modify_before_signing(
        &self,
        context: &mut BeforeTransmitInterceptorContextMut<'_>,
        _runtime_components: &RuntimeComponents,
        _cfg: &mut ConfigBag,
    ) -> Result<(), aws_sdk_secretsmanager::error::BoxError> {
        let request = context.request_mut();
        let agent = request.headers().get("user-agent").unwrap_or_default(); // Get current agent
        let full_agent = format!("{agent} {APPNAME}/{}", VERSION.unwrap_or("0.0.0"));
        request.headers_mut().insert("user-agent", full_agent); // Overwrite header.

        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::env::temp_dir;
    use std::thread_local;
    use std::time::{SystemTime, UNIX_EPOCH};

    // Used to cleanup resources after test completon.
    pub struct CleanUp<'a> {
        pub file: Option<&'a str>,
    }

    impl Drop for CleanUp<'_> {
        fn drop(&mut self) {
            // Clear env var injections.
            ENVVAR.set(None);

            // Cleanup temp files.
            if let Some(name) = self.file {
                let _ = std::fs::remove_file(name);
            }
        }
    }

    // Create a temp file name for a test.
    pub fn tmpfile_name(suffix: &str) -> String {
        format!(
            "{}/{}_{:?}_{suffix}",
            temp_dir().display(),
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
        )
    }

    // Used to inject env variable values for testing. Uses thread local data since
    // multi-threaded tests setting process wide env variables can collide.
    thread_local! {
        static ENVVAR: RefCell<Option<Vec<(&'static str, &'static str)>>> = const { RefCell::new(None) };
    }
    pub fn set_test_var(key: &'static str, val: &'static str) {
        ENVVAR.set(Some(vec![(key, val)]));
    }
    pub fn set_test_vars(vars: Vec<(&'static str, &'static str)>) {
        ENVVAR.set(Some(vars));
    }

    // Stub std::env::var that reads injected variables from thread_local
    pub fn var_test(key: &str) -> Result<String, VarError> {
        // Shortcut key to force failure.
        if key == "FAIL_TOKEN" {
            return Err(VarError::NotPresent);
        }
        if let Some(varvec) = ENVVAR.with_borrow(|v| v.clone()) {
            let found = varvec.iter().find(|keyval| keyval.0 == key);
            if let Some(some_found) = found {
                return Ok(some_found.1.to_string());
            }
        } else {
            // Return a default value if no value is injected.
            return Ok("xyzzy".to_string()); // Poof!
        }

        Err(VarError::NotPresent) // A fake value was injected but not for this key.
    }

    // Verify we can read the default config variable.
    #[test]
    fn test_env_set() {
        let _cleanup = CleanUp { file: None };
        set_test_var("AWS_TOKEN", "abc123");
        let cfg = Config::new(None).expect("config failed");
        assert_eq!(get_token(&cfg).expect("token fail"), "abc123");
    }

    // Verify we can use the second variable in the list
    #[test]
    fn test_alt_env_set() {
        let _cleanup = CleanUp { file: None };
        set_test_var("AWS_SESSION_TOKEN", "123abc");
        let cfg = Config::new(None).expect("config failed");
        assert_eq!(get_token(&cfg).expect("token fail"), "123abc");
    }

    // Verify the variable can point to a file and we use the file contents.
    #[test]
    fn test_file_token() {
        let token = "4 chosen by fair dice roll, guaranteed to be random";
        let tmpfile = tmpfile_name("test_file_token");
        let _cleanup = CleanUp {
            file: Some(&tmpfile),
        };
        std::fs::write(&tmpfile, token).expect("could not write");
        let file = Box::new(format!("file://{tmpfile}"));
        set_test_var("AWS_TOKEN", Box::leak(file));
        let cfg = Config::new(None).expect("config failed");
        assert_eq!(get_token(&cfg).expect("token fail"), token);
    }

    // Verify we correctly handle a missing file.
    #[test]
    fn test_file_token_missing() {
        #[cfg(unix)]
        const NO_SUCH_FILE_ERROR_MSG: &str = "No such file or directory (os error 2)";
        #[cfg(windows)]
        const NO_SUCH_FILE_ERROR_MSG: &str =
            "The system cannot find the file specified. (os error 2)";

        let _cleanup = CleanUp { file: None };
        set_test_var("AWS_TOKEN", "file:///NoSuchFile");
        let cfg = Config::new(None).expect("config failed");
        assert_eq!(
            get_token(&cfg).err().unwrap().to_string(),
            NO_SUCH_FILE_ERROR_MSG
        );
    }

    // Verify the first variable in the list takes precedence
    #[test]
    fn two_tokens() {
        let _cleanup = CleanUp { file: None };
        set_test_vars(vec![
            ("AWS_TOKEN", "yzzyx"),
            ("AWS_SESSION_TOKEN", "CTAtoken"),
        ]); // Good token, unusable token.
        let cfg = Config::new(None).expect("config failed");
        assert_eq!(get_token(&cfg).expect("token fail"), "yzzyx");
    }

    // Verify we return the correct error when a variable is not set.
    #[test]
    fn test_env_fail() {
        let tmpfile = tmpfile_name("test_env_fail.toml");
        let _cleanup = CleanUp {
            file: Some(&tmpfile),
        };
        set_test_var("", "");
        std::fs::write(&tmpfile, "ssrf_env_variables = [\"NOSUCHENV\"]").expect("could not write");
        let cfg = Config::new(Some(&tmpfile)).expect("config failed");
        assert!(get_token(&cfg)
            .err()
            .unwrap()
            .downcast_ref::<VarError>()
            .unwrap()
            .eq(&VarError::NotPresent));
    }

    // Make sure the timeout functon returns the correct value.
    #[test]
    fn test_time_out() {
        assert_eq!(time_out_impl(), Duration::from_secs(MAX_REQ_TIME_SEC));
    }
}
