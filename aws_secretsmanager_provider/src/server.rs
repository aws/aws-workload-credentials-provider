use bytes::Bytes;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{body::Incoming as IncomingBody, Method, Request, Response};
use hyper_util::rt::TokioIo;
use log::error;
use tokio::net::TcpListener;
use tokio::time::timeout;

use crate::cache_manager::CacheManager;
use crate::constants::MAX_BUF_BYTES;
use crate::error::HttpError;
use crate::parse::GSVQuery;
use crate::utils::{get_token, time_out};
use aws_workload_credentials_provider_common::config::types::ValidatedConfig;
use std::net::SocketAddr;
use std::sync::Arc;

/// Handle incoming HTTP requests.
#[derive(Debug, Clone)]
pub struct Server {
    listener: Arc<TcpListener>,
    cache_mgr: Arc<CacheManager>,
    ssrf_token: Arc<String>,
    ssrf_headers: Arc<Vec<String>>,
    path_prefix: Arc<String>,
    max_conn: usize,
}

/// Handle incoming HTTP requests.
///
/// Implements the HTTP handler. Each incoming request is handled in its own
/// thread.
impl Server {
    /// Create a server instance.
    ///
    /// # Arguments
    ///
    /// * `listener` - The TcpListener to use to accept incoming requests.
    /// * `cfg` - The config object to use for options such header names.
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` - The server object.
    /// * `Box<dyn std::error::Error>>` - Returned for errors initializing the provider
    pub async fn new(
        listener: TcpListener,
        cfg: &ValidatedConfig,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            listener: Arc::new(listener),
            cache_mgr: Arc::new(CacheManager::new(&cfg.secrets_manager).await?),
            ssrf_token: Arc::new(get_token(&cfg.secrets_manager.security.ssrf_env_variables)?),
            ssrf_headers: Arc::new(cfg.secrets_manager.security.ssrf_headers.clone()),
            path_prefix: Arc::new(cfg.secrets_manager.path_prefix.clone()),
            max_conn: cfg.secrets_manager.max_conn,
        })
    }

    /// Returns a clone of the Arc<CacheManager> for use by the prefetch task.
    pub fn cache_manager(&self) -> Arc<CacheManager> {
        self.cache_mgr.clone()
    }

    /// Accept the next request on the listener and process it in a separate thread.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - The request is being handled in the background.
    /// * `Err(Error)` - IOError while accepting request.
    ///
    /// # Errors
    ///
    /// * `std::io::Error` - Error while accepting request.
    pub async fn serve_request(&self) -> Result<(), Box<dyn std::error::Error>> {
        let (stream, peer_addr) = self.listener.accept().await?;
        stream.set_ttl(1)?; // Prohibit network hops
        let io = TokioIo::new(stream);
        let svr_clone = self.clone();
        let rq_cnt = Arc::strong_count(&self.cache_mgr); // concurrent request count
        tokio::task::spawn(async move {
            let svc_fn = service_fn(|req: Request<IncomingBody>| async {
                svr_clone.complete_req(req, rq_cnt, peer_addr).await
            });
            let mut http = http1::Builder::new();
            let http = http.max_buf_size(MAX_BUF_BYTES);
            if let Err(err) = timeout(time_out(), http.serve_connection(io, svc_fn)).await {
                error!("Failed to serve connection: {:?}", err);
            };
        });

        Ok(())
    }

    /// Private helper to process the incoming request body and format a response.
    ///
    /// # Arguments
    ///
    /// * `req` - The incoming HTTP request.
    /// * `count` - The number of concurrent requests being handled.
    ///
    /// # Returns
    ///
    /// * `Ok(Response<Full<Bytes>>)` - The HTTP response to send back.
    /// * `Err(Error)` - Never returned, converted to a response.
    #[doc(hidden)]
    async fn complete_req(
        &self,
        req: Request<IncomingBody>,
        count: usize,
        peer_addr: SocketAddr,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        let result = self.get_result(&req, count, peer_addr).await;

        // Format the response.
        match result {
            Ok(rsp_body) => Ok(Response::builder()
                .body(Full::new(Bytes::from(rsp_body)))
                .unwrap()),
            Err(e) => Ok(Response::builder()
                .status(e.0)
                .body(Full::new(Bytes::from(e.1)))
                .unwrap()),
        }
    }

    /// Parse an incoming request and provide the response data.
    ///
    /// # Arguments
    ///
    /// * `req` - The incoming HTTP request.
    /// * `count` - The number of concurrent requests being handled.
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - The payload to return.
    /// * `Err((u16, String))` - A HTTP error code and error message.
    #[doc(hidden)]
    async fn get_result(
        &self,
        req: &Request<IncomingBody>,
        count: usize,
        peer_addr: SocketAddr,
    ) -> Result<String, HttpError> {
        self.validate_max_conn(req, count)?; // Verify connection limits are not exceeded
        self.validate_token(req, peer_addr)?; // Check for a valid SSRF token
        self.validate_method(req)?; // Allow only GET requests

        match req.uri().path() {
            "/ping" => Ok("healthy".into()), // Standard health check

            // Lambda extension style query
            "/secretsmanager/get" => {
                let qry = GSVQuery::try_from_query(&req.uri().to_string())?;
                Ok(self
                    .cache_mgr
                    .fetch(
                        &qry.secret_id,
                        qry.version_id.as_deref(),
                        qry.version_stage.as_deref(),
                        qry.refresh_now,
                        qry.role_arn.as_deref(),
                    )
                    .await?)
            }

            // Path style request
            path if path.starts_with(self.path_prefix.as_str()) => {
                let qry = GSVQuery::try_from_path_query(&req.uri().to_string(), &self.path_prefix)?;
                Ok(self
                    .cache_mgr
                    .fetch(
                        &qry.secret_id,
                        qry.version_id.as_deref(),
                        qry.version_stage.as_deref(),
                        qry.refresh_now,
                        qry.role_arn.as_deref(),
                    )
                    .await?)
            }
            _ => Err(HttpError(404, "Not found".into())),
        }
    }

    /// Verify the incoming request does not exceed the maximum connection limit.
    ///
    /// The limit is not enforced for ping/health checks.
    ///
    /// # Arguments
    ///
    /// * `req` - The incoming HTTP request.
    /// * `count` - The number of concurrent requests being handled.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - For health checks or when the request is within limits.
    /// * `Err((u16, String))` - A 429 error code and error message.
    #[doc(hidden)]
    fn validate_max_conn(
        &self,
        req: &Request<IncomingBody>,
        count: usize,
    ) -> Result<(), HttpError> {
        // Add one to account for the extra server reference in main, allow 2 extra health check conns.
        let limit = if req.uri().path() == "/ping" {
            self.max_conn + 3
        } else {
            self.max_conn + 1
        };
        if count <= limit {
            return Ok(());
        }

        Err(HttpError(429, "Connection limit exceeded".into()))
    }

    /// Verify the request has the correct SSRF token and no forwarding header is set.
    ///
    /// Health checks are not subject to these checks.
    ///
    /// # Arguments
    ///
    /// * `req` - The incoming HTTP request.
    /// * `peer_addr` - The socket address of the connecting client.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - For health checks or when the request has the correct token.
    /// * `Err((u16, String))` - A 400 or 403 error code (if header is set or token is missing or wrong) and error message.
    #[doc(hidden)]
    fn validate_token(
        &self,
        req: &Request<IncomingBody>,
        peer_addr: SocketAddr,
    ) -> Result<(), HttpError> {
        if req.uri().path() == "/ping" {
            return Ok(());
        }

        let headers = req.headers();
        let method = req.method();
        let path = req.uri().path();

        // Prohibit forwarding — indicates a proxied request (potential SSRF).
        if headers.contains_key("X-Forwarded-For") {
            error!(
                "Rejecting request with X-Forwarded-For header; \
                 peer={}, method={}, path={}",
                peer_addr, method, path
            );
            return Err(HttpError(400, "Forwarded".into()));
        }

        // Check configured SSRF headers for a matching token.
        let mut token_header_present = false;
        for header in self.ssrf_headers.iter() {
            if headers.contains_key(header) {
                token_header_present = true;
                if headers[header] == self.ssrf_token.as_str() {
                    return Ok(());
                }
            }
        }

        if token_header_present {
            error!(
                "Rejecting request with incorrect SSRF token; \
                 reason=token_mismatch, peer={}, method={}, path={}",
                peer_addr, method, path
            );
        } else {
            error!(
                "Rejecting request with incorrect SSRF token; \
                 reason=missing_header, peer={}, method={}, path={}",
                peer_addr, method, path
            );
        }

        Err(HttpError(403, "Bad Token".into()))
    }

    /// Verify the request is using the GET HTTP verb.
    ///
    /// # Arguments
    ///
    /// * `req` - The incoming HTTP request.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the GET verb/method is used.
    /// * `Err((u16, String))` - A 405 error code and message when GET is not used.
    #[doc(hidden)]
    fn validate_method(&self, req: &Request<IncomingBody>) -> Result<(), HttpError> {
        if *req.method() == Method::GET {
            return Ok(());
        }

        Err(HttpError(405, "Not allowed".into()))
    }
}
