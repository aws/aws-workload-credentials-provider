//! Sends telemetry as SigV4-signed Smithy RPC v2 CBOR calls of the telemetry
//! service's `PutCertificateTelemetry` operation.
//!
//! The sender retries transient failures itself, with the AWS SDK standard
//! retry mode's attempt count and full-jitter exponential backoff, plus any
//! wait a throttling or 503 response asks for, up to `MAX_RETRY_AFTER`. It has
//! no retry quota because callers send rarely: the drain about hourly, stopping
//! a flush at the first request that still fails, and ACM discovery once per
//! batch of its daily scan. An outage costs three attempts per flush or batch.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use rand::RngExt;
use serde::Deserialize;

use aws_config::SdkConfig;
use aws_credential_types::provider::{ProvideCredentials, SharedCredentialsProvider};
use aws_credential_types::Credentials;
use aws_sigv4::http_request::{sign, SignableBody, SignableRequest, SigningSettings};
use aws_sigv4::sign::v4;
use aws_smithy_http_client::proxy::ProxyConfig;
use aws_smithy_http_client::tls::{rustls_provider::CryptoMode, Provider};
use aws_smithy_http_client::Connector;
use aws_smithy_runtime_api::client::http::{HttpConnector, SharedHttpConnector};
use aws_smithy_runtime_api::client::identity::Identity;
use aws_smithy_runtime_api::client::orchestrator::{HttpRequest, HttpResponse};
use aws_smithy_types::body::SdkBody;
use aws_smithy_types::byte_stream::ByteStream;

use super::identity::is_region;
use super::payload::{
    to_cbor, Capability, CborError, PayloadType, TelemetryRecord, MAX_REQUEST_BYTES,
};
use super::request::{PutCertificateTelemetryInput, RequestPart};
use crate::config::types::TelemetryConfig;
use crate::constants::PROVIDER_NAME;

/// The operation's Smithy RPC v2 CBOR path: the service shape's name, without
/// its namespace, then the operation's.
const REQUEST_PATH: &str = "/service/AWSWorkloadTelemetryService/operation/PutCertificateTelemetry";

/// `Content-Type` and `Accept` of a Smithy RPC v2 CBOR request.
const CONTENT_TYPE: &str = "application/cbor";

/// The `smithy-protocol` header every Smithy RPC v2 CBOR request and response
/// carries. The service compares it case-sensitively.
const SMITHY_PROTOCOL: &str = "rpc-v2-cbor";

/// Longest wait a throttling or 503 response may ask for before the next
/// attempt.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(30);

/// Largest error body read for the error's name and wait. An error is a short
/// CBOR map, so a bigger body isn't read.
const MAX_ERROR_BODY_BYTES: u64 = 4096;

/// SigV4 signing name of the telemetry service.
const SIGNING_NAME: &str = "workload-telemetry";

/// Replaces the default endpoint with one such as `https://host`, for testing.
/// Read in release builds too, so a customer image can be tested end to end.
/// Only an `https://` endpoint is used: the requests carry certificates and
/// host names.
const ENDPOINT_OVERRIDE_VAR: &str = "AWCP_TELEMETRY_ENDPOINT_OVERRIDE";

/// `log` target of what a dry run logs instead of sending: each request's
/// JSON, or a record's JSON when it has no request part.
/// [`crate::logging::init_logger`] writes it to its own file, or to the
/// console when `log_to_file` is false.
pub(crate) const DRY_RUN_LOG_TARGET: &str = "telemetry_dryrun";

/// Whether `capability`'s sender may send. Secrets Manager metrics aren't in
/// the request's shape, so outside a dry run its sender only logs a one-line
/// summary of each request.
fn live_sending(capability: Capability) -> bool {
    match capability {
        Capability::Acm => true,
        Capability::SecretsManager => false,
    }
}

/// Longest one attempt takes: credentials, connection and response.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// Attempts at a request, the first included, as in the AWS SDK's standard
/// retry mode.
pub(crate) const SEND_ATTEMPTS: u32 = 3;

/// The longest wait before the first retry, as in the AWS SDK's standard retry
/// mode. It doubles before each later one.
const FIRST_RETRY_DELAY: Duration = Duration::from_secs(1);

/// How long credentials without an expiry are reused, as in the SDK's identity
/// cache.
const CREDENTIALS_LIFETIME: Duration = Duration::from_secs(15 * 60);

/// How long before they expire credentials are reloaded, as in the SDK's
/// identity cache.
const CREDENTIALS_RELOAD_BEFORE_EXPIRY: Duration = Duration::from_secs(10);

/// Why a sender won't send a record, before any request is built.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    /// In a dry run, the JSON of a record without a request part is over
    /// [`MAX_REQUEST_BYTES`].
    TooLarge(String),
    /// Any other reason; see [`TelemetrySender::part_to_send`].
    Rejected(String),
}

impl From<Refused> for SendError {
    fn from(refused: Refused) -> Self {
        match refused {
            Refused::TooLarge(why) | Refused::Rejected(why) => Self::Rejected(why),
        }
    }
}

/// Why a send failed.
#[derive(Debug, PartialEq, Eq)]
pub enum SendError {
    /// Still failing after the sender's retries, but a later send could
    /// succeed: a timeout, a connection failure, unavailable credentials,
    /// throttling or a server error.
    Transient(String),
    /// Another attempt would fail the same way: the service rejected the
    /// request, the request couldn't be serialized, signed or built or is over
    /// [`MAX_REQUEST_BYTES`] or the service model's limits, or the sender won't
    /// send the record (see [`TelemetrySender::send`]).
    Rejected(String),
}

/// Whether the customer consented to sending `capability`'s `payload_type`
/// records. ACM discovery records need discovery turned on; other ACM records
/// need `[telemetry.acm]`.
fn consented(
    settings: &TelemetryConfig,
    capability: Capability,
    payload_type: PayloadType,
) -> bool {
    match (capability, payload_type) {
        (Capability::Acm, PayloadType::CertDiscovery) => settings.acm_discovery_enabled,
        (Capability::Acm, PayloadType::CertAutomation | PayloadType::MetricsBatch) => {
            settings.acm_enabled
        }
        (Capability::SecretsManager, PayloadType::MetricsBatch) => settings.secrets_manager_enabled,
        (Capability::SecretsManager, PayloadType::CertDiscovery | PayloadType::CertAutomation) => {
            false
        }
    }
}

/// The telemetry endpoint for `region`, the FIPS one with `use_fips`. An
/// `override_endpoint` that isn't blank replaces it if it is `https://`; one
/// that isn't is ignored with a warning, so the requests aren't sent in the
/// clear.
fn endpoint(region: &str, use_fips: bool, override_endpoint: Option<String>) -> String {
    if let Some(endpoint) = override_endpoint
        .as_deref()
        .map(str::trim)
        .filter(|endpoint| !endpoint.is_empty())
    {
        if endpoint
            .get(..8)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"))
        {
            log::info!("Telemetry: sending to {endpoint}, set by {ENDPOINT_OVERRIDE_VAR}");
            return endpoint.to_string();
        }
        log::warn!("Telemetry: ignoring {ENDPOINT_OVERRIDE_VAR}, which isn't an https:// endpoint");
    }
    // Hosts outside the `aws` partition and the FIPS host aren't confirmed.
    // If the host doesn't exist, each request fails as transient.
    let service = if use_fips {
        "workload-telemetry-fips"
    } else {
        "workload-telemetry"
    };
    format!("https://{service}.{region}.api.aws")
}

/// The endpoint override from [`ENDPOINT_OVERRIDE_VAR`].
fn endpoint_override() -> Option<String> {
    std::env::var(ENDPOINT_OVERRIDE_VAR).ok()
}

/// What a sender does with a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Delivery {
    /// Sends its request as CBOR.
    Send,
    /// Logs its request as JSON at INFO under [`DRY_RUN_LOG_TARGET`] and sends
    /// nothing, so the customer can inspect what would be sent.
    DryRun,
    /// Encodes its request as CBOR and logs a one-line summary at INFO instead
    /// of sending, while live sending is off for its capability
    /// ([`live_sending`]).
    HeldBack,
}

/// Credentials loaded once and reused until `reload_at`.
#[derive(Debug, Clone)]
struct CachedCredentials {
    credentials: Credentials,
    reload_at: SystemTime,
}

/// Signs and sends telemetry records for one process. Clones share the
/// connection pool, the credentials provider and the cached credentials.
#[derive(Debug, Clone)]
pub struct TelemetrySender {
    capability: Capability,
    /// What the customer consented to send, checked per record by [`consented`].
    consent: TelemetryConfig,
    connector: SharedHttpConnector,
    credentials: SharedCredentialsProvider,
    /// The last credentials loaded, reused until they are due for a reload.
    cached_credentials: Arc<Mutex<Option<CachedCredentials>>>,
    region: String,
    url: String,
    delivery: Delivery,
}

impl TelemetrySender {
    /// The sender for `capability`, or `None` when the customer hasn't
    /// consented to any of its records (`[telemetry.<capability>] enabled`,
    /// or discovery on for ACM). It sends only that capability's records, and
    /// only the types the customer consented to. With `dry_run` set, it logs
    /// each request's JSON under the `telemetry_dryrun` target instead of
    /// sending it. Otherwise, while live sending is off, it logs a one-line
    /// summary at INFO of each request.
    ///
    /// It signs with `sdk_config`'s credentials for its region, and uses the
    /// FIPS endpoint when the config asks for FIPS. It is also `None`, with a
    /// WARN, when the config has no credentials or region, or the region isn't
    /// a region name, since it becomes part of the hostname.
    ///
    /// Like the AWS SDK clients, it honors `HTTPS_PROXY` and `NO_PROXY` and
    /// uses the same TLS stack, which a FIPS build (rustls's `fips` feature)
    /// makes FIPS-only.
    pub fn for_capability(
        settings: &TelemetryConfig,
        capability: Capability,
        sdk_config: &SdkConfig,
    ) -> Option<Self> {
        let opted_in = match capability {
            Capability::SecretsManager => settings.secrets_manager_enabled,
            Capability::Acm => settings.acm_enabled || settings.acm_discovery_enabled,
        };
        if !opted_in {
            return None;
        }
        let delivery = if settings.dry_run {
            Delivery::DryRun
        } else if live_sending(capability) {
            Delivery::Send
        } else {
            Delivery::HeldBack
        };
        let sender = Self::from_config(
            capability,
            settings.clone(),
            sdk_config,
            endpoint_override(),
            delivery,
        )?;
        match delivery {
            Delivery::Send => {}
            Delivery::DryRun => log::warn!(
                "Telemetry dry run for {}: records aren't sent; each request is written to \
                 the *_telemetry_dryrun.log file next to the provider log as it would be \
                 sent, or to the console when log_to_file is false, queued records when \
                 the drain flushes (about hourly) and at shutdown",
                capability.as_str()
            ),
            Delivery::HeldBack => log::warn!(
                "Telemetry for {}: this release doesn't send its telemetry yet: each request \
                 is logged as a one-line summary, and a record type not in the request's \
                 shape is dropped",
                capability.as_str()
            ),
        }
        Some(sender)
    }

    fn from_config(
        capability: Capability,
        consent: TelemetryConfig,
        sdk_config: &SdkConfig,
        override_endpoint: Option<String>,
        delivery: Delivery,
    ) -> Option<Self> {
        let (Some(credentials), Some(region)) =
            (sdk_config.credentials_provider(), sdk_config.region())
        else {
            log::warn!("Telemetry is off: the AWS SDK config has no credentials or region");
            return None;
        };
        let region = region.as_ref();
        if !is_region(region) {
            log::warn!("Telemetry is off: {region:?} is not a region name");
            return None;
        }
        let use_fips = sdk_config.use_fips().unwrap_or(false);
        let connector = Connector::builder()
            .proxy_config(ProxyConfig::from_env())
            .tls_provider(Provider::Rustls(CryptoMode::AwsLc))
            .build();
        Some(Self::with_connector(
            capability,
            consent,
            SharedHttpConnector::new(connector),
            credentials,
            region,
            endpoint(region, use_fips, override_endpoint),
            delivery,
        ))
    }

    fn with_connector(
        capability: Capability,
        consent: TelemetryConfig,
        connector: SharedHttpConnector,
        credentials: SharedCredentialsProvider,
        region: &str,
        endpoint: String,
        delivery: Delivery,
    ) -> Self {
        Self {
            capability,
            consent,
            connector,
            credentials,
            cached_credentials: Arc::default(),
            region: region.to_string(),
            url: format!("{}{REQUEST_PATH}", endpoint.trim_end_matches('/')),
            delivery,
        }
    }

    /// This sender as a dry run, for other modules' tests.
    #[cfg(test)]
    pub(crate) fn into_dry_run(self) -> Self {
        Self {
            delivery: Delivery::DryRun,
            ..self
        }
    }

    /// An ACM sender in us-west-2 that sends through `connector` the record
    /// types `consent` allows, for other modules' tests.
    #[cfg(test)]
    pub(crate) fn for_tests(connector: SharedHttpConnector, consent: TelemetryConfig) -> Self {
        let credentials = SharedCredentialsProvider::new(Credentials::new(
            "AKIDEXAMPLE",
            "secret",
            None,
            None,
            "test",
        ));
        Self::with_connector(
            Capability::Acm,
            consent,
            connector,
            credentials,
            "us-west-2",
            endpoint("us-west-2", false, None),
            Delivery::Send,
        )
    }

    /// Whether the customer consented to sending this sender's
    /// `payload_type` records.
    pub(crate) fn consents_to(&self, payload_type: PayloadType) -> bool {
        consented(&self.consent, self.capability, payload_type)
    }

    /// `request` as this sender handles it: the JSON a dry run logs, or else
    /// the CBOR it sends.
    pub(crate) fn encode(&self, request: &PutCertificateTelemetryInput) -> Result<Vec<u8>, String> {
        match self.delivery {
            Delivery::DryRun => serde_json::to_vec(request).map_err(|err| err.to_string()),
            Delivery::Send | Delivery::HeldBack => to_cbor(request).map_err(|err| match err {
                CborError::Value(why) => why,
                CborError::Io(err) => err.to_string(),
            }),
        }
    }

    /// Sends `record` as a request of its own, retrying a transient failure, 3
    /// attempts in all, with a jittered wait before each retry plus any wait a
    /// throttling or 503 response asks for. A dry run logs the request's JSON
    /// instead, and while live sending is off a one-line summary is logged.
    ///
    /// Rejected even in a dry run or while live sending is off: a record of
    /// another capability or of a type the customer hasn't consented to, a
    /// record whose part's entry type or key isn't its own, a part over the
    /// service model's limits, or a request over [`MAX_REQUEST_BYTES`]. A
    /// record without a [`TelemetryRecord::request_part`] is rejected too,
    /// except that a dry run logs its [`TelemetryRecord::serialize`] JSON.
    pub async fn send(&self, record: &dyn TelemetryRecord) -> Result<(), SendError> {
        let Some(part) = self.part_to_send(record)? else {
            return Ok(());
        };
        let request = part.request();
        self.send_request(&request, &part.idempotency_key).await
    }

    /// `record`'s part of a request, or why this sender won't send it, even in
    /// a dry run or while live sending is off: it is another capability's or
    /// of a type the customer hasn't consented to, its part's entry type or
    /// key isn't its own, or the part is over the model's limits
    /// ([`RequestPart::check`]). A record without a
    /// [`TelemetryRecord::request_part`] is rejected too, except that a dry
    /// run logs its [`TelemetryRecord::serialize`] JSON and gives `None`.
    pub(crate) fn part_to_send(
        &self,
        record: &dyn TelemetryRecord,
    ) -> Result<Option<RequestPart>, Refused> {
        if record.capability() != self.capability {
            return Err(Refused::Rejected(format!(
                "a {} record can't go through the {} sender",
                record.capability().as_str(),
                self.capability.as_str()
            )));
        }
        if !self.consents_to(record.payload_type()) {
            return Err(Refused::Rejected(format!(
                "the customer hasn't consented to sending {} records",
                record.payload_type().as_str()
            )));
        }
        let Some(part) = record.request_part() else {
            if self.delivery != Delivery::DryRun {
                return Err(Refused::Rejected(format!(
                    "{} records aren't in the request's shape yet",
                    record.payload_type().as_str()
                )));
            }
            let json = record.serialize().map_err(|err| {
                Refused::Rejected(format!("could not serialize the record: {err}"))
            })?;
            check_size(json.len())
                .map_err(|why| Refused::TooLarge(format!("the record is {why}")))?;
            log_dry_run(&json);
            return Ok(None);
        };
        // Consent is checked against the record's type, so its entry must
        // be of that type too.
        if part.entry.payload_type() != record.payload_type() {
            return Err(Refused::Rejected(format!(
                "a {} record gave a {} entry",
                record.payload_type().as_str(),
                part.entry.payload_type().as_str()
            )));
        }
        // The part's key is the request's idempotencyKey, so it must be the
        // record's own.
        if part.idempotency_key != record.idempotency_key() {
            return Err(Refused::Rejected(format!(
                "its part has the key {}, not the record's",
                part.idempotency_key
            )));
        }
        part.check().map_err(Refused::Rejected)?;
        Ok(Some(part))
    }

    /// Sends `request`, retrying a transient failure, 3 attempts in all.
    /// Before each retry it waits a random time, up to 1 s and then up to 2 s,
    /// so providers that fail together don't retry together, plus the wait a
    /// throttling or 503 response asks for, up to [`MAX_RETRY_AFTER`]. Each
    /// attempt's outcome is logged at DEBUG, naming the request by `label`. A
    /// dry run logs the request's JSON instead, and while live sending is off a
    /// one-line summary is logged. A request over [`MAX_REQUEST_BYTES`] as
    /// [`Self::encode`] encodes it is rejected, even then.
    pub(crate) async fn send_request(
        &self,
        request: &PutCertificateTelemetryInput,
        label: &str,
    ) -> Result<(), SendError> {
        let body = self.encode(request).map_err(|err| {
            SendError::Rejected(format!("could not serialize the request: {err}"))
        })?;
        check_size(body.len())
            .map_err(|why| SendError::Rejected(format!("the request is {why}")))?;
        match self.delivery {
            Delivery::Send => {}
            Delivery::DryRun => {
                log_dry_run(&body);
                return Ok(());
            }
            Delivery::HeldBack => {
                log::info!(
                    "Telemetry (not sent): {} request {label} ({} bytes)",
                    request.telemetry.payload_type().as_str(),
                    body.len()
                );
                return Ok(());
            }
        }
        // Every attempt sends these same bytes; a clone shares them.
        let body = Bytes::from(body);
        let mut attempt = 1;
        loop {
            let failure = match self.attempt(&body).await {
                Ok(()) => {
                    log::debug!(
                        "Telemetry: request {label} sent on attempt {attempt} of {SEND_ATTEMPTS}"
                    );
                    return Ok(());
                }
                Err(failure) => failure,
            };
            if attempt == SEND_ATTEMPTS || matches!(failure.error, SendError::Rejected(_)) {
                log::debug!(
                    "Telemetry: attempt {attempt} of {SEND_ATTEMPTS} at request {label} failed, \
                     not retrying: {:?}",
                    failure.error
                );
                return Err(failure.error);
            }
            let wait = failure.retry_after + jittered(retry_delay(attempt - 1));
            log::debug!(
                "Telemetry: attempt {attempt} of {SEND_ATTEMPTS} at request {label} failed, \
                 retrying in {wait:?}: {:?}",
                failure.error
            );
            tokio::time::sleep(wait).await;
            attempt += 1;
        }
    }

    /// One signed call with `body`, response included, within
    /// [`SEND_TIMEOUT`].
    async fn attempt(&self, body: &Bytes) -> Result<(), Failure> {
        match tokio::time::timeout(SEND_TIMEOUT, self.call(body)).await {
            Ok(result) => result,
            Err(_) => {
                Err(SendError::Transient(format!("no response within {SEND_TIMEOUT:?}")).into())
            }
        }
    }

    /// One signed call with `body`, classified by its response: 2xx succeeds;
    /// throttling (a 429, or an error type starting with `Throttling`), a 408,
    /// a 5xx or no response is transient; anything else is rejected. Throttling
    /// and a 503 carry the wait the response asks for.
    async fn call(&self, body: &Bytes) -> Result<(), Failure> {
        let request = self.signed_request(body.clone()).await?;
        let response =
            self.connector.call(request).await.map_err(|err| {
                SendError::Transient(format!("could not reach the service: {err}"))
            })?;

        let status = response.status().as_u16();
        if (200..=299).contains(&status) {
            return Ok(());
        }
        let error = ErrorResponse::read(response).await;
        let why = format!("HTTP {status} {}", error.name)
            .trim_end()
            .to_string();
        // The service can also report throttling as a 400 with this error.
        let throttled = status == 429 || error.name.starts_with("Throttling");
        match status {
            _ if throttled || status == 503 => Err(Failure {
                error: SendError::Transient(why),
                retry_after: error.retry_after,
            }),
            // The service answers 408 when the request body stops arriving, so
            // sending the same request again can succeed.
            408 | 500..=599 => Err(SendError::Transient(why).into()),
            _ => Err(SendError::Rejected(why).into()),
        }
    }

    /// The cached credentials, or newly loaded ones when they are due for a
    /// reload. Credentials that fail to load are not cached, so the next send
    /// tries again.
    async fn load_credentials(&self) -> Result<Credentials, SendError> {
        let cached = self
            .cached_credentials
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(cached) = cached.filter(|cached| SystemTime::now() < cached.reload_at) {
            return Ok(cached.credentials);
        }
        let credentials = self
            .credentials
            .provide_credentials()
            .await
            .map_err(|err| {
                SendError::Transient(format!("could not load AWS credentials: {err}"))
            })?;
        let reload_at = match credentials.expiry() {
            Some(expiry) => expiry
                .checked_sub(CREDENTIALS_RELOAD_BEFORE_EXPIRY)
                .unwrap_or(expiry),
            None => SystemTime::now() + CREDENTIALS_LIFETIME,
        };
        *self
            .cached_credentials
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(CachedCredentials {
            credentials: credentials.clone(),
            reload_at,
        });
        Ok(credentials)
    }

    async fn signed_request(&self, body: Bytes) -> Result<HttpRequest, SendError> {
        let identity = Identity::from(self.load_credentials().await?);
        let params = v4::SigningParams::builder()
            .identity(&identity)
            .region(&self.region)
            .name(SIGNING_NAME)
            .time(SystemTime::now())
            .settings(SigningSettings::default())
            .build()
            .map_err(|err| SendError::Rejected(format!("could not sign the request: {err}")))?
            .into();

        let mut request = http::Request::builder()
            .method("POST")
            .uri(&self.url)
            .header("smithy-protocol", SMITHY_PROTOCOL)
            .header("content-type", CONTENT_TYPE)
            .header("accept", CONTENT_TYPE)
            .header("content-length", body.len())
            .header(
                "user-agent",
                format!("{PROVIDER_NAME}/{}", env!("CARGO_PKG_VERSION")),
            )
            .body(body)
            .map_err(|err| SendError::Rejected(format!("could not build the request: {err}")))?;
        if request.uri().host().is_none() {
            return Err(SendError::Rejected(format!(
                "endpoint has no host: {}",
                self.url
            )));
        }
        let headers = request
            .headers()
            .iter()
            .filter_map(|(name, value)| Some((name.as_str(), value.to_str().ok()?)));
        let signable = SignableRequest::new(
            "POST",
            self.url.as_str(),
            headers,
            SignableBody::Bytes(request.body()),
        );
        let (instructions, _signature) = signable
            .and_then(|signable| sign(signable, &params))
            .map_err(|err| SendError::Rejected(format!("could not sign the request: {err}")))?
            .into_parts();
        instructions.apply_to_request_http1x(&mut request);

        HttpRequest::try_from(request.map(SdkBody::from))
            .map_err(|err| SendError::Rejected(format!("could not build the request: {err}")))
    }
}

/// Why `bytes` of a request, or of a record's JSON, are too many to send, if
/// they are: over [`MAX_REQUEST_BYTES`].
fn check_size(bytes: usize) -> Result<(), String> {
    if bytes > MAX_REQUEST_BYTES {
        Err(format!(
            "{bytes} bytes, over the {MAX_REQUEST_BYTES}-byte limit"
        ))
    } else {
        Ok(())
    }
}

/// Logs `json` at INFO under [`DRY_RUN_LOG_TARGET`].
fn log_dry_run(json: &[u8]) {
    log::info!(target: DRY_RUN_LOG_TARGET, "{}", String::from_utf8_lossy(json));
}

/// An attempt that didn't succeed: why, and how long the service asked the
/// sender to wait before the next one, zero when it didn't say.
#[derive(Debug)]
struct Failure {
    error: SendError,
    retry_after: Duration,
}

impl From<SendError> for Failure {
    fn from(error: SendError) -> Self {
        Self {
            error,
            retry_after: Duration::ZERO,
        }
    }
}

/// What a response that isn't a success says about its error.
#[derive(Debug, Default, PartialEq, Eq)]
struct ErrorResponse {
    /// The service's error, such as `ThrottlingException`, or empty when the
    /// response doesn't name one.
    name: String,
    /// How long it asks the sender to wait before the next attempt, at most
    /// [`MAX_RETRY_AFTER`], or zero when it doesn't say.
    retry_after: Duration,
}

impl ErrorResponse {
    /// Reads a Smithy RPC v2 CBOR error: its name from its body's `__type`,
    /// and its wait from its `Retry-After` header, or else its body's
    /// `retryAfterSeconds`. As the protocol says, a response without its
    /// `smithy-protocol` header, such as a proxy's, is classified by status
    /// alone, and `x-amzn-errortype` is ignored.
    async fn read(response: HttpResponse) -> Self {
        if response.headers().get("smithy-protocol") != Some(SMITHY_PROTOCOL) {
            return Self::default();
        }
        let header = response
            .headers()
            .get("retry-after")
            .and_then(|value| value.parse::<u64>().ok());
        let body = error_body(response.into_body()).await.unwrap_or_default();
        let seconds = header.or(body
            .retry_after_seconds
            .and_then(|seconds| u64::try_from(seconds).ok()));
        Self {
            name: error_name(body.error_type.as_deref().unwrap_or_default()).to_string(),
            retry_after: seconds.map_or(Duration::ZERO, |seconds| {
                Duration::from_secs(seconds).min(MAX_RETRY_AFTER)
            }),
        }
    }
}

/// A Smithy RPC v2 CBOR error body.
#[derive(Debug, Default, Deserialize)]
struct ErrorBody {
    /// The error's shape ID.
    #[serde(rename = "__type")]
    error_type: Option<String>,
    /// A `ThrottlingException`'s wait. Signed, so a negative one is ignored
    /// without losing `__type`.
    #[serde(rename = "retryAfterSeconds")]
    retry_after_seconds: Option<i64>,
}

/// The error in `body`, if it is CBOR and its length is known and at most
/// [`MAX_ERROR_BODY_BYTES`]. A body of unknown length, which HTTP/2 allows,
/// isn't read.
async fn error_body(body: SdkBody) -> Option<ErrorBody> {
    if !body
        .content_length()
        .is_some_and(|length| length <= MAX_ERROR_BODY_BYTES)
    {
        return None;
    }
    let body = ByteStream::new(body).collect().await.ok()?.into_bytes();
    ciborium::from_reader(&body[..]).ok()
}

/// The error's name in a `__type` value, the error's shape ID. As the AWS SDKs
/// do, anything from the first `:` on and anything up to the first `#` are
/// dropped, so `example#ThrottlingException:http://internal.example/` names
/// `ThrottlingException`.
fn error_name(error_type: &str) -> &str {
    let name = error_type.split(':').next().unwrap_or_default();
    name.split_once('#').map_or(name, |(_, name)| name)
}

/// The longest wait before retry number `retry`, counting from 0:
/// [`FIRST_RETRY_DELAY`], doubled `retry` times.
fn retry_delay(retry: u32) -> Duration {
    FIRST_RETRY_DELAY * 2u32.pow(retry)
}

/// Up to `delay`, at random ("full jitter", as in the AWS SDK).
fn jittered(delay: Duration) -> Duration {
    delay.mul_f64(rand::rng().random_range(0.0..1.0))
}

/// A scripted service for this module's and other modules' tests.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use aws_smithy_runtime_api::client::http::HttpConnectorFuture;
    use aws_smithy_runtime_api::http::StatusCode;

    /// A request the service received: when it arrived, and its body.
    pub(crate) type Received = (tokio::time::Instant, Vec<u8>);

    /// Answers each request with the next status in `statuses`, repeating the
    /// last one, and records every request.
    #[derive(Debug)]
    pub(crate) struct ScriptedService {
        statuses: Mutex<Vec<u16>>,
        retry_after: Option<u64>,
        received: Arc<Mutex<Vec<Received>>>,
    }

    impl ScriptedService {
        /// The service, and the requests it will receive.
        pub(crate) fn answering(statuses: &[u16]) -> (Self, Arc<Mutex<Vec<Received>>>) {
            let received = Arc::new(Mutex::new(Vec::new()));
            let service = Self {
                statuses: Mutex::new(statuses.to_vec()),
                retry_after: None,
                received: Arc::clone(&received),
            };
            (service, received)
        }

        /// Makes every answer a Smithy RPC v2 CBOR response whose
        /// `Retry-After` asks for `seconds`.
        pub(crate) fn asking_to_wait(mut self, seconds: u64) -> Self {
            self.retry_after = Some(seconds);
            self
        }
    }

    impl HttpConnector for ScriptedService {
        fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
            let body = request.body().bytes().unwrap_or_default().to_vec();
            self.received
                .lock()
                .unwrap()
                .push((tokio::time::Instant::now(), body));
            let mut statuses = self.statuses.lock().unwrap();
            let status = if statuses.len() > 1 {
                statuses.remove(0)
            } else {
                statuses[0]
            };
            let status = StatusCode::try_from(status).unwrap();
            let mut response = HttpResponse::new(status, SdkBody::empty());
            if let Some(seconds) = self.retry_after {
                let headers = response.headers_mut();
                headers.insert("smithy-protocol", SMITHY_PROTOCOL);
                headers.insert("retry-after", seconds.to_string());
            }
            HttpConnectorFuture::ready(Ok(response))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{Received, ScriptedService};
    use super::*;
    use crate::telemetry::payload::{
        to_cbor, Blob, Capability, DeploymentType, PayloadEnvelope, PayloadType,
    };
    use crate::telemetry::request::{Discovery, Entry, Observation, ProbeOutcome};
    use aws_config::Region;
    use aws_credential_types::provider::{error::CredentialsError, future};
    use aws_credential_types::Credentials;
    use aws_smithy_http_client::test_util::NeverClient;
    use aws_smithy_runtime_api::client::http::HttpConnectorFuture;
    use aws_smithy_runtime_api::client::result::ConnectorError;
    use aws_smithy_runtime_api::http::StatusCode;
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    /// A record's JSON, which a dry run logs for a record without a request
    /// part.
    const FAKE_JSON: &[u8] = br#"{"payload_type":"cert_discovery"}"#;

    /// The key of every [`discovery`] part.
    const DISCOVERY_KEY: &str = "i-1:boot-1:acm:cert_discovery:0:0";

    /// A discovery batch with one observation per entry of `certificates`,
    /// each with that many 16,384-byte certificates, at least one.
    fn discovery(certificates: &[usize]) -> RequestPart {
        let envelope = PayloadEnvelope::new(
            Capability::Acm,
            PayloadType::CertDiscovery,
            0,
            0,
            "i-1",
            "boot-1",
            "4.0.0",
            "us-west-2",
            DeploymentType::Ec2,
        )
        .unwrap();
        let certificate = Blob(vec![0x30; 16_384]);
        let observations = certificates
            .iter()
            .map(|n| Observation {
                port: 443,
                sni: None,
                outcome: ProbeOutcome::Success,
                certificate_der: Some(certificate.clone()),
                chain_der: (*n > 1).then(|| vec![certificate.clone(); n - 1]),
                mtls_detected: None,
                tls_version: None,
                cipher_suite: None,
                handshake_signature_scheme: None,
                key_algorithm: None,
            })
            .collect();
        let discovery = Discovery {
            scan_time: 1_793_315_962_000,
            scan_id: "i-1:1793315962".to_string(),
            observations,
            batch_index: 1,
            total_batches: 1,
            scan_complete: None,
            total_targets_probed: None,
            successful_probes: None,
            failed_probes: None,
            dropped_observations: None,
            configured_certificate_count: None,
        };
        RequestPart::new(&envelope, Entry::Discovery(discovery))
    }

    /// A discovery record with one certificate.
    struct FakeRecord;

    impl TelemetryRecord for FakeRecord {
        fn payload_type(&self) -> PayloadType {
            PayloadType::CertDiscovery
        }
        fn capability(&self) -> Capability {
            Capability::Acm
        }
        fn serialize(&self) -> Result<Vec<u8>, serde_json::Error> {
            Ok(FAKE_JSON.to_vec())
        }
        fn request_part(&self) -> Option<RequestPart> {
            Some(discovery(&[1]))
        }
        fn idempotency_key(&self) -> &str {
            DISCOVERY_KEY
        }
    }

    /// `FakeRecord`'s request.
    fn fake_request() -> PutCertificateTelemetryInput {
        discovery(&[1]).request()
    }

    /// A record with JSON but no request part.
    struct JsonOnlyRecord;

    impl TelemetryRecord for JsonOnlyRecord {
        fn payload_type(&self) -> PayloadType {
            PayloadType::CertDiscovery
        }
        fn capability(&self) -> Capability {
            Capability::Acm
        }
        fn serialize(&self) -> Result<Vec<u8>, serde_json::Error> {
            Ok(FAKE_JSON.to_vec())
        }
        fn idempotency_key(&self) -> &str {
            "json-only"
        }
    }

    /// A discovery record with one observation per entry, each with that
    /// many certificates.
    struct SizedRecord(&'static [usize]);

    impl TelemetryRecord for SizedRecord {
        fn payload_type(&self) -> PayloadType {
            PayloadType::CertDiscovery
        }
        fn capability(&self) -> Capability {
            Capability::Acm
        }
        fn serialize(&self) -> Result<Vec<u8>, serde_json::Error> {
            Ok(FAKE_JSON.to_vec())
        }
        fn request_part(&self) -> Option<RequestPart> {
            Some(discovery(self.0))
        }
        fn idempotency_key(&self) -> &str {
            DISCOVERY_KEY
        }
    }

    /// A Smithy RPC v2 CBOR error response: `status`, the protocol's
    /// header, and `body` as CBOR.
    fn cbor_error(status: u16, body: serde_json::Value) -> HttpResponse {
        cbor_error_bytes(status, to_cbor(&body).unwrap())
    }

    /// A Smithy RPC v2 CBOR error response with `body` as it is.
    fn cbor_error_bytes(status: u16, body: Vec<u8>) -> HttpResponse {
        let mut response =
            HttpResponse::new(StatusCode::try_from(status).unwrap(), SdkBody::from(body));
        response
            .headers_mut()
            .insert("smithy-protocol", SMITHY_PROTOCOL);
        response.headers_mut().insert("content-type", CONTENT_TYPE);
        response
    }

    fn credentials() -> SharedCredentialsProvider {
        SharedCredentialsProvider::new(Credentials::new(
            "AKIDEXAMPLE",
            "secret",
            Some("session-token".to_string()),
            None,
            "test",
        ))
    }

    /// Consent to every record type, for tests that aren't about consent.
    fn consent_to_all() -> TelemetryConfig {
        TelemetryConfig {
            secrets_manager_enabled: true,
            acm_enabled: true,
            acm_discovery_enabled: true,
            dry_run: false,
        }
    }

    /// A service that answers every request with `status` and, if set, an
    /// error whose `__type` is `error_type`, and keeps the last request it
    /// received.
    #[derive(Debug)]
    struct FakeService {
        status: u16,
        error_type: Option<&'static str>,
        received: Arc<Mutex<Option<HttpRequest>>>,
    }

    impl HttpConnector for FakeService {
        fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
            *self.received.lock().unwrap() = Some(request);
            let response = match self.error_type {
                Some(error_type) => cbor_error(self.status, json!({ "__type": error_type })),
                None => {
                    HttpResponse::new(StatusCode::try_from(self.status).unwrap(), SdkBody::empty())
                }
            };
            HttpConnectorFuture::ready(Ok(response))
        }
    }

    fn sender_answering(
        status: u16,
        endpoint: Option<&str>,
    ) -> (TelemetrySender, Arc<Mutex<Option<HttpRequest>>>) {
        sender_answering_with(status, None, endpoint)
    }

    fn sender_answering_with(
        status: u16,
        error_type: Option<&'static str>,
        endpoint: Option<&str>,
    ) -> (TelemetrySender, Arc<Mutex<Option<HttpRequest>>>) {
        let received = Arc::new(Mutex::new(None));
        let service = FakeService {
            status,
            error_type,
            received: Arc::clone(&received),
        };
        let sender = TelemetrySender::with_connector(
            Capability::Acm,
            consent_to_all(),
            SharedHttpConnector::new(service),
            credentials(),
            "us-west-2",
            super::endpoint("us-west-2", false, endpoint.map(str::to_string)),
            Delivery::Send,
        );
        (sender, received)
    }

    fn sdk_config(region: Option<&'static str>, use_fips: bool) -> SdkConfig {
        let mut config = SdkConfig::builder()
            .credentials_provider(credentials())
            .use_fips(use_fips);
        if let Some(region) = region {
            config = config.region(Region::new(region));
        }
        config.build()
    }

    #[test]
    fn the_endpoint_is_regional_fips_on_request_and_replaced_by_an_override() {
        assert_eq!(
            super::endpoint("us-west-2", false, None),
            "https://workload-telemetry.us-west-2.api.aws"
        );
        assert_eq!(
            super::endpoint("us-west-2", true, None),
            "https://workload-telemetry-fips.us-west-2.api.aws"
        );
        assert_eq!(
            super::endpoint(
                "us-west-2",
                false,
                Some("https://localhost:8443".to_string())
            ),
            "https://localhost:8443"
        );
        assert_eq!(
            super::endpoint("us-west-2", false, Some(" ".to_string())),
            "https://workload-telemetry.us-west-2.api.aws"
        );
        assert_eq!(
            super::endpoint(
                "us-west-2",
                false,
                Some(" https://localhost:8443 ".to_string())
            ),
            "https://localhost:8443"
        );
        // The scheme is case-insensitive.
        assert_eq!(
            super::endpoint(
                "us-west-2",
                false,
                Some("HTTPS://localhost:8443".to_string())
            ),
            "HTTPS://localhost:8443"
        );
        // Not https, so ignored: the requests aren't sent in the clear.
        assert_eq!(
            super::endpoint(
                "us-west-2",
                false,
                Some("http://localhost:8443".to_string())
            ),
            "https://workload-telemetry.us-west-2.api.aws"
        );
    }

    #[test]
    fn a_sender_needs_credentials_and_a_region_name() {
        let sender = TelemetrySender::from_config(
            Capability::Acm,
            consent_to_all(),
            &sdk_config(Some("us-west-2"), false),
            None,
            Delivery::Send,
        )
        .unwrap();
        assert_eq!(sender.region, "us-west-2");

        let fips = TelemetrySender::from_config(
            Capability::Acm,
            consent_to_all(),
            &sdk_config(Some("us-west-2"), true),
            None,
            Delivery::Send,
        )
        .unwrap();
        assert!(
            fips.url.starts_with("https://workload-telemetry-fips."),
            "{}",
            fips.url
        );

        assert!(TelemetrySender::from_config(
            Capability::Acm,
            consent_to_all(),
            &sdk_config(None, false),
            None,
            Delivery::Send
        )
        .is_none());
        assert!(TelemetrySender::from_config(
            Capability::Acm,
            consent_to_all(),
            &sdk_config(Some("evil.example/x"), false),
            None,
            Delivery::Send,
        )
        .is_none());
        let no_credentials = SdkConfig::builder()
            .region(Region::new("us-west-2"))
            .build();
        assert!(TelemetrySender::from_config(
            Capability::Acm,
            consent_to_all(),
            &no_credentials,
            None,
            Delivery::Send
        )
        .is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn responses_classify_as_success_transient_or_rejected() {
        let cases = [
            (200, None),
            (204, None),
            (429, Some(SendError::Transient("HTTP 429".to_string()))),
            (408, Some(SendError::Transient("HTTP 408".to_string()))),
            (500, Some(SendError::Transient("HTTP 500".to_string()))),
            (503, Some(SendError::Transient("HTTP 503".to_string()))),
            (400, Some(SendError::Rejected("HTTP 400".to_string()))),
            (403, Some(SendError::Rejected("HTTP 403".to_string()))),
            (404, Some(SendError::Rejected("HTTP 404".to_string()))),
        ];
        for (status, expected) in cases {
            let (sender, _) = sender_answering(status, None);
            assert_eq!(
                sender.send(&FakeRecord).await.err(),
                expected,
                "HTTP {status}"
            );
        }
    }

    #[tokio::test]
    async fn request_is_a_signed_rpc_v2_cbor_call_to_the_regional_endpoint() {
        let (sender, received) = sender_answering(200, None);
        let request = fake_request();
        sender.send_request(&request, "key").await.unwrap();
        let cbor = to_cbor(&request).unwrap();

        let request = received.lock().unwrap().take().unwrap();
        assert_eq!(request.method(), "POST");
        assert_eq!(
            request.uri(),
            "https://workload-telemetry.us-west-2.api.aws\
             /service/AWSWorkloadTelemetryService/operation/PutCertificateTelemetry"
        );
        assert_eq!(
            request.headers().get("smithy-protocol"),
            Some("rpc-v2-cbor")
        );
        assert_eq!(
            request.headers().get("content-type"),
            Some("application/cbor")
        );
        assert_eq!(request.headers().get("accept"), Some("application/cbor"));
        assert_eq!(
            request.headers().get("content-length"),
            Some(cbor.len().to_string().as_str())
        );
        // The protocol forbids it, and the service rejects a request with it.
        assert_eq!(request.headers().get("x-amz-target"), None);
        assert_eq!(request.body().bytes().unwrap(), cbor);

        let authorization = request.headers().get("authorization").unwrap();
        assert!(
            authorization.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"),
            "{authorization}"
        );
        assert!(
            authorization.contains("/us-west-2/workload-telemetry/aws4_request"),
            "{authorization}"
        );
        assert!(
            authorization.contains(
                "SignedHeaders=accept;content-length;content-type;host;smithy-protocol;\
                 x-amz-date;x-amz-security-token,"
            ),
            "{authorization}"
        );
        assert_eq!(
            request.headers().get("user-agent"),
            Some(
                format!(
                    "aws-workload-credentials-provider/{}",
                    env!("CARGO_PKG_VERSION")
                )
                .as_str()
            )
        );
        assert!(request.headers().get("x-amz-date").is_some());
        assert_eq!(
            request.headers().get("x-amz-security-token"),
            Some("session-token")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_service_error_type_is_reported_and_throttling_is_transient() {
        let cases = [
            (
                400,
                "com.amazonaws.workloadtelemetry#ThrottlingException",
                SendError::Transient("HTTP 400 ThrottlingException".to_string()),
            ),
            (
                400,
                "com.amazonaws.workloadtelemetry#ValidationException",
                SendError::Rejected("HTTP 400 ValidationException".to_string()),
            ),
            (
                403,
                "com.amazonaws.workloadtelemetry#AccessDeniedException",
                SendError::Rejected("HTTP 403 AccessDeniedException".to_string()),
            ),
            (
                503,
                "com.amazonaws.workloadtelemetry#ServiceUnavailableException",
                SendError::Transient("HTTP 503 ServiceUnavailableException".to_string()),
            ),
            (
                400,
                "com.example.availability#ThrottlingException",
                SendError::Transient("HTTP 400 ThrottlingException".to_string()),
            ),
        ];
        for (status, error_type, expected) in cases {
            let (sender, _) = sender_answering_with(status, Some(error_type), None);
            assert_eq!(sender.send(&FakeRecord).await, Err(expected));
        }
    }

    #[test]
    fn the_error_name_drops_any_namespace_and_uri() {
        let cases = [
            ("ThrottlingException", "ThrottlingException"),
            (
                "com.example.availability#ThrottlingException",
                "ThrottlingException",
            ),
            (
                "ThrottlingException:http://internal.example/com.example.availability/",
                "ThrottlingException",
            ),
            (
                "example#ValidationException:http://internal.example/",
                "ValidationException",
            ),
            ("Name:http://internal.example/#fragment", "Name"),
            ("", ""),
        ];
        for (error_type, name) in cases {
            assert_eq!(error_name(error_type), name, "{error_type}");
        }
    }

    #[tokio::test]
    async fn the_error_name_comes_from_the_body_of_a_protocol_response_only() {
        let response = cbor_error(
            400,
            json!({ "__type": "com.amazonaws.workloadtelemetry#ValidationException" }),
        );
        assert_eq!(
            ErrorResponse::read(response).await.name,
            "ValidationException"
        );

        // A negative wait is ignored, and the name kept.
        let response = cbor_error(
            400,
            json!({
                "__type": "com.example.availability#ThrottlingException",
                "retryAfterSeconds": -1,
            }),
        );
        assert_eq!(
            ErrorResponse::read(response).await,
            ErrorResponse {
                name: "ThrottlingException".to_string(),
                retry_after: Duration::ZERO,
            }
        );

        // Clients must ignore `x-amzn-errortype`.
        let mut response = cbor_error(400, json!({ "message": "bad" }));
        response
            .headers_mut()
            .insert("x-amzn-errortype", "ThrottlingException");
        assert_eq!(
            ErrorResponse::read(response).await,
            ErrorResponse::default()
        );

        // Without the protocol's header, such as from a proxy, nothing of the
        // response is read.
        let mut response = HttpResponse::new(
            StatusCode::try_from(429).unwrap(),
            SdkBody::from(
                to_cbor(&json!({ "__type": "ThrottlingException", "retryAfterSeconds": 7 }))
                    .unwrap(),
            ),
        );
        response.headers_mut().insert("retry-after", "5");
        response
            .headers_mut()
            .insert("x-amzn-errortype", "ThrottlingException");
        assert_eq!(
            ErrorResponse::read(response).await,
            ErrorResponse::default()
        );

        // Nor with another value: it must match the request's exactly.
        let mut response = throttling_response(
            Some("5"),
            to_cbor(&json!({ "__type": "ThrottlingException", "retryAfterSeconds": 7 })).unwrap(),
        );
        response
            .headers_mut()
            .insert("smithy-protocol", "RPC-V2-CBOR");
        assert_eq!(
            ErrorResponse::read(response).await,
            ErrorResponse::default()
        );
    }

    /// A throttling error asking, if set, for `retry_after` in its header,
    /// with `body`.
    fn throttling_response(retry_after: Option<&str>, body: Vec<u8>) -> HttpResponse {
        let mut response = cbor_error_bytes(429, body);
        if let Some(retry_after) = retry_after {
            response
                .headers_mut()
                .insert("retry-after", retry_after.to_string());
        }
        response
    }

    #[tokio::test]
    async fn a_throttling_response_asks_for_its_wait_in_the_header_or_else_the_body() {
        let cbor = |body: serde_json::Value| to_cbor(&body).unwrap();
        let body = cbor(json!({
            "__type": "com.amazonaws.workloadtelemetry#ThrottlingException",
            "message": "slow down",
            "retryAfterSeconds": 7,
        }));
        let with_message =
            |message: String| cbor(json!({ "retryAfterSeconds": 7, "message": message }));
        let too_big = with_message("x".repeat(MAX_ERROR_BODY_BYTES as usize));
        // The message's length takes 2 bytes from 256 to 65,535 characters.
        let overhead = with_message("x".repeat(1000)).len() - 1000;
        let exactly_the_cap = with_message("x".repeat(MAX_ERROR_BODY_BYTES as usize - overhead));
        assert_eq!(exactly_the_cap.len() as u64, MAX_ERROR_BODY_BYTES);
        let cases = [
            (None, Vec::new(), 0),
            (Some("5"), Vec::new(), 5),
            (Some("3600"), Vec::new(), 30),
            (Some("2"), body.clone(), 2),
            (Some("0"), body.clone(), 0),
            (None, body.clone(), 7),
            (Some("Wed, 21 Oct 2026 07:28:00 GMT"), body.clone(), 7),
            (Some("-1"), Vec::new(), 0),
            (None, cbor(json!({ "retryAfterSeconds": -1 })), 0),
            (None, cbor(json!({ "retryAfterSeconds": 86400 })), 30),
            (None, b"not cbor".to_vec(), 0),
            (None, too_big, 0),
            (None, exactly_the_cap, 7),
        ];
        for (header, body, seconds) in cases {
            let response = throttling_response(header, body.clone());
            assert_eq!(
                ErrorResponse::read(response).await.retry_after,
                Duration::from_secs(seconds),
                "{header:?} {:02x?}",
                &body[..body.len().min(30)]
            );
        }
    }

    /// Throttles every request with `status` and, if set, an error whose
    /// `__type` is `error_type`, asking, if set, for a `retry_after` wait, and
    /// records when each arrived.
    #[derive(Debug)]
    struct ThrottlingService {
        status: u16,
        error_type: Option<&'static str>,
        retry_after: Option<&'static str>,
        arrivals: Arc<Mutex<Vec<tokio::time::Instant>>>,
    }

    impl HttpConnector for ThrottlingService {
        fn call(&self, _request: HttpRequest) -> HttpConnectorFuture {
            self.arrivals
                .lock()
                .unwrap()
                .push(tokio::time::Instant::now());
            let body = match self.error_type {
                Some(error_type) => json!({ "__type": error_type }),
                None => json!({}),
            };
            let mut response = throttling_response(self.retry_after, to_cbor(&body).unwrap());
            *response.status_mut() = StatusCode::try_from(self.status).unwrap();
            HttpConnectorFuture::ready(Ok(response))
        }
    }

    fn throttled_sender(
        status: u16,
        error_type: Option<&'static str>,
        retry_after: Option<&'static str>,
    ) -> (TelemetrySender, Arc<Mutex<Vec<tokio::time::Instant>>>) {
        let arrivals = Arc::new(Mutex::new(Vec::new()));
        let service = ThrottlingService {
            status,
            error_type,
            retry_after,
            arrivals: Arc::clone(&arrivals),
        };
        (
            TelemetrySender::for_tests(SharedHttpConnector::new(service), consent_to_all()),
            arrivals,
        )
    }

    #[tokio::test(start_paused = true)]
    async fn a_throttled_attempt_waits_the_asked_time_plus_the_jittered_backoff() {
        let (sender, arrivals) = throttled_sender(429, None, Some("5"));
        assert_eq!(
            sender.send(&FakeRecord).await,
            Err(SendError::Transient("HTTP 429".to_string()))
        );
        let arrivals = arrivals.lock().unwrap();
        assert_eq!(arrivals.len(), SEND_ATTEMPTS as usize);
        let asked = Duration::from_secs(5);
        for (retry, pair) in (0u32..).zip(arrivals.windows(2)) {
            let wait = pair[1] - pair[0];
            // Tokio rounds a timer up to the millisecond, so any jitter shows
            // as a wait longer than the one asked for.
            assert!(
                wait > asked && wait <= asked + retry_delay(retry),
                "retry {retry} waited {wait:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_400_throttling_error_asks_for_its_wait_too() {
        let (sender, _) = throttled_sender(
            400,
            Some("com.example.availability#ThrottlingException"),
            Some("5"),
        );
        let failure = sender
            .attempt(&Bytes::from_static(b"{}"))
            .await
            .unwrap_err();
        assert_eq!(
            failure.error,
            SendError::Transient("HTTP 400 ThrottlingException".to_string())
        );
        assert_eq!(failure.retry_after, Duration::from_secs(5));
    }

    /// Validates that a 503 asking for a wait is retried after that wait, at
    /// most [`MAX_RETRY_AFTER`], plus the jittered backoff: 5 s when it asks
    /// for 5 s, and 30 s when it asks for an hour.
    #[tokio::test(start_paused = true)]
    async fn a_503_attempt_waits_the_asked_time_up_to_the_cap_plus_the_jittered_backoff() {
        for (retry_after, asked) in [("5", Duration::from_secs(5)), ("3600", MAX_RETRY_AFTER)] {
            let (sender, arrivals) = throttled_sender(
                503,
                Some("com.amazonaws.workloadtelemetry#ServiceUnavailableException"),
                Some(retry_after),
            );
            assert_eq!(
                sender.send(&FakeRecord).await,
                Err(SendError::Transient(
                    "HTTP 503 ServiceUnavailableException".to_string()
                ))
            );
            let arrivals = arrivals.lock().unwrap();
            assert_eq!(arrivals.len(), SEND_ATTEMPTS as usize);
            for (retry, pair) in (0u32..).zip(arrivals.windows(2)) {
                let wait = pair[1] - pair[0];
                // Tokio rounds a timer up to the millisecond, so any jitter
                // shows as a wait longer than the one asked for.
                assert!(
                    wait > asked && wait <= asked + retry_delay(retry),
                    "Retry-After {retry_after}: retry {retry} waited {wait:?}"
                );
            }
        }
    }

    /// Validates that a 503 that asks for no wait is retried after the
    /// jittered backoff alone, and that another 5xx's `Retry-After` adds no
    /// wait.
    #[tokio::test(start_paused = true)]
    async fn a_503_without_a_wait_and_another_5xx_wait_the_jittered_backoff_alone() {
        for (status, retry_after) in [(503, None), (500, Some("5"))] {
            let (sender, arrivals) = throttled_sender(status, None, retry_after);
            assert_eq!(
                sender.send(&FakeRecord).await,
                Err(SendError::Transient(format!("HTTP {status}")))
            );
            let arrivals = arrivals.lock().unwrap();
            assert_eq!(arrivals.len(), SEND_ATTEMPTS as usize);
            for (retry, pair) in (0u32..).zip(arrivals.windows(2)) {
                let wait = pair[1] - pair[0];
                assert!(
                    wait <= retry_delay(retry),
                    "HTTP {status}: retry {retry} waited {wait:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn the_request_carries_a_valid_signature() {
        let (sender, received) = sender_answering(200, None);
        sender.send(&FakeRecord).await.unwrap();
        let request = received.lock().unwrap().take().unwrap();

        // Sign the received request again, at the time it says it was
        // signed: a signed header or the body changed after signing gives
        // another signature.
        let date = request.headers().get("x-amz-date").unwrap();
        let time = chrono::NaiveDateTime::parse_from_str(date, "%Y%m%dT%H%M%SZ")
            .unwrap()
            .and_utc();
        let identity = Identity::from(Credentials::new(
            "AKIDEXAMPLE",
            "secret",
            Some("session-token".to_string()),
            None,
            "test",
        ));
        let params = v4::SigningParams::builder()
            .identity(&identity)
            .region("us-west-2")
            .name("workload-telemetry")
            .time(time.into())
            .settings(SigningSettings::default())
            .build()
            .unwrap()
            .into();
        let headers = request.headers().iter().filter(|(name, _)| {
            !matches!(
                *name,
                "authorization" | "x-amz-date" | "x-amz-security-token"
            )
        });
        let signable = SignableRequest::new(
            "POST",
            request.uri(),
            headers,
            SignableBody::Bytes(request.body().bytes().unwrap()),
        )
        .unwrap();
        let (_, signature) = sign(signable, &params).unwrap().into_parts();
        let authorization = request.headers().get("authorization").unwrap();
        assert!(
            authorization.ends_with(&format!("Signature={signature}")),
            "{authorization}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn every_attempt_sends_the_same_request() {
        let (sender, received) = scripted_sender(&[503]);
        let request = fake_request();
        let result = sender.send_request(&request, "key").await;
        assert!(result.is_err());
        let received = received.lock().unwrap();
        assert_eq!(received.len(), 3);
        let cbor = to_cbor(&request).unwrap();
        assert!(received.iter().all(|(_, body)| *body == cbor));
    }

    #[tokio::test]
    async fn an_endpoint_without_a_host_is_rejected() {
        let (sender, received) = sender_answering(200, Some("https://"));
        let result = sender.send(&FakeRecord).await;
        assert!(matches!(result, Err(SendError::Rejected(_))), "{result:?}");
        assert!(received.lock().unwrap().is_none());
    }

    #[test]
    fn a_sender_exists_only_for_an_opted_in_capability() {
        let mut settings = TelemetryConfig::default();
        let sender = |settings: &TelemetryConfig, capability| {
            TelemetrySender::for_capability(
                settings,
                capability,
                &sdk_config(Some("us-west-2"), false),
            )
        };
        assert!(sender(&settings, Capability::Acm).is_none());
        assert!(sender(&settings, Capability::SecretsManager).is_none());

        settings.acm_enabled = true;
        assert!(sender(&settings, Capability::Acm).is_some());
        assert!(sender(&settings, Capability::SecretsManager).is_none());

        settings.secrets_manager_enabled = true;
        assert!(sender(&settings, Capability::SecretsManager).is_some());

        let discovery_only = TelemetryConfig {
            acm_discovery_enabled: true,
            ..TelemetryConfig::default()
        };
        assert_eq!(
            sender(&discovery_only, Capability::Acm).unwrap().consent,
            discovery_only
        );
        assert!(sender(&discovery_only, Capability::SecretsManager).is_none());

        settings.dry_run = true;
        assert_eq!(
            sender(&settings, Capability::Acm).unwrap().delivery,
            Delivery::DryRun
        );
    }

    /// Outside a dry run, ACM's sender sends and Secrets Manager's holds back.
    #[test]
    fn a_sender_that_isnt_a_dry_run_sends_acm_and_holds_back_secrets_manager() {
        let settings = TelemetryConfig {
            acm_enabled: true,
            secrets_manager_enabled: true,
            dry_run: false,
            ..TelemetryConfig::default()
        };
        let config = sdk_config(Some("us-west-2"), false);
        for (capability, delivery) in [
            (Capability::Acm, Delivery::Send),
            (Capability::SecretsManager, Delivery::HeldBack),
        ] {
            let sender = TelemetrySender::for_capability(&settings, capability, &config).unwrap();
            assert_eq!(sender.delivery, delivery, "{capability:?}");
        }
    }

    /// Says it is an automation record but gives a discovery batch.
    struct MislabeledRecord;

    impl TelemetryRecord for MislabeledRecord {
        fn payload_type(&self) -> PayloadType {
            PayloadType::CertAutomation
        }
        fn capability(&self) -> Capability {
            Capability::Acm
        }
        fn serialize(&self) -> Result<Vec<u8>, serde_json::Error> {
            Ok(FAKE_JSON.to_vec())
        }
        fn request_part(&self) -> Option<RequestPart> {
            Some(discovery(&[1]))
        }
        fn idempotency_key(&self) -> &str {
            DISCOVERY_KEY
        }
    }

    #[tokio::test]
    async fn a_record_whose_entry_is_of_another_type_is_rejected() {
        // Consent to automation only: the discovery batch must not get past
        // discovery's own consent under the automation label.
        let (mut sender, received) = sender_answering(200, None);
        sender.consent = TelemetryConfig {
            acm_enabled: true,
            ..TelemetryConfig::default()
        };
        assert_eq!(
            sender.send(&MislabeledRecord).await,
            Err(SendError::Rejected(
                "a cert_automation record gave a cert_discovery entry".to_string()
            ))
        );
        assert!(received.lock().unwrap().is_none());
    }

    /// A discovery record whose key isn't its part's.
    struct MiskeyedRecord;

    impl TelemetryRecord for MiskeyedRecord {
        fn payload_type(&self) -> PayloadType {
            PayloadType::CertDiscovery
        }
        fn capability(&self) -> Capability {
            Capability::Acm
        }
        fn serialize(&self) -> Result<Vec<u8>, serde_json::Error> {
            Ok(FAKE_JSON.to_vec())
        }
        fn request_part(&self) -> Option<RequestPart> {
            Some(discovery(&[1]))
        }
        fn idempotency_key(&self) -> &str {
            "another"
        }
    }

    #[tokio::test]
    async fn a_record_whose_part_has_another_key_is_rejected() {
        let (sender, received) = sender_answering(200, None);
        assert_eq!(
            sender.send(&MiskeyedRecord).await,
            Err(SendError::Rejected(format!(
                "its part has the key {DISCOVERY_KEY}, not the record's"
            )))
        );
        assert!(received.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn a_sender_rejects_another_capabilitys_record() {
        let (mut sender, received) = sender_answering(200, None);
        sender.capability = Capability::SecretsManager;
        let result = sender.send(&FakeRecord).await;
        assert!(
            matches!(&result, Err(SendError::Rejected(why)) if why.contains("can't go through")),
            "{result:?}"
        );
        assert!(received.lock().unwrap().is_none());
    }

    #[test]
    fn each_record_type_has_one_consent() {
        use Capability::{Acm, SecretsManager};
        use PayloadType::{CertAutomation, CertDiscovery, MetricsBatch};
        let sm = TelemetryConfig {
            secrets_manager_enabled: true,
            ..TelemetryConfig::default()
        };
        let acm = TelemetryConfig {
            acm_enabled: true,
            ..TelemetryConfig::default()
        };
        let discovery = TelemetryConfig {
            acm_discovery_enabled: true,
            ..TelemetryConfig::default()
        };
        // Each record type and the one setting that consents to it, if any.
        let cases = [
            (SecretsManager, MetricsBatch, Some(&sm)),
            (SecretsManager, CertDiscovery, None),
            (SecretsManager, CertAutomation, None),
            (Acm, MetricsBatch, Some(&acm)),
            (Acm, CertDiscovery, Some(&discovery)),
            (Acm, CertAutomation, Some(&acm)),
        ];
        for (capability, payload_type, consenting) in cases {
            for settings in [&sm, &acm, &discovery] {
                assert_eq!(
                    consented(settings, capability, payload_type),
                    consenting == Some(settings),
                    "{capability:?} {payload_type:?} with {settings:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn a_sender_rejects_a_record_type_the_customer_hasnt_consented_to() {
        let acm_only = TelemetryConfig {
            acm_enabled: true,
            ..TelemetryConfig::default()
        };
        for delivery in [Delivery::Send, Delivery::DryRun, Delivery::HeldBack] {
            let (mut sender, received) = sender_answering(200, None);
            sender.consent = acm_only.clone();
            sender.delivery = delivery;
            let result = sender.send(&FakeRecord).await;
            assert!(
                matches!(&result, Err(SendError::Rejected(why)) if why.contains("cert_discovery")),
                "{delivery:?}: {result:?}"
            );
            assert!(received.lock().unwrap().is_none(), "{delivery:?}");
        }

        let (mut sender, received) = sender_answering(200, None);
        sender.consent = TelemetryConfig {
            acm_discovery_enabled: true,
            ..TelemetryConfig::default()
        };
        assert_eq!(sender.send(&FakeRecord).await, Ok(()));
        assert!(received.lock().unwrap().is_some());
    }

    #[test]
    fn a_sender_encodes_cbor_and_a_dry_run_json() {
        let request = fake_request();
        let cbor = to_cbor(&request).unwrap();
        let json = serde_json::to_vec(&request).unwrap();
        for (delivery, encoded) in [
            (Delivery::Send, &cbor),
            (Delivery::HeldBack, &cbor),
            (Delivery::DryRun, &json),
        ] {
            let (mut sender, _) = sender_answering(200, None);
            sender.delivery = delivery;
            assert_eq!(sender.encode(&request).unwrap(), *encoded, "{delivery:?}");
        }
    }

    #[tokio::test]
    async fn a_record_without_a_request_part_is_rejected_but_a_dry_run_logs_it() {
        for delivery in [Delivery::Send, Delivery::HeldBack] {
            let (mut sender, received) = sender_answering(200, None);
            sender.delivery = delivery;
            assert_eq!(
                sender.send(&JsonOnlyRecord).await,
                Err(SendError::Rejected(
                    "cert_discovery records aren't in the request's shape yet".to_string()
                )),
                "{delivery:?}"
            );
            assert!(received.lock().unwrap().is_none(), "{delivery:?}");
        }
        let (mut sender, _) = sender_answering(200, None);
        sender.delivery = Delivery::DryRun;
        assert_eq!(sender.send(&JsonOnlyRecord).await, Ok(()));
    }

    #[tokio::test]
    async fn a_dry_run_or_held_back_sender_sends_nothing() {
        for delivery in [Delivery::DryRun, Delivery::HeldBack] {
            let (mut sender, received) = sender_answering(500, None);
            sender.delivery = delivery;
            assert_eq!(sender.send(&FakeRecord).await, Ok(()), "{delivery:?}");
            assert!(received.lock().unwrap().is_none(), "{delivery:?}");
        }
    }

    #[tokio::test]
    async fn a_record_whose_request_is_over_the_size_limit_is_rejected_unsent() {
        // A leaf and a 5-certificate chain, the model's most, fit in a
        // request even as JSON's base64.
        let (mut sender, received) = sender_answering(200, None);
        assert_eq!(sender.send(&SizedRecord(&[6])).await, Ok(()));
        assert!(received.lock().unwrap().take().is_some());
        sender.delivery = Delivery::DryRun;
        assert_eq!(sender.send(&SizedRecord(&[6])).await, Ok(()));

        for delivery in [Delivery::Send, Delivery::DryRun, Delivery::HeldBack] {
            let (mut sender, received) = sender_answering(200, None);
            sender.delivery = delivery;
            let result = sender.send(&SizedRecord(&[6, 6, 6])).await;
            assert!(
                matches!(result, Err(SendError::Rejected(_))),
                "{delivery:?}"
            );
            assert!(received.lock().unwrap().is_none(), "{delivery:?}");
        }
    }

    #[tokio::test]
    async fn a_custom_endpoint_keeps_the_request_path_and_signs_its_host() {
        let (sender, received) = sender_answering(200, Some("https://localhost:8443/"));
        sender.send(&FakeRecord).await.unwrap();
        let request = received.lock().unwrap().take().unwrap();
        assert_eq!(
            request.uri(),
            "https://localhost:8443/service/AWSWorkloadTelemetryService/operation/PutCertificateTelemetry"
        );
        let authorization = request.headers().get("authorization").unwrap();
        assert!(
            authorization.contains("SignedHeaders=accept;content-length;content-type;host;"),
            "{authorization}"
        );
    }

    #[derive(Debug)]
    struct RefusingService;

    impl HttpConnector for RefusingService {
        fn call(&self, _request: HttpRequest) -> HttpConnectorFuture {
            HttpConnectorFuture::ready(Err(ConnectorError::io("connection refused".into())))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_connection_failure_is_transient() {
        let (service, _) = sender_answering(200, None);
        let sender = TelemetrySender {
            connector: SharedHttpConnector::new(RefusingService),
            ..service
        };
        let result = sender.send(&FakeRecord).await;
        assert!(
            matches!(&result, Err(SendError::Transient(why)) if why.starts_with("could not reach")),
            "{result:?}"
        );
    }

    #[derive(Debug)]
    struct MissingCredentials;

    impl ProvideCredentials for MissingCredentials {
        fn provide_credentials<'a>(&'a self) -> future::ProvideCredentials<'a>
        where
            Self: 'a,
        {
            future::ProvideCredentials::ready(Err(CredentialsError::not_loaded("no credentials")))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn credentials_that_fail_to_load_are_transient() {
        let (service, received) = sender_answering(200, None);
        let sender = TelemetrySender {
            credentials: SharedCredentialsProvider::new(MissingCredentials),
            ..service
        };
        let result = sender.send(&FakeRecord).await;
        assert!(
            matches!(&result, Err(SendError::Transient(why)) if why.starts_with("could not load AWS credentials")),
            "{result:?}"
        );
        assert!(received.lock().unwrap().is_none());
    }

    #[derive(Debug)]
    struct HangingCredentials;

    impl ProvideCredentials for HangingCredentials {
        fn provide_credentials<'a>(
            &'a self,
        ) -> aws_credential_types::provider::future::ProvideCredentials<'a>
        where
            Self: 'a,
        {
            aws_credential_types::provider::future::ProvideCredentials::new(std::future::pending())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_attempt_whose_credentials_never_load_is_transient_after_the_timeout() {
        let (service, _) = sender_answering(200, None);
        let sender = TelemetrySender {
            credentials: SharedCredentialsProvider::new(HangingCredentials),
            ..service
        };
        let started = tokio::time::Instant::now();
        let result = sender.attempt(&Bytes::from_static(b"{}")).await;
        assert!(
            matches!(
                result,
                Err(Failure {
                    error: SendError::Transient(_),
                    ..
                })
            ),
            "{result:?}"
        );
        assert_eq!(started.elapsed(), SEND_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn an_attempt_without_a_response_is_transient_after_the_timeout() {
        let sender = TelemetrySender::with_connector(
            Capability::Acm,
            consent_to_all(),
            SharedHttpConnector::new(NeverClient::new()),
            credentials(),
            "us-west-2",
            super::endpoint("us-west-2", false, None),
            Delivery::Send,
        );
        let started = tokio::time::Instant::now();
        let result = sender.attempt(&Bytes::from_static(b"{}")).await;
        assert!(
            matches!(
                result,
                Err(Failure {
                    error: SendError::Transient(_),
                    ..
                })
            ),
            "{result:?}"
        );
        assert_eq!(started.elapsed(), SEND_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn a_request_to_a_service_that_never_answers_fails_after_three_timeouts() {
        let sender = TelemetrySender::with_connector(
            Capability::Acm,
            consent_to_all(),
            SharedHttpConnector::new(NeverClient::new()),
            credentials(),
            "us-west-2",
            super::endpoint("us-west-2", false, None),
            Delivery::Send,
        );
        let started = tokio::time::Instant::now();
        // Bounded, so a send that blocks fails here instead of hanging the test.
        let result = tokio::time::timeout(
            Duration::from_secs(60),
            sender.send_request(&fake_request(), "key"),
        )
        .await
        .expect("the send returns");
        assert!(matches!(result, Err(SendError::Transient(_))), "{result:?}");
        // Three timeouts, and the waits of up to 1 s and 2 s between them.
        let elapsed = started.elapsed();
        assert!(
            elapsed >= SEND_TIMEOUT * 3 && elapsed <= SEND_TIMEOUT * 3 + Duration::from_secs(3),
            "{elapsed:?}"
        );
    }

    #[test]
    fn the_retry_delay_doubles_from_1_s() {
        assert_eq!(retry_delay(0), Duration::from_secs(1));
        assert_eq!(retry_delay(1), Duration::from_secs(2));
    }

    #[test]
    fn a_jittered_delay_is_anywhere_up_to_the_delay() {
        let delay = Duration::from_secs(2);
        let jittered: Vec<Duration> = (0..1_000).map(|_| jittered(delay)).collect();
        assert!(jittered.iter().all(|wait| *wait < delay));
        assert!(jittered.iter().any(|wait| *wait < delay / 4));
        assert!(jittered.iter().any(|wait| *wait > delay * 3 / 4));
    }

    fn scripted_sender(statuses: &[u16]) -> (TelemetrySender, Arc<Mutex<Vec<Received>>>) {
        let (service, received) = ScriptedService::answering(statuses);
        (
            TelemetrySender::for_tests(SharedHttpConnector::new(service), consent_to_all()),
            received,
        )
    }

    #[tokio::test(start_paused = true)]
    async fn a_transient_failure_is_retried_after_a_jittered_wait() {
        // Over many sends, each retry's wait stays within its delay and
        // sometimes comes close to it.
        let mut longest = [Duration::ZERO; SEND_ATTEMPTS as usize - 1];
        for _ in 0..20 {
            let (sender, received) = scripted_sender(&[503]);
            let result = sender.send(&FakeRecord).await;
            assert!(matches!(result, Err(SendError::Transient(_))), "{result:?}");

            let arrivals: Vec<_> = received.lock().unwrap().iter().map(|(at, _)| *at).collect();
            assert_eq!(arrivals.len(), SEND_ATTEMPTS as usize);
            for (retry, pair) in (0u32..).zip(arrivals.windows(2)) {
                let wait = pair[1] - pair[0];
                // Tokio rounds a timer up to the millisecond, so a wait can
                // reach the delay itself.
                assert!(wait <= retry_delay(retry), "retry {retry} waited {wait:?}");
                longest[retry as usize] = longest[retry as usize].max(wait);
            }
        }
        for (retry, longest) in (0u32..).zip(longest) {
            assert!(
                longest > retry_delay(retry) / 2,
                "retry {retry} waited at most {longest:?}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_retries_stop_at_a_success_or_a_rejection() {
        let (sender, received) = scripted_sender(&[503, 200]);
        assert_eq!(sender.send(&FakeRecord).await, Ok(()));
        assert_eq!(received.lock().unwrap().len(), 2);

        let (sender, received) = scripted_sender(&[400]);
        let result = sender.send(&FakeRecord).await;
        assert!(matches!(result, Err(SendError::Rejected(_))), "{result:?}");
        assert_eq!(received.lock().unwrap().len(), 1);
    }

    /// Hands out credentials that expire `lifetime` from now, or never, and
    /// counts how often it is asked.
    #[derive(Debug)]
    struct CountingCredentials {
        lifetime: Option<Duration>,
        loads: Arc<Mutex<usize>>,
    }

    impl ProvideCredentials for CountingCredentials {
        fn provide_credentials<'a>(&'a self) -> future::ProvideCredentials<'a>
        where
            Self: 'a,
        {
            *self.loads.lock().unwrap() += 1;
            let expiry = self.lifetime.map(|lifetime| SystemTime::now() + lifetime);
            future::ProvideCredentials::ready(Ok(Credentials::new(
                "AKIDEXAMPLE",
                "secret",
                None,
                expiry,
                "test",
            )))
        }
    }

    fn sender_counting_loads(lifetime: Option<Duration>) -> (TelemetrySender, Arc<Mutex<usize>>) {
        let loads = Arc::new(Mutex::new(0));
        let (service, _) = sender_answering(200, None);
        let sender = TelemetrySender {
            credentials: SharedCredentialsProvider::new(CountingCredentials {
                lifetime,
                loads: Arc::clone(&loads),
            }),
            ..service
        };
        (sender, loads)
    }

    #[tokio::test]
    async fn credentials_are_loaded_once_and_reused() {
        for lifetime in [None, Some(Duration::from_secs(3600))] {
            let (sender, loads) = sender_counting_loads(lifetime);
            sender.send(&FakeRecord).await.unwrap();
            sender.send(&FakeRecord).await.unwrap();
            assert_eq!(*loads.lock().unwrap(), 1, "lifetime {lifetime:?}");
        }
    }

    #[tokio::test]
    async fn credentials_about_to_expire_are_reloaded() {
        let (sender, loads) = sender_counting_loads(Some(CREDENTIALS_RELOAD_BEFORE_EXPIRY / 2));
        sender.send(&FakeRecord).await.unwrap();
        sender.send(&FakeRecord).await.unwrap();
        assert_eq!(*loads.lock().unwrap(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn credentials_that_fail_to_load_are_not_cached() {
        let loads = Arc::new(Mutex::new(0));
        let (service, received) = sender_answering(200, None);
        let sender = TelemetrySender {
            credentials: SharedCredentialsProvider::new(MissingCredentials),
            ..service
        };
        assert!(sender.send(&FakeRecord).await.is_err());
        let sender = TelemetrySender {
            credentials: SharedCredentialsProvider::new(CountingCredentials {
                lifetime: None,
                loads: Arc::clone(&loads),
            }),
            ..sender
        };
        sender.send(&FakeRecord).await.unwrap();
        assert_eq!(*loads.lock().unwrap(), 1);
        assert!(received.lock().unwrap().is_some());
    }

    #[tokio::test]
    async fn clones_share_the_cached_credentials() {
        let (sender, loads) = sender_counting_loads(None);
        let clone = sender.clone();
        sender.send(&FakeRecord).await.unwrap();
        clone.send(&FakeRecord).await.unwrap();
        assert_eq!(*loads.lock().unwrap(), 1);
    }
}
