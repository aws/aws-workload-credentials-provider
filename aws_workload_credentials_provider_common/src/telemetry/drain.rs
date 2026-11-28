//! The drain: one background task per process that sends queued telemetry
//! records on a timer, so the code that produces a record never waits on the
//! network.
//!
//! A capability pushes records into the [`TelemetryQueue`]. About once an hour
//! the task sends them in queue order through the process's
//! [`TelemetrySender`]. The interval is drawn once per process, within 20% of
//! an hour, so providers that start together drift apart. Automation records
//! share a request, up to [`MAX_ENTRIES`] and [`MAX_REQUEST_BYTES`]; a
//! discovery batch gets a request of its own. A request that still fails after
//! the sender's retries means the service is likely down, so it ends the flush.
//! It goes to the back of the queue unchanged, so it doesn't block the others.
//! On shutdown the task tries once more to send what is queued and ends within
//! 5 seconds.
//!
//! Records live only in memory. Each is weighed by the size of its own request
//! as the sender encodes it: CBOR, or JSON in a dry run. The queue holds at
//! most 1,000 records or failed requests and 4 MiB, and drops the oldest when
//! full. Every drop is logged and counted by reason; see
//! [`TelemetryQueue::take_drop_metrics`].

use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use rand::RngExt;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::metrics::{Label, LabeledCounter, Metric};
use super::payload::{TelemetryRecord, MAX_REQUEST_BYTES};
use super::queue::BoundedQueue;
use super::request::{
    Automation, CertificateTelemetry, Entry, PutCertificateTelemetryInput, RequestPart, MAX_ENTRIES,
};
use super::sender::{Refused, SendError, TelemetrySender};

/// Time between flushes, before the per-process jitter.
const FLUSH_INTERVAL: Duration = Duration::from_secs(3600);

/// How far a process's flush interval may differ from [`FLUSH_INTERVAL`], as a
/// fraction of it.
const FLUSH_INTERVAL_JITTER: f64 = 0.2;

/// Longest the final flush on shutdown takes.
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(5);

/// Most items the queue holds. An item is a record or a failed request of up
/// to [`MAX_ENTRIES`] records.
const MAX_QUEUED: NonZeroUsize = NonZeroUsize::new(1_000).unwrap();

/// Most bytes the queue holds, 4 MiB, counting each record as the size of its
/// own request. That is about 700 automation records of about 6 KB, or 16 at
/// [`MAX_REQUEST_BYTES`].
const MAX_QUEUED_BYTES: NonZeroUsize = NonZeroUsize::new(4_194_304).unwrap();

/// Name of the metric that counts dropped records, by [`DropReason`].
const DROPPED_METRIC: &str = "events_dropped";

/// Why the drain dropped a record: the `reason` dimension of
/// [`DROPPED_METRIC`].
#[derive(Debug, Clone, Copy)]
enum DropReason {
    /// Evicted from a full queue.
    QueueFull,
    /// The sender or the service rejected it, or it can't be serialized, so
    /// retrying would fail the same way.
    Rejected,
    /// Its own request, as the sender encodes it, would be over
    /// [`MAX_REQUEST_BYTES`].
    TooLarge,
    /// Still queued, or not sent, when the final flush ended.
    UnsentAtShutdown,
    /// Pushed after the final flush, so nothing would send it.
    PushedAfterShutdown,
}

impl Label for DropReason {
    const KEY: &'static str = "reason";
    const ALL: &'static [Self] = &[
        Self::QueueFull,
        Self::Rejected,
        Self::TooLarge,
        Self::UnsentAtShutdown,
        Self::PushedAfterShutdown,
    ];

    fn index(self) -> usize {
        self as usize
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::QueueFull => "queue_full",
            Self::Rejected => "rejected",
            Self::TooLarge => "too_large",
            Self::UnsentAtShutdown => "unsent_at_shutdown",
            Self::PushedAfterShutdown => "pushed_after_shutdown",
        }
    }
}

/// A queued record: its part of a request, taken at push so the queue holds
/// nothing of the producer's.
struct QueuedRecord {
    part: RequestPart,
    /// Size of its own request as the sender encodes it.
    bytes: usize,
}

/// A request built from queued records, kept until it is sent or rejected, so
/// a request that fails is sent again unchanged.
struct Pending {
    request: PutCertificateTelemetryInput,
    /// Names the request in logs: its idempotency key and how many more
    /// records it holds.
    label: String,
    records: usize,
    /// Sum of its records' sizes. At least the request's size, since the
    /// request carries the shared fields once.
    bytes: usize,
}

impl Pending {
    /// The request for `first` and the automation records in `rest`, with
    /// `first`'s idempotency key.
    fn new(first: QueuedRecord, rest: Vec<QueuedRecord>) -> Self {
        let records = 1 + rest.len();
        let label = match rest.len() {
            0 => first.part.idempotency_key.clone(),
            more => format!("{} and {more} more", first.part.idempotency_key),
        };
        let bytes = first.bytes + rest.iter().map(|record| record.bytes).sum::<usize>();
        let telemetry = match first.part.entry {
            Entry::Discovery(discovery) => CertificateTelemetry::Discovery(discovery),
            Entry::Automation(record) => {
                let mut records = vec![record];
                // `rest` holds only automation records.
                for queued in rest {
                    if let Entry::Automation(record) = queued.part.entry {
                        records.push(record);
                    }
                }
                CertificateTelemetry::Automation(Automation { records })
            }
        };
        Self {
            request: first
                .part
                .header
                .request(telemetry, first.part.idempotency_key),
            records,
            label,
            bytes,
        }
    }
}

/// A queue item: a record, or a request that failed after the sender's
/// retries and is sent again unchanged. Boxed so each queue slot is a pointer.
enum Queued {
    Record(Box<QueuedRecord>),
    Request(Box<Pending>),
}

impl Queued {
    fn records(&self) -> usize {
        match self {
            Self::Record(_) => 1,
            Self::Request(pending) => pending.records,
        }
    }

    fn bytes(&self) -> usize {
        match self {
            Self::Record(record) => record.bytes,
            Self::Request(pending) => pending.bytes,
        }
    }
}

/// What a [`TelemetryQueue`] and its drain share.
struct Shared {
    queue: BoundedQueue<Queued>,
    /// Set before the final flush; later pushes are dropped.
    /// [`TelemetryQueue::push`] queues under this lock and the drain sets it
    /// under the lock, so each record is either in the final flush or dropped.
    closed: Mutex<bool>,
    /// Records dropped since the last [`TelemetryQueue::take_drop_metrics`].
    dropped: LabeledCounter<DropReason>,
    /// Records evicted since the last eviction WARN. The drain logs it once
    /// per flush, not on each push.
    evicted_unlogged: AtomicU64,
    /// Sends the queued records. [`TelemetryQueue::push`] also uses it to
    /// filter records and to weigh each one.
    sender: TelemetrySender,
}

impl Shared {
    /// Queues `item`, and counts the records the queue evicts to make room
    /// for it; [`Self::log_evictions`] logs them.
    fn enqueue(&self, item: Queued) {
        let evicted: usize = self.queue.push(item).iter().map(Queued::records).sum();
        if evicted > 0 {
            self.dropped.add(DropReason::QueueFull, evicted as u64);
            self.evicted_unlogged
                .fetch_add(evicted as u64, Ordering::Relaxed);
        }
    }

    /// Logs, once, the records evicted since the last call.
    fn log_evictions(&self) {
        let evicted = self.evicted_unlogged.swap(0, Ordering::Relaxed);
        if evicted > 0 {
            log::warn!("Telemetry: dropped {evicted} record(s) because the queue was full");
        }
    }

    /// Counts and logs a request the sender or the service rejected.
    fn count_rejected(&self, pending: &Pending, why: &str) {
        self.dropped
            .add(DropReason::Rejected, pending.records as u64);
        log::warn!(
            "Telemetry: request {} rejected and its {} record(s) dropped: {why}",
            pending.label,
            pending.records
        );
    }

    /// `record` as the queue holds it, or why it is dropped. A record the
    /// sender only logs, in a dry run, gives `None`.
    fn queued(
        &self,
        record: &dyn TelemetryRecord,
    ) -> Result<Option<QueuedRecord>, (DropReason, String)> {
        let rejected = |why| (DropReason::Rejected, why);
        let part = self
            .sender
            .part_to_send(record)
            .map_err(|refused| match refused {
                Refused::TooLarge(why) => (DropReason::TooLarge, why),
                Refused::Rejected(why) => rejected(why),
            })?;
        let Some(part) = part else {
            return Ok(None);
        };
        let bytes = self
            .weigh(&part)
            .map_err(|err| rejected(format!("could not serialize its request: {err}")))?;
        if bytes > MAX_REQUEST_BYTES {
            return Err((
                DropReason::TooLarge,
                format!("its request is {bytes} bytes, over the {MAX_REQUEST_BYTES}-byte limit"),
            ));
        }
        Ok(Some(QueuedRecord { part, bytes }))
    }

    /// The size of `part`'s request of its own as the sender encodes it.
    fn weigh(&self, part: &RequestPart) -> Result<usize, String> {
        let body = self.sender.encode(&part.request())?;
        Ok(body.len())
    }

    /// The next request: the front item if it is a failed request, as it is,
    /// or else a new one from the oldest records. A discovery batch goes alone. An automation record
    /// takes the automation records right after it with the same identity, up
    /// to [`MAX_ENTRIES`] records and [`MAX_REQUEST_BYTES`] in all.
    fn next_request(&self) -> Option<Pending> {
        let first = match self.queue.drain_up_to(1).pop()? {
            Queued::Request(pending) => return Some(*pending),
            Queued::Record(record) => *record,
        };
        let mut rest = Vec::new();
        if matches!(first.part.entry, Entry::Automation(_)) {
            let mut bytes = first.bytes;
            while rest.len() + 1 < MAX_ENTRIES {
                let Some(record) = self.queue.take_front(|next| match next {
                    Queued::Record(record)
                        if matches!(record.part.entry, Entry::Automation(_))
                            && record.part.header == first.part.header
                            && bytes + record.bytes <= MAX_REQUEST_BYTES =>
                    {
                        Ok(*record)
                    }
                    other => Err(other),
                }) else {
                    break;
                };
                bytes += record.bytes;
                rest.push(record);
            }
        }
        Some(Pending::new(first, rest))
    }
}

/// Where a capability puts records for the drain to send. Clones share the
/// same queue.
#[derive(Clone)]
pub struct TelemetryQueue(Arc<Shared>);

impl TelemetryQueue {
    /// Queues `record` for the next flush. Never waits on the network.
    ///
    /// A record of a type the customer hasn't consented to is skipped and not
    /// counted as a drop. A full queue drops its oldest records. A record the
    /// sender won't send, one too large for its own request, and one pushed
    /// after shutdown are dropped without evicting others. Every drop is logged
    /// and counted. In a dry run, a record without a request part is logged as
    /// JSON right away, not queued.
    pub fn push(&self, record: &dyn TelemetryRecord) {
        if !self.0.sender.consents_to(record.payload_type()) {
            log::debug!(
                "Telemetry: {} records aren't consented to, so record {} isn't queued",
                record.payload_type().as_str(),
                record.idempotency_key()
            );
            return;
        }
        let queued = match self.0.queued(record) {
            Ok(Some(queued)) => queued,
            Ok(None) => return,
            Err((reason, why)) => {
                self.0.dropped.incr(reason);
                log::warn!(
                    "Telemetry: record {} dropped: {why}",
                    record.idempotency_key()
                );
                return;
            }
        };
        {
            let closed = self.0.closed.lock().unwrap_or_else(PoisonError::into_inner);
            if !*closed {
                self.0.enqueue(Queued::Record(Box::new(queued)));
                return;
            }
        }
        self.0.dropped.incr(DropReason::PushedAfterShutdown);
        log::warn!(
            "Telemetry: record {} pushed after shutdown and dropped",
            queued.part.idempotency_key
        );
    }

    /// Returns the records dropped since the last call, as one `events_dropped`
    /// counter per `reason`, zeros included, and resets the counts.
    ///
    /// `unsent_at_shutdown` and `pushed_after_shutdown` are counted after the
    /// drain's last send, so no request carries them; their WARN logs are the
    /// only record.
    pub fn take_drop_metrics(&self) -> Vec<Metric> {
        self.0.dropped.take_metrics(DROPPED_METRIC)
    }
}

/// Starts the drain for the process's `sender`. It flushes about once an hour
/// until `token` is cancelled, then makes a final attempt at what is queued
/// and ends. Await the handle on shutdown so the final flush runs before the
/// process exits.
///
/// Cancel `token` only after everything that pushes records has stopped: a
/// record pushed after the final flush is dropped.
pub fn spawn(
    sender: TelemetrySender,
    token: CancellationToken,
) -> (TelemetryQueue, JoinHandle<()>) {
    spawn_with_interval(sender, token, flush_interval())
}

/// [`FLUSH_INTERVAL`], moved by a random amount of up to
/// [`FLUSH_INTERVAL_JITTER`] of it either way.
fn flush_interval() -> Duration {
    let jitter = FLUSH_INTERVAL_JITTER;
    FLUSH_INTERVAL.mul_f64(rand::rng().random_range(1.0 - jitter..1.0 + jitter))
}

fn spawn_with_interval(
    sender: TelemetrySender,
    token: CancellationToken,
    interval: Duration,
) -> (TelemetryQueue, JoinHandle<()>) {
    let shared = Arc::new(Shared {
        queue: BoundedQueue::new(MAX_QUEUED, MAX_QUEUED_BYTES, Queued::bytes),
        closed: Mutex::new(false),
        dropped: LabeledCounter::default(),
        evicted_unlogged: AtomicU64::new(0),
        sender,
    });
    let task = tokio::spawn(run(Arc::clone(&shared), token, interval));
    (TelemetryQueue(shared), task)
}

async fn run(shared: Arc<Shared>, token: CancellationToken, interval: Duration) {
    loop {
        tokio::select! {
            () = token.cancelled() => break,
            () = tokio::time::sleep(interval) => flush(&shared, &token).await,
        }
    }

    *shared.closed.lock().unwrap_or_else(PoisonError::into_inner) = true;
    // The deadline, not a token, ends the final flush, so a request cut off
    // mid-send stays in `in_flight` and is counted below.
    let mut in_flight = None;
    let never_cancelled = CancellationToken::new();
    let final_flush = send_queued(&shared, &mut in_flight, &never_cancelled);
    let _ = tokio::time::timeout(SHUTDOWN_DEADLINE, final_flush).await;
    shared.log_evictions();
    let queued: usize = shared.queue.drain().iter().map(Queued::records).sum();
    let left = in_flight.map_or(0, |pending| pending.records) + queued;
    shared
        .dropped
        .add(DropReason::UnsentAtShutdown, left as u64);
    if left > 0 {
        log::warn!("Telemetry: dropped {left} record(s) not sent before shutdown");
    }
}

/// Sends what is queued; see [`send_queued`].
async fn flush(shared: &Shared, token: &CancellationToken) {
    shared.log_evictions();
    if let Err(why) = send_queued(shared, &mut None, token).await {
        log::warn!("Telemetry: {why}; trying it again at the next flush");
    }
}

/// Sends what is queued, in queue order. Stops at a request that still fails
/// after the sender's retries, or as soon as `token` is cancelled, even
/// mid-send, and puts that request at the back of the queue. The request
/// being sent stays in `in_flight`, so a timeout that cuts it short can't
/// lose it.
async fn send_queued(
    shared: &Shared,
    in_flight: &mut Option<Pending>,
    token: &CancellationToken,
) -> Result<(), String> {
    loop {
        *in_flight = shared.next_request();
        let Some(pending) = in_flight.as_ref() else {
            return Ok(());
        };
        let result = tokio::select! {
            biased;
            () = token.cancelled() => Err(SendError::Transient("shutting down".to_string())),
            result = shared.sender.send_request(&pending.request, &pending.label) => result,
        };
        match result {
            Ok(()) => {}
            Err(SendError::Rejected(why)) => shared.count_rejected(pending, &why),
            Err(SendError::Transient(why)) => {
                let why = format!("request {} not sent: {why}", pending.label);
                if let Some(pending) = in_flight.take() {
                    shared.enqueue(Queued::Request(Box::new(pending)));
                }
                return Err(why);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::TelemetryConfig;
    use crate::telemetry::metrics::MetricValue;
    use crate::telemetry::payload::{
        Blob, Capability, DeploymentType, PayloadEnvelope, PayloadType,
    };
    use crate::telemetry::request::{
        AutomationRecord, AutomationResult, AutomationSuccess, Discovery, Observation, ProbeOutcome,
    };
    use crate::telemetry::sender::testing::{Received, ScriptedService};
    use crate::telemetry::sender::SEND_ATTEMPTS;
    use aws_smithy_http_client::test_util::NeverClient;
    use aws_smithy_runtime_api::client::http::SharedHttpConnector;
    use serde::Deserialize;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// An envelope from `host` for a `payload_type` record, with a unique
    /// idempotency key.
    fn envelope(host: &str, payload_type: PayloadType) -> PayloadEnvelope {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        PayloadEnvelope::new(
            Capability::Acm,
            payload_type,
            SEQUENCE.fetch_add(1, Ordering::Relaxed),
            0,
            host,
            "boot-1",
            "4.0.0",
            "us-west-2",
            DeploymentType::Ec2,
        )
        .unwrap()
    }

    /// `n` certificates of the model's largest size, as a leaf and its chain.
    fn largest_certificates(n: usize) -> (Option<Blob>, Option<Vec<Blob>>) {
        let certificate = Blob(vec![0x30; 16_384]);
        (
            (n > 0).then(|| certificate.clone()),
            (n > 1).then(|| vec![certificate; n - 1]),
        )
    }

    /// A named record. An automation record's certificate ARN ends in the
    /// name; a discovery batch's SNI is the name.
    struct FakeRecord {
        name: String,
        part: RequestPart,
    }

    impl FakeRecord {
        /// A small automation record from host `i-1`.
        fn new(name: impl Into<String>) -> Self {
            Self::automation(name, "i-1", 0)
        }

        /// An automation record from `host` with `certificates` certificates.
        fn automation(name: impl Into<String>, host: &str, certificates: usize) -> Self {
            let name = name.into();
            let (certificate_der, chain_der) = largest_certificates(certificates);
            let record = AutomationRecord {
                certificate_arn: format!("arn:aws:acm:us-west-2:111122223333:certificate/{name}"),
                event_time: 1_793_315_962_000,
                result: AutomationResult::Success(AutomationSuccess::Deployed),
                certificate_der,
                chain_der,
                refresh_duration_milliseconds: None,
                consecutive_failures: None,
                configured_certificate_count: None,
                refresh_cycle_id: None,
                cert_index: None,
            };
            Self {
                part: RequestPart::new(
                    &envelope(host, PayloadType::CertAutomation),
                    Entry::Automation(record),
                ),
                name,
            }
        }

        /// A discovery batch with one observation per entry of
        /// `certificates`, each with that many certificates, at least one.
        fn discovery(name: &str, certificates: &[usize]) -> Self {
            let observations = certificates
                .iter()
                .map(|n| {
                    let (certificate_der, chain_der) = largest_certificates(*n);
                    Observation {
                        port: 443,
                        sni: Some(name.to_string()),
                        outcome: ProbeOutcome::Success,
                        certificate_der,
                        chain_der,
                        mtls_detected: None,
                        tls_version: None,
                        cipher_suite: None,
                        handshake_signature_scheme: None,
                        key_algorithm: None,
                    }
                })
                .collect();
            let discovery = Discovery {
                scan_time: 1_793_315_962_000,
                scan_id: format!("i-1:{name}"),
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
            Self {
                name: name.to_string(),
                part: RequestPart::new(
                    &envelope("i-1", PayloadType::CertDiscovery),
                    Entry::Discovery(discovery),
                ),
            }
        }
    }

    impl TelemetryRecord for FakeRecord {
        fn payload_type(&self) -> PayloadType {
            match self.part.entry {
                Entry::Discovery(_) => PayloadType::CertDiscovery,
                Entry::Automation(_) => PayloadType::CertAutomation,
            }
        }
        fn capability(&self) -> Capability {
            Capability::Acm
        }
        fn serialize(&self) -> Result<Vec<u8>, serde_json::Error> {
            serde_json::to_vec(&serde_json::json!({ "name": self.name }))
        }
        fn request_part(&self) -> Option<RequestPart> {
            Some(self.part.clone())
        }
        fn idempotency_key(&self) -> &str {
            &self.part.idempotency_key
        }
    }

    /// A record with JSON but no request part.
    struct JsonOnlyRecord;

    impl TelemetryRecord for JsonOnlyRecord {
        fn payload_type(&self) -> PayloadType {
            PayloadType::CertAutomation
        }
        fn capability(&self) -> Capability {
            Capability::Acm
        }
        fn serialize(&self) -> Result<Vec<u8>, serde_json::Error> {
            serde_json::to_vec(&serde_json::json!({ "key": "json-only" }))
        }
        fn idempotency_key(&self) -> &str {
            "json-only"
        }
    }

    /// How many automation records with `certificates` certificates fit in
    /// the queue's byte limit.
    fn records_that_fit(shared: &Shared, certificates: usize) -> usize {
        let part = FakeRecord::automation("0", "i-1", certificates).part;
        // The limit is 4 MiB.
        4_194_304 / shared.weigh(&part).unwrap()
    }

    struct Drain {
        queue: TelemetryQueue,
        task: JoinHandle<()>,
        token: CancellationToken,
        received: Arc<Mutex<Vec<Received>>>,
    }

    impl Drain {
        /// The names of the records in each request the service received.
        fn sent(&self) -> Vec<Vec<String>> {
            sent_names(&self.received)
        }

        /// The names of every record the service received, in order.
        fn sent_records(&self) -> Vec<String> {
            self.sent().concat()
        }
    }

    /// The names of the records in each request the service received, in
    /// order.
    fn sent_names(received: &Mutex<Vec<Received>>) -> Vec<Vec<String>> {
        #[derive(Deserialize)]
        struct Request {
            telemetry: Telemetry,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        enum Telemetry {
            Discovery { observations: Vec<Observed> },
            Automation { records: Vec<Automated> },
        }
        #[derive(Deserialize)]
        struct Observed {
            sni: String,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Automated {
            certificate_arn: String,
        }

        received
            .lock()
            .unwrap()
            .iter()
            .map(|(_, body)| {
                let request: Request = ciborium::from_reader(&body[..]).unwrap();
                match request.telemetry {
                    Telemetry::Discovery { observations } => observations
                        .into_iter()
                        .map(|observation| observation.sni)
                        .collect(),
                    Telemetry::Automation { records } => records
                        .into_iter()
                        .map(|record| {
                            let (_, key) = record.certificate_arn.rsplit_once('/').unwrap();
                            key.to_string()
                        })
                        .collect(),
                }
            })
            .collect()
    }

    /// The `idempotencyKey` of each request the service received, in order.
    fn request_keys(received: &Mutex<Vec<Received>>) -> Vec<String> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Request {
            idempotency_key: String,
        }
        received
            .lock()
            .unwrap()
            .iter()
            .map(|(_, body)| {
                let request: Request = ciborium::from_reader(&body[..]).unwrap();
                request.idempotency_key
            })
            .collect()
    }

    /// Records dropped so far, by reason, leaving out zeros.
    fn dropped(queue: &TelemetryQueue) -> BTreeMap<&'static str, u64> {
        queue
            .take_drop_metrics()
            .iter()
            .filter_map(|metric| match metric.value() {
                MetricValue::Counter { value } if *value > 0 => {
                    assert_eq!(metric.name(), "events_dropped");
                    Some((metric.dimensions()["reason"], *value))
                }
                _ => None,
            })
            .collect()
    }

    /// Consent to every ACM record type.
    fn acm_consent() -> TelemetryConfig {
        TelemetryConfig {
            acm_enabled: true,
            acm_discovery_enabled: true,
            ..TelemetryConfig::default()
        }
    }

    fn drain_answering(statuses: &[u16]) -> Drain {
        let (service, received) = ScriptedService::answering(statuses);
        let token = CancellationToken::new();
        let sender = TelemetrySender::for_tests(SharedHttpConnector::new(service), acm_consent());
        let (queue, task) = spawn_with_interval(sender, token.clone(), FLUSH_INTERVAL);
        Drain {
            queue,
            task,
            token,
            received,
        }
    }

    fn drain_that_hangs() -> (TelemetryQueue, JoinHandle<()>, CancellationToken) {
        let token = CancellationToken::new();
        let sender =
            TelemetrySender::for_tests(SharedHttpConnector::new(NeverClient::new()), acm_consent());
        let (queue, task) = spawn_with_interval(sender, token.clone(), FLUSH_INTERVAL);
        (queue, task, token)
    }

    /// `names` as one request's record names.
    fn request(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| name.to_string()).collect()
    }

    /// The names "0" to `n - 1`.
    fn numbered(n: usize) -> Vec<String> {
        (0..n).map(|i| i.to_string()).collect()
    }

    #[test]
    fn the_flush_interval_is_within_20_percent_of_an_hour() {
        let intervals: Vec<Duration> = (0..1_000).map(|_| flush_interval()).collect();
        let hour = Duration::from_secs(3_600);
        assert!(intervals.iter().all(|interval| (Duration::from_secs(2_880)
            ..Duration::from_secs(4_320))
            .contains(interval)));
        assert!(intervals.iter().any(|interval| *interval < hour));
        assert!(intervals.iter().any(|interval| *interval > hour));
    }

    #[tokio::test(start_paused = true)]
    async fn drains_started_by_spawn_flush_at_different_times_within_20_percent_of_an_hour() {
        let started = tokio::time::Instant::now();
        let mut services = Vec::new();
        let mut queues = Vec::new();
        for _ in 0..10 {
            let (service, received) = ScriptedService::answering(&[200]);
            let sender =
                TelemetrySender::for_tests(SharedHttpConnector::new(service), acm_consent());
            let (queue, _task) = spawn(sender, CancellationToken::new());
            queue.push(&FakeRecord::new("a"));
            services.push(received);
            queues.push(queue);
        }

        tokio::time::sleep(FLUSH_INTERVAL.mul_f64(1.2) + Duration::from_secs(1)).await;
        let mut flushed_after = Vec::new();
        for received in &services {
            let received = received.lock().unwrap();
            assert_eq!(received.len(), 1);
            flushed_after.push(received[0].0 - started);
        }
        let window =
            FLUSH_INTERVAL.mul_f64(0.8)..=FLUSH_INTERVAL.mul_f64(1.2) + Duration::from_millis(1);
        assert!(
            flushed_after.iter().all(|after| window.contains(after)),
            "{flushed_after:?}"
        );
        assert!(
            flushed_after.iter().any(|after| *after != flushed_after[0]),
            "{flushed_after:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_queued_record_is_sent_at_the_next_flush() {
        let drain = drain_answering(&[200]);
        drain.queue.push(&FakeRecord::new("a"));

        tokio::time::sleep(FLUSH_INTERVAL - Duration::from_secs(1)).await;
        assert!(drain.sent().is_empty());

        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(drain.sent(), [request(&["a"])]);
        assert!(dropped(&drain.queue).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn automation_records_go_up_to_max_entries_to_a_request_in_queue_order() {
        let drain = drain_answering(&[200]);
        let keys = numbered(2 * MAX_ENTRIES + 1);
        let records: Vec<FakeRecord> = keys.iter().map(FakeRecord::new).collect();
        for record in &records {
            drain.queue.push(record);
        }

        tokio::time::sleep(FLUSH_INTERVAL + Duration::from_secs(5)).await;
        assert_eq!(
            drain.sent(),
            [
                &keys[..MAX_ENTRIES],
                &keys[MAX_ENTRIES..2 * MAX_ENTRIES],
                &keys[2 * MAX_ENTRIES..],
            ]
        );
        // Each request carries its first part's idempotency key.
        let first_keys: Vec<&str> = [0, MAX_ENTRIES, 2 * MAX_ENTRIES]
            .map(|i| records[i].part.idempotency_key.as_str())
            .to_vec();
        assert_eq!(request_keys(&drain.received), first_keys);
        assert!(dropped(&drain.queue).is_empty());
    }

    #[tokio::test]
    async fn a_request_is_named_by_its_first_parts_key_and_how_many_more() {
        let drain = drain_answering(&[200]);
        let records = ["a", "b", "c"].map(FakeRecord::new);
        drain.queue.push(&records[0]);
        let pending = drain.queue.0.next_request().unwrap();
        assert_eq!(pending.label, records[0].part.idempotency_key);

        drain.queue.push(&records[1]);
        drain.queue.push(&records[2]);
        let pending = drain.queue.0.next_request().unwrap();
        assert_eq!(
            pending.label,
            format!("{} and 1 more", records[1].part.idempotency_key)
        );

        let full: Vec<FakeRecord> = numbered(MAX_ENTRIES).iter().map(FakeRecord::new).collect();
        for record in &full {
            drain.queue.push(record);
        }
        let pending = drain.queue.0.next_request().unwrap();
        assert_eq!(
            pending.label,
            format!(
                "{} and {} more",
                full[0].part.idempotency_key,
                MAX_ENTRIES - 1
            )
        );
    }

    #[tokio::test(start_paused = true)]
    async fn automation_records_go_together_only_up_to_the_byte_limit() {
        let drain = drain_answering(&[200]);
        // Two records with 6 certificates each fit in one request; three
        // don't.
        for key in ["a", "b", "c"] {
            drain.queue.push(&FakeRecord::automation(key, "i-1", 6));
        }

        tokio::time::sleep(FLUSH_INTERVAL + Duration::from_secs(5)).await;
        assert_eq!(drain.sent(), [request(&["a", "b"]), request(&["c"])]);
        let sizes: Vec<usize> = drain
            .received
            .lock()
            .unwrap()
            .iter()
            .map(|(_, body)| body.len())
            .collect();
        assert!(sizes[0] <= MAX_REQUEST_BYTES, "{sizes:?}");
        assert!(sizes[0] + sizes[1] > MAX_REQUEST_BYTES, "{sizes:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_discovery_batch_and_another_identitys_records_get_requests_of_their_own() {
        let drain = drain_answering(&[200]);
        drain.queue.push(&FakeRecord::new("a"));
        drain.queue.push(&FakeRecord::discovery("d", &[1]));
        drain.queue.push(&FakeRecord::new("b"));
        drain.queue.push(&FakeRecord::automation("c", "i-2", 0));
        drain.queue.push(&FakeRecord::new("e"));

        tokio::time::sleep(FLUSH_INTERVAL + Duration::from_secs(5)).await;
        assert_eq!(
            drain.sent(),
            [
                request(&["a"]),
                request(&["d"]),
                request(&["b"]),
                request(&["c"]),
                request(&["e"]),
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_transient_failure_is_retried() {
        let drain = drain_answering(&[503, 200]);
        drain.queue.push(&FakeRecord::new("a"));

        tokio::time::sleep(FLUSH_INTERVAL + Duration::from_secs(5)).await;
        assert_eq!(drain.sent(), [request(&["a"]), request(&["a"])]);
        assert!(dropped(&drain.queue).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_rejected_request_drops_its_records_without_a_retry() {
        let drain = drain_answering(&[400]);
        drain.queue.push(&FakeRecord::new("a"));
        drain.queue.push(&FakeRecord::new("b"));

        tokio::time::sleep(FLUSH_INTERVAL + Duration::from_secs(5)).await;
        assert_eq!(drain.sent(), [request(&["a", "b"])]);
        assert_eq!(dropped(&drain.queue), BTreeMap::from([("rejected", 2)]));
    }

    #[tokio::test(start_paused = true)]
    async fn a_request_that_still_fails_is_named_in_the_flush_warning() {
        let drain = drain_answering(&[503; SEND_ATTEMPTS as usize]);
        let records: Vec<FakeRecord> = numbered(MAX_ENTRIES).iter().map(FakeRecord::new).collect();
        for record in &records {
            drain.queue.push(record);
        }
        // What `flush` logs after "Telemetry: ".
        let why = send_queued(&drain.queue.0, &mut None, &CancellationToken::new())
            .await
            .unwrap_err();
        let label = format!(
            "{} and {} more",
            records[0].part.idempotency_key,
            MAX_ENTRIES - 1
        );
        assert!(
            why.starts_with(&format!("request {label} not sent: ")),
            "{why}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_request_that_still_fails_goes_to_the_back_and_is_sent_again_unchanged() {
        let attempts = SEND_ATTEMPTS as usize;
        let mut statuses = vec![503; attempts];
        statuses.push(200);
        let drain = drain_answering(&statuses);
        let keys = numbered(MAX_ENTRIES + 1);
        for key in &keys {
            drain.queue.push(&FakeRecord::new(key));
        }

        // Every attempt at the first request, none at the rest.
        tokio::time::sleep(FLUSH_INTERVAL + Duration::from_secs(5)).await;
        assert_eq!(drain.sent(), vec![keys[..MAX_ENTRIES].to_vec(); attempts]);
        assert_eq!(drain.queue.0.queue.len(), 2);

        // The next flush sends the record that was behind it first, then the
        // same bytes again.
        tokio::time::sleep(FLUSH_INTERVAL + Duration::from_secs(5)).await;
        let mut expected = vec![keys[..MAX_ENTRIES].to_vec(); attempts];
        expected.push(keys[MAX_ENTRIES..].to_vec());
        expected.push(keys[..MAX_ENTRIES].to_vec());
        assert_eq!(drain.sent(), expected);
        let received = drain.received.lock().unwrap();
        assert_eq!(received[attempts + 1].1, received[0].1);
        drop(received);
        assert!(dropped(&drain.queue).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn evicting_a_failed_request_counts_each_of_its_records() {
        let drain = drain_answering(&[503]);
        for key in numbered(4) {
            drain.queue.push(&FakeRecord::new(key));
        }
        tokio::time::sleep(FLUSH_INTERVAL + Duration::from_secs(5)).await;
        assert_eq!(drain.queue.0.queue.len(), 1);

        // A full queue evicts the oldest: the failed request of 4 records.
        for _ in 0..MAX_QUEUED.get() {
            drain.queue.push(&FakeRecord::new("a"));
        }
        assert_eq!(dropped(&drain.queue), BTreeMap::from([("queue_full", 4)]));
    }

    #[tokio::test(start_paused = true)]
    async fn putting_a_failed_request_back_counts_the_records_it_evicts() {
        let (queue, _task, _token) = drain_that_hangs();
        queue.push(&FakeRecord::new("a"));

        // While the flush's attempts at "a" hang, the queue fills up, so
        // putting "a" back evicts the oldest record.
        tokio::time::sleep(FLUSH_INTERVAL + Duration::from_secs(1)).await;
        for _ in 0..MAX_QUEUED.get() {
            queue.push(&FakeRecord::new("b"));
        }
        assert!(dropped(&queue).is_empty());
        tokio::time::sleep(Duration::from_secs(60)).await;
        assert_eq!(queue.0.queue.len(), MAX_QUEUED.get());
        assert_eq!(dropped(&queue), BTreeMap::from([("queue_full", 1)]));
    }

    #[tokio::test(start_paused = true)]
    async fn a_record_is_weighed_as_the_sender_encodes_its_request() {
        // 13 certificates: within the limit as CBOR, over it as JSON's
        // base64.
        let record = FakeRecord::discovery("d", &[6, 6, 1]);
        for (dry_run, queued, dropped_as) in [
            (false, 1, BTreeMap::new()),
            (true, 0, BTreeMap::from([("too_large", 1)])),
        ] {
            let (service, _) = ScriptedService::answering(&[200]);
            let mut sender =
                TelemetrySender::for_tests(SharedHttpConnector::new(service), acm_consent());
            if dry_run {
                sender = sender.into_dry_run();
            }
            let (queue, _task) =
                spawn_with_interval(sender, CancellationToken::new(), FLUSH_INTERVAL);
            queue.push(&record);
            assert_eq!(queue.0.queue.len(), queued, "dry run {dry_run}");
            assert_eq!(dropped(&queue), dropped_as, "dry run {dry_run}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_record_the_sender_wont_send_is_dropped_and_counted() {
        let drain = drain_answering(&[200]);
        drain.queue.push(&JsonOnlyRecord);
        // Over the model's limits: a SUCCESS observation without a
        // certificate.
        let mut invalid = FakeRecord::discovery("d", &[1]);
        if let Entry::Discovery(discovery) = &mut invalid.part.entry {
            discovery.observations[0].certificate_der = None;
        }
        drain.queue.push(&invalid);
        assert_eq!(drain.queue.0.queue.len(), 0);
        assert_eq!(dropped(&drain.queue), BTreeMap::from([("rejected", 2)]));
    }

    #[tokio::test(start_paused = true)]
    async fn a_dry_run_logs_a_record_without_a_request_part_instead_of_queueing_it() {
        let (service, _) = ScriptedService::answering(&[200]);
        let sender = TelemetrySender::for_tests(SharedHttpConnector::new(service), acm_consent())
            .into_dry_run();
        let (queue, _task) = spawn_with_interval(sender, CancellationToken::new(), FLUSH_INTERVAL);
        queue.push(&JsonOnlyRecord);
        assert_eq!(queue.0.queue.len(), 0);
        assert!(dropped(&queue).is_empty());
    }

    /// A record without a request part whose JSON is `self.0` bytes.
    struct LargeJsonOnlyRecord(usize);

    impl TelemetryRecord for LargeJsonOnlyRecord {
        fn payload_type(&self) -> PayloadType {
            PayloadType::CertAutomation
        }
        fn capability(&self) -> Capability {
            Capability::Acm
        }
        fn serialize(&self) -> Result<Vec<u8>, serde_json::Error> {
            Ok(vec![b' '; self.0])
        }
        fn idempotency_key(&self) -> &str {
            "large-json-only"
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_dry_run_counts_a_record_without_a_request_part_too_large_to_log_as_too_large() {
        let (service, _) = ScriptedService::answering(&[200]);
        let sender = TelemetrySender::for_tests(SharedHttpConnector::new(service), acm_consent())
            .into_dry_run();
        let (queue, _task) = spawn_with_interval(sender, CancellationToken::new(), FLUSH_INTERVAL);
        queue.push(&LargeJsonOnlyRecord(MAX_REQUEST_BYTES));
        assert!(dropped(&queue).is_empty());
        queue.push(&LargeJsonOnlyRecord(MAX_REQUEST_BYTES + 1));
        assert_eq!(dropped(&queue), BTreeMap::from([("too_large", 1)]));
    }

    #[tokio::test(start_paused = true)]
    async fn a_full_queue_counts_what_it_evicts() {
        let drain = drain_answering(&[200]);
        for _ in 0..=MAX_QUEUED.get() {
            drain.queue.push(&FakeRecord::new("a"));
        }
        assert_eq!(dropped(&drain.queue), BTreeMap::from([("queue_full", 1)]));
    }

    #[tokio::test(start_paused = true)]
    async fn a_queue_over_its_byte_limit_drops_the_oldest() {
        let drain = drain_answering(&[200]);
        // One record more than fits evicts the first.
        let fit = records_that_fit(&drain.queue.0, 6);
        let keys = numbered(fit + 1);
        for key in &keys {
            drain.queue.push(&FakeRecord::automation(key, "i-1", 6));
        }
        assert_eq!(dropped(&drain.queue), BTreeMap::from([("queue_full", 1)]));

        tokio::time::sleep(FLUSH_INTERVAL + Duration::from_secs(5)).await;
        assert_eq!(drain.sent_records(), keys[1..]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_record_too_large_for_a_request_is_dropped_without_evicting_others() {
        let drain = drain_answering(&[200]);
        // As many records as fit, then one too large that would push the
        // queue past its byte limit if it were queued.
        let keys = numbered(records_that_fit(&drain.queue.0, 6));
        for key in &keys {
            drain.queue.push(&FakeRecord::automation(key, "i-1", 6));
        }
        drain
            .queue
            .push(&FakeRecord::discovery("too-large", &[6, 6, 6]));
        assert_eq!(dropped(&drain.queue), BTreeMap::from([("too_large", 1)]));

        tokio::time::sleep(FLUSH_INTERVAL + Duration::from_secs(5)).await;
        assert_eq!(drain.sent_records(), keys);
    }

    /// Each record another thread pushes during shutdown is sent or counted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn every_record_pushed_during_shutdown_is_sent_or_counted() {
        const PUSHES: u64 = 20;
        for _ in 0..50 {
            let drain = drain_answering(&[200]);
            let queue = drain.queue.clone();
            let pusher = std::thread::spawn(move || {
                for i in 0..PUSHES {
                    queue.push(&FakeRecord::automation(i.to_string(), "i-1", 6));
                }
            });
            drain.token.cancel();
            drain.task.await.unwrap();
            pusher.join().unwrap();

            let sent = sent_names(&drain.received).concat().len() as u64;
            let dropped: u64 = dropped(&drain.queue).values().sum();
            assert_eq!(sent + dropped, PUSHES);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_record_type_the_customer_hasnt_consented_to_isnt_queued() {
        let (service, received) = ScriptedService::answering(&[200]);
        let discovery_only = TelemetryConfig {
            acm_discovery_enabled: true,
            ..TelemetryConfig::default()
        };
        let sender = TelemetrySender::for_tests(SharedHttpConnector::new(service), discovery_only);
        let (queue, _task) = spawn_with_interval(sender, CancellationToken::new(), FLUSH_INTERVAL);

        queue.push(&FakeRecord::new("a"));
        assert_eq!(queue.0.queue.len(), 0);
        tokio::time::sleep(FLUSH_INTERVAL + Duration::from_secs(5)).await;
        assert!(sent_names(&received).is_empty());
        assert!(dropped(&queue).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_sends_what_is_queued() {
        let drain = drain_answering(&[200]);
        drain.queue.push(&FakeRecord::new("a"));
        drain.queue.push(&FakeRecord::new("b"));

        drain.token.cancel();
        drain.task.await.unwrap();
        assert_eq!(sent_names(&drain.received), [request(&["a", "b"])]);
        assert!(dropped(&drain.queue).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_during_a_retry_tries_the_request_once_more_without_waiting() {
        let drain = drain_answering(&[503, 200]);
        drain.queue.push(&FakeRecord::new("a"));

        // Shut down while the flush waits to retry its first failed attempt.
        tokio::task::yield_now().await;
        tokio::time::advance(FLUSH_INTERVAL).await;
        while drain.sent().is_empty() {
            tokio::task::yield_now().await;
        }
        let cancelled_at = tokio::time::Instant::now();
        drain.token.cancel();
        drain.task.await.unwrap();
        assert_eq!(
            sent_names(&drain.received),
            [request(&["a"]), request(&["a"])]
        );
        assert_eq!(cancelled_at.elapsed(), Duration::ZERO);
        assert!(dropped(&drain.queue).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_stops_at_a_request_that_still_fails_after_its_retries() {
        let drain = drain_answering(&[503]);
        let keys = numbered(MAX_ENTRIES + 1);
        for key in &keys {
            drain.queue.push(&FakeRecord::new(key));
        }

        drain.token.cancel();
        drain.task.await.unwrap();
        assert_eq!(
            sent_names(&drain.received),
            vec![keys[..MAX_ENTRIES].to_vec(); SEND_ATTEMPTS as usize]
        );
        assert_eq!(
            dropped(&drain.queue),
            BTreeMap::from([("unsent_at_shutdown", keys.len() as u64)])
        );
    }

    /// Validates that a 503 asking for a wait as long as the shutdown
    /// deadline gets one attempt in the final flush, and its record is
    /// counted as unsent.
    #[tokio::test(start_paused = true)]
    async fn shutdown_makes_one_attempt_at_a_503_that_asks_to_wait_as_long_as_the_deadline() {
        let (service, received) = ScriptedService::answering(&[503]);
        let service = service.asking_to_wait(SHUTDOWN_DEADLINE.as_secs());
        let token = CancellationToken::new();
        let sender = TelemetrySender::for_tests(SharedHttpConnector::new(service), acm_consent());
        let (queue, task) = spawn_with_interval(sender, token.clone(), FLUSH_INTERVAL);
        queue.push(&FakeRecord::new("a"));

        let cancelled_at = tokio::time::Instant::now();
        token.cancel();
        task.await.unwrap();
        assert_eq!(sent_names(&received), [request(&["a"])]);
        assert_eq!(cancelled_at.elapsed(), SHUTDOWN_DEADLINE);
        assert_eq!(dropped(&queue), BTreeMap::from([("unsent_at_shutdown", 1)]));
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_drops_a_rejected_request_and_sends_the_rest() {
        let drain = drain_answering(&[400, 200]);
        let keys = numbered(MAX_ENTRIES + 1);
        for key in &keys {
            drain.queue.push(&FakeRecord::new(key));
        }

        drain.token.cancel();
        drain.task.await.unwrap();
        assert_eq!(
            sent_names(&drain.received),
            [&keys[..MAX_ENTRIES], &keys[MAX_ENTRIES..]]
        );
        assert_eq!(
            dropped(&drain.queue),
            BTreeMap::from([("rejected", MAX_ENTRIES as u64)])
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_push_after_shutdown_is_dropped_and_counted() {
        let drain = drain_answering(&[200]);
        drain.token.cancel();
        drain.task.await.unwrap();

        drain.queue.push(&FakeRecord::new("a"));
        assert!(sent_names(&drain.received).is_empty());
        assert_eq!(
            dropped(&drain.queue),
            BTreeMap::from([("pushed_after_shutdown", 1)])
        );
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_ends_within_the_deadline_and_counts_the_request_in_flight() {
        let (queue, task, token) = drain_that_hangs();
        queue.push(&FakeRecord::new("a"));
        queue.push(&FakeRecord::new("b"));

        let started = tokio::time::Instant::now();
        token.cancel();
        task.await.unwrap();
        assert_eq!(started.elapsed(), Duration::from_secs(5));
        assert_eq!(dropped(&queue), BTreeMap::from([("unsent_at_shutdown", 2)]));
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_during_a_hanging_send_still_ends_within_the_deadline() {
        let (queue, task, token) = drain_that_hangs();
        queue.push(&FakeRecord::new("a"));

        // The flush's first send is hanging; shut down before it times out.
        tokio::time::sleep(FLUSH_INTERVAL + Duration::from_secs(1)).await;
        let cancelled_at = tokio::time::Instant::now();
        token.cancel();
        task.await.unwrap();
        assert_eq!(cancelled_at.elapsed(), Duration::from_secs(5));
        assert_eq!(dropped(&queue), BTreeMap::from([("unsent_at_shutdown", 1)]));
    }
}
