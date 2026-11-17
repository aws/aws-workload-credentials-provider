//! The startup hold window, the event loop, and keeping the watch alive.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use log::{debug, error, info, warn};
use tokio::sync::mpsc;
use tokio::time::{interval_at, Instant};

use crate::env::{InboxValidator, WatcherEnv};
use crate::error::RunError;
use crate::inbox::{self, Claim};
use crate::plan::{CommandId, ReloadPlan};
use crate::reload::ReloadSink;
use crate::watch::{InboxWatcher, RescanReason, WatchEvent};
use aws_workload_credentials_provider_common::watcher_request::RefreshRequest;

/// How long after startup requests are held instead of run.
///
/// The TLS server in this container is starting up at the same time as the
/// watcher, and a reload issued before it is listening fails. Holding briefly
/// and then running each distinct command once turns a startup burst into one
/// reload per command.
///
/// The requirement is a fixed startup window of unspecified length. 30
/// seconds is long enough for a typical nginx or httpd start, short enough
/// that a genuine renewal landing inside it is not noticeably delayed.
/// FLAGGED FOR RATIFICATION — change the constant, not the design.
///
/// This is the **default** rather than the only value: it is what
/// [`crate::env::WatcherEnv::startup_hold_window`] returns unless
/// [`crate::env::STARTUP_HOLD_MS_VAR`] overrides it, which exists so a test
/// that spawns the real binary need not wait 30 seconds. Every deployment that
/// does not set the variable gets exactly this.
pub const STARTUP_HOLD_WINDOW: Duration = Duration::from_secs(30);

/// How often the inbox directory is rescanned regardless of events.
///
/// This is what makes a lost notification self-healing: a dropped event costs
/// up to this much latency instead of a missed reload.
pub const PERIODIC_RESCAN_INTERVAL: Duration = Duration::from_secs(60);

/// The shortest gap between two attempts to re-establish the watch, and the
/// first step of the backoff after a failed one.
///
/// Triggers inside the gap are coalesced into the next attempt, so a flood of
/// watch errors costs one rebind and one scan per interval.
pub const REBIND_MIN_INTERVAL: Duration = Duration::from_secs(5);

/// The longest wait between failed attempts to re-establish the watch.
///
/// The backoff doubles from [`REBIND_MIN_INTERVAL`] up to this, and retries
/// continue at this interval for as long as the process runs.
pub const REBIND_MAX_BACKOFF: Duration = Duration::from_secs(60);

/// How long the loop runs without one successful scan before it exits with
/// [`RunError::InboxUnavailable`].
///
/// A successful scan is one whose validation passed and whose directory
/// listing succeeded. Ten periodic scans' worth: long enough to ride out a
/// remount or a re-provisioned volume, short enough that a watcher which can
/// no longer see its inbox is restarted rather than left reloading nothing.
pub const SCAN_FAILURE_EXIT_WINDOW: Duration = Duration::from_secs(600);

/// A finished reload, reported back to the loop.
type Done = (CommandId, Result<(), io::Error>);

/// Runs the watcher until shutdown.
///
/// Takes the watch as an [`InboxWatcher`] and the per-scan check as an
/// [`InboxValidator`] so that every loop test can be driven from a plain
/// channel and a scripted check, with no real filesystem watcher and no real
/// clock. The caller keeps the watch alive for the whole call.
///
/// `recovered` is what `inbox::prepare_startup_state` found in the pending
/// directory. It is queued before the first scan, so it is held and merged
/// with the inbox's requests like anything else that arrives during the
/// startup hold window.
///
/// Every listing of the inbox goes through [`Loop::scan`], which validates
/// the directory first. The watch is re-established when it may have stopped
/// delivering events: on a watch error, when the inbox itself is removed or
/// renamed, when the inbox passes validation after failing it, and when a
/// periodic scan finds a request no event reported. A rebind that fails is
/// retried with backoff and never stops the loop; the periodic scan keeps
/// finding requests meanwhile.
///
/// Returns `Err` when the event channel closes, and when no scan has
/// succeeded for [`SCAN_FAILURE_EXIT_WINDOW`].
pub async fn run<S, F, W, V>(
    env: &WatcherEnv,
    validator: &V,
    plan: Arc<ReloadPlan>,
    sink: Arc<S>,
    watch: &mut W,
    recovered: Vec<inbox::Claimed>,
    shutdown: F,
) -> Result<(), RunError>
where
    S: ReloadSink,
    F: Future<Output = ()>,
    W: InboxWatcher,
    V: InboxValidator,
{
    let (done_tx, mut done_rx) = mpsc::unbounded_channel::<Done>();
    let started = Instant::now();

    let mut state = Loop {
        env,
        validator,
        watch,
        inbox: env.inbox_dir(),
        pending_dir: env.pending_dir(),
        plan,
        sink,
        queued: BTreeMap::new(),
        in_flight: BTreeMap::new(),
        done_tx,
        holding: true,
        // `prepare` checked the roots just before this, so the first scan
        // passing is not a recovery.
        validated: true,
        last_success: started,
        rebind: RebindState {
            due: false,
            next_attempt: started,
            failures: 0,
            triggers: 0,
        },
    };

    // `STARTUP_HOLD_WINDOW` unless the environment overrode it; the resolution
    // and its bounds live on `WatcherEnv` with the other `WCP_WATCHER_*`
    // values.
    let hold = env.startup_hold_window();
    let hold_until = Instant::now() + hold;
    info!("Holding reloads for {:?} while the server starts", hold);

    for claimed in recovered {
        state.accept(claimed.name, claimed.request);
    }

    // Claims whatever is already in the inbox: requests a previous run never
    // picked up, and ones that landed before the watch was established and so
    // produced an event nobody was listening for.
    state.scan(ScanCause::Startup)?;

    let mut rescan = interval_at(
        Instant::now() + PERIODIC_RESCAN_INTERVAL,
        PERIODIC_RESCAN_INTERVAL,
    );

    // Pinned once, outside the loop: polling a freshly created shutdown future
    // on every iteration would reinstall the signal handlers each time and
    // could drop a signal delivered between iterations.
    let mut shutdown = std::pin::pin!(shutdown);

    loop {
        tokio::select! {
            // Re-borrowed on every iteration, so a rebind's new channel is
            // picked up with no extra code.
            event = state.watch.events().recv() => match event {
                Some(WatchEvent::Paths(paths)) => {
                    for path in &paths {
                        if state.validated {
                            state.admit(path);
                        } else {
                            // Left on disk for the next validated scan.
                            debug!(
                                "Not admitting {:?} until '{}' passes validation",
                                path,
                                state.inbox.display()
                            );
                        }
                    }
                }
                Some(WatchEvent::Rescan(reason)) => state.rescan(reason)?,
                // Never a rebind: the backend's thread is gone, and dropping
                // its watcher would panic.
                None => {
                    error!(
                        "The filesystem watch on '{}' is gone; exiting",
                        state.inbox.display()
                    );
                    return Err(RunError::WatchChannelClosed { path: state.inbox });
                }
            },

            // A rebind that was triggered inside the minimum interval, or
            // that failed, once its wait is over.
            _ = tokio::time::sleep_until(state.rebind.next_attempt), if state.rebind.due => {
                state.scan(ScanCause::Rebind)?;
            }

            done = done_rx.recv() => {
                // The loop owns a sender, so this channel cannot close while
                // the loop is alive.
                if let Some((id, result)) = done {
                    state.complete(id, result);
                }
            }

            _ = tokio::time::sleep_until(hold_until), if state.holding => {
                state.release_hold();
            }

            _ = rescan.tick() => {
                debug!("Periodic rescan of '{}'", state.inbox.display());
                state.scan(ScanCause::Periodic)?;
            }

            _ = &mut shutdown => {
                // In-flight reloads are dropped here. `execute_child_cmd`
                // spawns with `kill_on_drop(true)`, so their children are
                // killed rather than orphaned. Their requests stay in the
                // pending directory and are recovered on the next start.
                info!("Shutting down");
                return Ok(());
            }
        }
    }
}

/// What a scan was run for.
///
/// Only [`ScanCause::Periodic`] changes what a scan does: a request it finds
/// is one no event reported, which is the sign of a watch that has silently
/// stopped. The other scans run because an event or a timer asked for one, so
/// finding requests there says nothing about the watch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanCause {
    Startup,
    Event,
    Periodic,
    Rebind,
}

/// When the watch is next re-established.
struct RebindState {
    /// A rebind has been asked for and has not yet succeeded.
    due: bool,

    /// No attempt before this. [`REBIND_MIN_INTERVAL`] after a success, the
    /// backoff after a failure.
    ///
    /// Whenever `due` is set, an attempt at or after this either succeeds,
    /// clearing `due`, or fails and moves this into the future, so the timer
    /// arm cannot spin.
    next_attempt: Instant,

    /// Failed attempts since the last success.
    failures: u32,

    /// Triggers since the last success, reported when it is re-established.
    triggers: u32,
}

/// The requests one reload covers: the certificates it is for, and the names
/// of their files in the pending directory.
///
/// A name is in a batch once however many times it was claimed. A reused
/// name can be in more than one batch at a time (queued and in flight, or for
/// two commands), so a file is deleted only once no batch references it.
#[derive(Debug, Default)]
struct Batch {
    arns: BTreeSet<String>,
    files: BTreeSet<OsString>,
}

/// The loop's state.
struct Loop<'a, S: ReloadSink, W, V> {
    env: &'a WatcherEnv,
    validator: &'a V,
    watch: &'a mut W,
    inbox: PathBuf,
    pending_dir: PathBuf,
    plan: Arc<ReloadPlan>,
    sink: Arc<S>,

    /// Requests awaiting a reload, keyed by the command that reloads them.
    ///
    /// MERGED BY RESOLVED COMMAND, NOT PER CERTIFICATE, collapses pending
    /// requests to the set of distinct commands instead, and runs each command
    /// once per cycle. The reasons:
    ///
    /// - The configuration's own unit is the command. One `[[reload]]` group
    ///   lists every certificate one command reloads, so two certificates in a
    ///   group have nothing to merge per-certificate — running the group's
    ///   command twice is pure waste.
    /// - The serialization requirement is itself per command
    ///   ("each command runs at most one reload at a time; different commands
    ///   may reload in parallel"). A per-certificate map cannot express that
    ///   without a second command-keyed structure.
    /// - Per-certificate merging is strictly weaker: it is this key composed
    ///   with the ARN-to-command map, and that map is not injective.
    ///
    /// WHAT THIS GIVES UP, so the owner can overturn it: a reload no longer
    /// knows which certificate triggered it, only the set of ARNs in the
    /// batch. Nothing in Phase 1 passes an ARN to the command — the request
    /// carries no command or path and the configuration carries no paths — so
    /// the set is only ever a log line today. If Phase 2 needs per-certificate
    /// fidelity, this map has to be re-keyed.
    queued: BTreeMap<CommandId, Batch>,

    /// The batch each running reload covers. At most one per command.
    in_flight: BTreeMap<CommandId, Batch>,

    done_tx: mpsc::UnboundedSender<Done>,

    /// True until the startup hold window closes.
    holding: bool,

    /// False from a failed validation, or the inbox itself being removed or
    /// renamed, until the next scan whose validation passes. While false,
    /// requests named by events are left on disk rather than admitted.
    validated: bool,

    /// When the last scan whose validation and listing both succeeded ran,
    /// or when the loop started.
    last_success: Instant,

    rebind: RebindState,
}

impl<S: ReloadSink, W: InboxWatcher, V: InboxValidator> Loop<'_, S, W, V> {
    /// Handles a rescan request from the watch.
    ///
    /// A reason that needs a rebind inside [`REBIND_MIN_INTERVAL`] of the
    /// last attempt only marks one as due: the rebind timer arm then rebinds
    /// and scans once, however many triggers arrived.
    fn rescan(&mut self, reason: RescanReason) -> Result<(), RunError> {
        let what = match &reason {
            RescanReason::NeedRescan => "The filesystem watch lost track of events".to_string(),
            RescanReason::WatchError(e) => {
                format!("The filesystem watch reported an error ({})", e)
            }
            RescanReason::InboxReplaced => {
                // The path may now name a different directory, or nothing.
                self.validated = false;
                "The inbox directory itself was removed or renamed".to_string()
            }
        };

        if reason.needs_rebind() {
            self.request_rebind();
            if Instant::now() < self.rebind.next_attempt {
                debug!(
                    "{}; a rebind of '{}' is already scheduled",
                    what,
                    self.inbox.display()
                );
                return Ok(());
            }
            warn!(
                "{}; re-establishing the watch and rescanning '{}'",
                what,
                self.inbox.display()
            );
        } else {
            warn!("{}; rescanning '{}'", what, self.inbox.display());
        }

        self.scan(ScanCause::Event)
    }

    /// The only way the inbox directory is listed: validate it, re-establish
    /// the watch if that is due, then list and admit.
    ///
    /// A failed validation skips the listing; it is never fatal on its own.
    /// `Err` only once no scan has succeeded for [`SCAN_FAILURE_EXIT_WINDOW`].
    ///
    /// Always safe to repeat: [`Loop::admit`] moves each request out of the
    /// inbox before reading it, so a rescan cannot see, or double-run, a
    /// request that is queued or reloading.
    fn scan(&mut self, cause: ScanCause) -> Result<(), RunError> {
        let now = Instant::now();

        if let Err(e) = self.validator.validate(self.env) {
            error!(
                "Not scanning '{}': it failed validation. {}",
                self.inbox.display(),
                e
            );
            self.validated = false;
            // Never bind to a path that failed validation. A due attempt
            // counts as failed, which also moves the next one into the future.
            if self.rebind_ready(now) {
                self.rebind_failed(now, &format!("the directory failed validation ({})", e));
            }
            return self.scan_failed(now, e.to_string());
        }

        if !self.validated {
            info!(
                "'{}' passed validation; re-establishing the watch",
                self.inbox.display()
            );
            self.validated = true;
            self.request_rebind();
        }

        // Before the listing, so the listing covers whatever arrived while no
        // watch was live.
        let rebind_attempted = self.rebind_ready(now);
        if rebind_attempted {
            self.try_rebind(now);
        }

        match self.list_and_admit() {
            Ok(admitted) => {
                self.last_success = now;
                // A scan that has just tried to rebind expects to find what
                // arrived during the gap; that says nothing about the watch.
                if cause == ScanCause::Periodic && !rebind_attempted && !admitted.is_empty() {
                    let names: Vec<_> = admitted
                        .iter()
                        .filter_map(|path| path.file_name())
                        .map(|name| format!("{name:?}"))
                        .collect();
                    info!(
                        "The periodic scan of '{}' found request(s) no event reported ({}); \
                         re-establishing the watch",
                        self.inbox.display(),
                        names.join(", ")
                    );
                    // Performed by the rebind timer arm, which lists again
                    // once the new watch is live.
                    self.request_rebind();
                }
                Ok(())
            }
            Err(e) => {
                error!(
                    "Failed to list '{}': {}. Retrying on the next scan.",
                    self.inbox.display(),
                    e
                );
                self.scan_failed(now, e.to_string())
            }
        }
    }

    /// Lists the inbox directory and admits everything in it, returning the
    /// requests that were queued.
    fn list_and_admit(&mut self) -> io::Result<Vec<PathBuf>> {
        let (paths, truncated) = inbox::scan(&self.inbox)?;
        if truncated {
            warn!(
                "More than {} requests in '{}'; handling the first {} and leaving the \
                 rest for the next scan",
                inbox::MAX_REQUESTS_PER_SCAN,
                self.inbox.display(),
                inbox::MAX_REQUESTS_PER_SCAN
            );
        }

        let mut admitted = Vec::new();
        for path in paths {
            if self.admit(&path) {
                admitted.push(path);
            }
        }
        Ok(admitted)
    }

    /// Exits once no scan has succeeded for [`SCAN_FAILURE_EXIT_WINDOW`].
    fn scan_failed(&self, now: Instant, last_error: String) -> Result<(), RunError> {
        let since = now.duration_since(self.last_success);
        if since >= SCAN_FAILURE_EXIT_WINDOW {
            return Err(RunError::InboxUnavailable {
                path: self.inbox.clone(),
                since,
                last_error,
            });
        }
        Ok(())
    }

    fn request_rebind(&mut self) {
        self.rebind.due = true;
        self.rebind.triggers = self.rebind.triggers.saturating_add(1);
    }

    fn rebind_ready(&self, now: Instant) -> bool {
        self.rebind.due && now >= self.rebind.next_attempt
    }

    /// Re-establishes the watch. Only called after validation has passed.
    fn try_rebind(&mut self, now: Instant) {
        match self.watch.rebind(&self.inbox) {
            Ok(()) => {
                info!(
                    "Re-established the watch on '{}' ({} trigger(s) since it was last \
                     established)",
                    self.inbox.display(),
                    self.rebind.triggers
                );
                self.rebind = RebindState {
                    due: false,
                    next_attempt: now + REBIND_MIN_INTERVAL,
                    failures: 0,
                    triggers: 0,
                };
            }
            Err(e) => self.rebind_failed(now, &e.to_string()),
        }
    }

    /// Backs off. Never fatal: periodic scans keep finding requests meanwhile.
    fn rebind_failed(&mut self, now: Instant, cause: &str) {
        self.rebind.failures = self.rebind.failures.saturating_add(1);
        let backoff = rebind_backoff(self.rebind.failures);
        self.rebind.next_attempt = now + backoff;
        error!(
            "Failed to re-establish the watch on '{}' (attempt {}): {}. Retrying in {:?}; \
             periodic scans continue meanwhile.",
            self.inbox.display(),
            self.rebind.failures,
            cause,
            backoff
        );
    }

    /// The one place a request enters the system.
    ///
    /// Admission is by **name, then content**: `inbox::is_request_file` must
    /// accept the name (it ends in `.cmd`), and then the file must parse. A
    /// path that fails the name check is never opened, parsed or deleted.
    /// That is what keeps out the ACM provider's mid-write temp files, which
    /// are complete valid requests sitting in `inbox/` waiting to be renamed.
    /// See `inbox`'s module documentation.
    ///
    /// Every `.cmd` candidate has to be opened: the filename carries no
    /// certificate ARN, so a directory listing cannot say which certificate a
    /// request concerns.
    ///
    /// The file is claimed first: moved from `inbox/<name>` to
    /// `pending/<name>` (`inbox::claim`), then read there. A name that is
    /// already gone was claimed by an earlier event or scan. A claim that
    /// fails leaves the file in the inbox for the next scan. A claimed file
    /// that does not parse is deleted from the pending directory.
    ///
    /// Returns true when the request was parsed and queued.
    fn admit(&mut self, path: &Path) -> bool {
        if !inbox::is_request_file(path) {
            debug!("Ignoring {:?}: not a request file", path);
            return false;
        }
        // Always the inbox's own entry, whatever directory the path names.
        let Some(name) = path.file_name() else {
            return false;
        };

        let claimed = match inbox::claim(&self.inbox, &self.pending_dir, name) {
            Ok(Claim::Claimed(claimed)) => claimed,
            Ok(Claim::Gone) => {
                debug!("{:?} is gone; already claimed or removed", path);
                return false;
            }
            Ok(Claim::Directory) => {
                debug!("Ignoring the directory {:?}", path);
                return false;
            }
            Err(e) => {
                error!(
                    "Failed to move {:?} into the pending directory '{}': {}. Leaving it in \
                     the inbox for the next scan.",
                    path,
                    self.pending_dir.display(),
                    e
                );
                return false;
            }
        };

        let Some(request) = inbox::read_claimed(&claimed) else {
            return false;
        };

        self.accept(name.to_os_string(), request)
    }

    /// Queues a request whose file is `pending/<name>`, and starts its reload
    /// unless the startup hold window is open.
    ///
    /// Returns true when the request was queued. A request for a certificate
    /// this watcher has no command for is deleted instead.
    ///
    /// `request` comes from [`inbox::read`], which has already refused a
    /// malformed `command_id` or `certificate_arn`, so both are safe to log.
    fn accept(&mut self, name: OsString, request: RefreshRequest) -> bool {
        // `id` is this watcher's own `plan::CommandId` — an index into the
        // config's `[[reload]]` groups, derived here from the ARN. It is not
        // the request's `command_id`
        let Some(id) = self.plan.command_for(&request.certificate_arn) else {
            // Loud, and no fallback: running some other certificate's reload
            // command is a worse outcome than running none. The likely causes
            // are a certificate rerouted to a different watcher without this
            // container being restarted, or a request written into the wrong
            // watcher's directory.
            error!(
                "REJECTED request '{}': certificate '{}' has no reload command in this \
                 watcher's configuration ('{}'). No reload will run for it.",
                request.command_id,
                request.certificate_arn,
                self.inbox.display()
            );
            if !self.is_referenced(&name) {
                inbox::delete(&self.pending_dir.join(&name));
            }
            return false;
        };

        info!(
            "Accepted request '{}' for certificate '{}'",
            request.command_id, request.certificate_arn
        );

        let batch = self.queued.entry(id).or_default();
        batch.arns.insert(request.certificate_arn);
        batch.files.insert(name);

        if !self.holding {
            self.maybe_start(id);
        }
        true
    }

    /// Starts a reload for `id` unless one is already running for it.
    fn maybe_start(&mut self, id: CommandId) {
        if self.in_flight.contains_key(&id) {
            // Whatever accumulated while it runs is picked up by
            // `complete`, so a burst produces at most two reloads per command.
            debug!("A reload is already running for command {}; coalescing", id);
            return;
        }

        let Some(batch) = self.queued.remove(&id) else {
            return;
        };
        if batch.arns.is_empty() {
            return;
        }

        let command = self.plan.command(id).to_vec();
        let label = batch.arns.iter().cloned().collect::<Vec<_>>().join(", ");
        self.in_flight.insert(id, batch);
        let sink = Arc::clone(&self.sink);
        let done = self.done_tx.clone();

        info!("Running reload {:?} for {}", command, label);

        tokio::spawn(async move {
            // The reload runs in its own task, so a panic in it ends that task
            // and comes back here as a `JoinError`. Reported as a failure, so
            // `complete` still clears `in_flight`, deletes the batch's files
            // and starts whatever queued meanwhile; otherwise the command
            // would never reload again.
            let result = match tokio::spawn(async move { sink.reload(command, label).await }).await
            {
                Ok(result) => result,
                Err(e) => Err(join_error_to_io(e)),
            };
            // The receiver is gone only once the loop has returned.
            let _ = done.send((id, result));
        });
    }

    /// Handles a finished reload: deletes the pending files of the batch it
    /// covered, whether it succeeded or failed, then starts the next batch
    /// for the command if one queued meanwhile.
    ///
    /// Files that joined the queue while the reload ran are not part of its
    /// batch, so they stay until the reload that covers them completes. So
    /// does a file whose name another queued or running batch also
    /// references, so that it is still recovered after a crash.
    fn complete(&mut self, id: CommandId, result: Result<(), io::Error>) {
        let batch = self.in_flight.remove(&id);

        if let Err(e) = result {
            // Loud, and not retried. A reload that fails because the server is
            // still starting is expected, and Phase 1 has no alarms, so the
            // log line is the whole of the response.
            error!("Reload command {:?} failed: {}", self.plan.command(id), e);
        }

        for name in batch.iter().flat_map(|batch| &batch.files) {
            if self.is_referenced(name) {
                debug!(
                    "Keeping {:?}: another batch also covers it",
                    self.pending_dir.join(name)
                );
            } else {
                inbox::delete(&self.pending_dir.join(name));
            }
        }

        if self.queued.contains_key(&id) {
            self.maybe_start(id);
        }
    }

    /// True when a queued or running batch covers `pending/<name>`.
    ///
    /// A scan rather than a count: there are at most a few batches, one
    /// queued and one running per command.
    fn is_referenced(&self, name: &OsString) -> bool {
        self.queued
            .values()
            .chain(self.in_flight.values())
            .any(|batch| batch.files.contains(name))
    }

    /// Closes the hold window: every held command reloads exactly once.
    fn release_hold(&mut self) {
        self.holding = false;

        let ids: Vec<CommandId> = self.queued.keys().copied().collect();
        info!(
            "Startup hold window closed; running {} reload command(s)",
            ids.len()
        );

        for id in ids {
            self.maybe_start(id);
        }
    }
}

/// The wait after the `failures`th consecutive failed rebind: 5, 10, 20 and
/// 40 seconds, then [`REBIND_MAX_BACKOFF`].
fn rebind_backoff(failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(4);
    REBIND_MIN_INTERVAL
        .saturating_mul(1 << doublings)
        .min(REBIND_MAX_BACKOFF)
}

/// Turns a reload task that did not finish into a failed reload.
///
/// A panic payload is a `&str` or `String` for `panic!` with a literal or a
/// format string; anything else is reported without its payload.
fn join_error_to_io(e: tokio::task::JoinError) -> io::Error {
    if e.is_panic() {
        let payload = e.into_panic();
        let message = payload
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "non-string panic payload".to_string());
        io::Error::other(format!("reload panicked: {message}"))
    } else {
        io::Error::other(format!("reload task was cancelled: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::{atomic, Mutex};

    use crate::env::tests_support::{split_env, ReadOnlyConfigFileSystem, TEST_WATCHER_ID};
    use crate::env::FileSystemValidator;
    use crate::error::InboxCheckError;
    use crate::inbox::is_request_file;
    use crate::types::acm_provider_writer::{
        new_request, request_file_name, wcp_request_body, WCP_REQUEST_NAME, WCP_TEMP_NAME,
    };
    use crate::types::REQUEST_TEMP_SUFFIX;
    use aws_workload_credentials_provider_common::watcher_request::{enqueue, RequestsRoot};
    use tempfile::TempDir;
    use tokio::sync::{oneshot, Semaphore};

    const ARN_A: &str = "arn:aws:acm:us-west-2:123456789012:certificate/aaaa";
    const ARN_B: &str = "arn:aws:acm:us-west-2:123456789012:certificate/bbbb";
    const ARN_C: &str = "arn:aws:acm:us-west-2:123456789012:certificate/cccc";
    const ARN_UNKNOWN: &str = "arn:aws:acm:us-west-2:123456789012:certificate/zzzz";

    #[cfg(unix)]
    const NGINX: &str = "/usr/sbin/nginx";
    #[cfg(unix)]
    const APACHE: &str = "/usr/sbin/apachectl";
    #[cfg(windows)]
    const NGINX: &str = r"C:\nginx\nginx.exe";
    #[cfg(windows)]
    const APACHE: &str = r"C:\apache\bin\httpd.exe";

    /// A sink that records calls instead of running anything.
    ///
    /// Recording happens before the gate, so a reload that is being held open
    /// still counts as started.
    struct RecordingSink {
        calls: Mutex<Vec<(Vec<String>, String)>>,
        gate: Option<Arc<Semaphore>>,
        fail: bool,
        panic_first: bool,
    }

    impl RecordingSink {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                gate: None,
                fail: false,
                panic_first: false,
            })
        }

        /// A sink whose reloads block until the returned gate is released,
        /// one permit per reload.
        fn gated() -> (Arc<Self>, Arc<Semaphore>) {
            let gate = Arc::new(Semaphore::new(0));
            let sink = Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                gate: Some(Arc::clone(&gate)),
                fail: false,
                panic_first: false,
            });
            (sink, gate)
        }

        fn failing() -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                gate: None,
                fail: true,
                panic_first: false,
            })
        }

        /// A sink whose first reload panics and whose later ones succeed.
        fn panicking_once() -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                gate: None,
                fail: false,
                panic_first: true,
            })
        }

        fn calls(&self) -> Vec<(Vec<String>, String)> {
            self.calls.lock().unwrap().clone()
        }

        fn count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }

        fn commands(&self) -> Vec<Vec<String>> {
            self.calls()
                .into_iter()
                .map(|(command, _)| command)
                .collect()
        }
    }

    impl ReloadSink for RecordingSink {
        async fn reload(&self, command: Vec<String>, label: String) -> Result<(), io::Error> {
            // The lock is released before any panic, so it is not poisoned.
            let first = {
                let mut calls = self.calls.lock().unwrap();
                calls.push((command, label));
                calls.len() == 1
            };
            if self.panic_first && first {
                panic!("the reload sink panicked");
            }

            if let Some(gate) = &self.gate {
                // Consumed, not returned: each permit releases one reload.
                gate.acquire()
                    .await
                    .expect("the gate is never closed")
                    .forget();
            }

            if self.fail {
                return Err(io::Error::other("the reload command failed"));
            }
            Ok(())
        }
    }

    /// A watcher whose configuration routes A and B to nginx and C to apache.
    ///
    /// Separate config and requests roots, with the config mount faked
    /// read-only by `filesystem`, so the real per-scan check passes: `drive!`
    /// runs every loop test against it unless a test supplies its own
    /// validator.
    struct Fixture {
        _tmp: TempDir,
        env: WatcherEnv,
        filesystem: ReadOnlyConfigFileSystem,
        plan: Arc<ReloadPlan>,
        /// Per-fixture request counter, so `enqueue` produces distinct
        /// filenames the way the ACM provider's own per-process counter does.
        sequence: atomic::AtomicU64,
    }

    impl Fixture {
        fn new() -> Self {
            Self::build(NGINX, APACHE, None)
        }

        /// A fixture whose environment shortens the startup hold window, as
        /// the end-to-end test's spawned binary does.
        fn with_hold(hold_ms: u64) -> Self {
            Self::build(NGINX, APACHE, Some(hold_ms))
        }

        fn build(first: &str, second: &str, hold_ms: Option<u64>) -> Self {
            let tmp = TempDir::new().unwrap();
            let env = split_env(tmp.path(), TEST_WATCHER_ID, hold_ms);
            let filesystem = ReadOnlyConfigFileSystem::for_env(&env);

            fs::create_dir_all(env.inbox_dir()).unwrap();
            fs::create_dir_all(env.pending_dir()).unwrap();
            fs::create_dir_all(env.config_file().parent().unwrap()).unwrap();

            // The declared `watcher_id` must equal the environment's, or
            // `ReloadPlan::load`'s identity check refuses the configuration.
            let config = format!(
                "schema_version = 1\n\
                 watcher_id = \"{}\"\n\
                 \n\
                 [[reload]]\n\
                 command = [\"{}\", \"-s\", \"reload\"]\n\
                 certificate_arns = [\"{}\", \"{}\"]\n\
                 \n\
                 [[reload]]\n\
                 command = [\"{}\", \"-k\", \"graceful\"]\n\
                 certificate_arns = [\"{}\"]\n",
                TEST_WATCHER_ID,
                first.escape_default(),
                ARN_A,
                ARN_B,
                second.escape_default(),
                ARN_C,
            );
            fs::write(env.config_file(), config).unwrap();

            let plan = Arc::new(ReloadPlan::load(&env.config_file(), env.watcher_id()).unwrap());

            Self {
                _tmp: tmp,
                env,
                filesystem,
                plan,
                sequence: atomic::AtomicU64::new(0),
            }
        }

        /// Writes a request for `arn` under the real filename scheme and
        /// returns its path.
        fn enqueue(&self, arn: &str) -> PathBuf {
            let request = new_request(arn);
            let sequence = self.sequence.fetch_add(1, atomic::Ordering::Relaxed);
            let path = self.env.inbox_dir().join(request_file_name(
                1728331740000,
                sequence,
                &request.command_id,
            ));
            fs::write(&path, serde_json::to_string(&request).unwrap()).unwrap();
            path
        }

        /// Enqueues through the ACM provider's own writer, for the end-to-end
        /// case.
        fn enqueue_via_acm_provider(&self, arn: &str) -> PathBuf {
            let inbox = self.env.inbox_dir();
            let root = RequestsRoot::open(self.env.requests_dir()).unwrap();
            let name = enqueue(&root, self.env.watcher_id(), arn)
                .expect("the ACM provider's writer should enqueue into the provisioned inbox");
            inbox.join(name)
        }

        /// Writes a file into the inbox directory verbatim.
        fn write_raw(&self, name: &str, body: &str) -> PathBuf {
            let path = self.env.inbox_dir().join(name);
            fs::write(&path, body).unwrap();
            path
        }

        /// Writes a file into the pending directory verbatim, as a previous
        /// run that claimed it and never completed would have left it.
        fn write_pending(&self, name: &str, body: &str) -> PathBuf {
            let path = self.env.pending_dir().join(name);
            fs::write(&path, body).unwrap();
            path
        }

        /// Writes a request for `arn` into the pending directory.
        fn leave_pending(&self, arn: &str) -> PathBuf {
            let request = new_request(arn);
            let sequence = self.sequence.fetch_add(1, atomic::Ordering::Relaxed);
            self.write_pending(
                &request_file_name(1728331740000, sequence, &request.command_id),
                &serde_json::to_string(&request).unwrap(),
            )
        }

        /// Writes a request for `arn` into the inbox under `name`, replacing
        /// anything there.
        fn enqueue_named(&self, name: &str, arn: &str) -> PathBuf {
            self.write_raw(name, &serde_json::to_string(&new_request(arn)).unwrap())
        }

        /// Where `path`, an inbox request, is once it has been claimed.
        fn claimed(&self, path: &Path) -> PathBuf {
            self.env.pending_dir().join(path.file_name().unwrap())
        }

        fn inbox_entries(&self) -> usize {
            fs::read_dir(self.env.inbox_dir()).unwrap().count()
        }

        fn pending_entries(&self) -> usize {
            fs::read_dir(self.env.pending_dir()).unwrap().count()
        }

        fn pending_names(&self) -> BTreeSet<OsString> {
            fs::read_dir(self.env.pending_dir())
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect()
        }

        /// The certificates of the requests in the pending directory, as the
        /// next start would recover them.
        fn recoverable_arns(&self) -> Vec<String> {
            let mut arns: Vec<String> = inbox::recover(&self.env.pending_dir())
                .unwrap()
                .into_iter()
                .map(|claimed| claimed.request.certificate_arn)
                .collect();
            arns.sort();
            arns
        }
    }

    /// Lets the loop and any spawned reloads make progress.
    ///
    /// Yielding keeps this task runnable throughout, so the paused clock never
    /// auto-advances and the timing assertions stay exact.
    async fn settle() {
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
    }

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    fn nginx_reload() -> Vec<String> {
        argv(&[NGINX, "-s", "reload"])
    }

    fn apache_reload() -> Vec<String> {
        argv(&[APACHE, "-k", "graceful"])
    }

    /// Runs `driver` alongside the loop in one task.
    ///
    /// `run` borrows its environment, validator and watch, so it cannot be
    /// `tokio::spawn`ed; `join!` gives the same interleaving without the
    /// `'static` bound.
    ///
    /// The four-argument form validates against the fixture's real
    /// directories; the five-argument form takes the validator.
    macro_rules! drive {
        ($fixture:expr, $sink:expr, $watch:expr, $driver:expr) => {{
            let validator = FileSystemValidator(&$fixture.filesystem);
            drive!($fixture, $sink, $watch, validator, $driver)
        }};
        ($fixture:expr, $sink:expr, $watch:expr, $validator:expr, $driver:expr) => {{
            let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
            let driver = {
                let driver = $driver;
                async move {
                    driver(shutdown_tx).await;
                }
            };
            // What `prepare` would hand over: anything a test left in the
            // pending directory before the loop starts.
            let recovered = inbox::recover(&$fixture.env.pending_dir()).unwrap();
            let (result, ()) = tokio::join!(
                run(
                    &$fixture.env,
                    &$validator,
                    Arc::clone(&$fixture.plan),
                    Arc::clone(&$sink),
                    &mut $watch,
                    recovered,
                    async {
                        let _ = shutdown_rx.await;
                    },
                ),
                driver
            );
            result
        }};
    }

    /// A plain channel as a watch whose rebind always succeeds and changes
    /// nothing, for the tests that are not about rebinding.
    impl InboxWatcher for mpsc::UnboundedReceiver<WatchEvent> {
        fn events(&mut self) -> &mut mpsc::UnboundedReceiver<WatchEvent> {
            self
        }

        fn rebind(&mut self, _inbox: &Path) -> notify::Result<()> {
            Ok(())
        }
    }

    /// What a [`FakeWatch`] did, and the handle a test drives it through.
    struct WatchProbe {
        /// The sender for the watch's current channel. `None` once closed.
        sender: Mutex<Option<mpsc::UnboundedSender<WatchEvent>>>,
        /// When each rebind was attempted, successful or not.
        attempts: Mutex<Vec<Instant>>,
        /// Fail every rebind while set.
        fail: atomic::AtomicBool,
    }

    impl WatchProbe {
        /// Sends on the watch's current channel.
        fn send(&self, event: WatchEvent) {
            self.sender
                .lock()
                .unwrap()
                .as_ref()
                .expect("the channel is closed")
                .send(event)
                .expect("the loop holds the receiver");
        }

        /// Ends the watch's current channel, as `notify`'s thread dying does.
        fn close(&self) {
            self.sender.lock().unwrap().take();
        }

        fn rebinds(&self) -> usize {
            self.attempts.lock().unwrap().len()
        }

        /// Seconds between consecutive rebind attempts.
        fn gaps(&self) -> Vec<u64> {
            self.attempts
                .lock()
                .unwrap()
                .windows(2)
                .map(|pair| (pair[1] - pair[0]).as_secs())
                .collect()
        }

        fn set_failing(&self, fail: bool) {
            self.fail.store(fail, atomic::Ordering::SeqCst);
        }
    }

    /// A watch that records rebinds and, like [`crate::watch::InboxWatch`],
    /// replaces its channel on each successful one. Events still queued on
    /// the old channel are discarded with it.
    struct FakeWatch {
        events: mpsc::UnboundedReceiver<WatchEvent>,
        probe: Arc<WatchProbe>,
    }

    impl FakeWatch {
        fn new() -> (Self, Arc<WatchProbe>) {
            let (tx, events) = mpsc::unbounded_channel();
            let probe = Arc::new(WatchProbe {
                sender: Mutex::new(Some(tx)),
                attempts: Mutex::new(Vec::new()),
                fail: atomic::AtomicBool::new(false),
            });
            let watch = Self {
                events,
                probe: Arc::clone(&probe),
            };
            (watch, probe)
        }
    }

    impl InboxWatcher for FakeWatch {
        fn events(&mut self) -> &mut mpsc::UnboundedReceiver<WatchEvent> {
            &mut self.events
        }

        fn rebind(&mut self, _inbox: &Path) -> notify::Result<()> {
            self.probe.attempts.lock().unwrap().push(Instant::now());
            assert!(
                !self.events.is_closed(),
                "rebind was called after the event channel closed"
            );
            if self.probe.fail.load(atomic::Ordering::SeqCst) {
                return Err(notify::Error::generic("scripted rebind failure"));
            }
            let (tx, events) = mpsc::unbounded_channel();
            *self.probe.sender.lock().unwrap() = Some(tx);
            self.events = events;
            Ok(())
        }
    }

    /// A per-scan check whose answer the test sets.
    struct ScriptedValidator {
        ok: atomic::AtomicBool,
        calls: atomic::AtomicUsize,
    }

    impl ScriptedValidator {
        fn new(ok: bool) -> Self {
            Self {
                ok: atomic::AtomicBool::new(ok),
                calls: atomic::AtomicUsize::new(0),
            }
        }

        fn set(&self, ok: bool) {
            self.ok.store(ok, atomic::Ordering::SeqCst);
        }

        fn calls(&self) -> usize {
            self.calls.load(atomic::Ordering::SeqCst)
        }
    }

    impl InboxValidator for ScriptedValidator {
        fn validate(&self, env: &WatcherEnv) -> Result<(), InboxCheckError> {
            self.calls.fetch_add(1, atomic::Ordering::SeqCst);
            if self.ok.load(atomic::Ordering::SeqCst) {
                Ok(())
            } else {
                Err(InboxCheckError::NotADirectory {
                    path: env.inbox_dir(),
                })
            }
        }
    }

    /// Advances the paused clock one second at a time, letting the loop run
    /// after each step so that every timer fires at its own deadline.
    async fn advance_by_seconds(seconds: u64) {
        for _ in 0..seconds {
            tokio::time::advance(Duration::from_secs(1)).await;
            settle().await;
        }
    }

    fn watch_error() -> WatchEvent {
        WatchEvent::Rescan(RescanReason::WatchError("boom".to_string()))
    }

    /// Sends `paths` as one watch event.
    fn paths_event(paths: Vec<PathBuf>) -> WatchEvent {
        WatchEvent::Paths(paths)
    }

    #[tokio::test(start_paused = true)]
    async fn requests_during_the_hold_window_are_held() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (tx, mut rx) = mpsc::unbounded_channel();

        let result = drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            let fixture = &fixture;
            let sink = Arc::clone(&sink);
            let tx = tx.clone();
            async move {
                tx.send(paths_event(vec![fixture.enqueue(ARN_A)])).unwrap();
                tx.send(paths_event(vec![fixture.enqueue(ARN_C)])).unwrap();
                settle().await;

                tokio::time::advance(Duration::from_secs(10)).await;
                settle().await;

                assert_eq!(sink.count(), 0, "reloads ran inside the hold window");
                let _ = shutdown.send(());
            }
        });

        assert!(result.is_ok());
    }

    /// The merge collapse at loop level: three requests, two commands, two
    /// reloads.
    #[tokio::test(start_paused = true)]
    async fn window_close_runs_each_command_once() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (tx, mut rx) = mpsc::unbounded_channel();

        drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            let fixture = &fixture;
            let sink = Arc::clone(&sink);
            let tx = tx.clone();
            async move {
                for arn in [ARN_A, ARN_B, ARN_C] {
                    tx.send(paths_event(vec![fixture.enqueue(arn)])).unwrap();
                }
                settle().await;

                tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                settle().await;

                let mut commands = sink.commands();
                commands.sort();
                let mut expected = vec![nginx_reload(), apache_reload()];
                expected.sort();
                assert_eq!(commands, expected);
                let _ = shutdown.send(());
            }
        })
        .unwrap();
    }

    /// The loop reads the resolved window, not the constant.
    ///
    /// Advancing by the short override is far less than `STARTUP_HOLD_WINDOW`,
    /// so this test only passes if `run` honours
    /// `WatcherEnv::startup_hold_window`. That is what the end-to-end test's
    /// spawned binary depends on, and it is pinned here rather than left to a
    /// reviewer to notice.
    #[tokio::test(start_paused = true)]
    async fn an_overridden_hold_window_releases_early() {
        const HOLD_MS: u64 = 250;

        let fixture = Fixture::with_hold(HOLD_MS);
        let sink = RecordingSink::new();
        let (tx, mut rx) = mpsc::unbounded_channel();

        drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            let fixture = &fixture;
            let sink = Arc::clone(&sink);
            let tx = tx.clone();
            async move {
                tx.send(paths_event(vec![fixture.enqueue(ARN_A)])).unwrap();
                settle().await;
                assert_eq!(sink.count(), 0, "the request should still be held");

                tokio::time::advance(Duration::from_millis(HOLD_MS)).await;
                settle().await;

                assert_eq!(
                    sink.commands(),
                    vec![nginx_reload()],
                    "the overridden window should have closed well before \
                     STARTUP_HOLD_WINDOW"
                );
                let _ = shutdown.send(());
            }
        })
        .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn duplicate_requests_for_one_certificate_merge() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (tx, mut rx) = mpsc::unbounded_channel();

        drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            let fixture = &fixture;
            let sink = Arc::clone(&sink);
            let tx = tx.clone();
            async move {
                for _ in 0..3 {
                    tx.send(paths_event(vec![fixture.enqueue(ARN_A)])).unwrap();
                }
                settle().await;
                tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                settle().await;

                assert_eq!(sink.count(), 1);
                assert_eq!(sink.calls()[0].1, ARN_A);
                let _ = shutdown.send(());
            }
        })
        .unwrap();
    }

    /// The per-certificate versus per-command difference, made visible: two
    /// different certificates sharing one command produce one reload, and the
    /// label carries both ARNs.
    #[tokio::test(start_paused = true)]
    async fn requests_for_two_certificates_sharing_a_command_merge() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (tx, mut rx) = mpsc::unbounded_channel();

        drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            let fixture = &fixture;
            let sink = Arc::clone(&sink);
            let tx = tx.clone();
            async move {
                tx.send(paths_event(vec![fixture.enqueue(ARN_A)])).unwrap();
                tx.send(paths_event(vec![fixture.enqueue(ARN_B)])).unwrap();
                settle().await;
                tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                settle().await;

                assert_eq!(sink.count(), 1);
                let (command, label) = sink.calls().remove(0);
                assert_eq!(command, nginx_reload());
                assert!(label.contains(ARN_A), "{label}");
                assert!(label.contains(ARN_B), "{label}");
                let _ = shutdown.send(());
            }
        })
        .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn unknown_arn_is_rejected_and_never_reloads() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (tx, mut rx) = mpsc::unbounded_channel();

        drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            let fixture = &fixture;
            let sink = Arc::clone(&sink);
            let tx = tx.clone();
            async move {
                let path = fixture.enqueue(ARN_UNKNOWN);
                tx.send(paths_event(vec![path.clone()])).unwrap();
                settle().await;
                tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                settle().await;

                assert_eq!(sink.count(), 0, "an unknown ARN must not reload anything");
                assert!(!path.exists(), "the rejected request must be claimed");
                assert_eq!(
                    fixture.pending_entries(),
                    0,
                    "the rejected request must be deleted from the pending directory"
                );
                let _ = shutdown.send(());
            }
        })
        .unwrap();
    }

    /// Claim on pickup, delete on complete: the request leaves the inbox at
    /// once, waits in the pending directory through the hold window and the
    /// reload, and is deleted only once the reload completes.
    #[tokio::test(start_paused = true)]
    async fn a_request_is_claimed_on_pickup_and_deleted_once_its_reload_completes() {
        let fixture = Fixture::new();
        let (sink, gate) = RecordingSink::gated();
        let (tx, mut rx) = mpsc::unbounded_channel();

        drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            let fixture = &fixture;
            let sink = Arc::clone(&sink);
            let gate = Arc::clone(&gate);
            let tx = tx.clone();
            async move {
                let path = fixture.enqueue(ARN_A);
                tx.send(paths_event(vec![path.clone()])).unwrap();
                settle().await;

                assert!(!path.exists(), "a picked-up request must leave the inbox");
                assert_eq!(fixture.inbox_entries(), 0);
                let claimed = fixture.claimed(&path);
                assert!(claimed.is_file(), "held requests wait in pending/");

                tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                settle().await;
                assert_eq!(sink.count(), 1);
                assert!(claimed.is_file(), "deleted before its reload completed");

                gate.add_permits(1);
                settle().await;
                assert!(!claimed.exists(), "a completed request must be deleted");
                assert_eq!(fixture.pending_entries(), 0);
                let _ = shutdown.send(());
            }
        })
        .unwrap();
    }

    /// A failed reload's requests are deleted too: there is no retry.
    #[tokio::test(start_paused = true)]
    async fn a_failed_reloads_requests_are_deleted_too() {
        let fixture = Fixture::new();
        let sink = RecordingSink::failing();
        let (tx, mut rx) = mpsc::unbounded_channel();

        drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            let fixture = &fixture;
            let sink = Arc::clone(&sink);
            let tx = tx.clone();
            async move {
                tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                settle().await;

                let path = fixture.enqueue(ARN_A);
                tx.send(paths_event(vec![path.clone()])).unwrap();
                settle().await;

                assert_eq!(sink.count(), 1);
                assert!(!path.exists());
                assert_eq!(fixture.pending_entries(), 0);

                advance_by_seconds(PERIODIC_RESCAN_INTERVAL.as_secs() * 2).await;
                assert_eq!(sink.count(), 1, "a failed reload must not be retried");
                let _ = shutdown.send(());
            }
        })
        .unwrap();
    }

    /// A request that arrives while its command reloads joins the next batch:
    /// the first completion deletes only its own batch's files.
    #[tokio::test(start_paused = true)]
    async fn a_request_arriving_during_a_reload_is_deleted_by_the_next_one() {
        let fixture = Fixture::new();
        let (sink, gate) = RecordingSink::gated();
        let (tx, mut rx) = mpsc::unbounded_channel();

        drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            let fixture = &fixture;
            let sink = Arc::clone(&sink);
            let gate = Arc::clone(&gate);
            let tx = tx.clone();
            async move {
                tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                settle().await;

                let first = fixture.enqueue(ARN_A);
                tx.send(paths_event(vec![first.clone()])).unwrap();
                settle().await;
                assert_eq!(sink.count(), 1);

                let second = fixture.enqueue(ARN_B);
                tx.send(paths_event(vec![second.clone()])).unwrap();
                settle().await;
                assert_eq!(sink.count(), 1, "coalesced behind the running reload");
                assert!(fixture.claimed(&first).is_file());
                assert!(fixture.claimed(&second).is_file());

                gate.add_permits(1);
                settle().await;
                assert_eq!(sink.count(), 2, "the second batch should be running");
                assert_eq!(sink.calls()[1].1, ARN_B);
                assert!(!fixture.claimed(&first).exists());
                assert!(
                    fixture.claimed(&second).is_file(),
                    "the first completion must not delete the next batch's file"
                );

                gate.add_permits(1);
                settle().await;
                assert!(!fixture.claimed(&second).exists());
                assert_eq!(fixture.pending_entries(), 0);
                let _ = shutdown.send(());
            }
        })
        .unwrap();
    }

    /// A reused name, claimed again while the first request is still queued,
    /// overwrites the pending file and bundles both requests: one file, both
    /// ARNs in one batch, one reload, then the file is deleted.
    #[tokio::test(start_paused = true)]
    async fn a_name_claimed_twice_while_queued_bundles_into_one_reload() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (tx, mut rx) = mpsc::unbounded_channel();

        drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            let fixture = &fixture;
            let sink = Arc::clone(&sink);
            let tx = tx.clone();
            async move {
                let name = request_file_name(1728331740000, 1, "req-reused");
                let path = fixture.enqueue_named(&name, ARN_A);
                tx.send(paths_event(vec![path.clone()])).unwrap();
                settle().await;
                let path = fixture.enqueue_named(&name, ARN_B);
                tx.send(paths_event(vec![path.clone()])).unwrap();
                settle().await;
                assert_eq!(fixture.pending_entries(), 1, "one file for the name");

                tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                settle().await;

                assert_eq!(
                    sink.calls(),
                    vec![(nginx_reload(), format!("{ARN_A}, {ARN_B}"))]
                );
                assert_eq!(fixture.pending_entries(), 0);
                let _ = shutdown.send(());
            }
        })
        .unwrap();
    }

    /// A reused name claimed while its first request reloads: the file is in
    /// the running batch and the queued one, so it survives the first
    /// completion and is deleted after the second.
    #[tokio::test(start_paused = true)]
    async fn a_name_claimed_again_during_its_reload_survives_the_first_completion() {
        let fixture = Fixture::new();
        let (sink, gate) = RecordingSink::gated();
        let (tx, mut rx) = mpsc::unbounded_channel();

        drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            let fixture = &fixture;
            let sink = Arc::clone(&sink);
            let gate = Arc::clone(&gate);
            let tx = tx.clone();
            async move {
                tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                settle().await;

                let name = request_file_name(1728331740000, 1, "req-reused");
                let path = fixture.enqueue_named(&name, ARN_A);
                tx.send(paths_event(vec![path.clone()])).unwrap();
                settle().await;
                assert_eq!(sink.count(), 1);

                let path = fixture.enqueue_named(&name, ARN_B);
                tx.send(paths_event(vec![path.clone()])).unwrap();
                settle().await;
                let claimed = fixture.claimed(&path);

                gate.add_permits(1);
                settle().await;
                assert_eq!(sink.count(), 2, "the queued batch should be running");
                assert!(
                    claimed.is_file(),
                    "the running batch still references the name"
                );

                gate.add_permits(1);
                settle().await;
                assert!(!claimed.exists());
                let _ = shutdown.send(());
            }
        })
        .unwrap();
    }

    /// A reused name whose newer request is for another command: both
    /// commands reload, and the file is deleted only after both complete.
    #[tokio::test(start_paused = true)]
    async fn a_name_reused_for_another_command_is_deleted_after_both_reloads() {
        let fixture = Fixture::new();
        let (sink, gate) = RecordingSink::gated();
        let (tx, mut rx) = mpsc::unbounded_channel();

        drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            let fixture = &fixture;
            let sink = Arc::clone(&sink);
            let gate = Arc::clone(&gate);
            let tx = tx.clone();
            async move {
                tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                settle().await;

                let name = request_file_name(1728331740000, 1, "req-reused");
                let path = fixture.enqueue_named(&name, ARN_A);
                tx.send(paths_event(vec![path.clone()])).unwrap();
                settle().await;
                let path = fixture.enqueue_named(&name, ARN_C);
                tx.send(paths_event(vec![path.clone()])).unwrap();
                settle().await;
                let claimed = fixture.claimed(&path);

                let mut commands = sink.commands();
                commands.sort();
                let mut expected = vec![nginx_reload(), apache_reload()];
                expected.sort();
                assert_eq!(commands, expected, "both commands should be running");

                gate.add_permits(1);
                settle().await;
                assert!(
                    claimed.is_file(),
                    "the other command's running batch still references the name"
                );

                gate.add_permits(1);
                settle().await;
                assert!(!claimed.exists());
                assert_eq!(sink.count(), 2);
                let _ = shutdown.send(());
            }
        })
        .unwrap();
    }

    /// The duplicate-reload hazard of keeping a file until its reload
    /// completes, pinned: the claimed file is not in the inbox, so periodic
    /// rescans during a long reload neither queue it again nor count it as a
    /// missed event.
    #[tokio::test(start_paused = true)]
    async fn rescans_during_a_long_reload_do_not_rerun_it() {
        let fixture = Fixture::new();
        let (sink, gate) = RecordingSink::gated();
        let (mut watch, probe) = FakeWatch::new();
        let validator = ScriptedValidator::new(true);

        drive!(
            fixture,
            sink,
            watch,
            validator,
            |shutdown: oneshot::Sender<()>| {
                let fixture = &fixture;
                let sink = Arc::clone(&sink);
                let gate = Arc::clone(&gate);
                let probe = Arc::clone(&probe);
                async move {
                    tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                    settle().await;

                    let path = fixture.enqueue(ARN_A);
                    probe.send(paths_event(vec![path.clone()]));
                    settle().await;
                    assert_eq!(sink.count(), 1);

                    advance_by_seconds(PERIODIC_RESCAN_INTERVAL.as_secs() * 5).await;
                    probe.send(WatchEvent::Rescan(RescanReason::NeedRescan));
                    settle().await;
                    assert_eq!(sink.count(), 1);
                    assert!(fixture.claimed(&path).is_file());

                    gate.add_permits(1);
                    settle().await;
                    advance_by_seconds(PERIODIC_RESCAN_INTERVAL.as_secs()).await;
                    assert_eq!(sink.count(), 1, "a served request must not run again");
                    assert_eq!(probe.rebinds(), 0);
                    assert_eq!(fixture.pending_entries(), 0);
                    let _ = shutdown.send(());
                }
            }
        )
        .unwrap();
    }

    /// Startup recovery: requests a previous run left in the pending
    /// directory are held with the inbox's, merged per command, reloaded once
    /// when the window closes, and then deleted.
    #[tokio::test(start_paused = true)]
    async fn recovered_requests_reload_once_after_the_hold_window_merged_with_the_inbox() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (_tx, mut rx) = mpsc::unbounded_channel();

        let recovered_a = fixture.leave_pending(ARN_A);
        let recovered_c = fixture.leave_pending(ARN_C);
        // The same command as `recovered_a`, found by the startup scan.
        let inbox_b = fixture.enqueue(ARN_B);

        drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            let fixture = &fixture;
            let sink = Arc::clone(&sink);
            async move {
                settle().await;
                assert_eq!(sink.count(), 0, "recovered requests are held too");
                assert!(recovered_a.is_file() && recovered_c.is_file());
                assert!(fixture.claimed(&inbox_b).is_file());

                tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                settle().await;

                let mut calls = sink.calls();
                calls.sort();
                let mut expected = vec![
                    (nginx_reload(), format!("{ARN_A}, {ARN_B}")),
                    (apache_reload(), ARN_C.to_string()),
                ];
                expected.sort();
                assert_eq!(calls, expected);
                assert_eq!(fixture.pending_entries(), 0);
                assert_eq!(fixture.inbox_entries(), 0);
                let _ = shutdown.send(());
            }
        })
        .unwrap();
    }

    /// A recovered request for a certificate this watcher has no command for
    /// is deleted, like one claimed from the inbox.
    #[tokio::test(start_paused = true)]
    async fn a_recovered_request_for_an_unknown_arn_is_deleted() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (_tx, mut rx) = mpsc::unbounded_channel();

        let unknown = fixture.leave_pending(ARN_UNKNOWN);

        drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            let sink = Arc::clone(&sink);
            async move {
                tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                settle().await;

                assert_eq!(sink.count(), 0);
                assert!(!unknown.exists());
                let _ = shutdown.send(());
            }
        })
        .unwrap();
    }

    /// A claim that fails leaves the request in the inbox, unread, for the
    /// next scan: here the pending directory is gone between scans.
    #[tokio::test(start_paused = true)]
    async fn a_failed_claim_leaves_the_request_in_the_inbox() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (mut watch, probe) = FakeWatch::new();
        let validator = ScriptedValidator::new(true);

        drive!(
            fixture,
            sink,
            watch,
            validator,
            |shutdown: oneshot::Sender<()>| {
                let fixture = &fixture;
                let sink = Arc::clone(&sink);
                let probe = Arc::clone(&probe);
                async move {
                    tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                    settle().await;

                    fs::remove_dir(fixture.env.pending_dir()).unwrap();
                    let path = fixture.enqueue(ARN_A);
                    probe.send(paths_event(vec![path.clone()]));
                    settle().await;
                    assert_eq!(sink.count(), 0);
                    assert!(path.is_file(), "a failed claim must leave the request");

                    fs::create_dir(fixture.env.pending_dir()).unwrap();
                    advance_by_seconds(PERIODIC_RESCAN_INTERVAL.as_secs()).await;
                    assert_eq!(sink.count(), 1, "the next scan claims it");
                    assert!(!path.exists());
                    let _ = shutdown.send(());
                }
            }
        )
        .unwrap();
    }

    /// The real per-scan check covers the pending directory too: while it is
    /// missing, the inbox is not scanned and the request stays there.
    #[tokio::test(start_paused = true)]
    async fn a_failed_pending_directory_check_skips_the_scan() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (mut watch, probe) = FakeWatch::new();
        let validator = FileSystemValidator(&fixture.filesystem);

        drive!(
            fixture,
            sink,
            watch,
            validator,
            |shutdown: oneshot::Sender<()>| {
                let fixture = &fixture;
                let sink = Arc::clone(&sink);
                let probe = Arc::clone(&probe);
                async move {
                    tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                    settle().await;

                    fs::remove_dir(fixture.env.pending_dir()).unwrap();
                    fs::write(fixture.env.pending_dir(), "not a directory").unwrap();
                    let path = fixture.enqueue(ARN_A);
                    probe.send(WatchEvent::Rescan(RescanReason::NeedRescan));
                    settle().await;
                    assert_eq!(sink.count(), 0, "a failed check must skip the listing");
                    assert!(path.is_file());

                    fs::remove_file(fixture.env.pending_dir()).unwrap();
                    fs::create_dir(fixture.env.pending_dir()).unwrap();
                    advance_by_seconds(PERIODIC_RESCAN_INTERVAL.as_secs()).await;
                    assert_eq!(sink.count(), 1);
                    assert!(!path.exists());
                    let _ = shutdown.send(());
                }
            }
        )
        .unwrap();
    }

    /// The temp-suffix exception, at loop level: a *fully valid* request body
    /// under a temp name must not reload and must not be deleted, or the
    /// ACM provider's rename races the pickup.
    #[tokio::test(start_paused = true)]
    async fn temp_files_never_reload_even_with_valid_contents() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (tx, mut rx) = mpsc::unbounded_channel();

        drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            let fixture = &fixture;
            let sink = Arc::clone(&sink);
            let tx = tx.clone();
            async move {
                let request = new_request(ARN_A);
                let name = format!(
                    "{}{}",
                    request_file_name(1728331740000, 1, &request.command_id),
                    REQUEST_TEMP_SUFFIX
                );
                let path = fixture.write_raw(&name, &serde_json::to_string(&request).unwrap());
                tx.send(paths_event(vec![path.clone()])).unwrap();
                settle().await;
                tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                settle().await;

                assert_eq!(sink.count(), 0);
                assert!(path.exists(), "a mid-write file must be left alone");
                let _ = shutdown.send(());
            }
        })
        .unwrap();
    }

    /// The allowlist, at loop level, on both the event path and the scan path:
    /// each of these is a fully valid request under a name that does not end
    /// in `.cmd`. None may reload, and none may be deleted, which is what
    /// would happen to any of them that was read.
    #[tokio::test(start_paused = true)]
    async fn a_valid_request_under_a_non_request_name_never_reloads() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (tx, mut rx) = mpsc::unbounded_channel();

        drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            let fixture = &fixture;
            let sink = Arc::clone(&sink);
            let tx = tx.clone();
            async move {
                let body = serde_json::to_string(&new_request(ARN_A)).unwrap();
                let paths: Vec<PathBuf> = [
                    "nothing-like-a-request",
                    // The older name: the command_id on its own.
                    "req-1b4e28ba-2fa1-11d2-883f-0016d3cca427",
                    // Right shape, wrong extension.
                    "1728331740000-001-req-abcd.txt",
                    "x.tmp",
                    WCP_TEMP_NAME,
                    "x.cmd.tmp",
                    "x.txt",
                    "x",
                    ".cmd",
                    "x.CMD",
                    "x.cmdx",
                ]
                .into_iter()
                .map(|name| fixture.write_raw(name, &body))
                .collect();

                for path in &paths {
                    assert!(!is_request_file(path), "{}", path.display());
                    tx.send(paths_event(vec![path.clone()])).unwrap();
                }
                settle().await;
                tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                settle().await;

                // The scan path too, after the hold window, so anything it
                // admitted would reload at once.
                tx.send(WatchEvent::Rescan(RescanReason::NeedRescan))
                    .unwrap();
                settle().await;

                assert_eq!(sink.count(), 0, "a non-`.cmd` file must never reload");
                for path in &paths {
                    assert!(
                        path.exists(),
                        "{} must be left alone, not picked up",
                        path.display()
                    );
                }
                let _ = shutdown.send(());
            }
        })
        .unwrap();
    }

    /// Only the extension is checked: a valid request in any `.cmd` file
    /// reloads and is deleted once it has, even when its stem is not the
    /// ACM provider's `{epoch_millis}-{sequence}-{command_id}` shape.
    #[tokio::test(start_paused = true)]
    async fn a_valid_request_in_any_cmd_file_reloads() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (tx, mut rx) = mpsc::unbounded_channel();

        drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            let fixture = &fixture;
            let sink = Arc::clone(&sink);
            let tx = tx.clone();
            async move {
                let body = serde_json::to_string(&new_request(ARN_A)).unwrap();
                let paths: Vec<PathBuf> = [
                    "x.cmd",
                    // Non-numeric epoch_millis.
                    "nope-001-req-abcd.cmd",
                ]
                .into_iter()
                .map(|name| fixture.write_raw(name, &body))
                .collect();

                for path in &paths {
                    tx.send(paths_event(vec![path.clone()])).unwrap();
                }
                settle().await;
                tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                settle().await;

                // Same certificate, so one merged reload.
                assert_eq!(sink.commands(), vec![nginx_reload()]);
                for path in &paths {
                    assert!(
                        !path.exists(),
                        "{} should have been picked up",
                        path.display()
                    );
                }
                assert_eq!(fixture.inbox_entries(), 0);
                assert_eq!(fixture.pending_entries(), 0, "deleted once reloaded");
                let _ = shutdown.send(());
            }
        })
        .unwrap();
    }

    /// A directory named like a request passes the name check on the event
    /// path. It is not claimed, so it is left in place: no reload, no error,
    /// the loop carries on.
    #[tokio::test(start_paused = true)]
    async fn a_directory_named_like_a_request_is_skipped() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (tx, mut rx) = mpsc::unbounded_channel();

        let result = drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            let fixture = &fixture;
            let sink = Arc::clone(&sink);
            let tx = tx.clone();
            async move {
                tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                settle().await;

                let dir =
                    fixture
                        .env
                        .inbox_dir()
                        .join(request_file_name(1728331740000, 1, "req-dir"));
                fs::create_dir(&dir).unwrap();
                assert!(is_request_file(&dir), "{}", dir.display());
                tx.send(paths_event(vec![dir.clone()])).unwrap();
                tx.send(WatchEvent::Rescan(RescanReason::NeedRescan))
                    .unwrap();
                settle().await;

                assert_eq!(sink.count(), 0);
                assert!(dir.is_dir(), "the directory must be left in place");
                assert_eq!(fixture.pending_entries(), 0);

                // Still working afterwards.
                tx.send(paths_event(vec![fixture.enqueue(ARN_A)])).unwrap();
                settle().await;
                assert_eq!(sink.commands(), vec![nginx_reload()]);
                let _ = shutdown.send(());
            }
        });

        assert!(result.is_ok());
    }

    /// The hyphenated-`command_id` regression: a naive three-way split on `-`
    /// would reject every name the ACM provider writes today.
    #[tokio::test(start_paused = true)]
    async fn a_hyphenated_command_id_in_the_filename_still_reloads() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (tx, mut rx) = mpsc::unbounded_channel();

        drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            let fixture = &fixture;
            let sink = Arc::clone(&sink);
            let tx = tx.clone();
            async move {
                let mut request = new_request(ARN_A);
                request.command_id = "1b4e28ba-2fa1-11d2-883f-0016d3cca427".to_string();
                let name = request_file_name(1728331740000, 1, &request.command_id);
                assert_eq!(name.matches('-').count(), 6, "{name}");

                let path = fixture.write_raw(&name, &serde_json::to_string(&request).unwrap());
                tx.send(paths_event(vec![path.clone()])).unwrap();
                settle().await;
                tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                settle().await;

                assert_eq!(sink.commands(), vec![nginx_reload()]);
                assert!(!path.exists(), "an accepted request is claimed on pickup");
                assert_eq!(fixture.pending_entries(), 0, "deleted once reloaded");
                let _ = shutdown.send(());
            }
        })
        .unwrap();
    }

    /// The full cross-binary round trip: the ACM provider's writer produces
    /// the file, the watcher's read path consumes it and reloads.
    #[tokio::test(start_paused = true)]
    async fn a_request_written_by_the_acm_providers_reloads_end_to_end() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (tx, mut rx) = mpsc::unbounded_channel();

        drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            let fixture = &fixture;
            let sink = Arc::clone(&sink);
            let tx = tx.clone();
            async move {
                let path = fixture.enqueue_via_acm_provider(ARN_A);
                assert_eq!(path.parent().unwrap(), fixture.env.inbox_dir());

                tx.send(paths_event(vec![path.clone()])).unwrap();
                settle().await;
                tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                settle().await;

                assert_eq!(sink.commands(), vec![nginx_reload()]);
                assert!(!path.exists());
                assert_eq!(fixture.pending_entries(), 0);
                let _ = shutdown.send(());
            }
        })
        .unwrap();
    }

    /// The producer-consumer contract through `admit`: a request
    /// byte-identical to what the WCP writer
    /// (`aws_certificatemanager_provider/src/watcher_request.rs`) produces,
    /// under its file name, is accepted, reloads and is then deleted.
    #[tokio::test(start_paused = true)]
    async fn a_request_in_the_wcp_producers_format_reloads() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (tx, mut rx) = mpsc::unbounded_channel();

        drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            let fixture = &fixture;
            let sink = Arc::clone(&sink);
            let tx = tx.clone();
            async move {
                let path = fixture.write_raw(WCP_REQUEST_NAME, &wcp_request_body(ARN_A));
                tx.send(paths_event(vec![path.clone()])).unwrap();
                settle().await;
                tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                settle().await;

                assert_eq!(sink.calls(), vec![(nginx_reload(), ARN_A.to_string())]);
                assert!(!path.exists(), "an accepted request is claimed on pickup");
                assert_eq!(fixture.pending_entries(), 0, "deleted once reloaded");
                let _ = shutdown.send(());
            }
        })
        .unwrap();
    }

    /// The older `cert_arn` key is not an alias: such a request does not
    /// parse, so it never reloads and is deleted like any other unparseable
    /// file.
    #[tokio::test(start_paused = true)]
    async fn a_request_with_the_old_cert_arn_key_never_reloads() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (tx, mut rx) = mpsc::unbounded_channel();

        drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            let fixture = &fixture;
            let sink = Arc::clone(&sink);
            let tx = tx.clone();
            async move {
                let path = fixture.write_raw(
                    &request_file_name(1728331740000, 1, "req-old-key"),
                    &format!(
                        r#"{{"command_id":"req-old-key","cert_arn":"{ARN_A}","created_at":"2024-05-01T12:00:00Z"}}"#
                    ),
                );
                tx.send(paths_event(vec![path.clone()])).unwrap();
                settle().await;
                tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                settle().await;

                assert_eq!(sink.count(), 0, "a `cert_arn` request must not reload");
                assert!(!path.exists(), "an unparseable request is still claimed");
                assert_eq!(
                    fixture.pending_entries(),
                    0,
                    "an unparseable request is deleted from the pending directory"
                );
                let _ = shutdown.send(());
            }
        })
        .unwrap();
    }

    /// A `.cmd` file whose contents are unusable is skipped, not fatal, and
    /// deleted once claimed, so it is never read again. An unrelated file is
    /// not even read, and is left in place.
    #[tokio::test(start_paused = true)]
    async fn an_unparseable_file_is_skipped_not_fatal() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (tx, mut rx) = mpsc::unbounded_channel();

        let result = drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            let fixture = &fixture;
            let sink = Arc::clone(&sink);
            let tx = tx.clone();
            async move {
                // Not JSON at all.
                let garbage =
                    fixture.write_raw("1728331740000-001-req-aaaa.cmd", "not json at all");
                // Valid JSON, wrong shape: no `certificate_arn`.
                let wrong_shape = fixture.write_raw(
                    "1728331740000-002-req-bbbb.cmd",
                    r#"{"command_id":"req-bbbb","created_at":"2024-05-01T12:00:00Z"}"#,
                );
                // Truncated mid-write, which is what this actually guards.
                let truncated =
                    fixture.write_raw("1728331740000-003-req-cccc.cmd", r#"{"command_id":"#);
                // An unrelated file on the shared volume: not a request file,
                // so it is ignored by name without being read.
                let unrelated = fixture.write_raw("README", "nothing to do with requests");
                assert!(!is_request_file(&unrelated), "{}", unrelated.display());

                for path in [&garbage, &wrong_shape, &truncated] {
                    assert!(is_request_file(path), "{}", path.display());
                }
                for path in [&garbage, &wrong_shape, &truncated, &unrelated] {
                    tx.send(paths_event(vec![path.clone()])).unwrap();
                }
                settle().await;
                tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                settle().await;

                assert_eq!(sink.count(), 0);
                for path in [&garbage, &wrong_shape, &truncated] {
                    assert!(
                        !path.exists() && !fixture.claimed(path).exists(),
                        "an unparseable request must be claimed and deleted: {}",
                        path.display()
                    );
                }
                assert!(unrelated.exists(), "a non-request file must be left alone");
                assert_eq!(fixture.pending_entries(), 0);
                let _ = shutdown.send(());
            }
        });

        assert!(result.is_ok(), "an unparseable request must not be fatal");
    }

    /// A filename whose `command_id` segment disagrees with the body is still
    /// accepted — the body wins and the mismatch is only warned about.
    #[tokio::test(start_paused = true)]
    async fn filename_command_id_mismatch_warns_but_still_reloads() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (tx, mut rx) = mpsc::unbounded_channel();

        drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            let fixture = &fixture;
            let sink = Arc::clone(&sink);
            let tx = tx.clone();
            async move {
                let request = new_request(ARN_A);
                let path = fixture.write_raw(
                    &request_file_name(1728331740000, 1, "req-something-else"),
                    &serde_json::to_string(&request).unwrap(),
                );
                tx.send(paths_event(vec![path.clone()])).unwrap();
                settle().await;
                tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                settle().await;

                assert_eq!(sink.commands(), vec![nginx_reload()]);
                let _ = shutdown.send(());
            }
        })
        .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn one_reload_per_command_in_flight() {
        let fixture = Fixture::new();
        let (sink, gate) = RecordingSink::gated();
        let (tx, mut rx) = mpsc::unbounded_channel();

        drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            let fixture = &fixture;
            let sink = Arc::clone(&sink);
            let gate = Arc::clone(&gate);
            let tx = tx.clone();
            async move {
                tx.send(paths_event(vec![fixture.enqueue(ARN_A)])).unwrap();
                settle().await;
                tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                settle().await;
                assert_eq!(sink.count(), 1, "the first reload should be running");

                // A second request for the same command while the first is
                // still running must not start a second reload.
                tx.send(paths_event(vec![fixture.enqueue(ARN_B)])).unwrap();
                settle().await;
                assert_eq!(sink.count(), 1, "two reloads ran for one command");

                // Letting the first finish releases the coalesced batch.
                gate.add_permits(1);
                settle().await;
                assert_eq!(sink.count(), 2);
                assert_eq!(sink.calls()[1].1, ARN_B);

                let _ = shutdown.send(());
            }
        })
        .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn burst_produces_at_most_two_reloads_per_command() {
        let fixture = Fixture::new();
        let (sink, gate) = RecordingSink::gated();
        let (tx, mut rx) = mpsc::unbounded_channel();

        drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            let fixture = &fixture;
            let sink = Arc::clone(&sink);
            let gate = Arc::clone(&gate);
            let tx = tx.clone();
            async move {
                tx.send(paths_event(vec![fixture.enqueue(ARN_A)])).unwrap();
                settle().await;
                tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                settle().await;

                for _ in 0..5 {
                    tx.send(paths_event(vec![fixture.enqueue(ARN_A)])).unwrap();
                    tx.send(paths_event(vec![fixture.enqueue(ARN_B)])).unwrap();
                }
                settle().await;
                assert_eq!(sink.count(), 1);

                gate.add_permits(1);
                settle().await;
                assert_eq!(
                    sink.count(),
                    2,
                    "a burst should collapse into one more reload"
                );

                let _ = shutdown.send(());
            }
        })
        .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn distinct_commands_reload_concurrently() {
        let fixture = Fixture::new();
        let (sink, _gate) = RecordingSink::gated();
        let (tx, mut rx) = mpsc::unbounded_channel();

        drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            let fixture = &fixture;
            let sink = Arc::clone(&sink);
            let tx = tx.clone();
            async move {
                tx.send(paths_event(vec![fixture.enqueue(ARN_A)])).unwrap();
                settle().await;
                tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                settle().await;
                assert_eq!(sink.count(), 1);

                // Neither reload can finish, so a second one starting proves
                // different commands are not serialized against each other.
                tx.send(paths_event(vec![fixture.enqueue(ARN_C)])).unwrap();
                settle().await;

                let mut commands = sink.commands();
                commands.sort();
                let mut expected = vec![nginx_reload(), apache_reload()];
                expected.sort();
                assert_eq!(commands, expected);

                let _ = shutdown.send(());
            }
        })
        .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn need_rescan_triggers_a_full_scan() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (tx, mut rx) = mpsc::unbounded_channel();

        drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            let fixture = &fixture;
            let sink = Arc::clone(&sink);
            let tx = tx.clone();
            async move {
                tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                settle().await;

                // A request that produced no event of its own.
                fixture.enqueue(ARN_A);
                tx.send(WatchEvent::Rescan(RescanReason::NeedRescan))
                    .unwrap();
                settle().await;

                assert_eq!(sink.count(), 1, "a rescan must not drop the request");
                let _ = shutdown.send(());
            }
        })
        .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn watch_error_triggers_a_full_scan() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (tx, mut rx) = mpsc::unbounded_channel();

        drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            let fixture = &fixture;
            let sink = Arc::clone(&sink);
            let tx = tx.clone();
            async move {
                tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                settle().await;

                fixture.enqueue(ARN_A);
                tx.send(WatchEvent::Rescan(RescanReason::WatchError(
                    "inotify queue overflow".to_string(),
                )))
                .unwrap();
                settle().await;

                assert_eq!(sink.count(), 1);
                let _ = shutdown.send(());
            }
        })
        .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn periodic_rescan_finds_a_missed_request() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (_tx, mut rx) = mpsc::unbounded_channel();

        drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            let fixture = &fixture;
            let sink = Arc::clone(&sink);
            async move {
                tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                settle().await;

                // No event at all: only the periodic rescan can find this.
                fixture.enqueue(ARN_A);
                settle().await;
                assert_eq!(sink.count(), 0);

                tokio::time::advance(PERIODIC_RESCAN_INTERVAL).await;
                settle().await;

                assert_eq!(sink.count(), 1);
                let _ = shutdown.send(());
            }
        })
        .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn the_initial_scan_finds_a_request_that_landed_before_the_watch() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (_tx, mut rx) = mpsc::unbounded_channel();

        // Already on disk before `run` is ever polled.
        fixture.enqueue(ARN_A);

        drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            let sink = Arc::clone(&sink);
            async move {
                tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                settle().await;

                assert_eq!(sink.count(), 1);
                let _ = shutdown.send(());
            }
        })
        .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_duplicate_event_does_not_rerun_a_handled_request() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (tx, mut rx) = mpsc::unbounded_channel();

        drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            let fixture = &fixture;
            let sink = Arc::clone(&sink);
            let tx = tx.clone();
            async move {
                tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                settle().await;

                let path = fixture.enqueue(ARN_A);
                tx.send(paths_event(vec![path.clone()])).unwrap();
                settle().await;
                assert_eq!(sink.count(), 1);

                // The same path again, after the file is gone.
                tx.send(paths_event(vec![path])).unwrap();
                settle().await;
                assert_eq!(sink.count(), 1, "a stale event must not rerun a reload");

                let _ = shutdown.send(());
            }
        })
        .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn reload_failure_does_not_stop_the_loop() {
        let fixture = Fixture::new();
        let sink = RecordingSink::failing();
        let (tx, mut rx) = mpsc::unbounded_channel();

        drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            let fixture = &fixture;
            let sink = Arc::clone(&sink);
            let tx = tx.clone();
            async move {
                tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                settle().await;

                tx.send(paths_event(vec![fixture.enqueue(ARN_A)])).unwrap();
                settle().await;
                assert_eq!(sink.count(), 1);

                tx.send(paths_event(vec![fixture.enqueue(ARN_C)])).unwrap();
                settle().await;
                assert_eq!(sink.count(), 2, "the loop stopped after a failed reload");

                let _ = shutdown.send(());
            }
        })
        .unwrap();
    }

    /// A panicking reload is handled as a failed one: its request is deleted
    /// and its command is free to reload again.
    #[tokio::test(start_paused = true)]
    async fn a_panicking_reload_does_not_wedge_its_command() {
        let fixture = Fixture::new();
        let sink = RecordingSink::panicking_once();
        let (tx, mut rx) = mpsc::unbounded_channel();

        drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            let fixture = &fixture;
            let sink = Arc::clone(&sink);
            let tx = tx.clone();
            async move {
                tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                settle().await;

                let first = fixture.enqueue(ARN_A);
                tx.send(paths_event(vec![first.clone()])).unwrap();
                settle().await;
                assert_eq!(sink.count(), 1);
                assert!(
                    !fixture.claimed(&first).exists(),
                    "the panicked reload's request was not deleted"
                );

                // B shares A's command.
                tx.send(paths_event(vec![fixture.enqueue(ARN_B)])).unwrap();
                settle().await;
                assert_eq!(
                    sink.count(),
                    2,
                    "the command never reloaded again after a panic"
                );
                assert_eq!(fixture.pending_entries(), 0);

                let _ = shutdown.send(());
            }
        })
        .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_exits_the_loop() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (_tx, mut rx) = mpsc::unbounded_channel();

        let result = drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            async move {
                let _ = shutdown.send(());
            }
        });

        assert!(result.is_ok());
    }

    /// A closed event channel means the `notify` backend is gone. The loop
    /// exits with an error so the process exits non-zero.
    #[tokio::test(start_paused = true)]
    async fn a_closed_watch_channel_is_an_error() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        drop(tx);

        let result = drive!(fixture, sink, rx, |_shutdown: oneshot::Sender<()>| {
            async move {
                // Never signals shutdown: the loop must exit on its own.
                settle().await;
            }
        });

        assert!(matches!(result, Err(RunError::WatchChannelClosed { .. })));
    }

    // -- rebinding the watch --

    /// The closed-channel exit, through a watch that could rebind: `None` is
    /// never answered with a rebind. `FakeWatch` asserts that too.
    #[tokio::test(start_paused = true)]
    async fn a_closed_watch_channel_is_an_error_and_never_rebinds() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (mut watch, probe) = FakeWatch::new();
        let validator = ScriptedValidator::new(true);
        probe.close();

        let result = drive!(
            fixture,
            sink,
            watch,
            validator,
            |_shutdown: oneshot::Sender<()>| {
                async move {
                    settle().await;
                }
            }
        );

        assert!(matches!(result, Err(RunError::WatchChannelClosed { .. })));
        assert_eq!(probe.rebinds(), 0);
    }

    /// Trigger (a): one rebind, then the rescan finds the request.
    #[tokio::test(start_paused = true)]
    async fn a_watch_error_rebinds_once_then_rescans() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (mut watch, probe) = FakeWatch::new();
        let validator = ScriptedValidator::new(true);

        drive!(
            fixture,
            sink,
            watch,
            validator,
            |shutdown: oneshot::Sender<()>| {
                let fixture = &fixture;
                let sink = Arc::clone(&sink);
                let probe = Arc::clone(&probe);
                async move {
                    tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                    settle().await;

                    fixture.enqueue(ARN_A);
                    probe.send(watch_error());
                    settle().await;

                    assert_eq!(probe.rebinds(), 1);
                    assert_eq!(sink.count(), 1, "the rescan after the rebind admits it");

                    advance_by_seconds(PERIODIC_RESCAN_INTERVAL.as_secs() * 2).await;
                    assert_eq!(probe.rebinds(), 1, "nothing else should rebind");
                    let _ = shutdown.send(());
                }
            }
        )
        .unwrap();
    }

    /// Trigger (b): the inbox itself removed or renamed.
    #[tokio::test(start_paused = true)]
    async fn an_inbox_replaced_event_rebinds_once_then_rescans() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (mut watch, probe) = FakeWatch::new();
        let validator = ScriptedValidator::new(true);

        drive!(
            fixture,
            sink,
            watch,
            validator,
            |shutdown: oneshot::Sender<()>| {
                let fixture = &fixture;
                let sink = Arc::clone(&sink);
                let probe = Arc::clone(&probe);
                async move {
                    tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                    settle().await;

                    fixture.enqueue(ARN_A);
                    probe.send(WatchEvent::Rescan(RescanReason::InboxReplaced));
                    settle().await;

                    assert_eq!(probe.rebinds(), 1);
                    assert_eq!(sink.count(), 1);

                    advance_by_seconds(PERIODIC_RESCAN_INTERVAL.as_secs() * 2).await;
                    assert_eq!(probe.rebinds(), 1);
                    let _ = shutdown.send(());
                }
            }
        )
        .unwrap();
    }

    /// Trigger (c): validation failing and then passing again rebinds once,
    /// before the listing, and a request that arrived meanwhile is picked up
    /// without also counting as a missed event.
    #[tokio::test(start_paused = true)]
    async fn validation_recovery_rebinds_once() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (mut watch, probe) = FakeWatch::new();
        let validator = ScriptedValidator::new(true);

        drive!(
            fixture,
            sink,
            watch,
            validator,
            |shutdown: oneshot::Sender<()>| {
                let fixture = &fixture;
                let sink = Arc::clone(&sink);
                let probe = Arc::clone(&probe);
                let validator = &validator;
                async move {
                    tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                    settle().await;

                    validator.set(false);
                    advance_by_seconds(PERIODIC_RESCAN_INTERVAL.as_secs()).await;
                    assert_eq!(probe.rebinds(), 0, "a failure alone does not rebind");

                    fixture.enqueue(ARN_A);
                    validator.set(true);
                    advance_by_seconds(PERIODIC_RESCAN_INTERVAL.as_secs()).await;
                    assert_eq!(probe.rebinds(), 1);
                    assert_eq!(sink.count(), 1);

                    advance_by_seconds(PERIODIC_RESCAN_INTERVAL.as_secs() * 2).await;
                    assert_eq!(probe.rebinds(), 1);
                    let _ = shutdown.send(());
                }
            }
        )
        .unwrap();
    }

    /// Trigger (d): a periodic scan that admits a request no event reported.
    #[tokio::test(start_paused = true)]
    async fn a_periodic_scan_that_finds_a_missed_request_rebinds_once() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (mut watch, probe) = FakeWatch::new();
        let validator = ScriptedValidator::new(true);

        drive!(
            fixture,
            sink,
            watch,
            validator,
            |shutdown: oneshot::Sender<()>| {
                let fixture = &fixture;
                let sink = Arc::clone(&sink);
                let probe = Arc::clone(&probe);
                async move {
                    tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                    settle().await;

                    fixture.enqueue(ARN_A);
                    advance_by_seconds(PERIODIC_RESCAN_INTERVAL.as_secs()).await;
                    assert_eq!(sink.count(), 1);
                    assert_eq!(probe.rebinds(), 1);

                    advance_by_seconds(PERIODIC_RESCAN_INTERVAL.as_secs() * 2).await;
                    assert_eq!(probe.rebinds(), 1);
                    let _ = shutdown.send(());
                }
            }
        )
        .unwrap();
    }

    /// An unparseable `.cmd` file found by a periodic scan is deleted, not
    /// queued; it is not a missed request, so it must not rebind.
    #[tokio::test(start_paused = true)]
    async fn an_unparseable_request_found_by_a_periodic_scan_does_not_rebind() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (mut watch, probe) = FakeWatch::new();
        let validator = ScriptedValidator::new(true);

        drive!(
            fixture,
            sink,
            watch,
            validator,
            |shutdown: oneshot::Sender<()>| {
                let fixture = &fixture;
                let probe = Arc::clone(&probe);
                async move {
                    tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                    settle().await;

                    let garbage = fixture.write_raw("1728331740000-001-req-aaaa.cmd", "not json");
                    advance_by_seconds(PERIODIC_RESCAN_INTERVAL.as_secs() * 3).await;

                    assert!(!garbage.exists());
                    assert_eq!(fixture.pending_entries(), 0);
                    assert_eq!(probe.rebinds(), 0);
                    let _ = shutdown.send(());
                }
            }
        )
        .unwrap();
    }

    /// Only the periodic scan counts what it finds as missed: the startup
    /// scan and a `NeedRescan` scan are expected to find requests.
    #[tokio::test(start_paused = true)]
    async fn startup_and_need_rescan_scans_do_not_rebind() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (mut watch, probe) = FakeWatch::new();
        let validator = ScriptedValidator::new(true);

        // Found by the startup scan.
        fixture.enqueue(ARN_A);

        drive!(
            fixture,
            sink,
            watch,
            validator,
            |shutdown: oneshot::Sender<()>| {
                let fixture = &fixture;
                let sink = Arc::clone(&sink);
                let probe = Arc::clone(&probe);
                async move {
                    tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                    settle().await;
                    assert_eq!(sink.count(), 1);

                    fixture.enqueue(ARN_C);
                    probe.send(WatchEvent::Rescan(RescanReason::NeedRescan));
                    settle().await;
                    assert_eq!(sink.count(), 2);

                    advance_by_seconds(REBIND_MIN_INTERVAL.as_secs() * 2).await;
                    assert_eq!(probe.rebinds(), 0);
                    let _ = shutdown.send(());
                }
            }
        )
        .unwrap();
    }

    /// Watch errors inside the minimum interval are coalesced: no scan each,
    /// and one rebind once the interval is over.
    #[tokio::test(start_paused = true)]
    async fn a_burst_of_watch_errors_rebinds_once_per_interval() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (mut watch, probe) = FakeWatch::new();
        let validator = ScriptedValidator::new(true);

        drive!(
            fixture,
            sink,
            watch,
            validator,
            |shutdown: oneshot::Sender<()>| {
                let probe = Arc::clone(&probe);
                let validator = &validator;
                async move {
                    tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                    settle().await;

                    probe.send(watch_error());
                    settle().await;
                    assert_eq!(probe.rebinds(), 1);
                    let scans = validator.calls();

                    // On the new channel, all inside the interval.
                    for _ in 0..100 {
                        probe.send(watch_error());
                    }
                    settle().await;
                    assert_eq!(probe.rebinds(), 1, "a burst must not rebind each time");
                    assert_eq!(validator.calls(), scans, "a coalesced error must not scan");

                    advance_by_seconds(REBIND_MIN_INTERVAL.as_secs()).await;
                    assert_eq!(probe.rebinds(), 2, "one rebind for the whole burst");
                    assert_eq!(validator.calls(), scans + 1);

                    advance_by_seconds(REBIND_MIN_INTERVAL.as_secs() * 2).await;
                    assert_eq!(probe.rebinds(), 2);
                    let _ = shutdown.send(());
                }
            }
        )
        .unwrap();
    }

    /// A failing rebind backs off 5, 10, 20, 40, then 60 seconds, never stops
    /// the loop, and periodic scans keep admitting requests meanwhile. Its
    /// failures do not count towards the scan-failure exit either: this runs
    /// past `SCAN_FAILURE_EXIT_WINDOW`.
    #[tokio::test(start_paused = true)]
    async fn a_failing_rebind_backs_off_and_never_exits() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (mut watch, probe) = FakeWatch::new();
        let validator = ScriptedValidator::new(true);
        probe.set_failing(true);

        drive!(
            fixture,
            sink,
            watch,
            validator,
            |shutdown: oneshot::Sender<()>| {
                let fixture = &fixture;
                let sink = Arc::clone(&sink);
                let probe = Arc::clone(&probe);
                async move {
                    tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                    settle().await;

                    probe.send(watch_error());
                    settle().await;
                    assert_eq!(probe.rebinds(), 1);

                    // 5 + 10 + 20 + 40 + 60 + 60, and one second over.
                    advance_by_seconds(196).await;
                    assert_eq!(probe.gaps(), vec![5, 10, 20, 40, 60, 60]);

                    fixture.enqueue(ARN_A);
                    advance_by_seconds(PERIODIC_RESCAN_INTERVAL.as_secs()).await;
                    assert_eq!(sink.count(), 1, "periodic scans keep working");

                    let before = probe.rebinds();
                    advance_by_seconds(SCAN_FAILURE_EXIT_WINDOW.as_secs()).await;
                    assert!(probe.rebinds() > before, "retries continue");
                    assert!(probe.gaps().iter().skip(5).all(|&gap| gap == 60));

                    probe.set_failing(false);
                    advance_by_seconds(REBIND_MAX_BACKOFF.as_secs()).await;
                    let succeeded = probe.rebinds();
                    advance_by_seconds(REBIND_MAX_BACKOFF.as_secs() * 2).await;
                    assert_eq!(probe.rebinds(), succeeded, "a success stops the retries");

                    assert!(shutdown.send(()).is_ok(), "the loop exited");
                }
            }
        )
        .unwrap();
    }

    /// A failed validation skips the listing and the event path alike: the
    /// request stays on disk, and is picked up once validation passes.
    #[tokio::test(start_paused = true)]
    async fn a_failed_validation_skips_the_scan_and_event_admission() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (mut watch, probe) = FakeWatch::new();
        let validator = ScriptedValidator::new(true);

        drive!(
            fixture,
            sink,
            watch,
            validator,
            |shutdown: oneshot::Sender<()>| {
                let fixture = &fixture;
                let sink = Arc::clone(&sink);
                let probe = Arc::clone(&probe);
                let validator = &validator;
                async move {
                    tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                    settle().await;

                    validator.set(false);
                    let listed = fixture.enqueue(ARN_A);
                    probe.send(WatchEvent::Rescan(RescanReason::NeedRescan));
                    settle().await;
                    assert_eq!(sink.count(), 0, "a failed validation must skip the listing");
                    assert!(listed.exists());

                    let evented = fixture.enqueue(ARN_C);
                    probe.send(paths_event(vec![evented.clone()]));
                    settle().await;
                    assert_eq!(sink.count(), 0, "events are not admitted while invalid");
                    assert!(evented.exists());

                    validator.set(true);
                    advance_by_seconds(PERIODIC_RESCAN_INTERVAL.as_secs()).await;
                    assert_eq!(sink.count(), 2);
                    assert!(!listed.exists() && !evented.exists());
                    let _ = shutdown.send(());
                }
            }
        )
        .unwrap();
    }

    /// An `InboxReplaced` inside the minimum interval cannot scan yet, but
    /// still stops event admission until the deferred rebind's validated scan.
    #[tokio::test(start_paused = true)]
    async fn inbox_replaced_gates_events_until_the_next_validated_scan() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (mut watch, probe) = FakeWatch::new();
        let validator = ScriptedValidator::new(true);

        drive!(
            fixture,
            sink,
            watch,
            validator,
            |shutdown: oneshot::Sender<()>| {
                let fixture = &fixture;
                let sink = Arc::clone(&sink);
                let probe = Arc::clone(&probe);
                async move {
                    tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                    settle().await;

                    probe.send(watch_error());
                    settle().await;
                    assert_eq!(probe.rebinds(), 1);

                    probe.send(WatchEvent::Rescan(RescanReason::InboxReplaced));
                    let path = fixture.enqueue(ARN_A);
                    probe.send(paths_event(vec![path.clone()]));
                    settle().await;
                    assert_eq!(sink.count(), 0);
                    assert!(path.exists());

                    advance_by_seconds(REBIND_MIN_INTERVAL.as_secs()).await;
                    assert_eq!(probe.rebinds(), 2);
                    assert_eq!(sink.count(), 1);
                    assert!(!path.exists());
                    let _ = shutdown.send(());
                }
            }
        )
        .unwrap();
    }

    /// Ten minutes without a successful scan exits; rebind state is
    /// irrelevant.
    #[tokio::test(start_paused = true)]
    async fn ten_minutes_without_a_successful_scan_exits() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (mut watch, _probe) = FakeWatch::new();
        let validator = ScriptedValidator::new(false);

        let result = drive!(
            fixture,
            sink,
            watch,
            validator,
            |shutdown: oneshot::Sender<()>| {
                async move {
                    // Held, not sent: dropping it would shut the loop down.
                    let held = shutdown;
                    advance_by_seconds(SCAN_FAILURE_EXIT_WINDOW.as_secs() - 1).await;
                    assert!(!held.is_closed(), "the loop exited inside the window");
                    advance_by_seconds(1).await;
                }
            }
        );

        let Err(RunError::InboxUnavailable { since, .. }) = result else {
            panic!("expected InboxUnavailable, got {result:?}");
        };
        assert_eq!(since, SCAN_FAILURE_EXIT_WINDOW);
    }

    /// One successful scan at nine minutes restarts the window.
    #[tokio::test(start_paused = true)]
    async fn a_successful_scan_resets_the_exit_window() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (mut watch, _probe) = FakeWatch::new();
        let validator = ScriptedValidator::new(false);

        let result = drive!(
            fixture,
            sink,
            watch,
            validator,
            |shutdown: oneshot::Sender<()>| {
                let validator = &validator;
                async move {
                    // The ninth periodic scan, at 540 s, succeeds.
                    advance_by_seconds(PERIODIC_RESCAN_INTERVAL.as_secs() * 8).await;
                    validator.set(true);
                    advance_by_seconds(PERIODIC_RESCAN_INTERVAL.as_secs()).await;
                    validator.set(false);

                    // 1080 s: 540 s since the success, so still running.
                    advance_by_seconds(PERIODIC_RESCAN_INTERVAL.as_secs() * 9).await;
                    assert!(!shutdown.is_closed(), "the loop exited inside the window");

                    // 1140 s: 600 s since the success.
                    advance_by_seconds(PERIODIC_RESCAN_INTERVAL.as_secs()).await;
                }
            }
        );

        let Err(RunError::InboxUnavailable { since, .. }) = result else {
            panic!("expected InboxUnavailable, got {result:?}");
        };
        assert_eq!(since, SCAN_FAILURE_EXIT_WINDOW);
    }

    /// The real per-scan check, end to end: a removed inbox is not scanned,
    /// and once it is recreated the deferred rebind validates, rebinds and
    /// picks up what is in it.
    #[tokio::test(start_paused = true)]
    async fn a_removed_inbox_is_rebound_once_it_is_recreated() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (mut watch, probe) = FakeWatch::new();
        let validator = FileSystemValidator(&fixture.filesystem);

        drive!(
            fixture,
            sink,
            watch,
            validator,
            |shutdown: oneshot::Sender<()>| {
                let fixture = &fixture;
                let sink = Arc::clone(&sink);
                let probe = Arc::clone(&probe);
                async move {
                    tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                    settle().await;

                    fs::remove_dir(fixture.env.inbox_dir()).unwrap();
                    probe.send(WatchEvent::Rescan(RescanReason::InboxReplaced));
                    settle().await;
                    assert_eq!(probe.rebinds(), 0, "never bind to a path that failed");

                    fs::create_dir(fixture.env.inbox_dir()).unwrap();
                    fixture.enqueue(ARN_A);
                    // The first retry, after the first backoff step.
                    advance_by_seconds(REBIND_MIN_INTERVAL.as_secs()).await;
                    assert_eq!(probe.rebinds(), 1);
                    assert_eq!(sink.count(), 1);
                    let _ = shutdown.send(());
                }
            }
        )
        .unwrap();
    }

    /// The real per-scan check refuses an inbox replaced by a symlink: the
    /// valid request behind it is neither read nor deleted.
    #[cfg(unix)]
    #[tokio::test(start_paused = true)]
    async fn a_symlinked_inbox_is_not_scanned() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (mut watch, probe) = FakeWatch::new();
        let validator = FileSystemValidator(&fixture.filesystem);

        drive!(
            fixture,
            sink,
            watch,
            validator,
            |shutdown: oneshot::Sender<()>| {
                let fixture = &fixture;
                let sink = Arc::clone(&sink);
                let probe = Arc::clone(&probe);
                async move {
                    tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                    settle().await;

                    let inbox = fixture.env.inbox_dir();
                    let elsewhere = fixture.env.requests_dir().join("elsewhere");
                    fs::rename(&inbox, &elsewhere).unwrap();
                    std::os::unix::fs::symlink(&elsewhere, &inbox).unwrap();
                    let path = fixture.enqueue(ARN_A);

                    probe.send(WatchEvent::Rescan(RescanReason::NeedRescan));
                    settle().await;

                    assert_eq!(sink.count(), 0);
                    assert!(
                        path.exists(),
                        "a request behind a symlink must be left alone"
                    );
                    assert_eq!(probe.rebinds(), 0);
                    let _ = shutdown.send(());
                }
            }
        )
        .unwrap();
    }

    // -- crash safety: what an exit leaves in the pending directory --

    /// Shutdown drops a running reload, and its request stays in the pending
    /// directory for the next start to recover.
    #[tokio::test(start_paused = true)]
    async fn shutdown_during_a_reload_leaves_its_request_in_pending() {
        let fixture = Fixture::new();
        let (sink, _gate) = RecordingSink::gated();
        let (_tx, mut rx) = mpsc::unbounded_channel();
        let claimed = fixture.claimed(&fixture.enqueue(ARN_A));

        let result = drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            let sink = Arc::clone(&sink);
            async move {
                tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                settle().await;
                assert_eq!(sink.count(), 1, "the reload should be running");
                let _ = shutdown.send(());
            }
        });

        assert!(result.is_ok());
        assert!(
            claimed.is_file(),
            "an unfinished reload's request was deleted"
        );
        assert_eq!(fixture.recoverable_arns(), vec![ARN_A.to_string()]);
    }

    /// The scan-failure exit keeps both a running batch and the one queued
    /// behind it.
    #[tokio::test(start_paused = true)]
    async fn an_inbox_unavailable_exit_leaves_queued_and_running_requests_in_pending() {
        let fixture = Fixture::new();
        let (sink, _gate) = RecordingSink::gated();
        let (mut watch, probe) = FakeWatch::new();
        let validator = ScriptedValidator::new(true);
        let running = fixture.enqueue(ARN_A);

        let result = drive!(
            fixture,
            sink,
            watch,
            validator,
            |shutdown: oneshot::Sender<()>| {
                let fixture = &fixture;
                let sink = Arc::clone(&sink);
                let probe = Arc::clone(&probe);
                let validator = &validator;
                async move {
                    // Held, not sent: dropping it would shut the loop down.
                    let _held = shutdown;
                    settle().await;
                    assert!(fixture.claimed(&running).is_file());
                    // The startup scan passed; every scan from here on fails.
                    validator.set(false);

                    tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                    settle().await;
                    assert_eq!(sink.count(), 1, "the reload should be running");

                    // Admitted from its event: no scan has failed yet.
                    let queued = fixture.enqueue(ARN_B);
                    probe.send(paths_event(vec![queued.clone()]));
                    settle().await;
                    assert!(fixture.claimed(&queued).is_file());
                    assert_eq!(sink.count(), 1, "coalesced behind the running reload");

                    advance_by_seconds(
                        SCAN_FAILURE_EXIT_WINDOW.as_secs() - STARTUP_HOLD_WINDOW.as_secs(),
                    )
                    .await;
                }
            }
        );

        assert!(
            matches!(result, Err(RunError::InboxUnavailable { .. })),
            "{result:?}"
        );
        assert_eq!(
            fixture.recoverable_arns(),
            vec![ARN_A.to_string(), ARN_B.to_string()]
        );
    }

    /// The closed-channel exit keeps both a running batch and the one queued
    /// behind it.
    #[tokio::test(start_paused = true)]
    async fn a_closed_watch_channel_exit_leaves_queued_and_running_requests_in_pending() {
        let fixture = Fixture::new();
        let (sink, _gate) = RecordingSink::gated();
        let (mut watch, probe) = FakeWatch::new();
        let validator = ScriptedValidator::new(true);

        let result = drive!(
            fixture,
            sink,
            watch,
            validator,
            |shutdown: oneshot::Sender<()>| {
                let fixture = &fixture;
                let sink = Arc::clone(&sink);
                let probe = Arc::clone(&probe);
                async move {
                    let _held = shutdown;
                    tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                    settle().await;

                    probe.send(paths_event(vec![fixture.enqueue(ARN_A)]));
                    settle().await;
                    probe.send(paths_event(vec![fixture.enqueue(ARN_B)]));
                    settle().await;
                    assert_eq!(sink.count(), 1, "one running, one queued");

                    probe.close();
                    settle().await;
                }
            }
        );

        assert!(
            matches!(result, Err(RunError::WatchChannelClosed { .. })),
            "{result:?}"
        );
        assert_eq!(
            fixture.recoverable_arns(),
            vec![ARN_A.to_string(), ARN_B.to_string()]
        );
    }

    /// A name a previous run left in the pending directory, written to the
    /// inbox again for another certificate on the same command: the startup
    /// claim overwrites it, both certificates reload once after the hold
    /// window, and the file is deleted only once that reload completes.
    #[tokio::test(start_paused = true)]
    async fn a_recovered_name_claimed_again_at_startup_reloads_once_with_both_arns() {
        let fixture = Fixture::new();
        let (sink, gate) = RecordingSink::gated();
        let (_tx, mut rx) = mpsc::unbounded_channel();

        let name = request_file_name(1728331740000, 1, "req-reused");
        let left =
            fixture.write_pending(&name, &serde_json::to_string(&new_request(ARN_A)).unwrap());
        fixture.enqueue_named(&name, ARN_B);

        drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            let fixture = &fixture;
            let sink = Arc::clone(&sink);
            let gate = Arc::clone(&gate);
            async move {
                settle().await;
                assert_eq!(fixture.inbox_entries(), 0, "the startup scan claims it");
                assert_eq!(fixture.pending_entries(), 1);
                assert_eq!(sink.count(), 0, "held like any other request");

                tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                settle().await;
                assert_eq!(
                    sink.calls(),
                    vec![(nginx_reload(), format!("{ARN_A}, {ARN_B}"))]
                );
                assert!(left.is_file(), "deleted before its reload completed");

                gate.add_permits(1);
                settle().await;
                assert!(!left.exists());

                advance_by_seconds(PERIODIC_RESCAN_INTERVAL.as_secs() * 2).await;
                assert_eq!(sink.count(), 1);
                let _ = shutdown.send(());
            }
        })
        .unwrap();
    }

    /// A request for an unknown certificate, claimed under a name a running
    /// batch covers: the rejection keeps the file, and the running batch's
    /// completion deletes it.
    #[tokio::test(start_paused = true)]
    async fn an_unknown_arn_request_under_a_referenced_name_is_kept_until_that_batch_completes() {
        let fixture = Fixture::new();
        let (sink, gate) = RecordingSink::gated();
        let (tx, mut rx) = mpsc::unbounded_channel();

        drive!(fixture, sink, rx, |shutdown: oneshot::Sender<()>| {
            let fixture = &fixture;
            let sink = Arc::clone(&sink);
            let gate = Arc::clone(&gate);
            let tx = tx.clone();
            async move {
                tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                settle().await;

                let name = request_file_name(1728331740000, 1, "req-reused");
                let path = fixture.enqueue_named(&name, ARN_A);
                tx.send(paths_event(vec![path.clone()])).unwrap();
                settle().await;
                assert_eq!(sink.count(), 1);

                fixture.enqueue_named(&name, ARN_UNKNOWN);
                tx.send(paths_event(vec![path.clone()])).unwrap();
                settle().await;
                assert!(!path.exists(), "the rejected request must be claimed");
                let claimed = fixture.claimed(&path);
                assert!(
                    claimed.is_file(),
                    "the running batch still references the name"
                );

                gate.add_permits(1);
                settle().await;
                assert!(!claimed.exists());
                assert_eq!(sink.count(), 1, "the unknown ARN must not reload");
                let _ = shutdown.send(());
            }
        })
        .unwrap();
    }

    // -- pending-file bookkeeping, driving `Loop` directly --

    /// A `Loop` outside `run`, so a test can complete reloads in any order.
    /// Reloads are spawned onto `sink` as usual; nothing reads their
    /// completions.
    fn direct_loop<'a, S: ReloadSink, W: InboxWatcher, V: InboxValidator>(
        fixture: &'a Fixture,
        validator: &'a V,
        watch: &'a mut W,
        sink: Arc<S>,
        done_tx: mpsc::UnboundedSender<Done>,
    ) -> Loop<'a, S, W, V> {
        let now = Instant::now();
        Loop {
            env: &fixture.env,
            validator,
            watch,
            inbox: fixture.env.inbox_dir(),
            pending_dir: fixture.env.pending_dir(),
            plan: Arc::clone(&fixture.plan),
            sink,
            queued: BTreeMap::new(),
            in_flight: BTreeMap::new(),
            done_tx,
            holding: true,
            validated: true,
            last_success: now,
            rebind: RebindState {
                due: false,
                next_attempt: now,
                failures: 0,
                triggers: 0,
            },
        }
    }

    /// Every name a queued or running batch covers.
    fn referenced_files<S: ReloadSink, W, V>(state: &Loop<'_, S, W, V>) -> BTreeSet<OsString> {
        state
            .queued
            .values()
            .chain(state.in_flight.values())
            .flat_map(|batch| batch.files.iter().cloned())
            .collect()
    }

    /// Writes a request for `arn` into the inbox under `name` and admits it.
    fn admit_named<S: ReloadSink, W: InboxWatcher, V: InboxValidator>(
        state: &mut Loop<'_, S, W, V>,
        fixture: &Fixture,
        name: &str,
        arn: &str,
    ) {
        let path = fixture.enqueue_named(name, arn);
        state.admit(&path);
        assert!(!path.exists(), "'{name}' should have been claimed");
    }

    fn names(names: &[&str]) -> BTreeSet<OsString> {
        names.iter().map(OsString::from).collect()
    }

    /// The pending directory holds exactly the files the batches reference,
    /// after every kind of step: admit, same-name overwrite, start, success,
    /// failure, and an overwrite for another command.
    #[tokio::test(start_paused = true)]
    async fn the_pending_directory_matches_the_batches_after_every_step() {
        #[derive(Debug)]
        enum Step {
            Admit(&'static str, &'static str),
            ReleaseHold,
            /// Completes the running reload of the command for this ARN.
            Complete(&'static str, bool),
        }
        use Step::{Admit, Complete, ReleaseHold};

        let steps: &[(Step, &[&str])] = &[
            (Admit("a.cmd", ARN_A), &["a.cmd"]),
            // Overwritten while queued, same command.
            (Admit("a.cmd", ARN_B), &["a.cmd"]),
            (Admit("b.cmd", ARN_A), &["a.cmd", "b.cmd"]),
            (ReleaseHold, &["a.cmd", "b.cmd"]),
            // Overwritten while running: queued again behind it.
            (Admit("a.cmd", ARN_A), &["a.cmd", "b.cmd"]),
            // Overwritten for the other command, which starts at once.
            (Admit("a.cmd", ARN_C), &["a.cmd", "b.cmd"]),
            (Admit("u.cmd", ARN_UNKNOWN), &["a.cmd", "b.cmd"]),
            // Rejected, but nginx's running batch still covers `b.cmd`.
            (Admit("b.cmd", ARN_UNKNOWN), &["a.cmd", "b.cmd"]),
            // `a.cmd` is still queued for nginx and running for apache.
            (Complete(ARN_A, true), &["a.cmd"]),
            // `a.cmd` is now running for nginx.
            (Complete(ARN_C, false), &["a.cmd"]),
            (Admit("c.cmd", ARN_C), &["a.cmd", "c.cmd"]),
            (Complete(ARN_C, false), &["a.cmd"]),
            (Complete(ARN_A, true), &[]),
        ];

        let fixture = Fixture::new();
        let validator = ScriptedValidator::new(true);
        let (_tx, mut rx) = mpsc::unbounded_channel::<WatchEvent>();
        let (sink, _gate) = RecordingSink::gated();
        let (done_tx, _done_rx) = mpsc::unbounded_channel();
        let mut state = direct_loop(&fixture, &validator, &mut rx, sink, done_tx);

        for (i, (step, expected)) in steps.iter().enumerate() {
            match *step {
                Admit(name, arn) => admit_named(&mut state, &fixture, name, arn),
                ReleaseHold => state.release_hold(),
                Complete(arn, ok) => {
                    let id = fixture.plan.command_for(arn).unwrap();
                    assert!(state.in_flight.contains_key(&id), "step {i}: not running");
                    let result = if ok {
                        Ok(())
                    } else {
                        Err(io::Error::other("scripted reload failure"))
                    };
                    state.complete(id, result);
                }
            }

            let on_disk = fixture.pending_names();
            assert_eq!(on_disk, names(expected), "step {i}: {step:?}");
            assert_eq!(on_disk, referenced_files(&state), "step {i}: {step:?}");
        }
    }

    /// Two commands running at once, completed in the opposite order to the
    /// one they started in: each completion deletes only its own files.
    #[tokio::test(start_paused = true)]
    async fn reloads_completed_out_of_order_delete_only_their_own_files() {
        let fixture = Fixture::new();
        let validator = ScriptedValidator::new(true);
        let (_tx, mut rx) = mpsc::unbounded_channel::<WatchEvent>();
        let (sink, _gate) = RecordingSink::gated();
        let (done_tx, _done_rx) = mpsc::unbounded_channel();
        let mut state = direct_loop(&fixture, &validator, &mut rx, Arc::clone(&sink), done_tx);
        state.holding = false;

        admit_named(&mut state, &fixture, "a.cmd", ARN_A);
        admit_named(&mut state, &fixture, "b.cmd", ARN_B);
        admit_named(&mut state, &fixture, "c.cmd", ARN_C);
        settle().await;
        let nginx = fixture.plan.command_for(ARN_A).unwrap();
        let apache = fixture.plan.command_for(ARN_C).unwrap();
        assert!(state.in_flight.contains_key(&nginx) && state.in_flight.contains_key(&apache));
        assert_eq!(sink.count(), 2, "both commands should be running at once");

        state.complete(apache, Ok(()));
        assert_eq!(fixture.pending_names(), names(&["a.cmd", "b.cmd"]));

        // `b.cmd` was queued behind nginx's first reload, which now ends.
        state.complete(nginx, Ok(()));
        assert_eq!(fixture.pending_names(), names(&["b.cmd"]));

        state.complete(nginx, Ok(()));
        assert!(fixture.pending_names().is_empty());
    }

    // -- rebind and validation edges --

    /// Triggers that arrive while a failed rebind backs off join the pending
    /// attempt: they neither bring it forward nor push it back, and do not
    /// change the failure count the next backoff is computed from.
    #[tokio::test(start_paused = true)]
    async fn triggers_during_a_rebind_backoff_leave_its_schedule_alone() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (mut watch, probe) = FakeWatch::new();
        let validator = ScriptedValidator::new(true);
        probe.set_failing(true);

        drive!(
            fixture,
            sink,
            watch,
            validator,
            |shutdown: oneshot::Sender<()>| {
                let fixture = &fixture;
                let sink = Arc::clone(&sink);
                let probe = Arc::clone(&probe);
                async move {
                    // t = 30 s: attempts at 30, 35 and 45 s fail; the fourth
                    // is due at 65 s.
                    tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                    settle().await;
                    probe.send(watch_error());
                    settle().await;
                    advance_by_seconds(15).await;
                    assert_eq!(probe.gaps(), vec![5, 10]);

                    // t = 50 s.
                    advance_by_seconds(5).await;
                    probe.send(watch_error());
                    probe.send(WatchEvent::Rescan(RescanReason::InboxReplaced));
                    settle().await;
                    assert_eq!(probe.rebinds(), 3, "a trigger brought the attempt forward");

                    // No event: the periodic scan at 60 s finds it.
                    fixture.enqueue(ARN_A);
                    advance_by_seconds(10).await;
                    assert_eq!(sink.count(), 1, "the periodic scan should have queued it");
                    assert_eq!(probe.rebinds(), 3, "a missed request brought it forward");

                    advance_by_seconds(4).await;
                    assert_eq!(probe.rebinds(), 3);
                    advance_by_seconds(1).await;
                    assert_eq!(probe.rebinds(), 4, "a trigger pushed the attempt back");

                    // The fourth failure's backoff is 40 s: the count was
                    // neither reset nor advanced by the triggers.
                    advance_by_seconds(40).await;
                    assert_eq!(probe.gaps(), vec![5, 10, 20, 40]);
                    let _ = shutdown.send(());
                }
            }
        )
        .unwrap();
    }

    /// While validation fails and a rebind is due, each failed check moves
    /// the next attempt into the future, so the rebind timer cannot spin.
    /// Runs 30 minutes; one passing periodic scan every nine minutes keeps
    /// the exit window from closing, and the rebind stays due throughout.
    #[tokio::test(start_paused = true)]
    async fn a_due_rebind_does_not_spin_while_validation_fails() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (mut watch, probe) = FakeWatch::new();
        let validator = ScriptedValidator::new(true);
        probe.set_failing(true);

        drive!(
            fixture,
            sink,
            watch,
            validator,
            |shutdown: oneshot::Sender<()>| {
                let probe = Arc::clone(&probe);
                let validator = &validator;
                async move {
                    let origin = Instant::now();
                    let elapsed = || origin.elapsed().as_secs();

                    tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                    settle().await;
                    validator.set(false);
                    probe.send(watch_error());
                    settle().await;

                    for passes_at in [540, 1080, 1620] {
                        advance_by_seconds(passes_at - 1 - elapsed()).await;
                        validator.set(true);
                        advance_by_seconds(1).await;
                        validator.set(false);
                    }
                    let end = STARTUP_HOLD_WINDOW.as_secs() + 30 * 60;
                    advance_by_seconds(end - elapsed()).await;

                    // Every check is a scan. Over the 1800 s after the hold
                    // window, scans come only from:
                    // - the periodic timer: 30 ticks, at 60 s .. 1800 s;
                    // - the rebind timer: one per backoff slot, at most 4
                    //   ramp-up slots (5, 10, 20, 40 s) plus one per
                    //   `REBIND_MAX_BACKOFF` of the 1800 s, 34;
                    // - the startup scan and the watch error's scan: 2.
                    // Today that is exactly 64. A timer that did not move on
                    // would check on every poll.
                    let calls = validator.calls();
                    assert!(
                        calls <= 30 + 34 + 2,
                        "{calls} checks: the rebind timer spun"
                    );
                    assert!(calls > 30, "{calls} checks: the periodic scans stopped");
                    assert!(
                        probe.rebinds() <= 3,
                        "only the three passing scans may attempt a rebind"
                    );
                    assert!(shutdown.send(()).is_ok(), "the loop exited");
                }
            }
        )
        .unwrap();
    }

    /// Trigger (d) counts only what a periodic scan queued: a request for an
    /// unknown certificate is deleted, not queued. A missed request found by
    /// a later scan still rebinds.
    #[tokio::test(start_paused = true)]
    async fn a_periodic_scan_that_finds_only_an_unknown_arn_request_does_not_rebind() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (mut watch, probe) = FakeWatch::new();
        let validator = ScriptedValidator::new(true);

        drive!(
            fixture,
            sink,
            watch,
            validator,
            |shutdown: oneshot::Sender<()>| {
                let fixture = &fixture;
                let sink = Arc::clone(&sink);
                let probe = Arc::clone(&probe);
                async move {
                    tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                    settle().await;

                    let unknown = fixture.enqueue(ARN_UNKNOWN);
                    advance_by_seconds(PERIODIC_RESCAN_INTERVAL.as_secs()).await;
                    assert!(!unknown.exists());
                    assert_eq!(fixture.pending_entries(), 0);
                    assert_eq!(probe.rebinds(), 0);

                    fixture.enqueue(ARN_A);
                    advance_by_seconds(PERIODIC_RESCAN_INTERVAL.as_secs()).await;
                    assert_eq!(sink.count(), 1);
                    assert_eq!(probe.rebinds(), 1, "a queued missed request rebinds");
                    let _ = shutdown.send(());
                }
            }
        )
        .unwrap();
    }

    /// Trigger (d) counts only what a periodic scan queued: a request it
    /// could not claim stays in the inbox and is not counted. Once the claim
    /// works, the next scan queues it and rebinds.
    #[tokio::test(start_paused = true)]
    async fn a_periodic_scan_whose_claim_fails_does_not_rebind() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (mut watch, probe) = FakeWatch::new();
        // The real check would refuse the scan with the pending directory
        // missing.
        let validator = ScriptedValidator::new(true);

        drive!(
            fixture,
            sink,
            watch,
            validator,
            |shutdown: oneshot::Sender<()>| {
                let fixture = &fixture;
                let sink = Arc::clone(&sink);
                let probe = Arc::clone(&probe);
                async move {
                    tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                    settle().await;

                    fs::remove_dir(fixture.env.pending_dir()).unwrap();
                    let path = fixture.enqueue(ARN_A);
                    advance_by_seconds(PERIODIC_RESCAN_INTERVAL.as_secs()).await;
                    assert!(path.is_file(), "a failed claim must leave the request");
                    assert_eq!(sink.count(), 0);
                    assert_eq!(probe.rebinds(), 0);

                    fs::create_dir(fixture.env.pending_dir()).unwrap();
                    advance_by_seconds(PERIODIC_RESCAN_INTERVAL.as_secs()).await;
                    assert_eq!(sink.count(), 1);
                    assert_eq!(probe.rebinds(), 1, "a queued missed request rebinds");
                    let _ = shutdown.send(());
                }
            }
        )
        .unwrap();
    }

    /// Requests admitted from events while scans fail are not successful
    /// scans: the exit still comes `SCAN_FAILURE_EXIT_WINDOW` after the last
    /// scan that passed.
    #[tokio::test(start_paused = true)]
    async fn admitted_events_do_not_reset_the_scan_failure_exit_window() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (mut watch, probe) = FakeWatch::new();
        let validator = ScriptedValidator::new(true);

        let result = drive!(
            fixture,
            sink,
            watch,
            validator,
            |shutdown: oneshot::Sender<()>| {
                let fixture = &fixture;
                let probe = Arc::clone(&probe);
                let validator = &validator;
                async move {
                    let _held = shutdown;
                    // The startup scan, at 0 s, is the last to pass.
                    settle().await;
                    validator.set(false);

                    // One request every 10 s. Until the periodic scan at 60 s
                    // fails, events are still admitted.
                    let mut sent = Vec::new();
                    for _ in 0..59 {
                        advance_by_seconds(10).await;
                        let path = fixture.enqueue(ARN_A);
                        probe.send(paths_event(vec![path.clone()]));
                        settle().await;
                        sent.push(path);
                    }
                    let admitted = sent.iter().filter(|path| !path.exists()).count();
                    assert_eq!(admitted, 5, "the events at 10 .. 50 s are admitted");

                    advance_by_seconds(10).await;
                }
            }
        );

        let Err(RunError::InboxUnavailable { since, .. }) = result else {
            panic!("expected InboxUnavailable, got {result:?}");
        };
        assert_eq!(since, SCAN_FAILURE_EXIT_WINDOW);
    }

    /// Trigger (c) fires on the change to passing, not on passing: passing
    /// scans never rebind, and any run of failures then a pass rebinds once.
    #[tokio::test(start_paused = true)]
    async fn validation_recovery_rebinds_only_on_a_change_to_passing() {
        let fixture = Fixture::new();
        let sink = RecordingSink::new();
        let (mut watch, probe) = FakeWatch::new();
        let validator = ScriptedValidator::new(true);

        // Each periodic scan's validation, and the rebinds after it.
        let script = [
            (true, 0),
            (true, 0),
            (false, 0),
            (false, 0),
            (true, 1),
            (true, 1),
            (false, 1),
            (true, 2),
            (true, 2),
        ];

        drive!(
            fixture,
            sink,
            watch,
            validator,
            |shutdown: oneshot::Sender<()>| {
                let probe = Arc::clone(&probe);
                let validator = &validator;
                async move {
                    tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                    settle().await;

                    for (i, (ok, rebinds)) in script.into_iter().enumerate() {
                        validator.set(ok);
                        advance_by_seconds(PERIODIC_RESCAN_INTERVAL.as_secs()).await;
                        assert_eq!(probe.rebinds(), rebinds, "after scan {i} (ok = {ok})");
                    }
                    let _ = shutdown.send(());
                }
            }
        )
        .unwrap();
    }

    /// A rebind and its rescans while a reload runs: the claimed request is
    /// not in the inbox, so it is neither queued again nor counted as
    /// missed, and its one reload deletes it.
    #[tokio::test(start_paused = true)]
    async fn a_rebind_during_a_reload_does_not_rerun_it() {
        let fixture = Fixture::new();
        let (sink, gate) = RecordingSink::gated();
        let (mut watch, probe) = FakeWatch::new();
        let validator = ScriptedValidator::new(true);

        drive!(
            fixture,
            sink,
            watch,
            validator,
            |shutdown: oneshot::Sender<()>| {
                let fixture = &fixture;
                let sink = Arc::clone(&sink);
                let gate = Arc::clone(&gate);
                let probe = Arc::clone(&probe);
                async move {
                    tokio::time::advance(STARTUP_HOLD_WINDOW).await;
                    settle().await;

                    let path = fixture.enqueue(ARN_A);
                    probe.send(paths_event(vec![path.clone()]));
                    settle().await;
                    assert_eq!(sink.count(), 1);
                    let claimed = fixture.claimed(&path);

                    probe.send(watch_error());
                    settle().await;
                    advance_by_seconds(REBIND_MIN_INTERVAL.as_secs()).await;
                    probe.send(WatchEvent::Rescan(RescanReason::InboxReplaced));
                    settle().await;
                    assert_eq!(probe.rebinds(), 2);
                    assert_eq!(sink.count(), 1, "a rebind's rescan reran the reload");
                    assert!(claimed.is_file());

                    advance_by_seconds(PERIODIC_RESCAN_INTERVAL.as_secs()).await;
                    assert_eq!(probe.rebinds(), 2, "the running request counted as missed");

                    gate.add_permits(1);
                    settle().await;
                    assert!(!claimed.exists());

                    advance_by_seconds(PERIODIC_RESCAN_INTERVAL.as_secs() * 2).await;
                    assert_eq!(sink.count(), 1);
                    assert_eq!(probe.rebinds(), 2);
                    let _ = shutdown.send(());
                }
            }
        )
        .unwrap();
    }

    #[test]
    fn rebind_backoff_doubles_to_the_cap() {
        let secs: Vec<u64> = (1..=8).map(|n| rebind_backoff(n).as_secs()).collect();
        assert_eq!(secs, vec![5, 10, 20, 40, 60, 60, 60, 60]);
        assert_eq!(rebind_backoff(u32::MAX), REBIND_MAX_BACKOFF);
    }
}
