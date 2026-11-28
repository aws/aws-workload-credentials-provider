//! Consumes status records published by configured WCP watchers.
//!
//! The tracker is intentionally in-memory. A provider restart forgets requests
//! from the previous process, so those status records are logged and removed
//! as unknown rather than treated as a durable command ledger.

use std::collections::{BTreeSet, HashMap};
use std::ffi::{OsStr, OsString};
#[cfg(any(windows, not(any(unix, windows))))]
use std::fs;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aws_workload_credentials_provider_common::config::validate_watcher_id;
use aws_workload_credentials_provider_common::watcher_request::{
    self, RefreshRequest, RequestsRoot,
};
use aws_workload_credentials_provider_common::watcher_status::{
    command_id_from_status_filename, is_status_candidate, StatusOutcome, StatusRecord,
    StatusValidationError, MAX_STATUS_BYTES,
};
use log::{debug, error, info, warn};
use tokio::sync::{oneshot, Notify};
use tokio_util::sync::CancellationToken;

const OUTBOX_DIR: &str = "outbox";
pub(crate) const STATUS_RESCAN_INTERVAL: Duration = Duration::from_secs(30);
/// Rescan interval while at least one request waits for a status.
const ACTIVE_RESCAN_INTERVAL: Duration = Duration::from_secs(1);
/// Most outbox entries one scan reads. The TLS container writes this
/// directory, so a flood of files must not hold the shared scanner.
const MAX_OUTBOX_ENTRIES_PER_SCAN: usize = 4096;
/// Most statuses one scan handles; each is deleted, so the next scan moves on.
const MAX_STATUSES_PER_SCAN: usize = 256;
/// Most statuses kept in `unreadable` or `undeletable`. Only a full scan prunes
/// them, so this bounds them while an outbox stays over the scan limit.
const MAX_REMEMBERED_STATUSES: usize = MAX_OUTBOX_ENTRIES_PER_SCAN;

/// Adds `path` to `set` and says whether it was new. A full set is cleared
/// first, so a status in it is at worst warned about once more.
fn remember(set: &Mutex<BTreeSet<PathBuf>>, path: PathBuf) -> bool {
    let mut set = set.lock().unwrap();
    if set.len() >= MAX_REMEMBERED_STATUSES && !set.contains(&path) {
        set.clear();
    }
    set.insert(path)
}

/// The config's watcher ID rule, the same one the request writer applies.
fn is_safe_watcher_id(watcher_id: &str) -> bool {
    validate_watcher_id("watcher_id", watcher_id).is_ok()
}

#[derive(Debug)]
struct TrackedRequest {
    watcher_id: String,
    request: RefreshRequest,
    completion: oneshot::Sender<StatusRecord>,
    registration: Arc<()>,
}

/// A transient registration for one published watcher request.
pub(crate) struct PendingRequest {
    command_id: String,
    tracked: Arc<Mutex<HashMap<String, TrackedRequest>>>,
    completion: oneshot::Receiver<StatusRecord>,
    registration: Arc<()>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PendingWaitError {
    Deadline,
    Cancelled,
}

impl PendingRequest {
    pub(crate) async fn wait(
        mut self,
        deadline: tokio::time::Instant,
        cancel: &CancellationToken,
    ) -> Result<StatusRecord, PendingWaitError> {
        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(PendingWaitError::Cancelled),
            // Ahead of the deadline so a status found on the same poll wins.
            status = &mut self.completion => status.map_err(|_| PendingWaitError::Cancelled),
            _ = tokio::time::sleep_until(deadline) => Err(PendingWaitError::Deadline),
        };
        self.unregister();
        result
    }

    fn unregister(&mut self) {
        let mut tracked = self.tracked.lock().unwrap();
        if tracked
            .get(&self.command_id)
            .is_some_and(|request| Arc::ptr_eq(&request.registration, &self.registration))
        {
            tracked.remove(&self.command_id);
        }
    }
}

impl Drop for PendingRequest {
    fn drop(&mut self) {
        self.unregister();
    }
}

struct OpenOutbox {
    path: PathBuf,
    directory: File,
    #[cfg(windows)]
    _root: File,
    #[cfg(windows)]
    _watcher: File,
}

impl OpenOutbox {
    #[cfg(unix)]
    fn new(path: PathBuf, directory: File) -> Self {
        Self { path, directory }
    }

    #[cfg(windows)]
    fn new(path: PathBuf, directory: File, root: File, watcher: File) -> Self {
        Self {
            path,
            directory,
            _root: root,
            _watcher: watcher,
        }
    }
}

/// Tracks requests queued to watchers and consumes their status outboxes.
pub(crate) struct WatcherStatusTracker {
    requests_dir: PathBuf,
    watcher_ids: BTreeSet<String>,
    notify: Notify,
    tracked: Arc<Mutex<HashMap<String, TrackedRequest>>>,
    /// Watchers already warned about as predating status reports.
    pre_status_warned: Mutex<BTreeSet<String>>,
    /// Watchers already warned about an outbox scan hitting its limit.
    scan_limit_warned: Mutex<BTreeSet<String>>,
    /// Status names left in place and warned about once: unreadable ones,
    /// retried on later scans, and directories, which are never statuses.
    unreadable: Mutex<BTreeSet<PathBuf>>,
    /// Statuses already handled that couldn't be deleted, skipped on later scans.
    undeletable: Mutex<BTreeSet<PathBuf>>,
    /// Watchers whose outbox couldn't be opened or listed, warned about once
    /// until a scan succeeds.
    outbox_failed: Mutex<BTreeSet<String>>,
}

impl WatcherStatusTracker {
    pub(crate) fn new(
        requests_dir: PathBuf,
        watcher_ids: impl IntoIterator<Item = String>,
    ) -> Arc<Self> {
        Arc::new(Self {
            requests_dir,
            watcher_ids: watcher_ids.into_iter().collect(),
            notify: Notify::new(),
            tracked: Arc::new(Mutex::new(HashMap::new())),
            pre_status_warned: Mutex::new(BTreeSet::new()),
            scan_limit_warned: Mutex::new(BTreeSet::new()),
            unreadable: Mutex::new(BTreeSet::new()),
            undeletable: Mutex::new(BTreeSet::new()),
            outbox_failed: Mutex::new(BTreeSet::new()),
        })
    }

    #[cfg(test)]
    pub(crate) fn pending_count(&self) -> usize {
        self.tracked.lock().unwrap().len()
    }

    #[cfg(test)]
    fn track(&self, watcher_id: &str, request: RefreshRequest) -> PendingRequest {
        self.register(watcher_id, request).unwrap()
    }

    fn register(&self, watcher_id: &str, request: RefreshRequest) -> io::Result<PendingRequest> {
        use std::collections::hash_map::Entry;

        if !self.watcher_ids.contains(watcher_id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("watcher {watcher_id} is not configured"),
            ));
        }
        let command_id = request.command_id.clone();
        let (completion, receiver) = oneshot::channel();
        let registration = Arc::new(());
        match self.tracked.lock().unwrap().entry(command_id.clone()) {
            Entry::Vacant(entry) => {
                entry.insert(TrackedRequest {
                    watcher_id: watcher_id.to_string(),
                    request,
                    completion,
                    registration: Arc::clone(&registration),
                });
            }
            Entry::Occupied(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("command_id {command_id} is already pending"),
                ));
            }
        }
        Ok(PendingRequest {
            command_id,
            tracked: Arc::clone(&self.tracked),
            completion: receiver,
            registration,
        })
    }

    /// Registers before publishing, and wakes the scanner only after publication succeeds.
    pub(crate) fn enqueue_request(
        &self,
        root: &RequestsRoot,
        watcher_id: &str,
        certificate_arn: &str,
    ) -> io::Result<(PendingRequest, String)> {
        let prepared = watcher_request::prepare_request(certificate_arn)?;
        let request = prepared.request().clone();
        let pending = self.register(watcher_id, request)?;
        if let Err(error) = watcher_request::publish_prepared_request(root, watcher_id, &prepared) {
            drop(pending);
            return Err(error);
        }
        self.notify.notify_one();
        Ok((pending, prepared.name().to_string()))
    }

    /// Whether `watcher_id` has an `outbox/`, checked before its request is
    /// published. A current watcher creates `outbox/` before `inbox/`, so a
    /// watcher with an inbox but no outbox predates status reports. Any other
    /// error opening the outbox is returned, since no status could be read.
    pub(crate) fn reports_status(&self, watcher_id: &str) -> io::Result<bool> {
        match open_outbox(&self.requests_dir, watcher_id) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Warns, once per watcher, that a published request will get no status.
    pub(crate) fn warn_pre_status(&self, watcher_id: &str) {
        if self
            .pre_status_warned
            .lock()
            .unwrap()
            .insert(watcher_id.to_string())
        {
            let outbox = self.requests_dir.join(watcher_id).join(OUTBOX_DIR);
            warn!(
                "Watcher {} has an inbox but no status outbox {:?}, so it predates status reports: its refresh requests are queued without waiting for a result and reported as written but not reloaded. Upgrade the watcher to get reload results.",
                watcher_id, outbox
            );
        }
    }

    /// Runs one scanner over all deduplicated configured watcher outboxes.
    pub(crate) async fn run(self: Arc<Self>, cancel: CancellationToken) {
        loop {
            // Poll faster while a request waits, so refresh durations stay close to the real ones.
            let rescan = if self.tracked.lock().unwrap().is_empty() {
                STATUS_RESCAN_INTERVAL
            } else {
                ACTIVE_RESCAN_INTERVAL
            };
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = self.notify.notified() => self.process_all(),
                _ = tokio::time::sleep(rescan) => self.process_all(),
            }
        }
        self.tracked.lock().unwrap().clear();
    }

    fn process_all(&self) {
        for watcher_id in &self.watcher_ids {
            self.process_watcher(watcher_id);
        }
    }

    pub(crate) fn process_watcher(&self, watcher_id: &str) {
        let opened = match open_outbox(&self.requests_dir, watcher_id) {
            Ok(opened) => opened,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return,
            Err(error) => {
                let outbox = self.requests_dir.join(watcher_id).join(OUTBOX_DIR);
                self.outbox_failed(watcher_id, "open", &outbox, &error);
                return;
            }
        };
        let outbox = &opened.path;
        let scan = match enumerate_outbox(&opened) {
            Ok(scan) => scan,
            Err(error) => {
                self.outbox_failed(watcher_id, "list", outbox, &error);
                return;
            }
        };
        if self.outbox_failed.lock().unwrap().remove(watcher_id) {
            info!("Watcher status outbox {:?} can be read again", outbox);
        }
        if scan.limited
            && self
                .scan_limit_warned
                .lock()
                .unwrap()
                .insert(watcher_id.to_string())
        {
            warn!(
                "Watcher status outbox {:?} has more entries than one scan reads ({} entries or {} statuses); the rest are read on later scans",
                outbox, MAX_OUTBOX_ENTRIES_PER_SCAN, MAX_STATUSES_PER_SCAN
            );
        }
        // Forget remembered statuses that are gone. A limited scan didn't see
        // every name, so it keeps them, and `MAX_REMEMBERED_STATUSES` bounds them.
        if !scan.limited {
            let present: BTreeSet<PathBuf> =
                scan.statuses.iter().map(|name| outbox.join(name)).collect();
            let keep = |path: &PathBuf| !path.starts_with(outbox) || present.contains(path);
            self.unreadable.lock().unwrap().retain(keep);
            self.undeletable.lock().unwrap().retain(keep);
        }
        for name in scan.statuses {
            self.process_candidate(watcher_id, outbox, &opened.directory, name);
        }
    }

    fn process_candidate(&self, watcher_id: &str, outbox: &Path, directory: &File, name: OsString) {
        let path = outbox.join(&name);
        let Some(filename_command_id) = command_id_from_status_filename(&name) else {
            return;
        };
        if self.undeletable.lock().unwrap().contains(&path) {
            return;
        }
        let status = match read_status(directory, &name, &path) {
            Ok(status) => status,
            // Possibly transient, so the status is kept and read again next scan.
            Err(StatusReadError::Io(error)) => {
                if remember(&self.unreadable, path.clone()) {
                    warn!(
                        "Could not read watcher status {:?}, retrying on the next scan: {}",
                        path, error
                    );
                }
                return;
            }
            // Never a status, and deleting it would fail on every scan, so it's left alone.
            Err(StatusReadError::Directory) => {
                if remember(&self.unreadable, path.clone()) {
                    warn!(
                        "Ignoring directory {:?} in the watcher status outbox: it has a status name but is not a status",
                        path
                    );
                }
                return;
            }
            Err(error) => {
                self.unreadable.lock().unwrap().remove(&path);
                warn!("Deleting malformed watcher status {:?}: {}", path, error);
                self.delete_handled(directory, &name, path);
                return;
            }
        };
        self.unreadable.lock().unwrap().remove(&path);
        if status.command_id != filename_command_id {
            warn!("Deleting watcher status {:?}: filename command_id={} does not match body command_id={}", path, filename_command_id, status.command_id);
            self.delete_handled(directory, &name, path);
            return;
        }
        self.handle_status(watcher_id, status);
        self.delete_handled(directory, &name, path);
    }

    /// Deletes a handled status. One that can't be deleted is logged once and
    /// skipped on later scans, so it isn't handled and logged again every scan.
    fn delete_handled(&self, directory: &File, name: &OsStr, path: PathBuf) {
        if let Err(error) = delete_status(directory, name, &path) {
            error!(
                "Failed to delete watcher status {:?}, skipping it on later scans: {}",
                path, error
            );
            remember(&self.undeletable, path);
        }
    }

    /// Warns about an outbox that can't be opened or listed once, until a scan succeeds.
    fn outbox_failed(&self, watcher_id: &str, action: &str, outbox: &Path, error: &io::Error) {
        if self
            .outbox_failed
            .lock()
            .unwrap()
            .insert(watcher_id.to_string())
        {
            warn!(
                "Could not {} watcher status outbox {:?}, retrying on later scans: {}",
                action, outbox, error
            );
        } else {
            debug!(
                "Could not {} watcher status outbox {:?}: {}",
                action, outbox, error
            );
        }
    }

    fn handle_status(&self, watcher_id: &str, status: StatusRecord) {
        let mut tracked = self.tracked.lock().unwrap();
        let Some(expected) = tracked.get(&status.command_id) else {
            warn!(
                "Deleting unknown watcher status: watcher={}, command_id={}, cert_arn={:?}",
                watcher_id, status.command_id, status.cert_arn
            );
            return;
        };
        if expected.watcher_id != watcher_id
            || expected.request.certificate_arn != status.cert_arn
            || expected.request.created_at != status.request_created_at
        {
            warn!(
                "Deleting stale watcher status: watcher={}, command_id={}, cert_arn={:?}",
                watcher_id, status.command_id, status.cert_arn
            );
            return;
        }
        let expected = tracked
            .remove(&status.command_id)
            .expect("entry checked above");
        let outcome = map_outcome(status.outcome);
        log_outcome(watcher_id, &expected.request, &status, outcome);
        let _ = expected.completion.send(status);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MappedOutcome {
    Success,
    Failure,
    Timeout,
}

impl MappedOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Timeout => "timeout",
        }
    }
}

fn map_outcome(outcome: StatusOutcome) -> MappedOutcome {
    match outcome {
        StatusOutcome::Success => MappedOutcome::Success,
        StatusOutcome::Failure | StatusOutcome::NotFound | StatusOutcome::Superseded => {
            MappedOutcome::Failure
        }
        StatusOutcome::Timeout => MappedOutcome::Timeout,
    }
}

fn log_outcome(
    watcher_id: &str,
    request: &RefreshRequest,
    status: &StatusRecord,
    outcome: MappedOutcome,
) {
    let message = format!(
        "Watcher refresh command completed: watcher={}, cert_arn={:?}, command_id={}, outcome={}, exit_code={:?}, request_created_at={}, started_at={:?}, completed_at={:?}, error_detail={:?}",
        watcher_id,
        request.certificate_arn,
        request.command_id,
        outcome.as_str(),
        status.exit_code,
        status.request_created_at,
        status.started_at,
        status.completed_at,
        status.error_detail,
    );
    match outcome {
        MappedOutcome::Success => info!("{}", message),
        MappedOutcome::Failure => error!("{}", message),
        MappedOutcome::Timeout => warn!("{}", message),
    }
}

#[derive(Debug)]
enum StatusReadError {
    Io(io::Error),
    /// A directory with a status name, which a file unlink can't remove.
    Directory,
    NotRegular,
    TooLarge(u64),
    Parse(serde_json::Error),
    Invalid(StatusValidationError),
}

impl std::fmt::Display for StatusReadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "read failed: {error}"),
            Self::Directory => write!(formatter, "a directory"),
            Self::NotRegular => write!(formatter, "not a regular file"),
            Self::TooLarge(size) => {
                write!(
                    formatter,
                    "{size} bytes exceeds the {MAX_STATUS_BYTES}-byte limit"
                )
            }
            Self::Parse(error) => write!(formatter, "invalid JSON: {error}"),
            Self::Invalid(error) => write!(formatter, "invalid status fields: {error:?}"),
        }
    }
}

fn read_status(
    directory: &File,
    name: &OsStr,
    path: &Path,
) -> Result<StatusRecord, StatusReadError> {
    let file = open_status(directory, name, path)?;
    let metadata = file.metadata().map_err(StatusReadError::Io)?;
    if metadata.is_dir() {
        return Err(StatusReadError::Directory);
    }
    if !metadata.is_file() {
        return Err(StatusReadError::NotRegular);
    }
    if metadata.len() > MAX_STATUS_BYTES as u64 {
        return Err(StatusReadError::TooLarge(metadata.len()));
    }
    let mut bytes = Vec::new();
    file.take(MAX_STATUS_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(StatusReadError::Io)?;
    if bytes.len() > MAX_STATUS_BYTES {
        return Err(StatusReadError::TooLarge(bytes.len() as u64));
    }
    let status: StatusRecord = serde_json::from_slice(&bytes).map_err(StatusReadError::Parse)?;
    status.validate().map_err(StatusReadError::Invalid)?;
    Ok(status)
}

/// The status names one scan read from an outbox.
struct OutboxScan {
    statuses: Vec<OsString>,
    /// A per-scan limit stopped the read before the end of the directory.
    limited: bool,
}

/// Reads entries one at a time, keeping only status names, until the end of
/// the directory or a per-scan limit. Nothing else is held in memory.
fn collect_statuses(
    mut entries: impl Iterator<Item = io::Result<OsString>>,
) -> io::Result<OutboxScan> {
    let mut statuses = Vec::new();
    for _ in 0..MAX_OUTBOX_ENTRIES_PER_SCAN {
        let Some(entry) = entries.next() else {
            return Ok(OutboxScan {
                statuses,
                limited: false,
            });
        };
        let name = entry?;
        if is_status_candidate(&name) {
            statuses.push(name);
            if statuses.len() == MAX_STATUSES_PER_SCAN {
                break;
            }
        }
    }
    Ok(OutboxScan {
        statuses,
        limited: true,
    })
}

#[cfg(unix)]
fn enumerate_outbox(opened: &OpenOutbox) -> io::Result<OutboxScan> {
    use rustix::fs::Dir;
    use std::os::unix::ffi::OsStrExt;

    collect_statuses(Dir::read_from(&opened.directory)?.map(|entry| {
        entry
            .map(|entry| OsStr::from_bytes(entry.file_name().to_bytes()).to_os_string())
            .map_err(io::Error::from)
    }))
}

#[cfg(windows)]
fn enumerate_outbox(opened: &OpenOutbox) -> io::Result<OutboxScan> {
    fn verify_pinned_path(opened: &OpenOutbox) -> io::Result<()> {
        if final_path(&opened.directory)? != fs::canonicalize(&opened.path)? {
            return Err(io::Error::other(
                "status outbox path changed while enumerating entries",
            ));
        }
        Ok(())
    }

    verify_pinned_path(opened)?;
    let scan = collect_statuses(
        fs::read_dir(&opened.path)?.map(|entry| entry.map(|entry| entry.file_name())),
    )?;
    verify_pinned_path(opened)?;
    Ok(scan)
}

#[cfg(not(any(unix, windows)))]
fn enumerate_outbox(opened: &OpenOutbox) -> io::Result<OutboxScan> {
    collect_statuses(fs::read_dir(&opened.path)?.map(|entry| entry.map(|entry| entry.file_name())))
}

#[cfg(unix)]
fn open_outbox(requests_dir: &Path, watcher_id: &str) -> io::Result<OpenOutbox> {
    use rustix::fs::{open, openat, Mode, OFlags};
    use std::path::Component;

    if !is_safe_watcher_id(watcher_id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "watcher_id is not a valid single path segment",
        ));
    }
    if !requests_dir.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "requests directory must be absolute",
        ));
    }

    // The directories above the outbox are only passed through, so they are
    // opened as the request writer opens them: on Linux `<watcher_id>/`
    // (mode 0o710) grants the provider's group search but not read. Only the
    // outbox is read, to list its entries.
    let dir = OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let walk = dir | watcher_request::WALK;
    let mut parent = open(Path::new("/"), walk, Mode::empty())?;
    for component in requests_dir.components() {
        let Component::Normal(name) = component else {
            if matches!(component, Component::RootDir) {
                continue;
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "requests directory must not contain relative components",
            ));
        };
        parent = openat(&parent, name, walk, Mode::empty())?;
    }
    let watcher = openat(&parent, watcher_id, walk, Mode::empty())?;
    let directory = openat(&watcher, OUTBOX_DIR, dir | OFlags::RDONLY, Mode::empty())?;
    Ok(OpenOutbox::new(
        requests_dir.join(watcher_id).join(OUTBOX_DIR),
        File::from(directory),
    ))
}

#[cfg(unix)]
fn open_status(directory: &File, name: &OsStr, _path: &Path) -> Result<File, StatusReadError> {
    use rustix::fs::{openat, Mode, OFlags};
    openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| {
        // NOFOLLOW refuses a symlink with ELOOP: never readable, so not retried.
        if error == rustix::io::Errno::LOOP {
            StatusReadError::NotRegular
        } else {
            StatusReadError::Io(error.into())
        }
    })
}

#[cfg(unix)]
/// Deletes a status; one that is already gone counts as deleted.
fn delete_status(directory: &File, name: &OsStr, path: &Path) -> io::Result<()> {
    use rustix::fs::{unlinkat, AtFlags};
    match unlinkat(directory, name, AtFlags::empty()) {
        Err(rustix::io::Errno::NOENT) => {
            debug!("Watcher status {:?} was already deleted", path);
            Ok(())
        }
        result => result.map_err(io::Error::from),
    }
}

#[cfg(windows)]
fn open_relative_directory(parent: &File, name: &OsStr) -> io::Result<File> {
    nt_open_relative(parent, name, true)
}

#[cfg(windows)]
fn open_relative_status(parent: &File, name: &OsStr) -> io::Result<File> {
    nt_open_relative(parent, name, false)
}

#[cfg(windows)]
fn nt_open_relative(parent: &File, name: &OsStr, directory: bool) -> io::Result<File> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use windows::Win32::Foundation::HANDLE;

    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }
    #[repr(C)]
    struct ObjectAttributes {
        length: u32,
        root_directory: HANDLE,
        object_name: *mut UnicodeString,
        attributes: u32,
        security_descriptor: *mut c_void,
        security_quality_of_service: *mut c_void,
    }
    #[repr(C)]
    struct IoStatusBlock {
        status: isize,
        information: usize,
    }

    const DELETE: u32 = 0x0001_0000;
    const FILE_GENERIC_READ: u32 = 0x0012_0089;
    const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
    const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
    const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
    const FILE_OPEN: u32 = 1;
    const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
    const FILE_SHARE_READ: u32 = 1;
    const FILE_SHARE_WRITE: u32 = 2;

    #[link(name = "ntdll")]
    extern "system" {
        fn NtCreateFile(
            file_handle: *mut HANDLE,
            desired_access: u32,
            object_attributes: *mut ObjectAttributes,
            io_status_block: *mut IoStatusBlock,
            allocation_size: *mut i64,
            file_attributes: u32,
            share_access: u32,
            create_disposition: u32,
            create_options: u32,
            ea_buffer: *mut c_void,
            ea_length: u32,
        ) -> i32;
        fn RtlNtStatusToDosError(status: i32) -> u32;
    }

    let mut wide: Vec<u16> = name.encode_wide().collect();
    if wide.is_empty() || wide.len() * std::mem::size_of::<u16>() > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty or oversized relative path",
        ));
    }
    let mut unicode = UnicodeString {
        length: (wide.len() * 2) as u16,
        maximum_length: (wide.len() * 2) as u16,
        buffer: wide.as_mut_ptr(),
    };
    let mut attributes = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: HANDLE(parent.as_raw_handle()),
        object_name: std::ptr::addr_of_mut!(unicode),
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: std::ptr::null_mut(),
        security_quality_of_service: std::ptr::null_mut(),
    };
    let mut handle = HANDLE(std::ptr::null_mut());
    let mut io_status = IoStatusBlock {
        status: 0,
        information: 0,
    };
    let options = if directory {
        FILE_DIRECTORY_FILE
    } else {
        FILE_NON_DIRECTORY_FILE
    } | FILE_OPEN_REPARSE_POINT
        | FILE_SYNCHRONOUS_IO_NONALERT;
    let desired_access = if directory {
        FILE_GENERIC_READ
    } else {
        FILE_GENERIC_READ | DELETE
    };
    let status = unsafe {
        NtCreateFile(
            std::ptr::addr_of_mut!(handle),
            desired_access,
            std::ptr::addr_of_mut!(attributes),
            std::ptr::addr_of_mut!(io_status),
            std::ptr::null_mut(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            options,
            std::ptr::null_mut(),
            0,
        )
    };
    // `RtlNtStatusToDosError` maps this to `ERROR_ACCESS_DENIED`, which can't
    // be told apart from a real permission failure.
    const STATUS_FILE_IS_A_DIRECTORY: i32 = 0xC000_00BA_u32 as i32;
    if status == STATUS_FILE_IS_A_DIRECTORY {
        return Err(io::Error::new(
            io::ErrorKind::IsADirectory,
            "the name is a directory",
        ));
    }
    if status < 0 {
        let error = unsafe { RtlNtStatusToDosError(status) };
        return Err(io::Error::from_raw_os_error(error as i32));
    }
    // SAFETY: NtCreateFile returned an owned handle and this function transfers
    // it to File exactly once.
    Ok(unsafe { File::from_raw_handle(handle.0) })
}

#[cfg(windows)]
fn open_directory(path: &Path) -> io::Result<(File, PathBuf)> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_GENERIC_READ, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    let file = fs::OpenOptions::new()
        .access_mode(FILE_GENERIC_READ.0)
        .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "status outbox path is a reparse point or not a directory",
        ));
    }
    let actual = final_path(&file)?;
    let expected = fs::canonicalize(path)?;
    if actual != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "status outbox path was reached through a link",
        ));
    }
    Ok((file, actual))
}

#[cfg(windows)]
fn open_outbox(requests_dir: &Path, watcher_id: &str) -> io::Result<OpenOutbox> {
    if !is_safe_watcher_id(watcher_id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "watcher_id is not a valid single path segment",
        ));
    }
    let (root, root_path) = open_directory(requests_dir)?;
    let watcher = open_relative_directory(&root, OsStr::new(watcher_id))?;
    let watcher_path = root_path.join(watcher_id);
    let directory = open_relative_directory(&watcher, OsStr::new(OUTBOX_DIR))?;
    let outbox_path = watcher_path.join(OUTBOX_DIR);
    if final_path(&directory)? != fs::canonicalize(&outbox_path)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "status outbox path was reached through a link",
        ));
    }
    Ok(OpenOutbox::new(
        requests_dir.join(watcher_id).join(OUTBOX_DIR),
        directory,
        root,
        watcher,
    ))
}

#[cfg(windows)]
fn open_status(directory: &File, name: &OsStr, _path: &Path) -> Result<File, StatusReadError> {
    let file = open_relative_status(directory, name).map_err(|error| {
        if error.kind() == io::ErrorKind::IsADirectory {
            StatusReadError::Directory
        } else {
            StatusReadError::Io(error)
        }
    })?;
    let directory_path = final_path(directory).map_err(StatusReadError::Io)?;
    let file_path = final_path(&file).map_err(StatusReadError::Io)?;
    // A link out of the outbox: never readable, so not retried.
    if file_path.parent() != Some(directory_path.as_path()) {
        return Err(StatusReadError::NotRegular);
    }
    Ok(file)
}

#[cfg(windows)]
/// Deletes a status; one that is already gone counts as deleted.
fn delete_status(directory: &File, name: &OsStr, path: &Path) -> io::Result<()> {
    let file = match open_status(directory, name, path) {
        Ok(file) => file,
        Err(StatusReadError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            debug!("Watcher status {:?} was already deleted", path);
            return Ok(());
        }
        Err(StatusReadError::Io(error)) => return Err(error),
        Err(error) => return Err(io::Error::other(error.to_string())),
    };
    delete_by_handle(&file)
}

#[cfg(windows)]
fn final_path(file: &File) -> io::Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{GetFinalPathNameByHandleW, FILE_NAME_NORMALIZED};

    let mut buf = vec![0u16; 512];
    loop {
        let len = unsafe {
            GetFinalPathNameByHandleW(HANDLE(file.as_raw_handle()), &mut buf, FILE_NAME_NORMALIZED)
        } as usize;
        if len == 0 {
            return Err(io::Error::last_os_error());
        }
        if len < buf.len() {
            return Ok(PathBuf::from(std::ffi::OsString::from_wide(&buf[..len])));
        }
        buf.resize(len + 1, 0);
    }
}

#[cfg(windows)]
fn delete_by_handle(file: &File) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        FileDispositionInfo, SetFileInformationByHandle, FILE_DISPOSITION_INFO,
    };

    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    unsafe {
        SetFileInformationByHandle(
            HANDLE(file.as_raw_handle()),
            FileDispositionInfo,
            std::ptr::addr_of!(info).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    }
    .map_err(io::Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::test_support::{capture_logs, logged_on_this_thread};
    use aws_workload_credentials_provider_common::watcher_status::status_filename;
    use std::fs;
    use tokio::time::Instant;

    const ARN: &str = "arn:aws:acm:us-east-1:123456789012:certificate/test";
    const COMMAND_ID: &str = "00000000-0000-4000-8000-000000000001";

    fn request(created_at: &str) -> RefreshRequest {
        RefreshRequest {
            command_id: COMMAND_ID.to_string(),
            certificate_arn: ARN.to_string(),
            created_at: created_at.to_string(),
        }
    }

    fn status(outcome: StatusOutcome, created_at: &str) -> StatusRecord {
        StatusRecord {
            command_id: COMMAND_ID.to_string(),
            cert_arn: ARN.to_string(),
            request_created_at: created_at.to_string(),
            outcome,
            exit_code: match outcome {
                StatusOutcome::Success => Some(0),
                StatusOutcome::Failure => Some(1),
                _ => None,
            },
            started_at: Some("2025-01-01T00:00:01Z".to_string()),
            completed_at: Some("2025-01-01T00:00:02Z".to_string()),
            error_detail: None,
        }
    }

    fn write_status_file(outbox: &Path, status: &StatusRecord) {
        fs::write(
            outbox.join(status_filename(&status.command_id)),
            serde_json::to_vec(status).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn deduplicates_configured_watcher_ids() {
        let tracker = WatcherStatusTracker::new(
            PathBuf::from("/unused"),
            ["two".to_string(), "one".to_string(), "two".to_string()],
        );

        assert_eq!(
            tracker.watcher_ids,
            BTreeSet::from(["one".to_string(), "two".to_string()])
        );
    }

    #[tokio::test]
    async fn matching_status_completes_pending_request_once() {
        let tracker = WatcherStatusTracker::new(PathBuf::from("/unused"), ["one".to_string()]);
        let pending = tracker.track("one", request("2025-01-01T00:00:00Z"));
        let expected = status(StatusOutcome::Success, "2025-01-01T00:00:00Z");

        tracker.handle_status("one", expected.clone());
        let actual = pending
            .wait(
                Instant::now() + Duration::from_secs(1),
                &CancellationToken::new(),
            )
            .await
            .unwrap();

        assert_eq!(actual, expected);
        assert!(tracker.tracked.lock().unwrap().is_empty());
    }

    #[test]
    fn dropping_pending_request_unregisters_it() {
        let tracker = WatcherStatusTracker::new(PathBuf::from("/unused"), ["one".to_string()]);
        let pending = tracker.track("one", request("2025-01-01T00:00:00Z"));
        assert_eq!(tracker.tracked.lock().unwrap().len(), 1);

        drop(pending);

        assert!(tracker.tracked.lock().unwrap().is_empty());
    }

    #[test]
    fn duplicate_command_id_registration_fails_closed() {
        let tracker = WatcherStatusTracker::new(PathBuf::from("/unused"), ["one".to_string()]);
        let original = tracker.track("one", request("2025-01-01T00:00:00Z"));

        let duplicate = tracker
            .register("one", request("2025-01-01T00:00:00Z"))
            .err()
            .expect("duplicate command_id must be rejected");

        assert_eq!(duplicate.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(tracker.tracked.lock().unwrap().len(), 1);
        drop(original);
    }

    #[tokio::test]
    async fn completed_handle_does_not_unregister_reused_command_id() {
        let tracker = WatcherStatusTracker::new(PathBuf::from("/unused"), ["one".to_string()]);
        let completed = tracker.track("one", request("2025-01-01T00:00:00Z"));
        tracker.handle_status(
            "one",
            status(StatusOutcome::Success, "2025-01-01T00:00:00Z"),
        );
        let replacement = tracker.track("one", request("2025-01-01T00:00:00Z"));

        completed
            .wait(
                Instant::now() + Duration::from_secs(1),
                &CancellationToken::new(),
            )
            .await
            .unwrap();

        assert!(tracker.tracked.lock().unwrap().contains_key(COMMAND_ID));
        drop(replacement);
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_unregisters_pending_request() {
        let tracker = WatcherStatusTracker::new(PathBuf::from("/unused"), ["one".to_string()]);
        let pending = tracker.track("one", request("2025-01-01T00:00:00Z"));

        let result = pending
            .wait(
                Instant::now() + Duration::from_secs(5),
                &CancellationToken::new(),
            )
            .await;

        assert_eq!(result, Err(PendingWaitError::Deadline));
        assert!(tracker.tracked.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn cancellation_unregisters_pending_request() {
        let tracker = WatcherStatusTracker::new(PathBuf::from("/unused"), ["one".to_string()]);
        let pending = tracker.track("one", request("2025-01-01T00:00:00Z"));
        let cancel = CancellationToken::new();
        let waiter_cancel = cancel.clone();
        let waiter = tokio::spawn(async move {
            pending
                .wait(Instant::now() + Duration::from_secs(60), &waiter_cancel)
                .await
        });
        tokio::task::yield_now().await;

        cancel.cancel();

        assert_eq!(waiter.await.unwrap(), Err(PendingWaitError::Cancelled));
        assert!(tracker.tracked.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn shutdown_closes_and_removes_pending_requests() {
        let tracker = WatcherStatusTracker::new(PathBuf::from("/unused"), ["one".to_string()]);
        let pending = tracker.track("one", request("2025-01-01T00:00:00Z"));
        let shutdown = CancellationToken::new();
        let scanner = tokio::spawn(Arc::clone(&tracker).run(shutdown.clone()));

        shutdown.cancel();
        scanner.await.unwrap();

        assert!(tracker.tracked.lock().unwrap().is_empty());
        assert_eq!(
            pending
                .wait(
                    Instant::now() + Duration::from_secs(1),
                    &CancellationToken::new(),
                )
                .await,
            Err(PendingWaitError::Cancelled)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn failed_publication_unregisters_without_notifying_scanner() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("one")).unwrap();
        let requests = RequestsRoot::open(root.path()).unwrap();
        let tracker = WatcherStatusTracker::new(root.path().to_path_buf(), ["one".to_string()]);

        let error = tracker
            .enqueue_request(&requests, "one", ARN)
            .err()
            .expect("missing inbox must fail publication");

        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(tracker.tracked.lock().unwrap().is_empty());
        assert!(
            tokio::time::timeout(Duration::from_secs(1), tracker.notify.notified())
                .await
                .is_err()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn successful_publication_notifies_scanner() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("one").join("inbox")).unwrap();
        let requests = RequestsRoot::open(root.path()).unwrap();
        let tracker = WatcherStatusTracker::new(root.path().to_path_buf(), ["one".to_string()]);

        let (_pending, _name) = tracker.enqueue_request(&requests, "one", ARN).unwrap();

        tokio::time::timeout(Duration::from_secs(1), tracker.notify.notified())
            .await
            .expect("successful publication must wake the scanner");
    }

    #[tokio::test(start_paused = true)]
    async fn periodic_rescan_completes_a_status_without_notification() {
        let root = tempfile::tempdir().unwrap();
        let outbox = root.path().join("one").join(OUTBOX_DIR);
        fs::create_dir_all(&outbox).unwrap();
        let tracker = WatcherStatusTracker::new(root.path().to_path_buf(), ["one".to_string()]);
        let _pending = tracker.track("one", request("2025-01-01T00:00:00Z"));
        let shutdown = CancellationToken::new();
        let scanner = tokio::spawn(Arc::clone(&tracker).run(shutdown.clone()));
        tokio::task::yield_now().await;
        assert_eq!(tracker.tracked.lock().unwrap().len(), 1);

        write_status_file(
            &outbox,
            &status(StatusOutcome::Success, "2025-01-01T00:00:00Z"),
        );
        tokio::time::advance(STATUS_RESCAN_INTERVAL).await;
        tokio::task::yield_now().await;

        assert!(tracker.tracked.lock().unwrap().is_empty());
        assert!(!outbox.join(status_filename(COMMAND_ID)).exists());
        shutdown.cancel();
        scanner.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn pending_request_is_rescanned_every_second() {
        let root = tempfile::tempdir().unwrap();
        let outbox = root.path().join("one").join(OUTBOX_DIR);
        fs::create_dir_all(&outbox).unwrap();
        let tracker = WatcherStatusTracker::new(root.path().to_path_buf(), ["one".to_string()]);
        let _pending = tracker.track("one", request("2025-01-01T00:00:00Z"));
        let shutdown = CancellationToken::new();
        let scanner = tokio::spawn(Arc::clone(&tracker).run(shutdown.clone()));
        tokio::task::yield_now().await;

        write_status_file(
            &outbox,
            &status(StatusOutcome::Success, "2025-01-01T00:00:00Z"),
        );
        tokio::time::advance(ACTIVE_RESCAN_INTERVAL).await;
        tokio::task::yield_now().await;

        assert!(tracker.tracked.lock().unwrap().is_empty());
        shutdown.cancel();
        scanner.await.unwrap();
    }

    /// A status that can't be read is kept and read on a later scan, not deleted.
    #[cfg(unix)]
    #[test]
    fn unreadable_status_is_kept_and_read_on_a_later_scan() {
        use std::os::unix::fs::PermissionsExt;
        // Root bypasses file permissions, so EACCES can't be produced.
        if rustix::process::geteuid().is_root() {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let outbox = root.path().join("one").join(OUTBOX_DIR);
        fs::create_dir_all(&outbox).unwrap();
        let tracker = WatcherStatusTracker::new(root.path().to_path_buf(), ["one".to_string()]);
        let _pending = tracker.track("one", request("2025-01-01T00:00:00Z"));
        write_status_file(
            &outbox,
            &status(StatusOutcome::Success, "2025-01-01T00:00:00Z"),
        );
        let path = outbox.join(status_filename(COMMAND_ID));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();

        tracker.process_watcher("one");
        assert!(path.exists(), "an unreadable status must not be deleted");
        assert_eq!(tracker.pending_count(), 1);

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        tracker.process_watcher("one");
        assert!(!path.exists());
        assert_eq!(tracker.pending_count(), 0);
    }

    /// An unreadable status that disappears is no longer tracked.
    #[cfg(unix)]
    #[test]
    fn a_vanished_unreadable_status_is_forgotten() {
        use std::os::unix::fs::PermissionsExt;
        // Root bypasses file permissions, so EACCES can't be produced.
        if rustix::process::geteuid().is_root() {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let outbox = root.path().join("one").join(OUTBOX_DIR);
        fs::create_dir_all(&outbox).unwrap();
        let tracker = WatcherStatusTracker::new(root.path().to_path_buf(), ["one".to_string()]);
        write_status_file(
            &outbox,
            &status(StatusOutcome::Success, "2025-01-01T00:00:00Z"),
        );
        let path = outbox.join(status_filename(COMMAND_ID));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();

        tracker.process_watcher("one");
        assert!(tracker.unreadable.lock().unwrap().contains(&path));

        fs::remove_file(&path).unwrap();
        tracker.process_watcher("one");
        assert!(tracker.unreadable.lock().unwrap().is_empty());
    }

    /// A remembered-status set never grows past its cap, even with no full
    /// scan to prune it.
    #[test]
    fn remembered_statuses_are_bounded() {
        let set = Mutex::new(BTreeSet::new());
        for n in 0..MAX_REMEMBERED_STATUSES {
            assert!(remember(&set, PathBuf::from(format!("/outbox/{n}"))));
        }
        assert!(
            !remember(&set, PathBuf::from("/outbox/0")),
            "already remembered"
        );
        assert_eq!(set.lock().unwrap().len(), MAX_REMEMBERED_STATUSES);

        assert!(remember(&set, PathBuf::from("/outbox/new")));
        assert_eq!(set.lock().unwrap().len(), 1);
    }

    /// An outbox that can't be opened is warned about once, not on every
    /// scan, and again only after a scan has succeeded.
    #[cfg(unix)]
    #[test]
    fn unopenable_outbox_is_warned_about_once_until_a_scan_succeeds() {
        use std::os::unix::fs::PermissionsExt;
        // Root bypasses directory permissions, so EACCES can't be produced.
        if rustix::process::geteuid().is_root() {
            return;
        }
        capture_logs();
        let log_count = logged_on_this_thread().len();
        let root = tempfile::tempdir().unwrap();
        let outbox = root.path().join("one").join(OUTBOX_DIR);
        fs::create_dir_all(&outbox).unwrap();
        let tracker = WatcherStatusTracker::new(root.path().to_path_buf(), ["one".to_string()]);
        let warnings = || {
            logged_on_this_thread()[log_count..]
                .iter()
                .filter(|message| message.contains("Could not open watcher status outbox"))
                .count()
        };

        fs::set_permissions(&outbox, fs::Permissions::from_mode(0o000)).unwrap();
        for _ in 0..3 {
            tracker.process_watcher("one");
        }
        assert_eq!(warnings(), 1);

        fs::set_permissions(&outbox, fs::Permissions::from_mode(0o755)).unwrap();
        tracker.process_watcher("one");
        assert!(tracker.outbox_failed.lock().unwrap().is_empty());

        fs::set_permissions(&outbox, fs::Permissions::from_mode(0o000)).unwrap();
        tracker.process_watcher("one");
        fs::set_permissions(&outbox, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(warnings(), 2);
    }

    /// A status that can't be deleted completes its request once, and later
    /// scans skip it instead of handling and logging it again.
    #[cfg(unix)]
    #[test]
    fn undeletable_status_is_handled_once() {
        use std::os::unix::fs::PermissionsExt;
        // Root bypasses directory permissions, so the delete can't be made to fail.
        if rustix::process::geteuid().is_root() {
            return;
        }
        capture_logs();
        let log_count = logged_on_this_thread().len();
        let root = tempfile::tempdir().unwrap();
        let outbox = root.path().join("one").join(OUTBOX_DIR);
        fs::create_dir_all(&outbox).unwrap();
        let tracker = WatcherStatusTracker::new(root.path().to_path_buf(), ["one".to_string()]);
        let mut pending = tracker.track("one", request("2025-01-01T00:00:00Z"));
        write_status_file(
            &outbox,
            &status(StatusOutcome::Success, "2025-01-01T00:00:00Z"),
        );
        let path = outbox.join(status_filename(COMMAND_ID));
        // Readable but not writable: the status can be read but not unlinked.
        fs::set_permissions(&outbox, fs::Permissions::from_mode(0o555)).unwrap();

        for _ in 0..3 {
            tracker.process_watcher("one");
        }
        let logs = logged_on_this_thread()[log_count..].to_vec();
        fs::set_permissions(&outbox, fs::Permissions::from_mode(0o755)).unwrap();

        assert!(
            pending.completion.try_recv().is_ok(),
            "the request must complete"
        );
        assert!(tracker.undeletable.lock().unwrap().contains(&path));
        let count = |text: &str| logs.iter().filter(|m| m.contains(text)).count();
        assert_eq!(count("Failed to delete watcher status"), 1, "{logs:?}");
        assert_eq!(count("Deleting unknown watcher status"), 0, "{logs:?}");

        fs::remove_file(&path).unwrap();
        tracker.process_watcher("one");
        assert!(tracker.undeletable.lock().unwrap().is_empty());
    }

    /// A directory with a status name is left alone and warned about once,
    /// instead of a failed delete on every scan.
    #[test]
    fn a_directory_with_a_status_name_is_skipped() {
        capture_logs();
        let log_count = logged_on_this_thread().len();
        let root = tempfile::tempdir().unwrap();
        let outbox = root.path().join("one").join(OUTBOX_DIR);
        let path = outbox.join(status_filename(COMMAND_ID));
        fs::create_dir_all(&path).unwrap();
        let tracker = WatcherStatusTracker::new(root.path().to_path_buf(), ["one".to_string()]);

        tracker.process_watcher("one");
        tracker.process_watcher("one");

        assert!(path.is_dir());
        let logs = &logged_on_this_thread()[log_count..];
        assert_eq!(
            logs.iter()
                .filter(|message| message.contains("Ignoring directory"))
                .count(),
            1
        );
        assert!(!logs
            .iter()
            .any(|message| message.contains("Failed to delete")));
    }

    #[test]
    fn one_scan_stops_at_the_entry_limit() {
        let read = std::cell::Cell::new(0);
        let junk = std::iter::repeat_with(|| {
            read.set(read.get() + 1);
            Ok(OsString::from("not-a-status"))
        });

        let scan = collect_statuses(junk).unwrap();

        assert!(scan.limited);
        assert!(scan.statuses.is_empty());
        assert_eq!(read.get(), MAX_OUTBOX_ENTRIES_PER_SCAN);
    }

    #[test]
    fn one_scan_stops_at_the_status_limit() {
        let statuses = (0..).map(|n| {
            Ok(OsString::from(status_filename(&format!(
                "00000000-0000-4000-8000-{n:012}"
            ))))
        });

        let scan = collect_statuses(statuses).unwrap();

        assert!(scan.limited);
        assert_eq!(scan.statuses.len(), MAX_STATUSES_PER_SCAN);
    }

    #[test]
    fn a_scan_under_the_limits_reads_to_the_end() {
        let entries = [
            Ok(OsString::from("junk")),
            Ok(OsString::from(status_filename(COMMAND_ID))),
        ];

        let scan = collect_statuses(entries.into_iter()).unwrap();

        assert!(!scan.limited);
        assert_eq!(scan.statuses, [OsString::from(status_filename(COMMAND_ID))]);
    }

    #[tokio::test(start_paused = true)]
    async fn status_ready_at_the_deadline_wins() {
        let tracker = WatcherStatusTracker::new(PathBuf::from("/unused"), ["one".to_string()]);
        let pending = tracker.track("one", request("2025-01-01T00:00:00Z"));
        let expected = status(StatusOutcome::Success, "2025-01-01T00:00:00Z");
        tracker.handle_status("one", expected.clone());

        let actual = pending
            .wait(Instant::now(), &CancellationToken::new())
            .await;

        assert_eq!(actual, Ok(expected));
    }

    #[test]
    fn mismatched_watcher_arn_and_timestamp_do_not_complete_live_request() {
        let root = tempfile::tempdir().unwrap();
        let first = root.path().join("one").join(OUTBOX_DIR);
        let second = root.path().join("two").join(OUTBOX_DIR);
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        let tracker = WatcherStatusTracker::new(
            root.path().to_path_buf(),
            ["one".to_string(), "two".to_string()],
        );
        let _pending = tracker.track("one", request("2025-01-01T00:00:00Z"));

        write_status_file(
            &second,
            &status(StatusOutcome::Success, "2025-01-01T00:00:00Z"),
        );
        tracker.process_watcher("two");
        assert!(tracker.tracked.lock().unwrap().contains_key(COMMAND_ID));

        let wrong_arn = StatusRecord {
            cert_arn: "arn:aws:acm:us-east-1:123456789012:certificate/other".to_string(),
            ..status(StatusOutcome::Success, "2025-01-01T00:00:00Z")
        };
        write_status_file(&first, &wrong_arn);
        tracker.process_watcher("one");
        assert!(tracker.tracked.lock().unwrap().contains_key(COMMAND_ID));

        write_status_file(
            &first,
            &status(StatusOutcome::Success, "2025-01-02T00:00:00Z"),
        );
        tracker.process_watcher("one");
        assert!(tracker.tracked.lock().unwrap().contains_key(COMMAND_ID));
        assert!(!first.join(status_filename(COMMAND_ID)).exists());
        assert!(!second.join(status_filename(COMMAND_ID)).exists());
    }

    #[test]
    fn maps_not_found_and_superseded_to_failure() {
        assert_eq!(map_outcome(StatusOutcome::NotFound), MappedOutcome::Failure);
        assert_eq!(
            map_outcome(StatusOutcome::Superseded),
            MappedOutcome::Failure
        );
        assert_eq!(map_outcome(StatusOutcome::Success), MappedOutcome::Success);
        assert_eq!(map_outcome(StatusOutcome::Timeout), MappedOutcome::Timeout);
    }

    #[test]
    fn rejects_status_when_filename_and_body_command_ids_differ() {
        let root = tempfile::tempdir().unwrap();
        let outbox = root.path().join("one").join(OUTBOX_DIR);
        fs::create_dir_all(&outbox).unwrap();
        let tracker = WatcherStatusTracker::new(root.path().to_path_buf(), ["one".to_string()]);
        let _pending = tracker.track("one", request("2099-01-01T00:00:00Z"));

        let body_command_id = "00000000-0000-4000-8000-000000000002";
        let mismatched = StatusRecord {
            command_id: body_command_id.to_string(),
            ..status(StatusOutcome::Success, "2099-01-01T00:00:00Z")
        };
        let path = outbox.join(status_filename(COMMAND_ID));
        fs::write(&path, serde_json::to_vec(&mismatched).unwrap()).unwrap();

        tracker.process_watcher("one");

        assert!(!path.exists());
        assert!(tracker.tracked.lock().unwrap().contains_key(COMMAND_ID));
    }

    #[test]
    fn ignores_temp_and_dot_prefixed_status_names() {
        let root = tempfile::tempdir().unwrap();
        let outbox = root.path().join("one").join(OUTBOX_DIR);
        fs::create_dir_all(&outbox).unwrap();
        let tracker = WatcherStatusTracker::new(root.path().to_path_buf(), ["one".to_string()]);
        let _pending = tracker.track("one", request("2099-01-01T00:00:00Z"));
        let body =
            serde_json::to_vec(&status(StatusOutcome::Success, "2099-01-01T00:00:00Z")).unwrap();

        let names = [
            ".status.tmp".to_string(),
            format!(".{COMMAND_ID}.status.tmp"),
            format!(".{COMMAND_ID}.status"),
        ];
        for name in &names {
            fs::write(outbox.join(name), &body).unwrap();
        }

        tracker.process_watcher("one");

        assert!(tracker.tracked.lock().unwrap().contains_key(COMMAND_ID));
        for name in &names {
            assert!(
                outbox.join(name).exists(),
                "ignored candidate was consumed: {name}"
            );
        }
    }

    #[test]
    fn consumes_only_a_valid_command_id_status_filename() {
        let root = tempfile::tempdir().unwrap();
        let outbox = root.path().join("one").join(OUTBOX_DIR);
        fs::create_dir_all(&outbox).unwrap();
        let tracker = WatcherStatusTracker::new(root.path().to_path_buf(), ["one".to_string()]);
        let _pending = tracker.track("one", request("2099-01-01T00:00:00Z"));
        let valid = outbox.join(status_filename(COMMAND_ID));
        fs::write(
            &valid,
            serde_json::to_vec(&status(StatusOutcome::Success, "2099-01-01T00:00:00Z")).unwrap(),
        )
        .unwrap();
        fs::write(outbox.join("not-a-command.status"), b"{}").unwrap();
        fs::write(outbox.join("status.status"), b"{}").unwrap();

        tracker.process_watcher("one");

        assert!(!valid.exists());
        assert!(tracker.tracked.lock().unwrap().is_empty());
        assert!(outbox.join("not-a-command.status").exists());
        assert!(outbox.join("status.status").exists());
    }

    #[test]
    fn consumes_multiple_outboxes_and_deletes_accepted_statuses() {
        let root = tempfile::tempdir().unwrap();
        let first = root.path().join("one").join(OUTBOX_DIR);
        let second = root.path().join("two").join(OUTBOX_DIR);
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        let tracker = WatcherStatusTracker::new(
            root.path().to_path_buf(),
            ["one".to_string(), "two".to_string()],
        );
        let _first_pending = tracker.track("one", request("2025-01-01T00:00:00Z"));
        let _second_pending = tracker.track(
            "two",
            RefreshRequest {
                command_id: "00000000-0000-4000-8000-000000000002".to_string(),
                ..request("2025-01-01T00:00:00Z")
            },
        );
        write_status_file(
            &first,
            &status(StatusOutcome::Success, "2025-01-01T00:00:00Z"),
        );
        let second_status = StatusRecord {
            command_id: "00000000-0000-4000-8000-000000000002".to_string(),
            ..status(StatusOutcome::Failure, "2025-01-01T00:00:00Z")
        };
        write_status_file(&second, &second_status);

        tracker.process_watcher("one");
        tracker.process_watcher("two");

        assert!(!first.join(status_filename(COMMAND_ID)).exists());
        assert!(!second
            .join(status_filename(&second_status.command_id))
            .exists());
        assert!(tracker.tracked.lock().unwrap().is_empty());
    }

    #[test]
    fn deletes_unknown_and_stale_statuses() {
        let root = tempfile::tempdir().unwrap();
        let outbox = root.path().join("one").join(OUTBOX_DIR);
        fs::create_dir_all(&outbox).unwrap();
        let tracker = WatcherStatusTracker::new(root.path().to_path_buf(), ["one".to_string()]);

        let unknown = status(StatusOutcome::Success, "2025-01-01T00:00:00Z");
        write_status_file(&outbox, &unknown);
        tracker.process_watcher("one");
        assert!(!outbox.join(status_filename(COMMAND_ID)).exists());

        let _pending = tracker.track("one", request("2025-01-01T00:00:00Z"));
        let stale = StatusRecord {
            cert_arn: "arn:aws:acm:us-east-1:123456789012:certificate/other".to_string(),
            ..status(StatusOutcome::Success, "2025-01-01T00:00:00Z")
        };
        write_status_file(&outbox, &stale);
        tracker.process_watcher("one");
        assert!(!outbox.join(status_filename(COMMAND_ID)).exists());
        assert!(tracker.tracked.lock().unwrap().contains_key(COMMAND_ID));
    }

    #[test]
    fn deletes_malformed_and_oversized_statuses() {
        let root = tempfile::tempdir().unwrap();
        let outbox = root.path().join("one").join(OUTBOX_DIR);
        fs::create_dir_all(&outbox).unwrap();
        let tracker = WatcherStatusTracker::new(root.path().to_path_buf(), ["one".to_string()]);
        let malformed = outbox.join(status_filename(COMMAND_ID));
        fs::write(&malformed, b"not json").unwrap();
        tracker.process_watcher("one");
        assert!(!malformed.exists());

        let oversized = outbox.join(status_filename(COMMAND_ID));
        fs::write(&oversized, vec![b'x'; MAX_STATUS_BYTES + 1]).unwrap();
        tracker.process_watcher("one");
        assert!(!oversized.exists());
    }
    #[tokio::test]
    async fn status_ready_at_publication_handoff_is_correlated_after_registration() {
        let root = tempfile::tempdir().unwrap();
        let inbox = root.path().join("one").join("inbox");
        let outbox = root.path().join("one").join(OUTBOX_DIR);
        fs::create_dir_all(&inbox).unwrap();
        fs::create_dir_all(&outbox).unwrap();
        let tracker = WatcherStatusTracker::new(root.path().to_path_buf(), ["one".to_string()]);
        let prepared = watcher_request::prepare_request(ARN).unwrap();
        let request = prepared.request().clone();

        let pending = tracker.track("one", request.clone());
        watcher_request::publish_prepared_request(
            &RequestsRoot::open(root.path()).unwrap(),
            "one",
            &prepared,
        )
        .unwrap();
        // This models a watcher completing before the scanner handles the
        // successful-publication notification.
        let expected = StatusRecord {
            command_id: request.command_id.clone(),
            cert_arn: request.certificate_arn.clone(),
            request_created_at: request.created_at.clone(),
            ..status(StatusOutcome::Success, &request.created_at)
        };
        write_status_file(&outbox, &expected);
        tracker.process_watcher("one");

        assert_eq!(
            pending
                .wait(
                    Instant::now() + Duration::from_secs(1),
                    &CancellationToken::new(),
                )
                .await
                .unwrap(),
            expected
        );
        assert!(tracker.tracked.lock().unwrap().is_empty());
        assert!(!outbox.join(status_filename(&request.command_id)).exists());
    }

    #[cfg(unix)]
    #[test]
    fn intermediate_directory_replacement_does_not_redirect_status_access() {
        let root = tempfile::tempdir().unwrap();
        let watcher = root.path().join("one");
        let moved_watcher = root.path().join("one-moved");
        let outside = root.path().join("outside");
        let outbox = watcher.join(OUTBOX_DIR);
        let outside_outbox = outside.join(OUTBOX_DIR);
        fs::create_dir_all(&outbox).unwrap();
        fs::create_dir_all(&outside_outbox).unwrap();
        let tracker = WatcherStatusTracker::new(root.path().to_path_buf(), ["one".to_string()]);
        let opened = open_outbox(root.path(), "one").unwrap();
        let name = status_filename(COMMAND_ID);
        fs::rename(&watcher, &moved_watcher).unwrap();
        std::os::unix::fs::symlink(&outside, &watcher).unwrap();
        fs::write(outside_outbox.join(&name), b"outside must remain").unwrap();
        write_status_file(
            &moved_watcher.join(OUTBOX_DIR),
            &status(StatusOutcome::Success, "2025-01-01T00:00:00Z"),
        );
        let entries = enumerate_outbox(&opened).unwrap().statuses;
        assert!(entries.iter().any(|entry| entry == &OsString::from(&name)));

        tracker.process_candidate(
            "one",
            &opened.path,
            &opened.directory,
            OsString::from(name.clone()),
        );

        assert!(!moved_watcher.join(OUTBOX_DIR).join(&name).exists());
        assert_eq!(
            fs::read(outside_outbox.join(name)).unwrap(),
            b"outside must remain"
        );
    }

    /// Restores a directory's mode on drop, so a failed assertion still
    /// leaves the tempdir removable.
    #[cfg(target_os = "linux")]
    struct RestoreMode<'a> {
        path: &'a Path,
        mode: u32,
    }

    #[cfg(target_os = "linux")]
    impl Drop for RestoreMode<'_> {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(self.path, fs::Permissions::from_mode(self.mode));
        }
    }

    /// `<watcher_id>/` is 0o710, so a provider that shares only the
    /// watcher's group may search it but not read it. Owner search-only
    /// (0o100) reproduces that with one UID.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn search_only_watcher_directory_still_reaches_inbox_and_outbox() {
        use std::os::unix::fs::PermissionsExt;
        // Root bypasses directory permissions, so EACCES can't be produced.
        if rustix::process::geteuid().is_root() {
            eprintln!("skipping: running as root, permission checks are bypassed");
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let watcher = root.path().join("one");
        let outbox = watcher.join(OUTBOX_DIR);
        fs::create_dir_all(watcher.join("inbox")).unwrap();
        fs::create_dir_all(&outbox).unwrap();
        let tracker = WatcherStatusTracker::new(root.path().to_path_buf(), ["one".to_string()]);
        let requests = RequestsRoot::open(root.path()).unwrap();
        let pending = tracker.track("one", request("2025-01-01T00:00:00Z"));
        write_status_file(
            &outbox,
            &status(StatusOutcome::Success, "2025-01-01T00:00:00Z"),
        );
        fs::set_permissions(&watcher, fs::Permissions::from_mode(0o100)).unwrap();
        let _restore = RestoreMode {
            path: &watcher,
            mode: 0o700,
        };

        let opened = open_outbox(root.path(), "one");
        assert!(opened.is_ok(), "open_outbox failed: {:?}", opened.err());
        tracker.process_watcher("one");
        assert!(tracker.tracked.lock().unwrap().is_empty());
        pending
            .wait(
                Instant::now() + Duration::from_secs(1),
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        let prepared = watcher_request::prepare_request(ARN).unwrap();
        watcher_request::publish_prepared_request(&requests, "one", &prepared).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_status_without_following_it() {
        let root = tempfile::tempdir().unwrap();
        let outbox = root.path().join("one").join(OUTBOX_DIR);
        let target = root.path().join("target");
        fs::create_dir_all(&outbox).unwrap();
        fs::write(&target, b"must remain").unwrap();
        std::os::unix::fs::symlink(&target, outbox.join(status_filename(COMMAND_ID))).unwrap();
        let tracker = WatcherStatusTracker::new(root.path().to_path_buf(), ["one".to_string()]);
        tracker.process_watcher("one");
        assert_eq!(fs::read(&target).unwrap(), b"must remain");
        assert!(!outbox.join(status_filename(COMMAND_ID)).exists());
    }
}
