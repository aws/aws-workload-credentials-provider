//! The inbox and pending request directories: what counts as a request, how
//! one is claimed and read, and what startup recovers.
//!
//! # Lifecycle: claim to `pending/`, delete on complete
//!
//! The ACM provider writes requests into `<requests_dir>/<watcher_id>/inbox/`.
//! The watcher owns the sibling `pending/`, which holds every claimed request
//! whose reload has not completed:
//!
//! 1. **Claim.** [`claim`] renames `inbox/<name>` to `pending/<name>` before
//!    the file is read, so a later event or rescan cannot admit it twice.
//! 2. **Read.** [`read_claimed`] parses and checks it; one that does not parse,
//!    or whose `command_id` or `certificate_arn` is malformed, is deleted.
//! 3. **Complete.** When its reload finishes, successfully or not, the event
//!    loop deletes it ([`delete`]).
//! 4. **Recover.** At startup, [`prepare_startup_state`] re-reads what a
//!    previous run left in `pending/` and hands it to the startup hold window.
//!    Nothing in `inbox/` is deleted at startup.
//!
//! A request is therefore handled at least once: a crash between claim and
//! completion leaves it in `pending/`, and the next start runs its reload
//! again; that is safe, because a reload loads whatever certificate is on
//! disk. A failed reload is not retried, and a request whose reload crashes
//! the watcher crashes it again on every start. A name claimed twice
//! overwrites the earlier file ([`claim`]).
//!
//! # Acceptance: the `.cmd` extension, then the content
//!
//! A file is a candidate only if [`is_request_file`] accepts its name (it ends
//! in `.cmd`), and a request only if [`read`] parses it. A file whose name
//! fails that check is never claimed, opened or deleted. This keeps out the
//! ACM provider's mid-write temp file (`.{32 hex}.tmp`, written inside
//! `inbox/` and renamed to `{epoch_millis}-{sequence:03}-{command_id}.cmd`),
//! whose contents may already be a complete request, and any other stray file
//! on the shared volume. Only the extension is checked, not the shape of the
//! stem.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use aws_workload_credentials_provider_common::filesystem::FileSystem;
use log::{debug, error, info, warn};

use crate::env::WatcherEnv;
use crate::error::{RequestError, StartupError};
use aws_workload_credentials_provider_common::watcher_request::{
    RefreshRequest, REQUEST_EXTENSION,
};

/// Largest request file that will be read.
///
/// A well-formed request is a three-field JSON object of a few hundred bytes.
pub const MAX_REQUEST_BYTES: u64 = 4 * 1024;

/// A watcher that was down for a long time can come back to an arbitrarily large
/// inbox directory. Going over the cap is not an error — the requests over it
/// are picked up by the next scan, and merging means a backlog of thousands
/// still collapses to one reload per command. The specific number is chosen
/// here; no source specifies one.
///
/// The cap counts **`.cmd` candidates**, not confirmed requests: a scan cannot
/// know what parses without opening every candidate, and opening an unbounded
/// number of files is the thing the cap exists to prevent. Entries that are
/// not request files ([`is_request_file`]) are never opened and do not count.
pub const MAX_REQUESTS_PER_SCAN: usize = 1024;

/// True when `path` names a request file: its file name ends in `.` and
/// `watcher_request::REQUEST_EXTENSION` (`.cmd`), with a non-empty stem.
///
/// **The admission allowlist**, and the only filename rule. Every path the
/// watcher might read — from an event or from a scan — goes through this
/// first, and a path it rejects is never opened, parsed or deleted. See the
/// module documentation.
///
/// - Exact and case-sensitive: `x.CMD` and `x.cmdx` are not requests.
/// - The extension must be last, so the ACM provider's temp files
///   (`.{32 hex}.tmp`, or `<name>.cmd.tmp` from older writers) are not
///   requests.
/// - A bare `.cmd` has an empty stem and is not a request.
/// - A non-UTF-8 name is not something the ACM provider wrote, so it is not
///   a request.
///
/// Matched on the name rather than on a `notify` event kind: inotify and
/// `ReadDirectoryChangesW` report different kinds for the same filesystem
/// action, whereas the ACM provider's naming is identical on both platforms.
pub fn is_request_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(REQUEST_EXTENSION))
        .and_then(|name| name.strip_suffix('.'))
        .is_some_and(|stem| !stem.is_empty())
}

/// Lists the candidate request files in `dir`.
///
/// Returns the paths and whether the listing was truncated by
/// [`MAX_REQUESTS_PER_SCAN`]. Only entries that pass [`is_request_file`] and
/// are not directories are candidates; everything else, including the ACM
/// provider's temp files, is skipped without being opened. Whether a
/// candidate is a request is decided by [`read`] parsing it, not here.
pub fn scan(dir: &Path) -> io::Result<(Vec<PathBuf>, bool)> {
    list_candidates(dir, false)
}

/// [`scan`], optionally logging each skipped entry at debug.
///
/// `inbox/` is listed without that logging, because the ACM provider's temp
/// files pass through it on every scan. `pending/` is the watcher's own
/// directory, so anything unexpected there is worth a line.
fn list_candidates(dir: &Path, log_skipped: bool) -> io::Result<(Vec<PathBuf>, bool)> {
    let mut paths = Vec::new();
    let mut truncated = false;

    for entry in fs::read_dir(dir)? {
        // One unreadable entry must not abandon the rest of the scan: the
        // remaining requests are for other certificates.
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                warn!("Skipping an unreadable entry in '{}': {}", dir.display(), e);
                continue;
            }
        };

        let path = entry.path();

        // The allowlist.
        if !is_request_file(&path) {
            if log_skipped {
                debug!("Ignoring {:?}: not a request file", path);
            }
            continue;
        }

        // Ignore directories
        if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            if log_skipped {
                debug!("Ignoring the directory {:?}", path);
            }
            continue;
        }

        if paths.len() >= MAX_REQUESTS_PER_SCAN {
            truncated = true;
            break;
        }

        paths.push(path);
    }

    Ok((paths, truncated))
}

/// Reads and parses one candidate file: **this is the admission decision**.
///
/// A file that deserializes into a [`RefreshRequest`] whose `command_id` and
/// `certificate_arn` are well formed (`RefreshRequest::invalid_field`) is a
/// request. One that does not parse comes back as [`RequestError::Parse`],
/// and one with a malformed field as [`RequestError::Invalid`], for the
/// caller to skip. Callers pass only paths that [`is_request_file`] accepts.
///
/// # Untrusted files
///
/// The TLS container can write to the request volume, and [`claim`] moves
/// whatever is at a name as-is, so the file here may be anything. The event
/// loop calls this, so a read that blocks or never ends stalls the watcher.
/// On Unix:
///
/// - The open does not follow a symlink (`O_NOFOLLOW`): a symlink is
///   [`RequestError::NotAFile`], so a `x.cmd -> /dev/zero` is never read.
/// - The open does not block (`O_NONBLOCK`), so a FIFO is opened rather than
///   waited on, and then refused below.
/// - The opened handle must be a regular file, so a FIFO, device or socket
///   is [`RequestError::NotAFile`] before any byte is read.
/// - At most [`MAX_REQUEST_BYTES`]` + 1` bytes are read, whatever size the
///   file reports, so a file that grows after the size check is still
///   [`RequestError::TooLarge`].
///
/// The bytes are parsed as they are, so a body that is not UTF-8 is a
/// [`RequestError::Parse`] like any other malformed request.
///
/// On Windows the open returns a reparse point itself rather than its target
/// (`FILE_FLAG_OPEN_REPARSE_POINT`), and a handle that is a reparse point is
/// [`RequestError::NotAFile`]: symlinks, junctions and every other kind.
pub fn read(path: &Path) -> Result<RefreshRequest, RequestError> {
    use std::io::Read;

    let read_error = |source| RequestError::Read {
        path: path.to_path_buf(),
        source,
    };

    let file = open_request(path)?;
    let metadata = file.metadata().map_err(read_error)?;
    if !metadata.is_file() {
        return Err(RequestError::NotAFile {
            path: path.to_path_buf(),
            kind: kind_of(&metadata.file_type()),
        });
    }

    let too_large = |size| RequestError::TooLarge {
        path: path.to_path_buf(),
        size,
        limit: MAX_REQUEST_BYTES,
    };
    if metadata.len() > MAX_REQUEST_BYTES {
        return Err(too_large(metadata.len()));
    }

    let mut bytes = Vec::new();
    file.take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(read_error)?;
    let seen = bytes.len() as u64;
    if seen > MAX_REQUEST_BYTES {
        return Err(too_large(seen));
    }

    // `RefreshRequest` is not `deny_unknown_fields`, and nothing here adds
    // strictness on top of it. Tolerating unknown fields is the entire
    // forward-compatibility story: a request written by a later ACM provider
    // that added a field must still be actionable, rather than stopping this
    // watcher from reloading certificates.
    //
    // This module uses `command_id` only as a log label. Whether the field is
    // per-request or per-reload-command is still unsettled — see
    // `watcher_request::RefreshRequest::command_id` — but nothing here depends on
    // the answer any more, now that it is not the filename.
    let request: RefreshRequest =
        serde_json::from_slice(&bytes).map_err(|source| RequestError::Parse {
            path: path.to_path_buf(),
            source,
        })?;

    // Both fields the event loop logs are checked here, before anything logs
    // them, so a line break or control character in either cannot forge a
    // log line. Every request reaches the loop through this function, from a
    // scan, an event or startup recovery.
    if let Some(field) = request.invalid_field() {
        return Err(RequestError::Invalid {
            path: path.to_path_buf(),
            field,
        });
    }
    Ok(request)
}

/// Opens a request file for [`read`] without following a symlink or
/// blocking.
#[cfg(unix)]
fn open_request(path: &Path) -> Result<fs::File, RequestError> {
    use rustix::fs::{open, Mode, OFlags};
    use rustix::io::Errno;

    let flags =
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
    match open(path, flags, Mode::empty()) {
        Ok(fd) => Ok(fs::File::from(fd)),
        // `O_NOFOLLOW` on a symlink. The directories above the file are
        // checked to be symlink-free, so the last component is the symlink.
        Err(e) if e == Errno::LOOP => Err(RequestError::NotAFile {
            path: path.to_path_buf(),
            kind: "symlink",
        }),
        Err(e) => Err(RequestError::Read {
            path: path.to_path_buf(),
            source: e.into(),
        }),
    }
}

/// Opens a request file for [`read`] as itself, never what a reparse point
/// names.
///
/// `FILE_FLAG_OPEN_REPARSE_POINT` opens a symlink or junction rather than its
/// target, and the attribute check refuses it. The check is on the handle
/// [`read`] then reads from, so nothing can be swapped in between.
#[cfg(windows)]
fn open_request(path: &Path) -> Result<fs::File, RequestError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    let read_error = |source| RequestError::Read {
        path: path.to_path_buf(),
        source,
    };

    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)
        .map_err(read_error)?;
    let attributes = file.metadata().map_err(read_error)?.file_attributes();
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(RequestError::NotAFile {
            path: path.to_path_buf(),
            kind: "reparse point",
        });
    }
    Ok(file)
}

/// What a file that is not a regular file is, for the log.
fn kind_of(file_type: &fs::FileType) -> &'static str {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if file_type.is_fifo() {
            return "FIFO";
        }
        if file_type.is_char_device() {
            return "character device";
        }
        if file_type.is_block_device() {
            return "block device";
        }
        if file_type.is_socket() {
            return "socket";
        }
    }
    if file_type.is_dir() {
        "directory"
    } else if file_type.is_symlink() {
        "symlink"
    } else {
        "special file"
    }
}

/// What [`claim`] did with one name.
#[derive(Debug, PartialEq, Eq)]
pub enum Claim {
    /// Moved into the pending directory, at this path.
    Claimed(PathBuf),

    /// Nothing was at the name: an earlier event or scan already claimed it,
    /// or it was removed.
    Gone,

    /// A directory with a request's name. Left where it is.
    Directory,
}

/// Claims `inbox/<name>` by renaming it to `pending/<name>`.
///
/// Called before the file is read, so that whatever was at the name at the
/// instant of the rename is what gets processed, and so that no later event
/// or scan of `inbox/` can see the request again.
///
/// `Err` leaves the file in `inbox/` for the next scan.
///
/// A request already at `pending/<name>` is deliberately replaced: a plain
/// rename, with no no-replace check. The ACM provider never reuses a name,
/// and if one is reused the requests sharing it are bundled under the one
/// file. The event loop's reference-counted deletion
/// (`run::Loop::is_referenced`) keeps that file on disk until the last batch
/// that references the name has completed. Only the newer content is then on
/// disk, so a crash before the older request's reload runs loses that request
/// if it is for a different command, or if the newer content is not a usable
/// request.
pub fn claim(inbox: &Path, pending: &Path, name: &OsStr) -> io::Result<Claim> {
    let source = inbox.join(name);
    let destination = pending.join(name);

    match fs::symlink_metadata(&source) {
        Ok(metadata) if metadata.is_dir() => return Ok(Claim::Directory),
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Claim::Gone),
        Err(e) => return Err(e),
    }

    match fs::rename(&source, &destination) {
        Ok(()) => Ok(Claim::Claimed(destination)),
        // ENOENT names either end. Only a missing source means "already
        // handled"; a missing pending directory is an error.
        Err(e)
            if e.kind() == io::ErrorKind::NotFound
                && fs::symlink_metadata(&source)
                    .is_err_and(|e| e.kind() == io::ErrorKind::NotFound) =>
        {
            Ok(Claim::Gone)
        }
        Err(e) => Err(e),
    }
}

/// Reads a request file in the pending directory.
///
/// `None` when there is nothing to queue:
///
/// - the file is gone (debug);
/// - it is not a regular file, is too large, does not parse or has a
///   malformed field: it is deleted (warn), so the pending directory never keeps a file it cannot
///   use. Deleting a symlink removes the link, not what it points to;
/// - any other read error: it is left in place (error), and the next start
///   recovers it.
pub fn read_claimed(path: &Path) -> Option<RefreshRequest> {
    match read(path) {
        Ok(request) => Some(request),
        Err(e) if e.is_not_found() => {
            debug!("{:?} is gone; nothing to read", path);
            None
        }
        Err(e) if e.is_unusable() => {
            warn!("Deleting {:?}: it isn't a usable request ({})", path, e);
            delete(path);
            None
        }
        Err(e) => {
            error!(
                "Leaving {:?} in place: {}. It is recovered on the next start.",
                path, e
            );
            None
        }
    }
}

/// Deletes one request file from the pending directory.
///
/// A missing file is success: there is nothing left to delete.
pub fn delete(path: &Path) {
    match fs::remove_file(path) {
        Ok(()) => debug!("Deleted request {:?}", path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        // Loud: a request that cannot be deleted is recovered, and its reload
        // run again, on every start.
        Err(e) => error!("Failed to delete request {:?}: {}", path, e),
    }
}

/// A request in the pending directory, and the name of its file there.
#[derive(Debug)]
pub struct Claimed {
    pub name: OsString,
    pub request: RefreshRequest,
}

/// Prepares the request directories for the event loop and returns the
/// requests a previous run claimed and did not complete.
///
/// In order:
///
/// 1. Create `<watcher_id>/` if it is missing, with
///    [`WATCHER_REQUESTS_DIR_MODE`] on Unix. The requests root itself is
///    never created: `verify_roots_present` has already checked it.
/// 2. Check `<watcher_id>/` ([`WatcherEnv::verify_watcher_requests_dir`])
///    before anything is created in it.
/// 3. Create `inbox/` if it is missing, with [`INBOX_DIR_MODE`] on Unix.
/// 4. Check `inbox/` ([`WatcherEnv::verify_inbox_leaf`]).
/// 5. Create `pending/` if it is missing: owner-only on Unix, since the ACM
///    provider never uses it.
/// 6. Check `pending/` the same way.
/// 7. Recover its requests ([`recover`]).
///
/// Every create is one level only.
///
/// Nothing in `inbox/` is touched. Its requests, including any left by a
/// previous run, are claimed by the event loop's first scan, and the ACM
/// provider's temp files are never touched at all. `outbox/` is Phase 2 and
/// untouched.
///
/// Any failure is fatal: it means the volume this watcher exists to read is
/// not what it should be.
pub fn prepare_startup_state(
    env: &WatcherEnv,
    filesystem: &impl FileSystem,
) -> Result<Vec<Claimed>, StartupError> {
    // A symlink at `<watcher_id>` makes this a no-op (EEXIST), and the check
    // after it refuses the symlink before anything is created through it.
    create_shared_dir(&env.watcher_requests_dir(), WATCHER_REQUESTS_DIR_MODE)?;
    env.verify_watcher_requests_dir(filesystem)
        .map_err(|source| StartupError::RequestDirInvalid { source })?;

    create_shared_dir(&env.inbox_dir(), INBOX_DIR_MODE)?;
    env.verify_inbox_leaf(filesystem)
        .map_err(|source| StartupError::RequestDirInvalid { source })?;

    let pending = env.pending_dir();
    let unusable = |source| StartupError::PendingDirUnusable {
        path: pending.clone(),
        source,
    };
    if create_request_dir(&pending, PENDING_DIR_MODE).map_err(unusable)? {
        info!(
            "Created the pending request directory '{}'",
            pending.display()
        );
    }

    env.verify_pending_leaf(filesystem)
        .map_err(|source| StartupError::RequestDirInvalid { source })?;

    recover(&pending).map_err(unusable)
}

/// The Unix mode `<watcher_id>/` is created with. An existing one keeps its
/// own. The ACM provider's group only searches it, to reach `inbox/`: no
/// group write, so a group member cannot rename `inbox/` or `pending/`.
const WATCHER_REQUESTS_DIR_MODE: u32 = 0o710;

/// The Unix mode `inbox/` is created with. An existing inbox keeps its own.
///
/// The group is the one the ACM provider shares with the watcher where it
/// does not run as root with `CAP_DAC_OVERRIDE`, which bypasses the mode.
/// The directory takes the watcher's primary group, or the parent's group
/// when the parent is setgid. Anyone else is refused. The `docker` tests
/// check each case across real containers.
///
/// Group read as well as write and search: the provider opens the inbox
/// read-only to write relative to it (`watcher_request::enqueue`), which a
/// directory without read permission refuses.
const INBOX_DIR_MODE: u32 = 0o770;

/// The Unix mode `pending/` is created with. Owner-only: only the watcher
/// uses it.
const PENDING_DIR_MODE: u32 = 0o700;

/// Creates `<watcher_id>/` or `inbox/` with [`create_request_dir`], logging
/// a create.
fn create_shared_dir(path: &Path, mode: u32) -> Result<(), StartupError> {
    let created =
        create_request_dir(path, mode).map_err(|source| StartupError::RequestDirUncreatable {
            path: path.to_path_buf(),
            source,
        })?;
    if created {
        info!("Created the request directory '{}'", path.display());
    }
    Ok(())
}

/// Creates `path` with `mode` on Unix, returning false if something is
/// already there.
///
/// One level only. What is there is left for the leaf check to judge,
/// with its mode unchanged.
fn create_request_dir(path: &Path, mode: u32) -> io::Result<bool> {
    // `mut` is only needed for the Unix `mode` call below.
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        // Owner-only until `set_created_mode`, so the group never sees a
        // mode in between.
        builder.mode(0o700);
    }

    match builder.create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Ok(false),
        Err(e) => return Err(e),
    }

    #[cfg(unix)]
    set_created_mode(path, mode)?;
    #[cfg(not(unix))]
    let _ = mode;
    Ok(true)
}

/// Sets `mode` on the directory just created at `path`.
///
/// `mkdir`'s mode is filtered by the umask, which would strip the group bits
/// (`022` turns `0730` into `0710`), so the mode is set explicitly. Through a
/// handle opened without following a symlink, so a symlink swapped in after
/// the `mkdir` fails here instead of having its target's mode changed.
#[cfg(unix)]
fn set_created_mode(path: &Path, mode: u32) -> io::Result<()> {
    use rustix::fs::{fchmod, open, Mode, OFlags, RawMode};

    let dir = open(
        path,
        OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    // `RawMode` is `mode_t`: `u32` on Linux, `u16` on macOS. Permission bits
    // fit in either, so the conversion never fails for a valid mode.
    let raw = RawMode::try_from(mode)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "mode out of range"))?;
    fchmod(&dir, Mode::from_raw_mode(raw))?;
    Ok(())
}

/// Reads every request left in the pending directory `dir`.
///
/// The same allowlist as `inbox/`, without the rename: only `.cmd` files are
/// read, other entries are logged at debug and left, and directories are
/// skipped. A file that does not parse is deleted ([`read_claimed`]). At most
/// [`MAX_REQUESTS_PER_SCAN`] are read; the rest stay for the next start.
pub fn recover(dir: &Path) -> io::Result<Vec<Claimed>> {
    let (paths, truncated) = list_candidates(dir, true)?;
    if truncated {
        warn!(
            "More than {} requests in '{}'; recovering the first {} and leaving the rest \
             for the next start",
            MAX_REQUESTS_PER_SCAN,
            dir.display(),
            MAX_REQUESTS_PER_SCAN
        );
    }

    let mut recovered = Vec::new();
    for path in paths {
        let Some(name) = path.file_name() else {
            continue;
        };
        if let Some(request) = read_claimed(&path) {
            recovered.push(Claimed {
                name: name.to_os_string(),
                request,
            });
        }
    }

    info!(
        "Recovered {} request(s) left in '{}' by a previous run",
        recovered.len(),
        dir.display()
    );
    Ok(recovered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use crate::types::acm_provider_writer::{
        is_request_file_name, new_request, request_file_name, wcp_request_body, WCP_COMMAND_ID,
        WCP_CREATED_AT, WCP_REQUEST_NAME, WCP_TEMP_NAME,
    };
    use crate::types::REQUEST_TEMP_SUFFIX;
    use aws_workload_credentials_provider_common::filesystem::RealFileSystem;
    use aws_workload_credentials_provider_common::watcher_request::{
        enqueue, inbox_path, RequestsRoot,
    };
    use tempfile::TempDir;

    const ARN: &str = "arn:aws:acm:us-west-2:123456789012:certificate/abcd";

    fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, body).unwrap();
        path
    }

    fn valid_body() -> String {
        serde_json::to_string(&new_request(ARN)).unwrap()
    }

    /// A realistic request filename, so the fixtures exercise the real shape.
    fn req_name(sequence: u64) -> String {
        request_file_name(1728331740000, sequence, "req-abcd")
    }

    // -- acceptance: the `.cmd` allowlist, then the content --

    /// The allowlist, name by name: exactly a trailing, case-sensitive `.cmd`
    /// with a non-empty stem.
    #[test]
    fn only_names_ending_in_the_request_extension_are_request_files() {
        for name in [
            "x.cmd",
            req_name(1).as_str(),
            WCP_REQUEST_NAME,
            // Only the extension is checked, not the stem's shape.
            "nope-001-req-abcd.cmd",
            // `.tmp` in the middle is not the end of the name.
            "1728331740000-001-req.tmp.cmd",
        ] {
            assert!(is_request_file(Path::new(name)), "{name}");
        }

        for name in [
            "x.tmp",
            // The WCP writer's temp name.
            WCP_TEMP_NAME,
            // An older writer's temp name: `.cmd` is not the end of it.
            "x.cmd.tmp",
            &format!("{}{REQUEST_TEMP_SUFFIX}", req_name(1)),
            "x.txt",
            "x",
            // Empty stem.
            ".cmd",
            // Case-sensitive.
            "x.CMD",
            "x.Cmd",
            // The extension must be exactly `.cmd`.
            "x.cmdx",
            "xcmd",
            "cmd",
            "",
        ] {
            assert!(!is_request_file(Path::new(name)), "{name}");
        }
    }

    /// A non-UTF-8 name is not something the ACM provider wrote.
    #[cfg(unix)]
    #[test]
    fn a_non_utf8_name_is_not_a_request_file() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        assert!(!is_request_file(Path::new(OsStr::from_bytes(b"\xff.cmd"))));
    }

    /// The point of an allowlist: a body that is a perfectly valid request is
    /// still not a candidate under a name that does not end in `.cmd`, so it
    /// is never read. A `.cmd` file with the same body is.
    #[test]
    fn a_valid_body_under_a_non_request_name_is_not_a_candidate() {
        let tmp = TempDir::new().unwrap();

        let ignored = [
            "nothing-like-a-request",
            // Older naming: the command_id alone.
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
            "notes.txt",
            "README",
        ];
        for name in ignored {
            let path = write(tmp.path(), name, &valid_body());
            // The body would be accepted if it were read...
            assert!(read(&path).is_ok(), "{name}");
            // ...but the name keeps it from being read.
            assert!(!is_request_file(&path), "{name}");
        }
        // Must not match a name above case-insensitively: on NTFS or default
        // APFS, writing `x.cmd` overwrites `x.CMD` and keeps the `x.CMD` name.
        let accepted = write(tmp.path(), "accepted.cmd", &valid_body());

        let (listed, truncated) = scan(tmp.path()).unwrap();
        assert_eq!(listed, vec![accepted]);
        assert!(!truncated);
    }

    /// The ACM provider's mid-write file is **not** a candidate even though
    /// its contents are a perfectly valid request. Without this the watcher
    /// picks up the ACM provider's file mid-write and races the rename.
    #[test]
    fn a_temp_suffixed_file_is_not_accepted_even_with_valid_contents() {
        let tmp = TempDir::new().unwrap();
        let path = write(
            tmp.path(),
            &format!("{}{REQUEST_TEMP_SUFFIX}", req_name(1)),
            &valid_body(),
        );

        // The body is a complete request — that is exactly the hazard.
        assert!(read(&path).is_ok(), "the body is a valid request");
        assert!(!is_request_file(&path), "{}", path.display());

        let (listed, _) = scan(tmp.path()).unwrap();
        assert!(
            listed.is_empty(),
            "a temp file must never be a candidate: {listed:?}"
        );
    }

    /// A malformed `.cmd` file is skipped, not fatal: `read` returns an error
    /// the caller drops.
    #[test]
    fn unparseable_request_files_are_rejected_by_read() {
        let tmp = TempDir::new().unwrap();

        for (sequence, body) in [
            (1, "not json at all"),
            (2, ""),
            // Valid JSON, wrong shape.
            (3, r#"{"hello":"world"}"#),
            // A request missing a required field.
            (
                4,
                r#"{"command_id":"req-x","created_at":"2024-05-01T12:00:00Z"}"#,
            ),
            // Truncated mid-write.
            (5, r#"{"command_id":"#),
        ] {
            let path = write(tmp.path(), &req_name(sequence), body);
            // It IS a candidate — the name lets it in...
            assert!(is_request_file(&path), "{}", path.display());
            // ...and the parse keeps it out.
            assert!(matches!(
                read(&path).unwrap_err(),
                RequestError::Parse { .. }
            ));
        }
    }

    // -- read --

    /// Pins the ACM-provider-to-watcher file contract from the writer's own
    /// API: if either side changes the filename or the JSON shape, this fails.
    ///
    /// A full round trip — the ACM provider's writer produces the file, this
    /// module parses it — so the two binaries cannot drift apart silently. The
    /// raw text is asserted as well as the parsed value, because a `serde`
    /// rename on both sides at once would keep the parse working while
    /// changing what is actually on disk.
    #[test]
    fn reads_a_request_written_by_the_acm_provider() {
        let tmp = TempDir::new().unwrap();
        let inbox = inbox_path(tmp.path(), "nginx");
        fs::create_dir_all(&inbox).unwrap();

        let root = RequestsRoot::open(tmp.path()).unwrap();
        let path = inbox.join(enqueue(&root, "nginx", ARN).unwrap());

        assert!(is_request_file(&path), "{}", path.display());
        assert_eq!(
            fs::read_dir(&inbox).unwrap().count(),
            1,
            "no temp file left"
        );

        // The WCP producer's field set, exactly: `command_id`,
        // `certificate_arn` and `created_at`. An older format named the ARN
        // field `cert_arn`; the field now matches the WCP producer.
        let raw: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let mut keys: Vec<&str> = raw
            .as_object()
            .expect("a request is a JSON object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["certificate_arn", "command_id", "created_at"]);

        // Value forms, not just names: the ARN verbatim and the timestamp an
        // RFC 3339 string. `created_at` is checked through the raw JSON rather
        // than the parsed struct because both would deserialize from a bare
        // number too; the writer's own test pins the full RFC 3339 parse.
        let created_at = raw["created_at"]
            .as_str()
            .expect("created_at should be a JSON string, not epoch millis");
        assert!(
            created_at.contains('T'),
            "created_at should be RFC 3339: {created_at}"
        );

        let request = read(&path).unwrap();
        assert_eq!(request.certificate_arn, ARN);

        // The filename contract, from the reader's side: it is
        // `{epoch_millis}-{sequence}-{command_id}.cmd`, so the id is a
        // component of the name and no longer the whole of it.
        let name = path.file_name().unwrap().to_string_lossy();
        assert_ne!(name, request.command_id, "{name}");
        assert!(
            name.ends_with(&format!("{}.cmd", request.command_id)),
            "{name}"
        );
    }

    #[test]
    fn unknown_fields_are_tolerated() {
        let tmp = TempDir::new().unwrap();
        let body = format!(
            r#"{{"command_id":"{WCP_COMMAND_ID}","certificate_arn":"{ARN}","created_at":"2024-05-01T12:00:00Z","priority":"high"}}"#
        );
        let path = write(tmp.path(), &req_name(1), &body);

        let request = read(&path).expect("an unknown field must not break parsing");

        assert_eq!(request.certificate_arn, ARN);
    }

    /// The producer-consumer contract: a request byte-identical to what the
    /// WCP writer (`common::watcher_request::enqueue`) puts in the inbox is
    /// listed by `scan` and accepted by `read`, and the writer's temp file is
    /// skipped.
    #[test]
    fn reads_a_request_exactly_as_the_wcp_producer_writes_it() {
        // The fixture pins the bytes the shared type serializes to, so a
        // `serde` rename shows up here as well as in the parse.
        let produced = serde_json::to_string(&RefreshRequest {
            command_id: WCP_COMMAND_ID.to_string(),
            certificate_arn: ARN.to_string(),
            created_at: WCP_CREATED_AT.to_string(),
        })
        .unwrap();
        assert_eq!(produced, wcp_request_body(ARN));

        let tmp = TempDir::new().unwrap();
        let temp = write(tmp.path(), WCP_TEMP_NAME, &wcp_request_body(ARN));
        let path = write(tmp.path(), WCP_REQUEST_NAME, &wcp_request_body(ARN));

        assert!(!is_request_file(&temp), "{}", temp.display());
        assert!(is_request_file(&path), "{}", path.display());
        assert!(is_request_file_name(WCP_REQUEST_NAME));
        let (listed, truncated) = scan(tmp.path()).unwrap();
        assert_eq!(listed, vec![path.clone()]);
        assert!(!truncated);

        let request = read(&path).expect("a WCP-written request must be accepted");
        assert_eq!(
            request,
            RefreshRequest {
                command_id: WCP_COMMAND_ID.to_string(),
                certificate_arn: ARN.to_string(),
                created_at: WCP_CREATED_AT.to_string(),
            }
        );
    }

    /// The older `cert_arn` key is not an alias: a request that names the
    /// certificate only as `cert_arn` is not a request.
    #[test]
    fn a_request_with_the_old_cert_arn_key_is_rejected() {
        let tmp = TempDir::new().unwrap();
        let path = write(
            tmp.path(),
            &req_name(1),
            &format!(
                r#"{{"command_id":"req-x","cert_arn":"{ARN}","created_at":"2024-05-01T12:00:00Z"}}"#
            ),
        );

        let err = read(&path).unwrap_err();
        assert!(matches!(err, RequestError::Parse { .. }), "{err}");
        assert!(err.to_string().contains("certificate_arn"), "{err}");
    }

    #[test]
    fn missing_required_field_is_a_parse_error() {
        let tmp = TempDir::new().unwrap();
        // No `certificate_arn`: the watcher cannot route a request without it.
        let path = write(
            tmp.path(),
            &req_name(1),
            r#"{"command_id":"req-x","created_at":"2024-05-01T12:00:00Z"}"#,
        );

        assert!(matches!(
            read(&path).unwrap_err(),
            RequestError::Parse { .. }
        ));
    }

    #[test]
    fn oversized_request_is_rejected() {
        let tmp = TempDir::new().unwrap();
        let body = format!(
            r#"{{"command_id":"req-x","certificate_arn":"{ARN}","created_at":"x","pad":"{}"}}"#,
            "p".repeat(MAX_REQUEST_BYTES as usize)
        );
        let path = write(tmp.path(), &req_name(1), &body);

        assert!(matches!(
            read(&path).unwrap_err(),
            RequestError::TooLarge { .. }
        ));
    }

    #[test]
    fn missing_file_reads_as_not_found() {
        let tmp = TempDir::new().unwrap();
        let err = read(&tmp.path().join(req_name(1))).unwrap_err();
        assert!(err.is_not_found(), "{err}");
    }

    /// Runs `read` on another thread, failing instead of hanging if it does
    /// not return promptly.
    #[cfg(unix)]
    fn read_within_a_deadline(path: &Path) -> Result<RefreshRequest, RequestError> {
        let (tx, rx) = std::sync::mpsc::channel();
        let path = path.to_path_buf();
        std::thread::spawn(move || {
            let _ = tx.send(read(&path));
        });
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .expect("read must not block or read without end")
    }

    /// A symlink is refused even when what it points to is a valid request:
    /// its target is not the TLS container's to choose.
    #[cfg(unix)]
    #[test]
    fn a_symlink_to_a_valid_request_is_not_read() {
        let tmp = TempDir::new().unwrap();
        let target = write(tmp.path(), "target.json", &valid_body());
        let link = tmp.path().join(req_name(1));
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = read(&link).unwrap_err();

        assert!(
            matches!(
                err,
                RequestError::NotAFile {
                    kind: "symlink",
                    ..
                }
            ),
            "{err}"
        );
        assert!(err.is_unusable(), "{err}");
    }

    /// `x.cmd -> /dev/zero` reports 0 bytes and never ends; it is refused at
    /// the open.
    #[cfg(unix)]
    #[test]
    fn a_symlink_to_dev_zero_is_refused_without_reading() {
        let tmp = TempDir::new().unwrap();
        let link = tmp.path().join(req_name(1));
        std::os::unix::fs::symlink("/dev/zero", &link).unwrap();

        let err = read_within_a_deadline(&link).unwrap_err();

        assert!(
            matches!(
                err,
                RequestError::NotAFile {
                    kind: "symlink",
                    ..
                }
            ),
            "{err}"
        );
    }

    /// A FIFO is opened without waiting for a writer, then refused.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_fifo_is_refused_without_blocking() {
        use rustix::fs::{mknodat, FileType, Mode, CWD};

        let tmp = TempDir::new().unwrap();
        let fifo = tmp.path().join(req_name(1));
        mknodat(CWD, &fifo, FileType::Fifo, Mode::from_raw_mode(0o600), 0).unwrap();

        let err = read_within_a_deadline(&fifo).unwrap_err();

        assert!(
            matches!(err, RequestError::NotAFile { kind: "FIFO", .. }),
            "{err}"
        );
        assert!(err.is_unusable(), "{err}");
    }

    /// A body that is not UTF-8 is malformed like any other, so it is deleted
    /// rather than kept and re-read on every start.
    #[test]
    fn a_non_utf8_body_is_a_parse_error() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(req_name(1));
        let mut body = valid_body().into_bytes();
        let arn = body
            .windows(ARN.len())
            .position(|window| window == ARN.as_bytes())
            .unwrap();
        body[arn] = 0xff;
        fs::write(&path, &body).unwrap();

        let err = read(&path).unwrap_err();

        assert!(matches!(err, RequestError::Parse { .. }), "{err}");
        assert!(err.is_unusable(), "{err}");
    }

    /// Bytes that are not UTF-8 inside an unknown field are ignored with the
    /// field, so the request is still read.
    #[test]
    fn a_non_utf8_unknown_field_is_ignored() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(req_name(1));
        let mut body = valid_body().into_bytes();
        body.splice(1..1, *b"\"later\":\"\xff\",");
        fs::write(&path, &body).unwrap();

        assert_eq!(read(&path).unwrap().certificate_arn, ARN);
    }

    /// A symlink is refused as a reparse point even when it names a valid
    /// request, and `read_claimed` deletes the link but not its target.
    ///
    /// Creating a symlink needs administrator rights or Developer Mode;
    /// without either the test cannot set up and skips.
    #[cfg(windows)]
    #[test]
    fn a_symlink_is_not_read_on_windows() {
        let tmp = TempDir::new().unwrap();
        let target = write(tmp.path(), "target.json", &valid_body());
        let link = tmp.path().join(req_name(1));
        if let Err(e) = std::os::windows::fs::symlink_file(&target, &link) {
            println!("SKIPPED: cannot create a symlink here: {e}");
            return;
        }

        let err = read(&link).unwrap_err();
        assert!(
            matches!(
                err,
                RequestError::NotAFile {
                    kind: "reparse point",
                    ..
                }
            ),
            "{err}"
        );

        assert!(read_claimed(&link).is_none());
        assert!(fs::symlink_metadata(&link).is_err(), "the link is deleted");
        assert!(target.is_file(), "its target is not");
    }

    /// An unusable symlink in `pending/` is deleted, and the file it points
    /// to is left alone.
    #[cfg(unix)]
    #[test]
    fn read_claimed_deletes_a_symlink_but_not_its_target() {
        let tmp = TempDir::new().unwrap();
        let target = write(tmp.path(), "target.json", &valid_body());
        let link = tmp.path().join(req_name(1));
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert!(read_claimed(&link).is_none());

        assert!(fs::symlink_metadata(&link).is_err(), "the link is deleted");
        assert!(target.is_file(), "its target is not");
    }

    // -- scan --

    /// Only `.cmd` files are listed: the legacy name, the unrelated file, the
    /// temp file and the subdirectories — including one named like a
    /// request — are not.
    #[test]
    fn scan_lists_only_request_files() {
        let tmp = TempDir::new().unwrap();
        let a = write(tmp.path(), &req_name(1), &valid_body());
        let b = write(tmp.path(), &req_name(2), &valid_body());
        write(tmp.path(), "notes.txt", "");
        write(tmp.path(), "req-legacy-name", &valid_body());
        write(
            tmp.path(),
            &format!("{}{REQUEST_TEMP_SUFFIX}", req_name(3)),
            &valid_body(),
        );
        fs::create_dir(tmp.path().join("a-subdirectory")).unwrap();
        fs::create_dir(tmp.path().join(req_name(4))).unwrap();

        let (mut paths, truncated) = scan(tmp.path()).unwrap();
        paths.sort();
        let mut expected = vec![a, b];
        expected.sort();

        assert_eq!(paths, expected);
        assert!(!truncated);
    }

    #[test]
    fn scan_caps_its_result() {
        let tmp = TempDir::new().unwrap();
        for i in 0..MAX_REQUESTS_PER_SCAN + 5 {
            write(tmp.path(), &req_name(i as u64), &valid_body());
        }

        let (paths, truncated) = scan(tmp.path()).unwrap();

        assert_eq!(paths.len(), MAX_REQUESTS_PER_SCAN);
        assert!(truncated);
    }

    /// Files that are not requests are never candidates, so however many of
    /// them there are, they cannot crowd a real request out of a scan.
    #[test]
    fn non_request_files_do_not_count_toward_the_cap() {
        let tmp = TempDir::new().unwrap();
        for i in 0..MAX_REQUESTS_PER_SCAN + 5 {
            write(tmp.path(), &format!(".{i:032x}.tmp"), &valid_body());
        }
        let request = write(tmp.path(), &req_name(1), &valid_body());

        let (paths, truncated) = scan(tmp.path()).unwrap();

        assert_eq!(paths, vec![request]);
        assert!(!truncated);
    }

    #[test]
    fn scan_of_a_missing_directory_is_an_error() {
        let tmp = TempDir::new().unwrap();
        assert!(scan(&tmp.path().join("absent")).is_err());
    }

    // -- claim --

    /// `inbox/` and `pending/` side by side under one temp directory.
    fn request_dirs(tmp: &TempDir) -> (PathBuf, PathBuf) {
        let inbox = tmp.path().join("inbox");
        let pending = tmp.path().join("pending");
        fs::create_dir(&inbox).unwrap();
        fs::create_dir(&pending).unwrap();
        (inbox, pending)
    }

    #[test]
    fn claim_moves_a_request_into_the_pending_directory() {
        let tmp = TempDir::new().unwrap();
        let (inbox, pending) = request_dirs(&tmp);
        let name = req_name(1);
        let source = write(&inbox, &name, &valid_body());

        let outcome = claim(&inbox, &pending, OsStr::new(&name)).unwrap();

        let destination = pending.join(&name);
        assert_eq!(outcome, Claim::Claimed(destination.clone()));
        assert!(!source.exists());
        assert_eq!(read(&destination).unwrap().certificate_arn, ARN);
    }

    #[test]
    fn claim_of_a_missing_name_is_gone() {
        let tmp = TempDir::new().unwrap();
        let (inbox, pending) = request_dirs(&tmp);

        let outcome = claim(&inbox, &pending, OsStr::new(&req_name(1))).unwrap();

        assert_eq!(outcome, Claim::Gone);
        assert_eq!(fs::read_dir(&pending).unwrap().count(), 0);
    }

    #[test]
    fn claim_leaves_a_directory_named_like_a_request() {
        let tmp = TempDir::new().unwrap();
        let (inbox, pending) = request_dirs(&tmp);
        let name = req_name(1);
        fs::create_dir(inbox.join(&name)).unwrap();

        let outcome = claim(&inbox, &pending, OsStr::new(&name)).unwrap();

        assert_eq!(outcome, Claim::Directory);
        assert!(inbox.join(&name).is_dir());
        assert_eq!(fs::read_dir(&pending).unwrap().count(), 0);
    }

    /// A missing pending directory is an error, not "already handled", and
    /// the request stays in the inbox.
    #[test]
    fn claim_into_a_missing_pending_directory_is_an_error() {
        let tmp = TempDir::new().unwrap();
        let (inbox, pending) = request_dirs(&tmp);
        fs::remove_dir(&pending).unwrap();
        let name = req_name(1);
        let source = write(&inbox, &name, &valid_body());

        let err = claim(&inbox, &pending, OsStr::new(&name)).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(source.is_file());
    }

    /// A name already in the pending directory is overwritten by the newer
    /// request, which is claimed like any other.
    #[test]
    fn claim_overwrites_a_pending_request_of_the_same_name() {
        let tmp = TempDir::new().unwrap();
        let (inbox, pending) = request_dirs(&tmp);
        let name = req_name(1);
        let newer = valid_body();
        let source = write(&inbox, &name, &newer);
        let existing = write(&pending, &name, "the earlier request");

        let outcome = claim(&inbox, &pending, OsStr::new(&name)).unwrap();

        assert_eq!(outcome, Claim::Claimed(existing.clone()));
        assert!(!source.exists());
        assert_eq!(fs::read_to_string(&existing).unwrap(), newer);
        assert_eq!(fs::read_dir(&pending).unwrap().count(), 1);
    }

    // -- read_claimed and delete --

    #[test]
    fn read_claimed_deletes_an_unparseable_request() {
        let tmp = TempDir::new().unwrap();
        let garbage = write(tmp.path(), &req_name(1), "not json at all");
        let oversized = write(
            tmp.path(),
            &req_name(2),
            &"p".repeat(MAX_REQUEST_BYTES as usize + 1),
        );

        assert!(read_claimed(&garbage).is_none());
        assert!(read_claimed(&oversized).is_none());

        assert!(!garbage.exists());
        assert!(!oversized.exists());
    }

    #[test]
    fn read_claimed_returns_a_valid_request_and_keeps_its_file() {
        let tmp = TempDir::new().unwrap();
        let path = write(tmp.path(), &req_name(1), &valid_body());

        let request = read_claimed(&path).expect("a valid request");

        assert_eq!(request.certificate_arn, ARN);
        assert!(path.is_file(), "deleted only once its reload completes");
    }

    #[test]
    fn read_claimed_of_a_missing_file_is_none() {
        let tmp = TempDir::new().unwrap();
        assert!(read_claimed(&tmp.path().join(req_name(1))).is_none());
    }

    #[test]
    fn delete_tolerates_a_missing_file() {
        let tmp = TempDir::new().unwrap();
        delete(&tmp.path().join(req_name(1)));
    }

    // -- recover --

    /// Only `.cmd` files are recovered; anything else in the pending
    /// directory, including a directory named like a request, is left.
    #[test]
    fn recover_reads_only_request_files() {
        let tmp = TempDir::new().unwrap();
        let first = write(tmp.path(), &req_name(1), &valid_body());
        let second = write(tmp.path(), &req_name(2), &valid_body());
        let stray = write(tmp.path(), "notes.txt", &valid_body());
        let temp = write(tmp.path(), WCP_TEMP_NAME, &valid_body());
        let directory = tmp.path().join(req_name(3));
        fs::create_dir(&directory).unwrap();

        let mut names: Vec<OsString> = recover(tmp.path())
            .unwrap()
            .into_iter()
            .map(|claimed| claimed.name)
            .collect();
        names.sort();

        assert_eq!(
            names,
            vec![
                first.file_name().unwrap().to_os_string(),
                second.file_name().unwrap().to_os_string()
            ]
        );
        for path in [&first, &second, &stray, &temp] {
            assert!(path.is_file(), "{}", path.display());
        }
        assert!(directory.is_dir());
    }

    #[test]
    fn recover_deletes_an_unparseable_request() {
        let tmp = TempDir::new().unwrap();
        let good = write(tmp.path(), &req_name(1), &valid_body());
        let garbage = write(tmp.path(), &req_name(2), "not json at all");

        let recovered = recover(tmp.path()).unwrap();

        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].name, good.file_name().unwrap());
        assert!(!garbage.exists());
    }

    #[test]
    fn recover_caps_what_it_reads() {
        let tmp = TempDir::new().unwrap();
        for i in 0..MAX_REQUESTS_PER_SCAN + 5 {
            write(tmp.path(), &req_name(i as u64), &valid_body());
        }

        assert_eq!(recover(tmp.path()).unwrap().len(), MAX_REQUESTS_PER_SCAN);
        assert_eq!(
            fs::read_dir(tmp.path()).unwrap().count(),
            MAX_REQUESTS_PER_SCAN + 5,
            "the rest stay for the next start"
        );
    }

    /// Across restarts: once the first start's requests are deleted, the
    /// next start recovers exactly the ones the cap left.
    #[test]
    fn recover_reads_what_the_cap_left_on_the_next_start() {
        let tmp = TempDir::new().unwrap();
        for i in 0..MAX_REQUESTS_PER_SCAN + 5 {
            write(tmp.path(), &req_name(i as u64), &valid_body());
        }

        let first = recover(tmp.path()).unwrap();
        assert_eq!(first.len(), MAX_REQUESTS_PER_SCAN);
        for claimed in &first {
            delete(&tmp.path().join(&claimed.name));
        }

        let second = recover(tmp.path()).unwrap();
        assert_eq!(second.len(), 5);
        assert!(
            second
                .iter()
                .all(|claimed| first.iter().all(|done| done.name != claimed.name)),
            "the second start must read only what the first left"
        );
    }

    // -- prepare_startup_state --

    /// An environment whose inbox exists, and whose leaf checks pass on the
    /// real filesystem: `env_at` canonicalizes the root.
    fn startup_env(tmp: &TempDir) -> WatcherEnv {
        let env = crate::env::tests_support::env_at(tmp.path(), "nginx");
        fs::create_dir_all(env.inbox_dir()).unwrap();
        env
    }

    /// Startup deletes nothing in `inbox/`: requests are left for the first
    /// scan, and the ACM provider's temp files, current and legacy, are never
    /// touched.
    #[test]
    fn startup_never_deletes_anything_in_the_inbox() {
        let tmp = TempDir::new().unwrap();
        let env = startup_env(&tmp);
        let inbox = env.inbox_dir();
        let files = [
            write(&inbox, &req_name(1), &valid_body()),
            write(&inbox, WCP_TEMP_NAME, &valid_body()),
            write(
                &inbox,
                &format!("{}{REQUEST_TEMP_SUFFIX}", req_name(2)),
                "half-written",
            ),
            write(&inbox, "notes.txt", "stray"),
        ];

        let recovered = prepare_startup_state(&env, &RealFileSystem).unwrap();

        assert!(recovered.is_empty(), "the inbox is not recovered from");
        for file in &files {
            assert!(file.is_file(), "{} must be left", file.display());
        }
    }

    /// A missing pending directory is created, one level only, and
    /// owner-only on Unix.
    #[test]
    fn startup_creates_a_missing_pending_directory() {
        let tmp = TempDir::new().unwrap();
        let env = startup_env(&tmp);

        prepare_startup_state(&env, &RealFileSystem).unwrap();

        assert!(env.pending_dir().is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(env.pending_dir())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700, "{mode:o}");
        }
    }

    /// An existing pending directory is reused, and what is in it is
    /// recovered.
    #[test]
    fn startup_recovers_an_existing_pending_directory() {
        let tmp = TempDir::new().unwrap();
        let env = startup_env(&tmp);
        fs::create_dir(env.pending_dir()).unwrap();
        let left = write(&env.pending_dir(), &req_name(1), &valid_body());

        let recovered = prepare_startup_state(&env, &RealFileSystem).unwrap();

        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].name, left.file_name().unwrap());
        assert_eq!(recovered[0].request.certificate_arn, ARN);
        assert!(left.is_file(), "deleted only once its reload completes");
    }

    /// Startup touches nothing in `outbox/`, which is Phase 2.
    #[test]
    fn startup_leaves_the_outbox_alone() {
        let tmp = TempDir::new().unwrap();
        let env = startup_env(&tmp);
        let outbox = env.inbox_dir().parent().unwrap().join("outbox");
        fs::create_dir_all(&outbox).unwrap();
        let artifact = write(&outbox, &req_name(1), &valid_body());

        let recovered = prepare_startup_state(&env, &RealFileSystem).unwrap();

        assert!(recovered.is_empty());
        assert!(artifact.is_file(), "outbox/ must be left untouched");
    }

    /// A missing inbox is created, one level only, with `INBOX_DIR_MODE` on
    /// Unix.
    #[test]
    fn startup_creates_a_missing_inbox_directory() {
        let tmp = TempDir::new().unwrap();
        let env = crate::env::tests_support::env_at(tmp.path(), "nginx");
        fs::create_dir(env.watcher_requests_dir()).unwrap();

        let recovered = prepare_startup_state(&env, &RealFileSystem).unwrap();

        assert!(recovered.is_empty());
        assert!(env.inbox_dir().is_dir());
        assert!(env.pending_dir().is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(env.inbox_dir()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, INBOX_DIR_MODE, "{mode:o}");
        }
    }

    /// An existing inbox keeps its mode.
    #[cfg(unix)]
    #[test]
    fn startup_leaves_an_existing_inbox_directorys_mode_alone() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let env = startup_env(&tmp);
        fs::set_permissions(env.inbox_dir(), fs::Permissions::from_mode(0o755)).unwrap();

        prepare_startup_state(&env, &RealFileSystem).unwrap();

        let mode = fs::metadata(env.inbox_dir()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755, "{mode:o}");
    }

    /// A missing `<watcher_id>/` is created with `WATCHER_REQUESTS_DIR_MODE`
    /// on Unix, and `inbox/` and `pending/` in it.
    #[test]
    fn startup_creates_a_missing_watcher_directory() {
        let tmp = TempDir::new().unwrap();
        let env = crate::env::tests_support::env_at(tmp.path(), "nginx");

        let recovered = prepare_startup_state(&env, &RealFileSystem).unwrap();

        assert!(recovered.is_empty());
        assert!(env.inbox_dir().is_dir());
        assert!(env.pending_dir().is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(env.watcher_requests_dir())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, WATCHER_REQUESTS_DIR_MODE, "{mode:o}");
        }
    }

    /// A `<watcher_id>/` that cannot be created is fatal and names it. Here
    /// the requests root is read-only.
    #[cfg(unix)]
    #[test]
    fn startup_reports_a_watcher_directory_that_cannot_be_created() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let env = crate::env::tests_support::env_at(tmp.path(), "nginx");
        let root = env.requests_dir().to_path_buf();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o500)).unwrap();
        let result = prepare_startup_state(&env, &RealFileSystem);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();

        // Root ignores directory permissions, so there is nothing to check.
        if rustix::process::geteuid().is_root() {
            return;
        }
        let err = result.expect_err("a read-only requests root must refuse the create");
        let StartupError::RequestDirUncreatable { path, .. } = &err else {
            panic!("expected RequestDirUncreatable, got {err}");
        };
        assert_eq!(*path, env.watcher_requests_dir());
        assert!(err.to_string().contains("nginx"), "{err}");
    }

    /// A symlinked `<watcher_id>/` is refused before `inbox/` is created
    /// behind it.
    #[cfg(unix)]
    #[test]
    fn startup_refuses_a_symlinked_watcher_directory_before_creating_the_inbox() {
        let tmp = TempDir::new().unwrap();
        let env = crate::env::tests_support::env_at(tmp.path(), "nginx");
        let elsewhere = env.requests_dir().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, env.watcher_requests_dir()).unwrap();

        let err = prepare_startup_state(&env, &RealFileSystem).unwrap_err();

        assert!(
            matches!(
                &err,
                StartupError::RequestDirInvalid {
                    source: crate::error::InboxCheckError::NotCanonical { path, .. }
                } if *path == env.watcher_requests_dir()
            ),
            "{err}"
        );
        assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);
    }

    /// An inbox that cannot be created is fatal and names it. Here
    /// `<watcher_id>/` is read-only.
    #[cfg(unix)]
    #[test]
    fn startup_reports_an_inbox_directory_that_cannot_be_created() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let env = crate::env::tests_support::env_at(tmp.path(), "nginx");
        let watcher_dir = env.watcher_requests_dir();
        fs::create_dir(&watcher_dir).unwrap();
        fs::set_permissions(&watcher_dir, fs::Permissions::from_mode(0o500)).unwrap();
        let result = prepare_startup_state(&env, &RealFileSystem);
        fs::set_permissions(&watcher_dir, fs::Permissions::from_mode(0o700)).unwrap();

        // Root ignores directory permissions, so there is nothing to check.
        if rustix::process::geteuid().is_root() {
            return;
        }
        let err = result.expect_err("a read-only <watcher_id>/ must refuse the create");
        let StartupError::RequestDirUncreatable { path, .. } = &err else {
            panic!("expected RequestDirUncreatable, got {err}");
        };
        assert_eq!(*path, env.inbox_dir());
        assert!(err.to_string().contains("inbox"), "{err}");
        assert!(!env.pending_dir().exists());
    }

    /// Which ACM providers, in their own container, can use an inbox that the
    /// watcher created with `INBOX_DIR_MODE` as a non-root user in another
    /// container.
    ///
    /// Each step re-runs this test binary in a container that mounts one
    /// Docker volume as the requests root, filtered to the `role` test: the
    /// watcher's steps call `prepare_startup_state` and `claim`, and the
    /// provider's calls the provider's own `watcher_request::enqueue`.
    ///
    /// Ignored by default, since it needs Docker and pulls an image. Run with
    /// `cargo test --bin wcp-watcher -- --ignored shared_inbox`.
    /// `WCP_DOCKER_TEST_IMAGE` overrides the image, which must be able to run
    /// this host-built binary.
    #[cfg(target_os = "linux")]
    mod docker {
        use super::*;
        use std::process::{Command, Output};

        use aws_workload_credentials_provider_common::watcher_request;

        const ROLE_VAR: &str = "WCP_DOCKER_TEST_ROLE";
        const EXPECT_VAR: &str = "WCP_DOCKER_TEST_EXPECT";
        const IMAGE_VAR: &str = "WCP_DOCKER_TEST_IMAGE";
        const DEFAULT_IMAGE: &str = "public.ecr.aws/amazonlinux/amazonlinux:2023";

        /// Where the volume is mounted in every container.
        const REQUESTS_DIR: &str = "/shared";
        const WATCHER_ID: &str = "nginx";
        /// The watcher container's user. Not root, and not the provider's.
        const WATCHER_USER: &str = "1000:1000";
        /// The watcher's primary group, which its directories take: the
        /// group a provider shares with it.
        const WATCHER_GROUP: &str = "1000";
        /// A non-root provider, different from the watcher.
        const OTHER_USER: &str = "2000:2000";

        /// One step, run inside a container by [`Scenario::run`].
        #[test]
        #[ignore = "a step of the Docker tests; does nothing on its own"]
        fn role() {
            use std::os::unix::fs::MetadataExt;

            let Ok(role) = std::env::var(ROLE_VAR) else {
                return;
            };
            let expect_ok = std::env::var(EXPECT_VAR).as_deref() != Ok("denied");
            let env = crate::env::tests_support::env_at(Path::new(REQUESTS_DIR), WATCHER_ID);
            let inbox = env.inbox_dir();

            match role.as_str() {
                "watcher-start" => {
                    assert!(!env.watcher_requests_dir().exists());
                    prepare_startup_state(&env, &RealFileSystem)
                        .expect("the watcher should create its directories");
                    for (dir, expected) in [
                        (env.watcher_requests_dir(), WATCHER_REQUESTS_DIR_MODE),
                        (inbox.clone(), INBOX_DIR_MODE),
                    ] {
                        let mode = fs::metadata(&dir).unwrap().mode() & 0o7777;
                        assert_eq!(mode, expected, "{}: {mode:o}", dir.display());
                    }
                }
                "wcp-enqueue" => {
                    // What the provider sees: numeric ids, since the
                    // watcher's user has no name in this container.
                    match fs::metadata(&inbox) {
                        Ok(m) => println!(
                            "provider (uid {}) sees inbox owner {}:{} mode {:o}",
                            rustix::process::geteuid().as_raw(),
                            m.uid(),
                            m.gid(),
                            m.mode() & 0o7777
                        ),
                        Err(e) => println!("provider cannot stat the inbox: {e}"),
                    }
                    let root = watcher_request::RequestsRoot::open(Path::new(REQUESTS_DIR))
                        .expect("the provider should open the requests root");
                    match watcher_request::enqueue(&root, WATCHER_ID, ARN) {
                        Ok(name) => {
                            assert!(expect_ok, "enqueue succeeded but was expected to be denied");
                            println!("provider wrote '{name}'");
                        }
                        Err(e) => {
                            assert!(!expect_ok, "enqueue failed: {e}");
                            assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
                            println!("provider was denied: {e}");
                        }
                    }
                }
                "watcher-claim" => {
                    let (paths, _) = scan(&inbox).unwrap();
                    assert_eq!(paths.len(), 1, "{paths:?}");
                    let name = paths[0].file_name().unwrap();
                    let Claim::Claimed(claimed) = claim(&inbox, &env.pending_dir(), name).unwrap()
                    else {
                        panic!("the request should be claimed");
                    };
                    let request = read(&claimed).expect("the watcher should read the request");
                    assert_eq!(request.certificate_arn, ARN);
                }
                other => panic!("unknown role '{other}'"),
            }
        }

        /// One Docker volume, removed on drop.
        struct Scenario {
            volume: String,
            image: String,
        }

        impl Scenario {
            /// Creates the volume and hands its root to the watcher's user,
            /// as whatever provisions the volume would. The watcher creates
            /// everything under it.
            fn new(name: &str) -> Self {
                let image = std::env::var(IMAGE_VAR).unwrap_or_else(|_| DEFAULT_IMAGE.to_string());
                let volume = format!("wcp-watcher-test-{}-{name}", std::process::id());
                let created = docker(&["volume", "create", &volume]);
                assert!(created.status.success(), "{}", render(&created));
                let scenario = Self { volume, image };

                let setup = scenario.container(None, &[], &["chown", WATCHER_USER, REQUESTS_DIR]);
                assert!(setup.status.success(), "{}", render(&setup));
                scenario
            }

            /// Runs `role` as `user` (the image's root when `None`), with
            /// `docker run` options `extra`, and checks it exits as expected.
            fn run(&self, role: &str, user: Option<&str>, extra: &[&str], expect_ok: bool) {
                let role_env = format!("{ROLE_VAR}={role}");
                let expect_env =
                    format!("{EXPECT_VAR}={}", if expect_ok { "ok" } else { "denied" });
                let mut options = vec!["-e", role_env.as_str(), "-e", expect_env.as_str()];
                options.extend_from_slice(extra);
                let output = self.container(
                    user,
                    &options,
                    &[
                        "/wcp-test",
                        "--exact",
                        "inbox::tests::docker::role",
                        "--ignored",
                        "--nocapture",
                        "--test-threads=1",
                    ],
                );
                println!("--- {role} ---\n{}", render(&output));
                assert!(
                    output.status.success(),
                    "{role} failed:\n{}",
                    render(&output)
                );
            }

            fn container(&self, user: Option<&str>, options: &[&str], command: &[&str]) -> Output {
                let exe = std::env::current_exe().unwrap();
                let volume = format!("{}:{REQUESTS_DIR}", self.volume);
                let binary = format!("{}:/wcp-test:ro", exe.display());
                let mut args = vec![
                    "run",
                    "--rm",
                    "--network",
                    "none",
                    "-v",
                    volume.as_str(),
                    "-v",
                    binary.as_str(),
                ];
                if let Some(user) = user {
                    args.extend(["--user", user]);
                }
                args.extend_from_slice(options);
                args.push(&self.image);
                args.extend_from_slice(command);
                docker(&args)
            }
        }

        impl Drop for Scenario {
            fn drop(&mut self) {
                let _ = docker(&["volume", "rm", "-f", &self.volume]);
            }
        }

        fn docker(args: &[&str]) -> Output {
            Command::new("docker")
                .args(args)
                .output()
                .expect("these tests need the docker CLI")
        }

        fn render(output: &Output) -> String {
            format!(
                "status: {}\nstdout:\n{}\nstderr:\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        }

        /// The provider as its image runs by default: root, with Docker's
        /// default capabilities, `CAP_DAC_OVERRIDE` among them. No group
        /// needed.
        #[test]
        #[ignore = "needs Docker; run with --ignored"]
        fn shared_inbox_is_usable_by_a_root_provider() {
            let scenario = Scenario::new("root");
            scenario.run("watcher-start", Some(WATCHER_USER), &[], true);
            scenario.run("wcp-enqueue", None, &[], true);
            scenario.run("watcher-claim", Some(WATCHER_USER), &[], true);
        }

        /// A non-root provider with no capabilities, in the watcher's group.
        #[test]
        #[ignore = "needs Docker; run with --ignored"]
        fn shared_inbox_is_usable_by_a_non_root_provider_in_the_group() {
            let scenario = Scenario::new("group");
            scenario.run("watcher-start", Some(WATCHER_USER), &[], true);
            scenario.run(
                "wcp-enqueue",
                Some(OTHER_USER),
                &["--group-add", WATCHER_GROUP, "--cap-drop", "ALL"],
                true,
            );
            scenario.run("watcher-claim", Some(WATCHER_USER), &[], true);
        }

        /// Root without `CAP_DAC_OVERRIDE` is held to the mode like anyone
        /// else, so it needs the group too.
        #[test]
        #[ignore = "needs Docker; run with --ignored"]
        fn shared_inbox_is_usable_by_a_root_provider_without_dac_override_in_the_group() {
            let scenario = Scenario::new("root-group");
            scenario.run("watcher-start", Some(WATCHER_USER), &[], true);
            scenario.run(
                "wcp-enqueue",
                None,
                &["--group-add", WATCHER_GROUP, "--cap-drop", "ALL"],
                true,
            );
            scenario.run("watcher-claim", Some(WATCHER_USER), &[], true);
        }

        /// Root without `CAP_DAC_OVERRIDE`, outside the group, is refused.
        #[test]
        #[ignore = "needs Docker; run with --ignored"]
        fn shared_inbox_refuses_a_root_provider_without_dac_override() {
            let scenario = Scenario::new("no-dac-override");
            scenario.run("watcher-start", Some(WATCHER_USER), &[], true);
            scenario.run("wcp-enqueue", None, &["--cap-drop", "DAC_OVERRIDE"], false);
        }

        /// A non-root provider outside the group is refused.
        #[test]
        #[ignore = "needs Docker; run with --ignored"]
        fn shared_inbox_refuses_a_non_root_provider_outside_the_group() {
            let scenario = Scenario::new("non-root");
            scenario.run("watcher-start", Some(WATCHER_USER), &[], true);
            scenario.run("wcp-enqueue", Some(OTHER_USER), &[], false);
        }
    }

    /// A symlink in place of the inbox is refused before anything under it,
    /// or beside it, is touched.
    #[cfg(unix)]
    #[test]
    fn startup_refuses_a_symlinked_inbox_before_touching_anything() {
        let tmp = TempDir::new().unwrap();
        let env = crate::env::tests_support::env_at(tmp.path(), "nginx");
        let elsewhere = env.requests_dir().join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        fs::create_dir_all(env.inbox_dir().parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&elsewhere, env.inbox_dir()).unwrap();
        let behind = write(&elsewhere, &req_name(1), &valid_body());

        let err = prepare_startup_state(&env, &RealFileSystem).unwrap_err();

        assert!(
            matches!(
                err,
                StartupError::RequestDirInvalid {
                    source: crate::error::InboxCheckError::NotCanonical { .. }
                }
            ),
            "{err}"
        );
        assert!(behind.is_file());
        assert!(!env.pending_dir().exists());
    }

    #[test]
    fn startup_refuses_a_file_in_place_of_the_pending_directory() {
        let tmp = TempDir::new().unwrap();
        let env = startup_env(&tmp);
        fs::write(env.pending_dir(), "not a directory").unwrap();

        let err = prepare_startup_state(&env, &RealFileSystem).unwrap_err();

        assert!(
            matches!(
                err,
                StartupError::RequestDirInvalid {
                    source: crate::error::InboxCheckError::NotADirectory { .. }
                }
            ),
            "{err}"
        );
        assert!(err.to_string().contains("pending"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn startup_refuses_a_symlinked_pending_directory() {
        let tmp = TempDir::new().unwrap();
        let env = startup_env(&tmp);
        let elsewhere = env.requests_dir().join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, env.pending_dir()).unwrap();
        let behind = write(&elsewhere, &req_name(1), &valid_body());

        let err = prepare_startup_state(&env, &RealFileSystem).unwrap_err();

        assert!(
            matches!(
                err,
                StartupError::RequestDirInvalid {
                    source: crate::error::InboxCheckError::NotCanonical { .. }
                }
            ),
            "{err}"
        );
        assert!(behind.is_file(), "nothing behind the symlink is recovered");
    }

    /// A pending directory that cannot be created is fatal and names it.
    /// Here `<watcher_id>/` is read-only.
    #[cfg(unix)]
    #[test]
    fn startup_reports_a_pending_directory_that_cannot_be_created() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let env = startup_env(&tmp);
        let watcher_dir = env.inbox_dir().parent().unwrap().to_path_buf();
        fs::set_permissions(&watcher_dir, fs::Permissions::from_mode(0o500)).unwrap();
        let result = prepare_startup_state(&env, &RealFileSystem);
        fs::set_permissions(&watcher_dir, fs::Permissions::from_mode(0o700)).unwrap();

        // Root ignores directory permissions, so there is nothing to check.
        if rustix::process::geteuid().is_root() {
            return;
        }
        let err = result.expect_err("a read-only <watcher_id>/ must refuse the create");
        let StartupError::PendingDirUnusable { path, .. } = &err else {
            panic!("expected PendingDirUnusable, got {err}");
        };
        assert_eq!(*path, env.pending_dir());
        assert!(err.to_string().contains("pending"), "{err}");
    }
}
