//! Refresh requests the provider writes to a watcher's inbox.
//!
//! A request names only the certificate. The watcher looks up the reload
//! command in its own config, so a request can never introduce a command.
//! The watcher reads requests with [`RefreshRequest`].

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

use crate::config::field_validators::{validate_watcher_id, ArnValidator};

/// Directory under a watcher's request directory that holds pending requests.
pub const INBOX_DIR: &str = "inbox";

/// Extension of a request file. The watcher reacts only to this extension.
pub const REQUEST_EXTENSION: &str = "cmd";

/// Orders request names written in the same millisecond. Restarts at zero.
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Body of a `.cmd` file. Unknown fields are ignored, so a watcher still reads
/// requests from a newer provider that adds one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshRequest {
    /// Random (version 4) UUID, also the last part of the file name.
    pub command_id: String,
    /// An ACM certificate ARN.
    pub certificate_arn: String,
    /// RFC 3339, UTC, whole seconds.
    pub created_at: String,
}

impl RefreshRequest {
    /// The name of the first field the watcher logs that is malformed, or
    /// `None` when both are well formed.
    ///
    /// `command_id` must pass [`is_valid_command_id`]; `certificate_arn` must
    /// pass the same check a `[[reload]]` entry's ARNs do. Only the field name
    /// is returned: the value came from an untrusted file and may contain line
    /// breaks or control characters, so it must not be logged.
    pub fn invalid_field(&self) -> Option<&'static str> {
        if !is_valid_command_id(&self.command_id) {
            return Some("command_id");
        }
        if ArnValidator::validate_certificate_arn("certificate_arn", &self.certificate_arn).is_err()
        {
            return Some("certificate_arn");
        }
        // Copied unchanged into the status, whose reader requires RFC 3339 UTC.
        if !crate::watcher_status::is_valid_timestamp(&self.created_at)
            || chrono::DateTime::parse_from_rfc3339(&self.created_at)
                .is_ok_and(|time| time.offset().local_minus_utc() != 0)
        {
            return Some("created_at");
        }
        None
    }
}

/// The inbox of watcher `watcher_id` under `requests_dir`.
pub fn inbox_path(requests_dir: &Path, watcher_id: &str) -> PathBuf {
    requests_dir.join(watcher_id).join(INBOX_DIR)
}

/// The shared requests directory, `<requests_dir>`, opened once at startup
/// after config validation found it canonical. Every request walks from here
/// to `<watcher_id>/inbox` one component at a time (see [`enqueue`]).
pub struct RequestsRoot {
    /// A handle on the root itself; the walk is relative to it.
    #[cfg(unix)]
    fd: std::os::fd::OwnedFd,
    /// The root's canonical path in verbatim (`\\?\`) form, the form
    /// `GetFinalPathNameByHandleW` reports, so the inbox's real path can be
    /// compared with it at any length.
    #[cfg(windows)]
    path: PathBuf,
}

impl RequestsRoot {
    /// Opens `requests_dir`, which must be a directory and, on Unix, not a
    /// symlink. Call it after `requests_dir` has been validated canonical.
    #[cfg(unix)]
    pub fn open(requests_dir: &Path) -> io::Result<Self> {
        use rustix::fs::{open, Mode, OFlags};

        let fd = open(
            requests_dir,
            OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | WALK,
            Mode::empty(),
        )?;
        Ok(Self { fd })
    }

    /// Captures the canonical path of `requests_dir`, which must exist. Call
    /// it after `requests_dir` has been validated canonical.
    ///
    /// This keeps the `\\?\` prefix that `std::fs::canonicalize` adds:
    /// `dunce` drops it only from paths of 260 UTF-16 units or fewer, so a
    /// short root and a long inbox under it would otherwise end up in
    /// different forms and never compare equal.
    #[cfg(windows)]
    pub fn open(requests_dir: &Path) -> io::Result<Self> {
        Ok(Self {
            path: std::fs::canonicalize(requests_dir)?,
        })
    }
}

/// Flags for a directory the walk only passes through. On Linux `O_PATH`
/// needs search permission alone, as a path lookup does, so a provider that
/// may only search `<watcher_id>/` (mode 0o710) still reaches the inbox, and
/// the provider's status scanner the outbox beside it.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub const WALK: rustix::fs::OFlags = rustix::fs::OFlags::PATH;
#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
pub const WALK: rustix::fs::OFlags = rustix::fs::OFlags::RDONLY;

/// A request prepared for publication into a watcher's inbox.
///
/// Preparation is separate from publication so a provider can register the
/// command with its in-memory status consumer before the request becomes
/// visible to the watcher.
pub struct PreparedRequest {
    request: RefreshRequest,
    name: String,
    body: Vec<u8>,
}

impl PreparedRequest {
    /// Returns the exact request body that will be published.
    pub fn request(&self) -> &RefreshRequest {
        &self.request
    }

    /// Returns the exact file name that will be published.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Creates a request without publishing it.
pub fn prepare_request(certificate_arn: &str) -> io::Result<PreparedRequest> {
    let now = Utc::now();
    let request = RefreshRequest {
        command_id: uuid_v4()?,
        certificate_arn: certificate_arn.to_string(),
        created_at: now.to_rfc3339_opts(SecondsFormat::Secs, true),
    };
    let name = request_name(
        now,
        SEQUENCE.fetch_add(1, Ordering::Relaxed),
        &request.command_id,
    );
    let body = serde_json::to_vec(&request)?;
    Ok(PreparedRequest {
        request,
        name,
        body,
    })
}

/// Publishes a prepared request into the inbox of `watcher_id` under `root`.
/// The watcher owns the inbox, so it must exist. Fails, writing nothing, when
/// a symlink or (on Windows) a junction sits at `<watcher_id>` or `inbox`.
pub fn publish_prepared_request(
    root: &RequestsRoot,
    watcher_id: &str,
    prepared: &PreparedRequest,
) -> io::Result<()> {
    // The walk refuses a link at each component it opens, so the ID must be
    // exactly one component.
    if validate_watcher_id("watcher_id", watcher_id).is_err() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "watcher_id is not a valid single path segment",
        ));
    }
    let temp = format!(".{}.tmp", hex(&random_bytes()?));
    write_atomically(root, watcher_id, &temp, &prepared.name, &prepared.body)
}

/// Writes one refresh request and returns the exact request and file name.
pub fn enqueue_request(
    root: &RequestsRoot,
    watcher_id: &str,
    certificate_arn: &str,
) -> io::Result<(RefreshRequest, String)> {
    let prepared = prepare_request(certificate_arn)?;
    publish_prepared_request(root, watcher_id, &prepared)?;
    Ok((prepared.request, prepared.name))
}

/// Writes one refresh request and returns its file name.
pub fn enqueue(root: &RequestsRoot, watcher_id: &str, certificate_arn: &str) -> io::Result<String> {
    enqueue_request(root, watcher_id, certificate_arn).map(|(_, name)| name)
}

/// True when `command_id` is a UUIDv4 in canonical form: 32 hex digits in
/// groups of 8-4-4-4-12, separated by hyphens.
pub fn is_valid_command_id(command_id: &str) -> bool {
    const HYPHENS: [usize; 4] = [8, 13, 18, 23];
    command_id.len() == 36
        && command_id.bytes().enumerate().all(|(i, b)| {
            if HYPHENS.contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}

fn random_bytes() -> io::Result<[u8; 16]> {
    let mut bytes = [0u8; 16];
    aws_lc_rs::rand::fill(&mut bytes).map_err(|_| io::Error::other("random generation failed"))?;
    Ok(bytes)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A random (version 4) UUID, `xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx`.
fn uuid_v4() -> io::Result<String> {
    let mut b = random_bytes()?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex(&b);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    ))
}

/// `{epoch_millis}-{sequence}-{command_id}.cmd`, sortable for debugging.
fn request_name(now: DateTime<Utc>, sequence: u64, command_id: &str) -> String {
    format!(
        "{}-{:03}-{}.{}",
        now.timestamp_millis(),
        sequence,
        command_id,
        REQUEST_EXTENSION
    )
}

/// Writes `body` to `temp` in `<root>/<watcher_id>/inbox` and renames it to
/// `name`. The inbox is synced after the rename so the request survives a
/// crash.
///
/// The inbox is reached one component at a time from the handle on `root`:
/// `<watcher_id>`, then `inbox`, each opened relative to the one before with
/// `O_DIRECTORY | O_NOFOLLOW`, so a symlink at either fails the open instead
/// of being followed. Both flags are needed: `<watcher_id>` is opened with
/// [`WALK`], and on Linux `O_PATH | O_NOFOLLOW` alone opens the symlink itself.
/// The walk is repeated on every write and has no gap between a check and an
/// open, so swapping in a symlink at any time can't redirect it. The temp
/// file is created, renamed and on failure removed relative to the inbox
/// handle. Nothing above `root` is checked here: `root` was validated
/// canonical before it was opened.
#[cfg(unix)]
fn write_atomically(
    root: &RequestsRoot,
    watcher_id: &str,
    temp: &str,
    name: &str,
    body: &[u8],
) -> io::Result<()> {
    use rustix::fs::{fsync, openat, renameat, unlinkat, AtFlags, Mode, OFlags};

    let dir = OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let watcher = openat(&root.fd, watcher_id, dir | WALK, Mode::empty())?;
    let inbox = openat(&watcher, INBOX_DIR, dir | OFlags::RDONLY, Mode::empty())?;

    let file = openat(
        &inbox,
        temp,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o644),
    )?;
    let mut file = std::fs::File::from(file);
    let written = file
        .write_all(body)
        .and_then(|()| file.sync_all())
        .and_then(|()| renameat(&inbox, temp, &inbox, name).map_err(io::Error::from));
    if written.is_err() {
        let _ = unlinkat(&inbox, temp, AtFlags::empty());
        return written;
    }
    // The request is queued once renamed; a failed sync only risks losing it
    // in a crash, so it doesn't fail the request (which would queue it twice).
    let _ = fsync(&inbox);
    Ok(())
}

/// Windows has no `openat`, so this pins the inbox with a handle and checks
/// where that handle really is: the inbox is opened as itself (not what a
/// reparse point there names) and without `FILE_SHARE_DELETE`, so it can't be
/// renamed or replaced while the request is written. Its final path must be
/// exactly `<root>\<watcher_id>\inbox`, built from the canonical root captured
/// at startup, so a junction or symlink at `<watcher_id>` (which the open
/// follows) is refused. The temp file's final parent must be that same path,
/// which catches `<watcher_id>` being swapped between the two opens. Both
/// sides of each check are verbatim (`\\?\`) paths, so neither depends on
/// how long the path is. The temp file is renamed relative to the inbox
/// handle and deleted through its own handle on failure.
#[cfg(windows)]
fn write_atomically(
    root: &RequestsRoot,
    watcher_id: &str,
    temp: &str,
    name: &str,
    body: &[u8],
) -> io::Result<()> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows::Win32::Storage::FileSystem::{
        DELETE, FILE_ADD_FILE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
        FILE_SHARE_WRITE,
    };

    let inbox = root.path.join(watcher_id).join(INBOX_DIR);
    let dir = std::fs::OpenOptions::new()
        .access_mode(FILE_GENERIC_READ.0 | FILE_ADD_FILE.0)
        .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(&inbox)?;
    let meta = dir.metadata()?;
    if !meta.is_dir() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "watcher inbox is a symlink or not a directory",
        ));
    }
    if final_path(&dir)? != inbox {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "watcher inbox is reached through a link",
        ));
    }

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .access_mode(FILE_GENERIC_WRITE.0 | DELETE.0)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(inbox.join(temp))?;
    let written = (|| {
        if final_path(&file)?.parent() != Some(inbox.as_path()) {
            return Err(io::Error::other("watcher inbox changed while writing"));
        }
        file.write_all(body)?;
        file.sync_all()?;
        rename_into(&file, &dir, name)
    })();
    if written.is_err() {
        let _ = delete_by_handle(&file);
    }
    written
}

/// The path the system resolves `file`'s handle to, in verbatim (`\\?\`)
/// form, as `std::fs::canonicalize` returns it. It is not simplified: `dunce`
/// keeps the prefix only above 260 UTF-16 units, so simplifying a file's path
/// and its directory's path could leave them in different forms.
#[cfg(windows)]
fn final_path(file: &std::fs::File) -> io::Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{GetFinalPathNameByHandleW, FILE_NAME_NORMALIZED};

    let mut buf = vec![0u16; 512];
    loop {
        // SAFETY: the handle is open for the duration of the call and the
        // buffer is writable for its whole length.
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

/// Renames `file` to `name` inside the directory that `dir` holds open. The
/// Win32 rename rejects a name relative to a directory handle, so this calls
/// the native API underneath it, which takes one.
#[cfg(windows)]
fn rename_into(file: &std::fs::File, dir: &std::fs::File, name: &str) -> io::Result<()> {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::FILE_RENAME_INFO;

    #[repr(C)]
    struct IoStatusBlock {
        status: isize,
        information: usize,
    }
    /// `FileRenameInformation`, whose layout matches `FILE_RENAME_INFO`.
    const FILE_RENAME_INFORMATION: u32 = 10;
    #[link(name = "ntdll")]
    extern "system" {
        fn NtSetInformationFile(
            file: *mut c_void,
            io_status: *mut IoStatusBlock,
            information: *const c_void,
            length: u32,
            class: u32,
        ) -> i32;
        fn RtlNtStatusToDosError(status: i32) -> u32;
    }

    let name: Vec<u16> = name.encode_utf16().collect();
    let header = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
    let size = header + name.len() * std::mem::size_of::<u16>();
    // Zeroed, so `ReplaceIfExists` is false; u64s keep it aligned.
    let mut buf = vec![0u64; size.div_ceil(8)];
    let info = buf.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    let mut io_status = IoStatusBlock {
        status: 0,
        information: 0,
    };
    // SAFETY: `buf` holds at least `size` bytes, aligned for FILE_RENAME_INFO,
    // and both handles stay open for the duration of the call.
    let status = unsafe {
        (*info).RootDirectory = HANDLE(dir.as_raw_handle());
        (*info).FileNameLength = (name.len() * std::mem::size_of::<u16>()) as u32;
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            std::ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
            name.len(),
        );
        NtSetInformationFile(
            file.as_raw_handle(),
            &mut io_status,
            info.cast(),
            size as u32,
            FILE_RENAME_INFORMATION,
        )
    };
    if status < 0 {
        // SAFETY: a pure conversion of the status code.
        let code = unsafe { RtlNtStatusToDosError(status) };
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    Ok(())
}

/// Marks `file` for deletion when its handle closes.
#[cfg(windows)]
fn delete_by_handle(file: &std::fs::File) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        FileDispositionInfo, SetFileInformationByHandle, FILE_DISPOSITION_INFO,
    };

    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: `info` lives for the duration of the call and the handle is open.
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

    const ARN: &str = "arn:aws:acm:us-west-2:123456789012:certificate/abc";

    fn files(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    fn open(requests_dir: &Path) -> RequestsRoot {
        RequestsRoot::open(requests_dir).unwrap()
    }

    #[test]
    fn writes_one_request_and_no_temp_file() {
        let root = tempfile::tempdir().unwrap();
        let inbox = inbox_path(root.path(), "nginx");
        std::fs::create_dir_all(&inbox).unwrap();

        let name = enqueue(&open(root.path()), "nginx", ARN).unwrap();

        assert_eq!(files(&inbox), vec![name.clone()]);
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(inbox.join(&name)).unwrap()).unwrap();
        assert_eq!(json["certificate_arn"], ARN);
        let command_id = json["command_id"].as_str().unwrap();
        assert_eq!(command_id.len(), 36);
        assert!(name.ends_with(&format!("-{command_id}.cmd")));
        assert!(DateTime::parse_from_rfc3339(json["created_at"].as_str().unwrap()).is_ok());
        assert_eq!(json.as_object().unwrap().len(), 3);
    }

    #[test]
    fn enqueue_request_returns_the_published_request() {
        let root = tempfile::tempdir().unwrap();
        let inbox = inbox_path(root.path(), "nginx");
        std::fs::create_dir_all(&inbox).unwrap();

        let (request, name) = enqueue_request(&open(root.path()), "nginx", ARN).unwrap();
        let published: RefreshRequest =
            serde_json::from_slice(&std::fs::read(inbox.join(&name)).unwrap()).unwrap();
        assert_eq!(request, published);
        assert!(name.ends_with(&format!("-{}.{REQUEST_EXTENSION}", request.command_id)));
    }
    #[test]
    fn the_watcher_reads_back_what_the_provider_writes() {
        let root = tempfile::tempdir().unwrap();
        let inbox = inbox_path(root.path(), "nginx");
        std::fs::create_dir_all(&inbox).unwrap();

        let name = enqueue(&open(root.path()), "nginx", ARN).unwrap();
        let request: RefreshRequest =
            serde_json::from_slice(&std::fs::read(inbox.join(&name)).unwrap()).unwrap();

        assert_eq!(request.certificate_arn, ARN);
        assert!(name.ends_with(&format!("-{}.{REQUEST_EXTENSION}", request.command_id)));
    }

    #[test]
    fn a_request_with_an_unknown_field_still_parses() {
        let json = format!(
            r#"{{"command_id":"id","certificate_arn":"{ARN}","created_at":"2026-10-07T19:45:00Z","new_field":1}}"#
        );
        let request: RefreshRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(request.certificate_arn, ARN);
    }

    #[test]
    fn invalid_field_reports_the_first_invalid_field() {
        let valid_command_id = "00000000-0000-4000-8000-000000000001";
        let cases = [
            (valid_command_id, ARN, None),
            ("not-a-command-id", ARN, Some("command_id")),
            (
                valid_command_id,
                "not-a-certificate-arn",
                Some("certificate_arn"),
            ),
            (
                "not-a-command-id",
                "not-a-certificate-arn",
                Some("command_id"),
            ),
        ];

        for (command_id, certificate_arn, expected) in cases {
            let request = RefreshRequest {
                command_id: command_id.to_string(),
                certificate_arn: certificate_arn.to_string(),
                created_at: "2025-10-20T17:06:40Z".to_string(),
            };
            assert_eq!(request.invalid_field(), expected);
        }
    }

    #[test]
    fn invalid_field_requires_a_utc_rfc3339_created_at() {
        let request = |created_at: &str| RefreshRequest {
            command_id: "00000000-0000-4000-8000-000000000001".to_string(),
            certificate_arn: ARN.to_string(),
            created_at: created_at.to_string(),
        };
        assert_eq!(request("2025-10-20T17:06:40Z").invalid_field(), None);
        assert_eq!(request("2025-10-20T17:06:40+00:00").invalid_field(), None);
        let long = format!("2025-10-20T17:06:40.{}Z", "1".repeat(200));
        for invalid in ["", "yesterday", "2025-10-20T17:06:40+02:00", long.as_str()] {
            assert_eq!(
                request(invalid).invalid_field(),
                Some("created_at"),
                "{invalid}"
            );
        }
    }

    #[test]
    fn a_failed_rename_leaves_no_temp_file() {
        let root = tempfile::tempdir().unwrap();
        let inbox = inbox_path(root.path(), "nginx");
        // A directory at the request name makes the rename fail.
        std::fs::create_dir_all(inbox.join("request.cmd")).unwrap();

        let requests = open(root.path());
        assert!(write_atomically(&requests, "nginx", ".temp.tmp", "request.cmd", b"{}").is_err());
        assert_eq!(files(&inbox), vec!["request.cmd".to_string()]);
    }

    #[test]
    fn missing_inbox_is_an_error_and_is_not_created() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("nginx")).unwrap();
        let inbox = inbox_path(root.path(), "nginx");

        let err = enqueue(&open(root.path()), "nginx", ARN).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(!inbox.exists());
    }

    /// The walk opens `watcher_id` as one component, so an ID that is more or
    /// less than one path segment is refused before anything is opened. A
    /// real inbox at `<root>/../x/inbox` shows where `../x` would have landed.
    #[test]
    fn refuses_a_watcher_id_that_is_not_one_path_segment() {
        let root = tempfile::tempdir().unwrap();
        let requests = root.path().join("requests");
        let outside = inbox_path(root.path(), "x");
        std::fs::create_dir(&requests).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let requests = open(&requests);

        for id in ["../x", "a/b", "..", ""] {
            let err = enqueue(&requests, id, ARN).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{id:?}: {err}");
        }
        assert!(files(&outside).is_empty());
    }

    #[test]
    fn requests_get_distinct_names() {
        let root = tempfile::tempdir().unwrap();
        let inbox = inbox_path(root.path(), "nginx");
        std::fs::create_dir_all(&inbox).unwrap();

        let requests = open(root.path());
        let first = enqueue(&requests, "nginx", ARN).unwrap();
        let second = enqueue(&requests, "nginx", ARN).unwrap();

        assert_ne!(first, second);
        assert_eq!(files(&inbox).len(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_symlinked_inbox() {
        let root = tempfile::tempdir().unwrap();
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::create_dir(root.path().join("nginx")).unwrap();
        let inbox = inbox_path(root.path(), "nginx");
        std::os::unix::fs::symlink(&elsewhere, &inbox).unwrap();

        assert!(enqueue(&open(root.path()), "nginx", ARN).is_err());
        assert!(files(&elsewhere).is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn refuses_a_symlinked_inbox() {
        let root = tempfile::tempdir().unwrap();
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::create_dir(root.path().join("nginx")).unwrap();
        let inbox = inbox_path(root.path(), "nginx");
        // Creating a symlink needs admin rights or Developer Mode on Windows.
        if std::os::windows::fs::symlink_dir(&elsewhere, &inbox).is_err() {
            eprintln!("skipped: can't create a symlink here");
            return;
        }

        assert!(enqueue(&open(root.path()), "nginx", ARN).is_err());
        assert!(files(&elsewhere).is_empty());
    }

    /// A symlink at `<requests_dir>/<watcher_id>`, not at `inbox`, must not
    /// redirect the write. The target has an `inbox` of its own, so a writer
    /// that follows the link would succeed there.
    #[cfg(unix)]
    #[test]
    fn refuses_a_symlinked_watcher_directory() {
        let root = tempfile::tempdir().unwrap();
        let requests = root.path().join("requests");
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir(&requests).unwrap();
        std::fs::create_dir_all(elsewhere.join(INBOX_DIR)).unwrap();
        std::os::unix::fs::symlink(&elsewhere, requests.join("nginx")).unwrap();

        assert!(enqueue(&open(&requests), "nginx", ARN).is_err());
        assert!(files(&elsewhere.join(INBOX_DIR)).is_empty());
    }

    /// [`refuses_a_symlinked_watcher_directory`] for both kinds of Windows
    /// directory link at `<requests_dir>/<watcher_id>`: a junction, which any
    /// user can create, and a directory symlink, which needs admin rights or
    /// Developer Mode and is skipped without them.
    #[cfg(windows)]
    #[test]
    fn refuses_a_symlinked_watcher_directory() {
        let root = tempfile::tempdir().unwrap();
        let requests = root.path().join("requests");
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir(&requests).unwrap();
        std::fs::create_dir_all(elsewhere.join(INBOX_DIR)).unwrap();

        // `std` has no junction API; `mklink /J` needs no privilege.
        let junction = requests.join("nginx");
        let status = std::process::Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(&junction)
            .arg(&elsewhere)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "mklink /J failed: {status}");

        assert!(
            enqueue(&open(&requests), "nginx", ARN).is_err(),
            "followed a junction at the watcher directory"
        );
        assert!(files(&elsewhere.join(INBOX_DIR)).is_empty());

        let symlink = requests.join("apache");
        if std::os::windows::fs::symlink_dir(&elsewhere, &symlink).is_err() {
            eprintln!("symlink case skipped: can't create a symlink here");
            return;
        }
        assert!(
            enqueue(&open(&requests), "apache", ARN).is_err(),
            "followed a symlink at the watcher directory"
        );
        assert!(files(&elsewhere.join(INBOX_DIR)).is_empty());
    }

    /// UTF-16 length of `path` without any `\\?\` prefix.
    #[cfg(windows)]
    fn legacy_len(path: &Path) -> usize {
        let path = path.to_string_lossy();
        path.strip_prefix(r"\\?\")
            .unwrap_or(&path)
            .encode_utf16()
            .count()
    }

    /// `base` plus padding components of at most 200 units each, so that
    /// `<requests>\nginx\inbox` is `inbox_len` UTF-16 units. `base` must be
    /// canonical and without the `\\?\` prefix. Creates nothing.
    #[cfg(windows)]
    fn padded_requests(base: &Path, inbox_len: usize) -> Result<PathBuf, String> {
        // Each padding component costs its length plus one for its `\`.
        let mut room = inbox_len
            .checked_sub(legacy_len(base) + r"\nginx\inbox".len())
            .filter(|&n| n >= 2)
            .ok_or_else(|| {
                format!(
                    "{} ({} units) is too long for an inbox of {inbox_len}",
                    base.display(),
                    legacy_len(base)
                )
            })?;
        let mut requests = base.to_path_buf();
        while room > 0 {
            let mut n = (room - 1).min(200);
            // Never leave a single unit, which can't hold a `\` and a name.
            if room - 1 - n == 1 {
                n -= 1;
            }
            requests.push("r".repeat(n));
            room -= n + 1;
        }
        match legacy_len(&inbox_path(&requests, "nginx")) {
            len if len == inbox_len => Ok(requests),
            len => Err(format!("padded inbox is {len} units, not {inbox_len}")),
        }
    }

    /// A requests directory under `tmp` whose `<requests>\nginx\inbox`,
    /// canonical and without the `\\?\` prefix, is `inbox_len` UTF-16 units
    /// long. The inbox is created.
    #[cfg(windows)]
    fn requests_with_inbox_len(tmp: &Path, inbox_len: usize) -> Result<PathBuf, String> {
        let base =
            dunce::canonicalize(tmp).map_err(|e| format!("canonicalize the temp dir: {e}"))?;
        let requests = padded_requests(&base, inbox_len)?;
        let inbox = inbox_path(&requests, "nginx");
        std::fs::create_dir_all(&inbox).map_err(|e| format!("create the inbox: {e}"))?;
        let canonical =
            std::fs::canonicalize(&inbox).map_err(|e| format!("canonicalize the inbox: {e}"))?;
        match legacy_len(&canonical) {
            len if len == inbox_len => Ok(requests),
            len => Err(format!("canonical inbox is {len} units, not {inbox_len}")),
        }
    }

    /// Writes a request where `<requests>\nginx\inbox` is `len` UTF-16 units
    /// and checks it is the only file in the inbox. Setup failures panic with
    /// a message starting `SETUP:`.
    #[cfg(windows)]
    fn assert_writes_at_inbox_len(len: usize) {
        let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("SETUP: len={len}: tempdir: {e}"));
        let requests = requests_with_inbox_len(tmp.path(), len)
            .unwrap_or_else(|e| panic!("SETUP: len={len}: {e}"));
        let inbox = inbox_path(&requests, "nginx");

        let name = RequestsRoot::open(&requests)
            .and_then(|root| enqueue(&root, "nginx", ARN))
            .unwrap_or_else(|e| panic!("len={len}: write failed: {:?}: {e}", e.kind()));
        assert_eq!(files(&inbox), vec![name], "len={len}: wrong inbox contents");
    }

    /// One test per inbox length. `dunce` keeps the `\\?\` prefix only on
    /// paths over 260 UTF-16 units, counting the prefix, so the temp file (38
    /// units below the inbox), the inbox and the root cross that limit at
    /// different lengths: 218/219 for the temp file, 256/257 for the inbox,
    /// and at 300 the root is over it too.
    ///
    /// On current code 218 and 300 pass; 219 and 256 fail ("watcher inbox
    /// changed while writing"); 257 fails ("watcher inbox is reached through
    /// a link"). After the verbatim-path fix, all pass.
    macro_rules! long_path_write_tests {
        ($($name:ident: $len:expr,)*) => {$(
            #[cfg(windows)]
            #[test]
            fn $name() {
                assert_writes_at_inbox_len($len);
            }
        )*};
    }

    long_path_write_tests! {
        writes_at_inbox_len_218_all_short: 218,
        writes_at_inbox_len_219_temp_file_over_max_path: 219,
        writes_at_inbox_len_256_inbox_at_limit: 256,
        writes_at_inbox_len_257_inbox_over_max_path: 257,
        writes_at_inbox_len_300_root_over_max_path: 300,
    }

    /// [`refuses_a_symlinked_watcher_directory`] where the inbox is long
    /// enough to keep the `\\?\` prefix and the root is not, so comparing
    /// verbatim paths still refuses a junction. `mklink` can't work at that
    /// length, so the junction is made in a short directory that is then
    /// renamed to the long path.
    ///
    /// Passes on both the current code and after the verbatim-path fix.
    #[cfg(windows)]
    #[test]
    fn refuses_a_junctioned_watcher_directory_with_inbox_over_max_path() {
        use std::os::windows::fs::MetadataExt;
        use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

        let tmp = tempfile::tempdir().expect("SETUP: tempdir");
        let base = dunce::canonicalize(tmp.path()).expect("SETUP: canonicalize the temp dir");
        let elsewhere = base.join("elsewhere");
        std::fs::create_dir_all(elsewhere.join(INBOX_DIR)).expect("SETUP: create elsewhere");
        let short = base.join("short");
        std::fs::create_dir(&short).expect("SETUP: create the short requests dir");

        // `std` has no junction API; `mklink /J` needs no privilege.
        let mklink = std::process::Command::new("cmd")
            .current_dir(&short)
            .args(["/C", "mklink", "/J", "nginx"])
            .arg(&elsewhere)
            .output()
            .expect("SETUP: run mklink");
        assert!(
            mklink.status.success(),
            "SETUP: mklink /J failed: {}: {}",
            mklink.status,
            String::from_utf8_lossy(&mklink.stderr).trim()
        );

        // The junction's target is absolute, so the rename doesn't break it.
        let requests = padded_requests(&base, 257).unwrap_or_else(|e| panic!("SETUP: {e}"));
        std::fs::create_dir_all(requests.parent().unwrap()).expect("SETUP: create the padding");
        std::fs::rename(&short, &requests).expect("SETUP: rename to the long path");
        let junction = requests.join("nginx");
        let meta = std::fs::symlink_metadata(&junction).expect("SETUP: no junction after rename");
        assert!(
            meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0,
            "SETUP: {} is not a reparse point",
            junction.display()
        );
        assert_eq!(
            std::fs::canonicalize(junction.join(INBOX_DIR)).expect("SETUP: follow the junction"),
            std::fs::canonicalize(elsewhere.join(INBOX_DIR))
                .expect("SETUP: canonicalize elsewhere"),
            "SETUP: the junction doesn't lead to elsewhere"
        );

        assert!(enqueue(&open(&requests), "nginx", ARN).is_err());
        assert!(files(&elsewhere.join(INBOX_DIR)).is_empty());
    }

    #[test]
    fn uuid_v4_has_the_version_and_variant_bits() {
        let id = uuid_v4().unwrap();
        let groups: Vec<&str> = id.split('-').collect();
        assert_eq!(
            groups.iter().map(|g| g.len()).collect::<Vec<_>>(),
            [8, 4, 4, 4, 12]
        );
        assert!(groups[2].starts_with('4'));
        assert!(matches!(
            groups[3].chars().next(),
            Some('8' | '9' | 'a' | 'b')
        ));
        assert_ne!(id, uuid_v4().unwrap());
    }

    #[test]
    fn name_sorts_by_time_then_sequence() {
        let now = DateTime::parse_from_rfc3339("2026-10-07T19:45:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            request_name(now, 7, "id"),
            format!("{}-007-id.cmd", now.timestamp_millis())
        );
    }
}
