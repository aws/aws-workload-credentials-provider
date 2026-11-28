//! Status records written after watcher requests finish.

#[cfg(windows)]
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{SecondsFormat, Utc};

#[allow(unused_imports)]
pub use aws_workload_credentials_provider_common::watcher_status::{
    cap_error_detail, status_filename, StatusOutcome, StatusRecord, MAX_ERROR_DETAIL_BYTES,
};

/// Produces the timestamp format used by status records.
pub fn timestamp_now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// The status-writing seam used by the event loop and its tests.
pub trait StatusSink: Send + Sync + 'static {
    fn write(&self, status: &StatusRecord) -> io::Result<()>;
}

/// Writes statuses into the watcher-provisioned outbox.
#[derive(Debug, Clone)]
pub struct FileStatusSink {
    outbox: PathBuf,
}

impl FileStatusSink {
    pub fn new(outbox: PathBuf) -> Self {
        Self { outbox }
    }
}

impl StatusSink for FileStatusSink {
    fn write(&self, status: &StatusRecord) -> io::Result<()> {
        write_atomically(&self.outbox, status)
    }
}

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Serializes a complete record to a same-directory temporary file and then
/// atomically renames it over the final status path. The outbox directory is
/// opened at publication time and held for every child operation, so replacing
/// its path cannot redirect the write.
pub fn write_atomically(outbox: &Path, status: &StatusRecord) -> io::Result<()> {
    // The provider rejects an invalid record, so it is never published.
    status.validate().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid status: {error:?}"),
        )
    })?;
    let body = serde_json::to_vec(status).map_err(io::Error::other)?;
    write_atomically_platform(outbox, status, &body, || {}, || {})
}

#[cfg(test)]
fn write_atomically_with_hooks<F, G>(
    outbox: &Path,
    status: &StatusRecord,
    after_directory_open: F,
    before_write: G,
) -> io::Result<()>
where
    F: FnOnce(),
    G: FnOnce(),
{
    let body = serde_json::to_vec(status).map_err(io::Error::other)?;
    write_atomically_platform(outbox, status, &body, after_directory_open, before_write)
}

#[cfg(unix)]
fn write_atomically_platform<F, G>(
    outbox: &Path,
    status: &StatusRecord,
    body: &[u8],
    after_directory_open: F,
    before_write: G,
) -> io::Result<()>
where
    F: FnOnce(),
    G: FnOnce(),
{
    use rustix::fs::{fsync, open, openat, renameat, unlinkat, AtFlags, Mode, OFlags};

    let directory = open(
        outbox,
        OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::RDONLY,
        Mode::empty(),
    )?;
    after_directory_open();

    let destination = status_filename(&status.command_id);
    let mut temp = None;
    for _ in 0..16 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let candidate = format!(
            ".{}.{}.{}.status.tmp",
            status.command_id,
            std::process::id(),
            sequence
        );
        match openat(
            &directory,
            &candidate,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o644),
        ) {
            Ok(file) => {
                temp = Some((candidate, std::fs::File::from(file)));
                break;
            }
            Err(error) if error == rustix::io::Errno::EXIST => continue,
            Err(error) => return Err(io::Error::from(error)),
        }
    }

    let Some((temp_name, mut file)) = temp else {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a status temporary file",
        ));
    };

    before_write();
    // Explicit mode so the container's umask can't hide it from the provider's group.
    let result = rustix::fs::fchmod(&file, Mode::from_raw_mode(0o644))
        .map_err(io::Error::from)
        .and_then(|()| file.write_all(body))
        .and_then(|()| file.sync_all())
        .and_then(|()| {
            renameat(&directory, &temp_name, &directory, &destination).map_err(io::Error::from)
        });
    if result.is_err() {
        let _ = unlinkat(&directory, &temp_name, AtFlags::empty());
        return result;
    }
    // The status is published once renamed; a failed sync only risks losing
    // it in a crash, so it doesn't fail the write.
    let _ = fsync(&directory);
    Ok(())
}

#[cfg(windows)]
fn write_atomically_platform<F, G>(
    outbox: &Path,
    status: &StatusRecord,
    body: &[u8],
    after_directory_open: F,
    before_write: G,
) -> io::Result<()>
where
    F: FnOnce(),
    G: FnOnce(),
{
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows::Win32::Storage::FileSystem::{
        DELETE, FILE_ADD_FILE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
        FILE_SHARE_WRITE,
    };

    // No FILE_SHARE_DELETE pins the opened directory against rename or
    // replacement until the complete temp-file write and replacement finish.
    let directory = OpenOptions::new()
        .access_mode(FILE_GENERIC_READ.0 | FILE_ADD_FILE.0)
        .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(outbox)?;
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "status outbox is a reparse point or not a directory",
        ));
    }
    if !same_path(&final_path(&directory)?, outbox) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "status outbox is reached through a link",
        ));
    }
    after_directory_open();

    let destination = status_filename(&status.command_id);
    let mut temp = None;
    for _ in 0..16 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let candidate = outbox.join(format!(
            ".{}.{}.{}.status.tmp",
            status.command_id,
            std::process::id(),
            sequence
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .access_mode(FILE_GENERIC_WRITE.0 | DELETE.0)
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(&candidate)
        {
            Ok(file) => {
                temp = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }

    let Some((temp_path, mut file)) = temp else {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a status temporary file",
        ));
    };

    let result = (|| {
        let temp_parent = final_path(&file)?.parent().map(Path::to_path_buf);
        if temp_parent
            .as_deref()
            .map(|parent| same_path(parent, outbox))
            != Some(true)
        {
            return Err(io::Error::other("status outbox changed while writing"));
        }
        before_write();
        file.write_all(body)?;
        file.sync_all()?;
        rename_into(&file, &directory, &destination)
    })();
    if result.is_err() {
        let _ = delete_by_handle(&file);
    }
    let _ = temp_path;
    result
}

#[cfg(windows)]
fn same_path(actual: &Path, expected: &Path) -> bool {
    let normalize = |path: &Path| {
        let text = path.to_string_lossy().into_owned();
        text.strip_prefix(r"\\?\")
            .unwrap_or(&text)
            .to_ascii_lowercase()
    };
    normalize(actual) == normalize(expected)
}

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

#[cfg(windows)]
fn rename_into(file: &std::fs::File, directory: &std::fs::File, name: &str) -> io::Result<()> {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::FILE_RENAME_INFO;

    #[repr(C)]
    struct IoStatusBlock {
        status: isize,
        information: usize,
    }
    const FILE_RENAME_INFORMATION: u32 = 10;
    let name: Vec<u16> = name.encode_utf16().collect();
    let header = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
    let size = header + name.len() * std::mem::size_of::<u16>();
    let mut buf = vec![0u64; size.div_ceil(8)];
    let info = buf.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    let mut io_status = IoStatusBlock {
        status: 0,
        information: 0,
    };
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtSetInformationFile(
            file: *mut c_void,
            io_status: *mut IoStatusBlock,
            information: *const c_void,
            length: u32,
            class: u32,
        ) -> i32;
        fn RtlNtStatusToDosError(status: i32) -> u32;
    }

    // SAFETY: `buf` holds at least `size` bytes, is aligned for
    // FILE_RENAME_INFO, and both handles remain open for the call.
    let status = unsafe {
        (*info).Anonymous.ReplaceIfExists = true;
        (*info).RootDirectory = HANDLE(directory.as_raw_handle());
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
    use std::fs;
    use tempfile::TempDir;

    const COMMAND_ID: &str = "3f2b8c1e-7a4d-4e9b-8c2f-1d6e5a9b0c7d";

    /// A record whose fields agree with `outcome`.
    fn record(outcome: StatusOutcome) -> StatusRecord {
        let ran = !matches!(outcome, StatusOutcome::NotFound | StatusOutcome::Superseded);
        StatusRecord {
            command_id: COMMAND_ID.to_string(),
            cert_arn: "arn:aws:acm:us-west-2:123456789012:certificate/test".to_string(),
            request_created_at: "2025-10-20T17:06:40Z".to_string(),
            outcome,
            exit_code: match outcome {
                StatusOutcome::Success => Some(0),
                StatusOutcome::Failure => Some(1),
                _ => None,
            },
            started_at: ran.then(|| "2025-10-20T17:06:41.123Z".to_string()),
            completed_at: ran.then(|| "2025-10-20T17:06:41.456Z".to_string()),
            error_detail: None,
        }
    }

    #[test]
    fn an_inconsistent_record_is_not_published() {
        let temp = TempDir::new().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let mut status = record(StatusOutcome::Success);
        status.exit_code = Some(3);

        let error = write_atomically(&root, &status).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    }

    #[test]
    fn serializes_protocol_fields_and_outcomes() {
        let value = serde_json::to_value(record(StatusOutcome::Success)).unwrap();
        assert_eq!(value["command_id"], COMMAND_ID);
        assert_eq!(
            value["cert_arn"],
            "arn:aws:acm:us-west-2:123456789012:certificate/test"
        );
        assert_eq!(value["request_created_at"], "2025-10-20T17:06:40Z");
        assert_eq!(value["outcome"], "success");
        assert_eq!(value["exit_code"], 0);
        assert_eq!(value["error_detail"], serde_json::Value::Null);
    }

    #[test]
    fn status_filename_uses_command_id() {
        assert_eq!(status_filename(COMMAND_ID), format!("{COMMAND_ID}.status"));
    }

    #[test]
    fn stderr_is_capped_without_splitting_utf8() {
        let stderr = format!("{}é", "x".repeat(MAX_ERROR_DETAIL_BYTES));
        let detail = cap_error_detail(stderr.as_bytes()).unwrap();
        assert!(detail.len() <= MAX_ERROR_DETAIL_BYTES);
        assert!(detail.is_char_boundary(detail.len()));
    }

    #[test]
    fn writes_complete_json_and_cleans_temporary_file() {
        let temp = TempDir::new().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        write_atomically(&root, &record(StatusOutcome::Success)).unwrap();
        let path = root.join(format!("{COMMAND_ID}.status"));
        let bytes = fs::read(&path).unwrap();
        assert_eq!(
            serde_json::from_slice::<StatusRecord>(&bytes).unwrap(),
            record(StatusOutcome::Success)
        );
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_symlinked_outbox() {
        let temp = TempDir::new().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let target = root.join("target");
        let outbox = root.join("outbox");
        fs::create_dir(&target).unwrap();
        std::os::unix::fs::symlink(&target, &outbox).unwrap();

        let error = write_atomically(&outbox, &record(StatusOutcome::Success)).unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::NotADirectory | io::ErrorKind::PermissionDenied
        ));
        assert!(fs::read_dir(&target).unwrap().next().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn directory_replacement_after_open_does_not_redirect_status() {
        let temp = TempDir::new().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let outbox = root.join("outbox");
        let moved = root.join("moved-outbox");
        fs::create_dir(&outbox).unwrap();

        write_atomically_with_hooks(
            &outbox,
            &record(StatusOutcome::Success),
            || {
                fs::rename(&outbox, &moved).unwrap();
                fs::create_dir(&outbox).unwrap();
            },
            || {},
        )
        .unwrap();

        let status_name = format!("{COMMAND_ID}.status");
        assert!(!outbox.join(&status_name).exists());
        assert!(fs::read_dir(&outbox).unwrap().next().is_none());
        assert_eq!(fs::read_dir(&moved).unwrap().count(), 1);
        assert_eq!(
            serde_json::from_slice::<StatusRecord>(&fs::read(moved.join(status_name)).unwrap())
                .unwrap(),
            record(StatusOutcome::Success)
        );
    }

    #[cfg(windows)]
    #[test]
    fn directory_handle_prevents_replacement_during_status_write() {
        let temp = TempDir::new().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let outbox = root.join("outbox");
        let moved = root.join("moved-outbox");
        fs::create_dir(&outbox).unwrap();

        write_atomically_with_hooks(
            &outbox,
            &record(StatusOutcome::Success),
            || {
                assert!(fs::rename(&outbox, &moved).is_err());
            },
            || {},
        )
        .unwrap();

        assert!(!moved.exists());
        assert!(outbox.join(format!("{COMMAND_ID}.status")).is_file());
    }

    #[test]
    fn replacement_keeps_previous_complete_file_visible_until_publish() {
        let temp = TempDir::new().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        write_atomically(&root, &record(StatusOutcome::Success)).unwrap();

        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let outbox = root.to_path_buf();
        let replacement = {
            let mut replacement = record(StatusOutcome::Failure);
            replacement.exit_code = Some(7);
            replacement
        };
        let expected = replacement.clone();
        let writer = std::thread::spawn(move || {
            write_atomically_with_hooks(
                &outbox,
                &replacement,
                || {},
                || {
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                },
            )
        });

        started_rx.recv().unwrap();
        let path = root.join(format!("{COMMAND_ID}.status"));
        assert_eq!(
            serde_json::from_slice::<StatusRecord>(&fs::read(&path).unwrap()).unwrap(),
            record(StatusOutcome::Success)
        );

        release_tx.send(()).unwrap();
        writer.join().unwrap().unwrap();
        assert_eq!(
            serde_json::from_slice::<StatusRecord>(&fs::read(path).unwrap()).unwrap(),
            expected
        );
    }

    #[test]
    fn replacement_is_atomic_from_the_reader_perspective() {
        let temp = TempDir::new().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        write_atomically(&root, &record(StatusOutcome::Success)).unwrap();
        let mut replacement = record(StatusOutcome::Failure);
        replacement.exit_code = Some(7);
        write_atomically(&root, &replacement).unwrap();
        let path = root.join(format!("{COMMAND_ID}.status"));
        let parsed: StatusRecord = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(parsed, replacement);
    }
}
