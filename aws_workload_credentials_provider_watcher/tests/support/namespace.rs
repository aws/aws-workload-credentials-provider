//! Linux-only: runs the `wcp-watcher` binary on real tmpfs mounts, made
//! without privilege in a private user and mount namespace.
//!
//! A [`CommandExt::pre_exec`] hook in the child calls
//! `unshare(CLONE_NEWUSER | CLONE_NEWNS)`, maps its own uid and gid, mounts a
//! tmpfs on each root, writes the test's layout, remounts the roots marked
//! [`MountMode::ReadOnly`], and execs the watcher. The mounts exist only in
//! the child's mount namespace and vanish when it exits. This cannot be done
//! in the test process: `unshare(CLONE_NEWUSER)` fails with `EINVAL` in a
//! multithreaded process, and libtest always runs tests on their own thread.
//!
//! Where unprivileged user namespaces are blocked (e.g. Ubuntu 24.04's
//! `kernel.apparmor_restrict_unprivileged_userns=1`), the spawn fails and
//! [`skip_without_namespaces`] turns that into `SKIPPED: <reason>`, unless
//! `WCP_WATCHER_E2E_REQUIRE_MOUNTS=1` makes it fail.

use std::ffi::{CStr, CString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Set to `1` to turn a missing-user-namespace skip into a failure.
pub const REQUIRE_MOUNTS_VAR: &str = "WCP_WATCHER_E2E_REQUIRE_MOUNTS";

/// tmpfs mount options: owner-only writable roots, and small, since the tests
/// write a few hundred bytes.
const TMPFS_OPTIONS: &CStr = c"mode=0755,size=4m";

/// The access mode a root's tmpfs has when the watcher starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountMode {
    ReadOnly,
    ReadWrite,
}

/// Everything the `pre_exec` hook needs, allocated before `fork`.
///
/// The hook runs in the forked child, where only async-signal-safe calls are
/// allowed, so it may not allocate. Every buffer it touches is owned here.
pub struct NamespaceSetup {
    uid_map: CString,
    gid_map: CString,
    mounts: Vec<(CString, MountMode)>,
    dirs: Vec<CString>,
    files: Vec<(CString, Vec<u8>)>,
}

impl NamespaceSetup {
    /// Mounts a tmpfs on each of `mounts`, creates `dirs` in order, writes
    /// each of `files`, then remounts each [`MountMode::ReadOnly`] mount
    /// read-only.
    ///
    /// The uid/gid maps are identity maps for the current user
    /// (`"<id> <id> 1\n"`), so the watcher keeps the real uid and runs
    /// unprivileged after `exec`.
    pub fn for_current_user(
        mounts: &[(&Path, MountMode)],
        dirs: &[&PathBuf],
        files: &[(PathBuf, Vec<u8>)],
    ) -> Self {
        // SAFETY: `getuid`/`getgid` always succeed and touch no memory.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        Self {
            uid_map: CString::new(format!("{uid} {uid} 1\n")).unwrap(),
            gid_map: CString::new(format!("{gid} {gid} 1\n")).unwrap(),
            mounts: mounts
                .iter()
                .map(|(path, mode)| (cstring(path), *mode))
                .collect(),
            dirs: dirs.iter().map(|dir| cstring(dir)).collect(),
            files: files
                .iter()
                .map(|(path, bytes)| (cstring(path), bytes.clone()))
                .collect(),
        }
    }

    /// Installs the hook that builds the namespace, mounts and layout in the
    /// child before it execs the watcher.
    pub fn install(self, cmd: &mut Command) {
        // SAFETY: the closure runs in the child after `fork`, where the only
        // thread is the one that called `fork` and another thread may have
        // held the allocator or any other lock. It therefore:
        // - makes only raw libc calls (`unshare`, `open`, `write`, `close`,
        //   `mount`, including the `MS_REMOUNT` call, and `mkdir`).
        //   `open`/`write`/`close`/`mkdir` are on signal-safety(7)'s
        //   async-signal-safe list; `unshare` and `mount` are thin syscall
        //   wrappers with no libc state;
        // - reads only buffers allocated before `fork` and moved in here, plus
        //   `c"..."` literals: no `format!`, `Path::join`, `std::fs`, logging
        //   or other allocation;
        // - reports failure with `io::Error::last_os_error()`, which reads
        //   `errno` into the non-allocating `Os` variant. `spawn` sends that
        //   errno back to the parent.
        // `Command` already makes a panic here abort rather than unwind.
        unsafe {
            cmd.pre_exec(move || {
                if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) != 0 {
                    return Err(io::Error::last_os_error());
                }
                // `setgroups` must be denied before an unprivileged process
                // may write its gid_map (user_namespaces(7)).
                raw_write(c"/proc/self/setgroups", b"deny", 0)?;
                raw_write(c"/proc/self/uid_map", self.uid_map.as_bytes(), 0)?;
                raw_write(c"/proc/self/gid_map", self.gid_map.as_bytes(), 0)?;
                // The new mount namespace is owned by a less privileged user
                // namespace, so these mounts cannot propagate to the host
                // (mount_namespaces(7)).
                for (mountpoint, _) in &self.mounts {
                    let rc = libc::mount(
                        c"tmpfs".as_ptr(),
                        mountpoint.as_ptr(),
                        c"tmpfs".as_ptr(),
                        libc::MS_NOSUID | libc::MS_NODEV,
                        TMPFS_OPTIONS.as_ptr().cast(),
                    );
                    if rc != 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                for dir in &self.dirs {
                    if libc::mkdir(dir.as_ptr(), 0o755) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                for (path, bytes) in &self.files {
                    raw_write(path, bytes, libc::O_CREAT | libc::O_EXCL)?;
                }
                // Remount the read-only roots now that their contents exist.
                // `MS_BIND` is what lets an unprivileged remount change only
                // the per-mount flags (a plain tmpfs remount is EINVAL here),
                // and `MS_NOSUID | MS_NODEV` must be repeated or the remount
                // clears them.
                for (mountpoint, mode) in &self.mounts {
                    if *mode != MountMode::ReadOnly {
                        continue;
                    }
                    let rc = libc::mount(
                        std::ptr::null(),
                        mountpoint.as_ptr(),
                        std::ptr::null(),
                        libc::MS_REMOUNT
                            | libc::MS_BIND
                            | libc::MS_RDONLY
                            | libc::MS_NOSUID
                            | libc::MS_NODEV,
                        std::ptr::null(),
                    );
                    if rc != 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
    }
}

/// Whether the test should skip because `error`, from spawning a command with
/// a [`NamespaceSetup`] installed, means the host cannot create the
/// namespace. Prints `SKIPPED: <reason>` when it does, and panics instead
/// when [`REQUIRE_MOUNTS_VAR`] is `1`. Any other error is `false`: a test
/// defect, for the caller to fail on.
pub fn skip_without_namespaces(error: &io::Error) -> bool {
    if !is_missing_namespace_support(error) {
        return false;
    }
    let reason = format!(
        "could not create a private user+mount namespace with tmpfs mounts \
         ({error}); unprivileged user namespaces are probably disabled on this host"
    );
    if std::env::var(REQUIRE_MOUNTS_VAR).as_deref() == Ok("1") {
        panic!("{reason}, and {REQUIRE_MOUNTS_VAR}=1 requires them");
    }
    println!("SKIPPED: {reason}");
    true
}

/// Opens `path` write-only with `extra_flags`, writes all of `bytes`, and
/// closes it, using only async-signal-safe libc calls and no allocation.
///
/// # Safety
///
/// Safe to call in a forked child before `exec`; see
/// [`NamespaceSetup::install`].
unsafe fn raw_write(path: &CStr, bytes: &[u8], extra_flags: libc::c_int) -> io::Result<()> {
    let fd = libc::open(
        path.as_ptr(),
        libc::O_WRONLY | libc::O_CLOEXEC | extra_flags,
        0o644 as libc::c_uint,
    );
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut written = 0;
    while written < bytes.len() {
        let rest = &bytes[written..];
        let n = libc::write(fd, rest.as_ptr().cast(), rest.len());
        if n < 0 {
            // Read `errno` before `close` can overwrite it.
            let error = io::Error::last_os_error();
            libc::close(fd);
            return Err(error);
        }
        written += n as usize;
    }
    if libc::close(fd) != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Whether a `spawn` error means the host does not allow an unprivileged
/// user+mount namespace with tmpfs mounts, as opposed to a test defect.
///
/// `EPERM`/`EACCES`: blocked by policy (AppArmor, a sysctl, seccomp).
/// `ENOSPC`: `user.max_user_namespaces=0`. `EINVAL`: the kernel does not
/// support the flags.
fn is_missing_namespace_support(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EPERM | libc::EACCES | libc::ENOSPC | libc::EINVAL)
    )
}

fn cstring(path: &Path) -> CString {
    CString::new(path.as_os_str().as_bytes()).expect("a path without NUL bytes")
}
