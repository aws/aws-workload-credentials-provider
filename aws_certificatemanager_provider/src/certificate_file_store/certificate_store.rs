use std::path::{Path, PathBuf};

use log::{debug, warn};

use super::error::StoreError;
use aws_workload_credentials_provider_common::filesystem::FileSystem;
use aws_workload_credentials_provider_common::fs_permissions::PathPermission;

/// Use: Use update_store_files or sequence calls to write_temp_file and atomic_rename.
/// Use separate write_temp_file and atomic_rename calls if you have custom logic to perform between these
///
/// let temp1 = write_temp_file(file1)
/// let temp2 = write_temp_file(file2)
///
/// atomic_rename(temp1, file1)
/// atomic_rename(temp2, file2)
///
/// Order verifies permissions by creating temp files before destructive act of renaming
pub trait UpdateStoreFile {
    /// Errs if cannot create temp file or if the parent directory contains symlinks
    /// (canonicalize check at write time for TOCTOU mitigation).
    /// Some(None) if file does not need updating
    /// Some(temp_path) if temp file was created
    ///
    /// If permission is set to None, will not set permission and leave as default private permissions
    /// Default permissions are the same as that of files created by the `tempfile` crate
    ///     This is 0o600 for unix (subject to process umask) and owner/admin/system only access for windows
    ///
    /// If force_replace = true, will always overwite current file, even if contents are identical.
    /// This should be used to confirm new permissions are used in case of config changes
    fn write_temp_file(
        &self,
        path: &Path,
        content: &str,
        permission: Option<&PathPermission>,
        force_replace: bool,
    ) -> Result<Option<TempFileWithDropCleanup<'_>>, StoreError>;
    /// Sequences write_temp_file for all paths and contents, followed by an atomic_rename for all
    ///
    /// If permission is set to None, will not set permission and leave as default
    /// Default permissions are the same as that of files created by the `tempfile` crate
    ///     This is 0o600 for unix (subject to process umask) and owner/admin/system only access for windows
    ///
    /// If force_replace = true, will always overwite current file, even if contents are identical.
    /// This should be used to confirm new permissions are used in case of a config change
    ///
    /// Returns `true` if at least one file was written, `false` if all files were unchanged.
    fn update_store_files(
        &self,
        paths_contents: &[(&Path, &str, Option<&PathPermission>)],
        force_replace: bool,
    ) -> Result<bool, StoreError>;
    /// Errs if fails to rename.
    /// Should generally not happen, as permissions to create files are verified by writing temp file
    fn atomic_rename(&self, temp_path: &Path, path: &Path) -> Result<(), StoreError>;
}

/// Wraps a FileSystem object and implements methods for safely updating files
pub struct CertificateFileStore {
    fs: Box<dyn FileSystem>,
}

impl UpdateStoreFile for CertificateFileStore {
    /// if new content is not same as existing file contents
    /// then writes 'content' to a new temp file in same directory as the existing file
    ///
    /// Canonicalizes the parent directory before writing to reject paths containing symlinks.
    /// Returns the temp file path in a TempFileWithDropCleanup object if there is content diff
    /// Returns None if no content difference
    /// Errs if there is a filesystem error or if the path resolves differently than expected
    fn write_temp_file(
        &self,
        existing_file_path: &Path,
        content: &str,
        permission: Option<&PathPermission>,
        force_update: bool,
    ) -> Result<Option<TempFileWithDropCleanup<'_>>, StoreError> {
        let parent_dir = self.parent_result(existing_file_path)?;

        // Re-verify no symlinks at write time (TOCTOU mitigation)
        let canonical_parent = self.fs.canonicalize(&parent_dir)?;
        if canonical_parent != parent_dir {
            return Err(StoreError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Path traversal detected at write time: '{}' resolves to '{}'",
                    parent_dir.display(),
                    canonical_parent.display()
                ),
            )));
        }

        // Confirm update is different from existing file contents
        if !force_update && self.fs.exists(existing_file_path) {
            let old_content = self.fs.read_to_string(existing_file_path)?;
            if old_content == content {
                debug!(
                    "File unchanged, skipping write: {}",
                    existing_file_path.display()
                );
                return Ok(None);
            }
        }
        let temp_path = self.fs.write_string_to_temp(&parent_dir, content)?;
        let temp_file = TempFileWithDropCleanup {
            path: temp_path,
            fs: &*self.fs,
        };
        if let Some(perm) = permission {
            self.fs.grant_permissions(&temp_file.path, perm)?;
        }
        Ok(Some(temp_file))
    }
    /// Uses the filesystem's rename to replace the existing file with the given temp file
    fn atomic_rename(&self, temp_path: &Path, existing_file_path: &Path) -> Result<(), StoreError> {
        Ok(self.fs.atomic_rename(temp_path, existing_file_path)?)
    }

    /// writes to temp all input paths and contents. then atomic renames overwriting existing paths with created temp files
    ///
    /// Immediately returns error on the first filesystem error.
    /// If this happens during the rename process some files may be updated and some left as is
    /// Temp files will be cleaned up regardless
    fn update_store_files(
        &self,
        paths_contents: &[(&Path, &str, Option<&PathPermission>)],
        force_update: bool,
    ) -> Result<bool, StoreError> {
        let mut temps: Vec<Option<TempFileWithDropCleanup>> =
            Vec::with_capacity(paths_contents.len());
        // First, create all the temp files, confirming write permissions
        for (path, content, permission) in paths_contents {
            temps.push(self.write_temp_file(path, content, *permission, force_update)?);
        }
        let changed = temps.iter().any(|t| t.is_some());
        // Rename temp files to final locations
        for (i, temp) in temps.iter().enumerate() {
            if let Some(t) = temp {
                self.atomic_rename(&t.path, paths_contents[i].0)?;
            }
        }
        Ok(changed)
    }
}

impl CertificateFileStore {
    /// Wraps filesystem in a CertificateFileStore Object
    pub fn new(fs: Box<dyn FileSystem>) -> Result<Self, StoreError> {
        Ok(Self { fs })
    }

    /// Converts the self.fs.parent method to return a Result, instead of an Option
    ///
    /// This method simplifies integration with FileSystem parent method
    fn parent_result(&self, path: &Path) -> std::io::Result<PathBuf> {
        self.fs.parent(path).ok_or(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("failed to get parent dir of path, {}", path.display()),
        ))
    }
}

/// Wrapper around a filesystem and an owned filepath
pub struct TempFileWithDropCleanup<'a> {
    path: PathBuf,
    fs: &'a dyn FileSystem,
}

/// Ensures tempfiles are not left on filesystem
impl<'a> Drop for TempFileWithDropCleanup<'a> {
    fn drop(&mut self) {
        if self.fs.exists(&self.path) {
            debug!("deleting leftover temp file {}", self.path.display());
            match self.fs.remove_file(&self.path) {
                Ok(()) => (),
                Err(e) => warn!("failed to remove temp file {}", e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_workload_credentials_provider_common::filesystem::{MockFileSystem, RealFileSystem};
    use aws_workload_credentials_provider_common::fs_permissions::PathPermission;
    #[cfg(windows)]
    use aws_workload_credentials_provider_common::fs_permissions::{Rights, TrusteeType};
    use std::fs;
    use tempfile::TempDir;
    #[cfg(windows)]
    use windows::Win32::Security::Authorization::TRUSTEE_W;

    /// Helper: creates a TempDir and returns paths for cert, chain, and key files inside it.
    fn setup_paths(dir: &TempDir) -> (PathBuf, PathBuf, PathBuf) {
        let fs = RealFileSystem;
        let base = fs.canonicalize(dir.path()).unwrap();
        let cert = base.join("cert.pem");
        let chain = base.join("chain.pem");
        let key = base.join("key.pem");
        (cert, chain, key)
    }

    fn real_fs() -> Box<dyn FileSystem> {
        Box::new(RealFileSystem)
    }

    /// Unix 0o644: owner read/write, group and others read-only.
    #[cfg(unix)]
    pub fn all_read_permission() -> PathPermission {
        PathPermission { mode: 0o644 }
    }

    #[cfg(unix)]
    pub fn restricted_permissions() -> PathPermission {
        PathPermission { mode: 0o600 }
    }

    /// Builds an all-read `&PathPermission` granting `FILE_GENERIC_READ | READ_CONTROL`
    /// to the built-in Guest account.
    /// Is not exactly granting read access to Everyone, but is close enough for testing
    #[cfg(windows)]
    pub fn all_read_permission() -> PathPermission {
        PathPermission {
            trustee_name: "Everyone".to_owned(),
            rights: Rights::Read,
            trustee_type: TrusteeType::Group,
        }
    }

    // This is a bit silly, adding Admin read access, when Admin already has full access does nothing
    #[cfg(windows)]
    pub fn restricted_permissions() -> PathPermission {
        PathPermission {
            trustee_name: "Administrators".to_owned(),
            rights: Rights::Read,
            trustee_type: TrusteeType::Group,
        }
    }

    // ── Permission assertion helpers ────────────────────────────────

    /// Asserts that the file at `path` has Unix mode 0o644 (owner rw, group/others r).
    #[cfg(unix)]
    fn assert_has_all_read_permissions(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(path).expect("failed to read metadata");
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "expected 0o644 (all-read), got 0o{:o}", mode);
    }

    /// Asserts that the file at `path` has Unix mode 0o600 (owner rw only).
    #[cfg(unix)]
    fn assert_has_restricted_permissions(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(path).expect("failed to read metadata");
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0o600 (owner-only), got 0o{:o}", mode);
    }

    /// Asserts that the Guest account has `FILE_GENERIC_READ | READ_CONTROL` on the file,
    /// matching the ACE granted by `all_read_permission()`.
    #[cfg(windows)]
    fn assert_has_all_read_permissions(path: &Path) {
        use std::ptr;
        use windows::core::PWSTR;
        use windows::Win32::Security::Authorization::{
            GetEffectiveRightsFromAclW, GetNamedSecurityInfoW, SE_FILE_OBJECT, TRUSTEE_IS_NAME,
            TRUSTEE_IS_USER,
        };
        use windows::Win32::Security::{ACL, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
        use windows::Win32::Storage::FileSystem::{FILE_READ_DATA, READ_CONTROL};

        let wide_name: Vec<u16> = "Guest".encode_utf16().chain(std::iter::once(0)).collect();
        let mut trustee = TRUSTEE_W::default();
        trustee.TrusteeForm = TRUSTEE_IS_NAME;
        trustee.TrusteeType = TRUSTEE_IS_USER;
        trustee.ptstrName = PWSTR(wide_name.as_ptr() as *mut u16);

        unsafe {
            let wide_path: Vec<u16> = path
                .to_str()
                .unwrap()
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let mut p_sd = PSECURITY_DESCRIPTOR::default();
            let mut p_dacl: *mut ACL = ptr::null_mut();
            let result = GetNamedSecurityInfoW(
                PWSTR(wide_path.as_ptr() as *mut _),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut p_dacl),
                None,
                &mut p_sd,
            );
            assert!(result.0 == 0, "GetNamedSecurityInfoW failed: {}", result.0);

            let mut access: u32 = 0;
            let result = GetEffectiveRightsFromAclW(p_dacl, &trustee, &mut access);
            windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(
                p_sd.0 as *mut _,
            )));
            assert!(
                result.0 == 0,
                "GetEffectiveRightsFromAclW failed: {}",
                result.0
            );

            assert!(
                access & FILE_READ_DATA.0 == FILE_READ_DATA.0,
                "expected FILE_READ_DATA for Guest, got 0x{:08X}",
                access
            );
            assert!(
                access & READ_CONTROL.0 == READ_CONTROL.0,
                "expected READ_CONTROL for Guest, got 0x{:08X}",
                access
            );
        }
    }

    /// Asserts that only the Administrators group, SYSTEM, and the file
    /// owner have any access in the DACL.  Every ACCESS_ALLOWED ACE must
    /// belong to one of those three principals; any other SID causes a
    /// test failure.
    #[cfg(windows)]
    fn assert_has_restricted_permissions(path: &Path) {
        use std::ffi::c_void;
        use std::ptr;
        use windows::core::PWSTR;
        use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
        use windows::Win32::Security::PSID;
        use windows::Win32::Security::{
            EqualSid, GetAce, IsWellKnownSid, WinBuiltinAdministratorsSid, WinLocalSystemSid,
            ACCESS_ALLOWED_ACE, ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
            PSECURITY_DESCRIPTOR,
        };

        // SAFETY: This block calls Win32 security APIs that require raw pointer manipulation.
        // All invariants are upheld as follows:
        // - `wide_path` is a valid null-terminated UTF-16 string that outlives the entire block.
        // - `GetNamedSecurityInfoW` allocates `p_sd` (the security descriptor) which owns the
        //   memory backing both `p_dacl` and `p_owner`; these point into `p_sd` and are not
        //   freed independently.
        // - The success of `GetNamedSecurityInfoW` (result == 0) is asserted before any
        //   pointer dereference, guaranteeing `p_dacl` and `p_owner` are valid.
        // - `(*p_dacl).AceCount` is read only after the DACL pointer is confirmed valid, and
        //   `GetAce` is called only with indices in `0..AceCount`, so every returned ACE
        //   pointer is within the bounds of the ACL buffer.
        // - Each ACE pointer is cast to `*const ACCESS_ALLOWED_ACE` only after verifying
        //   `AceType == ACCESS_ALLOWED_ACE_TYPE` (0), which guarantees the layout matches.
        // - The SID embedded in the ACE (`&ace.SidStart`) is passed to `IsWellKnownSid` and
        //   `EqualSid` as a `PSID`; these are read-only operations on memory owned by the
        //   security descriptor.
        // - `p_sd` is freed via `LocalFree` exactly once, after all reads are complete, per
        //   the Win32 API contract.
        unsafe {
            let wide_path: Vec<u16> = path
                .to_str()
                .unwrap()
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let mut p_sd = PSECURITY_DESCRIPTOR::default();
            let mut p_dacl: *mut ACL = ptr::null_mut();
            let mut p_owner = PSID::default();

            // Retrieve both the DACL and the owner SID in one call.
            let result = GetNamedSecurityInfoW(
                PWSTR(wide_path.as_ptr() as *mut _),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                Some(&mut p_owner),
                None,
                Some(&mut p_dacl),
                None,
                &mut p_sd,
            );
            assert!(result.0 == 0, "GetNamedSecurityInfoW failed: {}", result.0);

            // a null dacl grants full access to all users. fails assertion
            assert!(
                !p_dacl.is_null(),
                "DACL is null — file has no access restrictions"
            );
            // Walk every ACE in the DACL.
            let ace_count = (*p_dacl).AceCount as u32;
            for i in 0..ace_count {
                let mut ace_ptr: *mut c_void = ptr::null_mut();
                GetAce(p_dacl, i, &mut ace_ptr).expect("GetAce failed");

                let ace = &*(ace_ptr as *const ACCESS_ALLOWED_ACE);

                // Only inspect ACCESS_ALLOWED ACEs (type 0).
                const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
                if ace.Header.AceType != ACCESS_ALLOWED_ACE_TYPE {
                    continue;
                }

                // Skip inherited ACEs — we only validate explicitly set permissions.
                const INHERITED_ACE: u8 = 0x10;
                if ace.Header.AceFlags & INHERITED_ACE != 0 {
                    continue;
                }

                // The SID starts at the SidStart field of the ACE struct.
                let sid = PSID(&ace.SidStart as *const u32 as *mut c_void);

                let is_admin = IsWellKnownSid(sid, WinBuiltinAdministratorsSid).as_bool();
                let is_system = IsWellKnownSid(sid, WinLocalSystemSid).as_bool();
                let is_owner = !p_owner.is_invalid() && EqualSid(sid, p_owner).is_ok();

                assert!(
                    is_admin || is_system || is_owner,
                    "ACE {} grants access to a SID that is not Administrators, \
                     SYSTEM, or the owner (access mask 0x{:08X})",
                    i,
                    ace.Mask,
                );
            }

            windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(
                p_sd.0 as *mut _,
            )));
        }
    }

    // ── TempFileWithDropCleanup tests ───────────────────────────────

    #[test]
    fn test_temp_cert_drop_removes_existing() {
        let dir = TempDir::new().unwrap();
        let temp_path = dir.path().join("leftover.tmp");
        fs::write(&temp_path, "leftover").unwrap();

        let fs: Box<dyn FileSystem> = real_fs();
        {
            let _guard = TempFileWithDropCleanup {
                path: temp_path.clone(),
                fs: &*fs,
            };
            // File still exists while guard is alive.
            assert!(temp_path.exists());
        }
        // After drop, the file should be removed.
        assert!(!temp_path.exists());
    }

    #[test]
    fn test_temp_cert_drop_noop_for_missing() {
        let fs: Box<dyn FileSystem> = real_fs();
        let missing_path = PathBuf::from("/nonexistent/path/tmp.file");
        // Should not panic when the file doesn't exist.
        {
            let _guard = TempFileWithDropCleanup {
                path: missing_path.clone(),
                fs: &*fs,
            };
            // File doesn't exist while guard is alive.
            assert!(!missing_path.exists());
        }
        // After drop, the file should be removed.
        assert!(!missing_path.exists());
    }

    // ── update failure tests: invalid paths ──────────────────────────

    /// A mock FileSystem that returns an error from write_string_to_temp.
    struct FailWriteTempFs;
    impl FileSystem for FailWriteTempFs {
        fn exists(&self, _: &Path) -> bool {
            false
        }
        fn is_dir(&self, _: &Path) -> bool {
            false
        }
        fn read_to_string(&self, _: &Path) -> std::io::Result<String> {
            Ok(String::new())
        }
        fn write_string_to_temp(&self, _: &Path, _: &str) -> std::io::Result<PathBuf> {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "mock: write denied",
            ))
        }
        fn atomic_rename(&self, _: &Path, _: &Path) -> std::io::Result<()> {
            Ok(())
        }
        fn remove_file(&self, _: &Path) -> std::io::Result<()> {
            Ok(())
        }
        fn canonicalize(&self, path: &Path) -> std::io::Result<PathBuf> {
            Ok(path.to_path_buf())
        }
        fn grant_permissions(&self, _: &Path, _: &PathPermission) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A mock FileSystem that succeeds on write_string_to_temp but fails on atomic_rename.
    struct FailRenameFs;
    impl FileSystem for FailRenameFs {
        fn exists(&self, _: &Path) -> bool {
            false
        }
        fn is_dir(&self, _: &Path) -> bool {
            false
        }
        fn read_to_string(&self, _: &Path) -> std::io::Result<String> {
            Ok(String::new())
        }
        fn write_string_to_temp(&self, _: &Path, _: &str) -> std::io::Result<PathBuf> {
            Ok(PathBuf::from("/tmp/fake_temp_file"))
        }
        fn atomic_rename(&self, _: &Path, _: &Path) -> std::io::Result<()> {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "mock: rename target not found",
            ))
        }
        fn remove_file(&self, _: &Path) -> std::io::Result<()> {
            Ok(())
        }
        fn canonicalize(&self, path: &Path) -> std::io::Result<PathBuf> {
            Ok(path.to_path_buf())
        }
        fn grant_permissions(&self, _: &Path, _: &PathPermission) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A mock FileSystem where canonicalize returns a different path, simulating a symlink in the path.
    struct SymlinkFs;
    impl FileSystem for SymlinkFs {
        fn exists(&self, _: &Path) -> bool {
            false
        }
        fn is_dir(&self, _: &Path) -> bool {
            false
        }
        fn read_to_string(&self, _: &Path) -> std::io::Result<String> {
            Ok(String::new())
        }
        fn write_string_to_temp(&self, _: &Path, _: &str) -> std::io::Result<PathBuf> {
            Ok(PathBuf::from("/tmp/fake_temp_file"))
        }
        fn atomic_rename(&self, _: &Path, _: &Path) -> std::io::Result<()> {
            Ok(())
        }
        fn remove_file(&self, _: &Path) -> std::io::Result<()> {
            Ok(())
        }
        fn canonicalize(&self, _path: &Path) -> std::io::Result<PathBuf> {
            // Simulate symlink resolving to a different path
            Ok(PathBuf::from("/etc/shadow"))
        }
        fn grant_permissions(&self, _: &Path, _: &PathPermission) -> std::io::Result<()> {
            Ok(())
        }
    }

    // ── UpdateStoreFile trait (write_temp_file) tests ────────────────

    #[test]
    fn test_write_temp_file_rejects_symlink_path() {
        let store = CertificateFileStore::new(Box::new(SymlinkFs)).unwrap();

        let result =
            store.write_temp_file(Path::new("/opt/certs/cert.pem"), "content", None, false);
        match result {
            Err(StoreError::Io(e)) => {
                assert!(
                    e.to_string().contains("Path traversal detected"),
                    "error should mention path traversal, got: {}",
                    e
                );
            }
            Err(other) => {
                panic!("expected StoreError::Io with path traversal message, got: {other}")
            }
            Ok(_) => panic!("should reject when canonicalize resolves to a different path"),
        }
    }

    #[test]
    fn test_write_temp_file_creates_temp_when_file_missing() {
        let dir = TempDir::new().unwrap();
        let (cert, _chain, _key) = setup_paths(&dir);
        let store = CertificateFileStore::new(real_fs()).unwrap();

        let result =
            store.write_temp_file(&cert, "new content", Some(&all_read_permission()), false);
        assert!(result.is_ok());
        let temp = result.unwrap();
        assert!(temp.is_some(), "should create a temp file for new content");
        let temp = temp.unwrap();
        assert!(temp.path.exists(), "temp file should exist on disk");
        assert_eq!(fs::read_to_string(&temp.path).unwrap(), "new content");
        assert_has_all_read_permissions(&temp.path);
    }

    #[test]
    fn test_write_temp_file_creates_temp_when_content_differs() {
        let dir = TempDir::new().unwrap();
        let (cert, _chain, _key) = setup_paths(&dir);
        fs::write(&cert, "old content").unwrap();

        let store = CertificateFileStore::new(real_fs()).unwrap();

        let result = store.write_temp_file(&cert, "new content", None, false);
        assert!(result.is_ok());
        let temp = result.unwrap();
        assert!(temp.is_some(), "should create temp when content differs");
        assert_eq!(
            fs::read_to_string(&temp.unwrap().path).unwrap(),
            "new content"
        );
    }

    #[test]
    fn test_write_temp_file_returns_none_when_content_same() {
        let dir = TempDir::new().unwrap();
        let (cert, _chain, _key) = setup_paths(&dir);
        fs::write(&cert, "same content").unwrap();

        let store = CertificateFileStore::new(real_fs()).unwrap();

        let result =
            store.write_temp_file(&cert, "same content", Some(&all_read_permission()), false);
        // No error encountered
        assert!(result.is_ok());
        // But no changes to write
        assert!(
            result.unwrap().is_none(),
            "should return None when content is identical"
        );
    }

    #[test]
    fn test_write_temp_file_fails_invalid_parent() {
        let dir = TempDir::new().unwrap();
        let (_cert, _chain, _key) = setup_paths(&dir);
        let store = CertificateFileStore::new(real_fs()).unwrap();

        let result = store.write_temp_file(
            Path::new("/nonexistent_dir_12345/file.pem"),
            "content",
            None,
            false,
        );
        assert!(
            result.is_err(),
            "should fail when parent dir does not exist"
        );
    }

    #[test]
    fn test_write_temp_file_with_mock_fs() {
        let mock_fs = MockFileSystem::new().with_dir("/mock/certs");
        let store = CertificateFileStore::new(Box::new(mock_fs)).unwrap();

        // MockFileSystem.exists returns false and read_to_string returns empty,
        // so content "new" differs from "" and write_string_to_temp returns Ok("")
        let result = store.write_temp_file(
            Path::new("/mock/certs/cert.pem"),
            "new",
            Some(&all_read_permission()),
            false,
        );
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_write_temp_file_fails_when_write_temp_errors() {
        let store = CertificateFileStore::new(Box::new(FailWriteTempFs)).unwrap();

        let result = store.write_temp_file(Path::new("/any/cert.pem"), "content", None, false);
        match result {
            Err(StoreError::Io(_)) => (),
            Err(other) => panic!("expected StoreError::Io, got: {other}"),
            Ok(_) => panic!("should fail when write_string_to_temp returns an error"),
        }
    }

    #[test]
    fn test_write_temp_file_drop_cleans_up() {
        let dir = TempDir::new().unwrap();
        let (cert, _chain, _key) = setup_paths(&dir);
        let store = CertificateFileStore::new(real_fs()).unwrap();

        let temp_path;
        {
            let temp = store
                .write_temp_file(&cert, "ephemeral", Some(&all_read_permission()), false)
                .unwrap()
                .unwrap();
            temp_path = temp.path.clone();
            assert!(temp_path.exists());
        }
        // After drop, temp file should be cleaned up
        assert!(
            !temp_path.exists(),
            "temp file should be removed after drop"
        );
    }

    // ── UpdateStoreFile trait (atomic_rename) tests ──────────────────

    #[test]
    fn test_trait_atomic_rename_creates_destination_file() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("src.tmp");
        let dst = dir.path().join("dst.pem");
        fs::write(&src, "renamed content").unwrap();

        assert!(!dst.exists());
        let store = CertificateFileStore::new(real_fs()).unwrap();
        let result = UpdateStoreFile::atomic_rename(&store, &src, &dst);
        assert!(result.is_ok());
        assert!(!src.exists());
        assert_eq!(fs::read_to_string(&dst).unwrap(), "renamed content");
    }

    #[test]
    fn test_trait_atomic_rename_missing_source() {
        let dir = TempDir::new().unwrap();
        let dst = dir.path().join("dst.pem");

        let store = CertificateFileStore::new(real_fs()).unwrap();
        let result =
            UpdateStoreFile::atomic_rename(&store, Path::new("/nonexistent/src.tmp"), &dst);
        assert!(result.is_err());
    }

    #[test]
    fn test_trait_atomic_rename_overwrites_existing() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("src.tmp");
        let dst = dir.path().join("dst.pem");
        fs::write(&src, "new").unwrap();
        fs::write(&dst, "old").unwrap();

        let store = CertificateFileStore::new(real_fs()).unwrap();
        UpdateStoreFile::atomic_rename(&store, &src, &dst).unwrap();
        assert_eq!(fs::read_to_string(&dst).unwrap(), "new");
    }

    #[test]
    fn test_trait_atomic_rename_fails_with_mock() {
        let store = CertificateFileStore::new(Box::new(FailRenameFs)).unwrap();

        let result =
            UpdateStoreFile::atomic_rename(&store, Path::new("/tmp/src"), Path::new("/tmp/dst"));
        assert!(result.is_err());
    }

    // ── UpdateStoreFile trait (update_store_files) tests ─────────────

    #[test]
    fn test_update_store_files_writes_all_files() {
        let dir = TempDir::new().unwrap();
        let (cert, chain, key) = setup_paths(&dir);
        let store = CertificateFileStore::new(real_fs()).unwrap();

        store
            .update_store_files(
                &[
                    (&cert, "c1", Some(&all_read_permission())),
                    (&chain, "ch1", Some(&all_read_permission())),
                    (&key, "k1", None),
                ],
                false,
            )
            .unwrap();

        assert_eq!(fs::read_to_string(&cert).unwrap(), "c1");
        assert_eq!(fs::read_to_string(&chain).unwrap(), "ch1");
        assert_eq!(fs::read_to_string(&key).unwrap(), "k1");
        assert_has_all_read_permissions(&cert);
        assert_has_all_read_permissions(&chain);
    }

    #[test]
    fn test_update_store_files_overwrites_existing() {
        let dir = TempDir::new().unwrap();
        let (cert, chain, key) = setup_paths(&dir);
        for path in [&cert, &chain, &key] {
            fs::write(path, "stale").unwrap();
        }

        let store = CertificateFileStore::new(real_fs()).unwrap();
        store
            .update_store_files(
                &[
                    (&cert, "fresh-c", Some(&all_read_permission())),
                    (&chain, "fresh-ch", Some(&all_read_permission())),
                    (&key, "fresh-k", None),
                ],
                false,
            )
            .unwrap();

        assert_eq!(fs::read_to_string(&cert).unwrap(), "fresh-c");
        assert_eq!(fs::read_to_string(&chain).unwrap(), "fresh-ch");
        assert_eq!(fs::read_to_string(&key).unwrap(), "fresh-k");
        assert_has_all_read_permissions(&cert);
        assert_has_all_read_permissions(&chain);
    }

    #[test]
    fn test_update_store_files_skips_unchanged() {
        let dir = TempDir::new().unwrap();
        let (cert, chain, key) = setup_paths(&dir);
        fs::write(&cert, "same").unwrap();
        fs::write(&chain, "same").unwrap();

        let store = CertificateFileStore::new(real_fs()).unwrap();
        // cert and chain have same content, key is new
        store
            .update_store_files(
                &[
                    (&cert, "same", Some(&all_read_permission())),
                    (&chain, "same", Some(&all_read_permission())),
                    (&key, "new-key", None),
                ],
                false,
            )
            .unwrap();

        assert_eq!(fs::read_to_string(&cert).unwrap(), "same");
        assert_eq!(fs::read_to_string(&chain).unwrap(), "same");
        assert_eq!(fs::read_to_string(&key).unwrap(), "new-key");
    }

    #[test]
    fn test_update_store_files_all_unchanged_is_noop() {
        let dir = TempDir::new().unwrap();
        let (cert, chain, key) = setup_paths(&dir);
        fs::write(&cert, "c").unwrap();
        fs::write(&chain, "ch").unwrap();
        fs::write(&key, "k").unwrap();

        let store = CertificateFileStore::new(real_fs()).unwrap();
        store
            .update_store_files(
                &[
                    (&cert, "c", Some(&all_read_permission())),
                    (&chain, "ch", Some(&all_read_permission())),
                    (&key, "k", None),
                ],
                false,
            )
            .unwrap();

        // Files should remain unchanged
        assert_eq!(fs::read_to_string(&cert).unwrap(), "c");
        assert_eq!(fs::read_to_string(&chain).unwrap(), "ch");
        assert_eq!(fs::read_to_string(&key).unwrap(), "k");
    }

    #[test]
    fn test_update_store_files_called_twice() {
        let dir = TempDir::new().unwrap();
        let (cert, chain, _key) = setup_paths(&dir);
        let store = CertificateFileStore::new(real_fs()).unwrap();

        store
            .update_store_files(
                &[
                    (&cert, "v1-c", Some(&all_read_permission())),
                    (&chain, "v1-ch", Some(&all_read_permission())),
                ],
                false,
            )
            .unwrap();
        assert_eq!(fs::read_to_string(&cert).unwrap(), "v1-c");
        assert_has_all_read_permissions(&cert);
        assert_has_all_read_permissions(&chain);

        store
            .update_store_files(
                &[
                    (&cert, "v2-c", Some(&all_read_permission())),
                    (&chain, "v2-ch", Some(&all_read_permission())),
                ],
                false,
            )
            .unwrap();
        assert_eq!(fs::read_to_string(&cert).unwrap(), "v2-c");
        assert_eq!(fs::read_to_string(&chain).unwrap(), "v2-ch");
        assert_has_all_read_permissions(&cert);
        assert_has_all_read_permissions(&chain);
    }

    #[test]
    fn test_update_store_files_no_leftover_temp_files() {
        let dir = TempDir::new().unwrap();
        let (cert, chain, key) = setup_paths(&dir);
        let store = CertificateFileStore::new(real_fs()).unwrap();

        store
            .update_store_files(
                &[
                    (&cert, "c", Some(&all_read_permission())),
                    (&chain, "ch", Some(&all_read_permission())),
                    (&key, "k", None),
                ],
                false,
            )
            .unwrap();

        let entries: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(entries.len(), 3, "only the 3 target files should remain");
    }

    #[test]
    fn test_update_store_files_mismatched_lengths() {
        let dir = TempDir::new().unwrap();
        let (cert, chain, _key) = setup_paths(&dir);
        let store = CertificateFileStore::new(real_fs()).unwrap();

        // With the tuple API, mismatched lengths are no longer possible at the call site.
        // This test now just verifies that a normal call succeeds.
        store
            .update_store_files(
                &[
                    (&cert, "c", Some(&all_read_permission())),
                    (&chain, "ch", Some(&all_read_permission())),
                ],
                false,
            )
            .unwrap();
        assert_eq!(fs::read_to_string(&cert).unwrap(), "c");
        assert_eq!(fs::read_to_string(&chain).unwrap(), "ch");
    }

    #[test]
    fn test_update_store_files_empty_slices() {
        let store = CertificateFileStore::new(real_fs()).unwrap();

        let empty: &[(&Path, &str, Option<&PathPermission>)] = &[];
        let result = store.update_store_files(empty, false);
        assert!(result.is_ok(), "empty slices should succeed as a no-op");
    }

    #[test]
    fn test_update_store_files_single_file() {
        let dir = TempDir::new().unwrap();
        let (cert, _chain, _key) = setup_paths(&dir);
        let store = CertificateFileStore::new(real_fs()).unwrap();

        store
            .update_store_files(&[(&cert, "single", Some(&all_read_permission()))], false)
            .unwrap();
        assert_eq!(fs::read_to_string(&cert).unwrap(), "single");
        assert_has_all_read_permissions(&cert);
    }

    #[test]
    fn test_update_store_files_fails_invalid_path() {
        let store = CertificateFileStore::new(real_fs()).unwrap();

        let invalid = PathBuf::from("/nonexistent_dir_12345/file.pem");
        let result = store.update_store_files(
            &[(&invalid, "content", Some(&all_read_permission()))],
            false,
        );
        assert!(
            result.is_err(),
            "should fail when path parent does not exist"
        );
    }

    #[test]
    fn test_update_store_files_fails_when_write_temp_errors() {
        let store = CertificateFileStore::new(Box::new(FailWriteTempFs)).unwrap();

        let result = store.update_store_files(
            &[(
                Path::new("/any/cert.pem"),
                "content",
                Some(&all_read_permission()),
            )],
            false,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            StoreError::Io(_) => (),
            other => panic!("expected StoreError::Io, got: {other}"),
        }
    }

    #[test]
    fn test_update_store_files_fails_when_rename_errors() {
        let store = CertificateFileStore::new(Box::new(FailRenameFs)).unwrap();

        let result = store.update_store_files(
            &[(
                Path::new("/any/cert.pem"),
                "content",
                Some(&all_read_permission()),
            )],
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_update_store_files_no_leftover_temp_on_failure() {
        let dir = TempDir::new().unwrap();
        let (cert, _chain, _key) = setup_paths(&dir);
        let store = CertificateFileStore::new(real_fs()).unwrap();

        let invalid = PathBuf::from("/nonexistent_dir_12345/file.pem");
        // First path is valid, second is invalid — should fail partway
        let _ = store.update_store_files(
            &[
                (&cert, "c", Some(&all_read_permission())),
                (&invalid, "x", Some(&all_read_permission())),
            ],
            false,
        );

        let entries: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(
            entries.len(),
            0,
            "no temp files should remain after failure"
        );
    }

    #[test]
    fn test_update_store_files_with_mock_fs() {
        let mock_fs = MockFileSystem::new().with_dir("/mock/certs");
        let store = CertificateFileStore::new(Box::new(mock_fs)).unwrap();

        let result = store.update_store_files(
            &[
                (
                    Path::new("/mock/certs/cert.pem"),
                    "cert-data",
                    Some(&all_read_permission()),
                ),
                (
                    Path::new("/mock/certs/chain.pem"),
                    "chain-data",
                    Some(&all_read_permission()),
                ),
            ],
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_update_store_files_changes_all_read_to_owner_only() {
        let dir = TempDir::new().unwrap();
        let (cert, chain, _key) = setup_paths(&dir);
        let store = CertificateFileStore::new(real_fs()).unwrap();

        // Initial write with all-read permissions
        store
            .update_store_files(
                &[
                    (&cert, "v1", Some(&all_read_permission())),
                    (&chain, "v1", Some(&all_read_permission())),
                ],
                false,
            )
            .unwrap();
        assert_has_all_read_permissions(&cert);
        assert_has_all_read_permissions(&chain);

        // Update with restricted permissions (content must differ to trigger a write)
        // This is also testing that default tempfile permissions are restricted
        store
            .update_store_files(
                &[
                    (&cert, "v2", Some(&restricted_permissions())),
                    (&chain, "v2", None),
                ],
                false,
            )
            .unwrap();
        assert_eq!(fs::read_to_string(&cert).unwrap(), "v2");
        assert_eq!(fs::read_to_string(&chain).unwrap(), "v2");
        assert_has_restricted_permissions(&cert);
        assert_has_restricted_permissions(&chain);
    }

    // ── force_update tests ──────────────────────────────────────────

    #[test]
    fn test_write_temp_file_force_update_rewrites_when_content_same() {
        let dir = TempDir::new().unwrap();
        let (cert, _chain, _key) = setup_paths(&dir);
        fs::write(&cert, "same content").unwrap();

        let store = CertificateFileStore::new(real_fs()).unwrap();

        // Without force_update, identical content returns None
        let result =
            store.write_temp_file(&cert, "same content", Some(&all_read_permission()), false);
        assert!(result.is_ok());
        assert!(
            result.unwrap().is_none(),
            "without force_update, same content should return None"
        );

        // With force_update, identical content still creates a temp file
        let result =
            store.write_temp_file(&cert, "same content", Some(&all_read_permission()), true);
        assert!(result.is_ok());
        let temp = result.unwrap();
        assert!(
            temp.is_some(),
            "force_update should create temp file even when content is identical"
        );
        let temp = temp.unwrap();
        assert!(temp.path.exists());
        assert_eq!(fs::read_to_string(&temp.path).unwrap(), "same content");
    }

    #[test]
    fn test_write_temp_file_force_update_creates_temp_when_file_missing() {
        let dir = TempDir::new().unwrap();
        let (cert, _chain, _key) = setup_paths(&dir);
        let store = CertificateFileStore::new(real_fs()).unwrap();

        let result =
            store.write_temp_file(&cert, "new content", Some(&all_read_permission()), true);
        assert!(result.is_ok());
        let temp = result.unwrap();
        assert!(
            temp.is_some(),
            "force_update should create temp file when file is missing"
        );
        assert_eq!(
            fs::read_to_string(&temp.unwrap().path).unwrap(),
            "new content"
        );
    }

    #[test]
    fn test_write_temp_file_force_update_creates_temp_when_content_differs() {
        let dir = TempDir::new().unwrap();
        let (cert, _chain, _key) = setup_paths(&dir);
        fs::write(&cert, "old content").unwrap();

        let store = CertificateFileStore::new(real_fs()).unwrap();

        let result = store.write_temp_file(&cert, "new content", None, true);
        assert!(result.is_ok());
        let temp = result.unwrap();
        assert!(
            temp.is_some(),
            "force_update should create temp file when content differs"
        );
        assert_eq!(
            fs::read_to_string(&temp.unwrap().path).unwrap(),
            "new content"
        );
    }

    #[test]
    fn test_write_temp_file_force_update_applies_permissions_on_same_content() {
        let dir = TempDir::new().unwrap();
        let (cert, _chain, _key) = setup_paths(&dir);
        fs::write(&cert, "same").unwrap();

        let store = CertificateFileStore::new(real_fs()).unwrap();

        // Force update with all_read permissions on identical content
        let result = store.write_temp_file(&cert, "same", Some(&all_read_permission()), true);
        assert!(result.is_ok());
        let temp = result.unwrap().unwrap();
        assert_has_all_read_permissions(&temp.path);

        // Force update with owner-only permissions on identical content
        let result = store.write_temp_file(&cert, "same", Some(&restricted_permissions()), true);
        assert!(result.is_ok());
        let temp = result.unwrap().unwrap();
        assert_has_restricted_permissions(&temp.path);
    }

    #[test]
    fn test_write_temp_file_force_update_fails_invalid_parent() {
        let store = CertificateFileStore::new(real_fs()).unwrap();

        let result = store.write_temp_file(
            Path::new("/nonexistent_dir_12345/file.pem"),
            "content",
            None,
            true,
        );
        assert!(
            result.is_err(),
            "force_update should still fail when parent dir does not exist"
        );
    }

    #[test]
    fn test_update_store_files_force_update_rewrites_all_unchanged() {
        let dir = TempDir::new().unwrap();
        let (cert, chain, key) = setup_paths(&dir);
        fs::write(&cert, "c").unwrap();
        fs::write(&chain, "ch").unwrap();
        fs::write(&key, "k").unwrap();

        let store = CertificateFileStore::new(real_fs()).unwrap();

        // Without force_update this would be a no-op (all content identical).
        // With force_update the files are rewritten so permissions are refreshed.
        store
            .update_store_files(
                &[
                    (&cert, "c", Some(&all_read_permission())),
                    (&chain, "ch", Some(&all_read_permission())),
                    (&key, "k", Some(&restricted_permissions())),
                ],
                true,
            )
            .unwrap();

        assert_eq!(fs::read_to_string(&cert).unwrap(), "c");
        assert_eq!(fs::read_to_string(&chain).unwrap(), "ch");
        assert_eq!(fs::read_to_string(&key).unwrap(), "k");
        assert_has_all_read_permissions(&cert);
        assert_has_all_read_permissions(&chain);
        assert_has_restricted_permissions(&key);
    }

    #[test]
    fn test_update_store_files_force_update_changes_permissions_without_content_change() {
        let dir = TempDir::new().unwrap();
        let (cert, _chain, _key) = setup_paths(&dir);
        let store = CertificateFileStore::new(real_fs()).unwrap();

        // Write initial file with owner-only permissions
        store
            .update_store_files(&[(&cert, "data", Some(&restricted_permissions()))], false)
            .unwrap();
        assert_has_restricted_permissions(&cert);

        // Same content, different permissions, force_update=false → skipped (no rewrite)
        store
            .update_store_files(&[(&cert, "data", Some(&all_read_permission()))], false)
            .unwrap();
        // Permissions remain owner-only because the write was skipped
        assert_has_restricted_permissions(&cert);

        // Same content, different permissions, force_update=true → rewritten
        store
            .update_store_files(&[(&cert, "data", Some(&all_read_permission()))], true)
            .unwrap();
        assert_eq!(fs::read_to_string(&cert).unwrap(), "data");
        assert_has_all_read_permissions(&cert);
    }

    #[test]
    fn test_update_store_files_force_update_no_leftover_temp_files() {
        let dir = TempDir::new().unwrap();
        let (cert, chain, key) = setup_paths(&dir);
        let store = CertificateFileStore::new(real_fs()).unwrap();

        store
            .update_store_files(
                &[
                    (&cert, "c", Some(&all_read_permission())),
                    (&chain, "ch", Some(&all_read_permission())),
                    (&key, "k", None),
                ],
                true,
            )
            .unwrap();

        let entries: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(
            entries.len(),
            3,
            "only the 3 target files should remain, no temp leftovers"
        );
    }

    #[test]
    fn test_update_store_files_changes_owner_only_to_all_read() {
        let dir = TempDir::new().unwrap();
        let (cert, chain, _key) = setup_paths(&dir);
        let store = CertificateFileStore::new(real_fs()).unwrap();

        // Initial write with owner-only permissions
        store
            .update_store_files(
                &[
                    (&cert, "v1", Some(&restricted_permissions())),
                    (&chain, "v1", Some(&restricted_permissions())),
                ],
                false,
            )
            .unwrap();
        assert_has_restricted_permissions(&cert);
        assert_has_restricted_permissions(&chain);

        // Update with all-read permissions (content must differ to trigger a write)
        store
            .update_store_files(
                &[
                    (&cert, "v2", Some(&all_read_permission())),
                    (&chain, "v2", Some(&all_read_permission())),
                ],
                false,
            )
            .unwrap();
        assert_eq!(fs::read_to_string(&cert).unwrap(), "v2");
        assert_eq!(fs::read_to_string(&chain).unwrap(), "v2");
        assert_has_all_read_permissions(&cert);
        assert_has_all_read_permissions(&chain);
    }
}
