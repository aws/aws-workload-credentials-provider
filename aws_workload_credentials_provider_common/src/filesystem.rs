//! FileSystem abstraction for validation.
//!
//! This module provides a trait for filesystem operations needed during
//! configuration validation, along with real and mock implementations.

use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

use crate::fs_permissions::PathPermission;

#[cfg(windows)]
use crate::fs_permissions::{Rights, TrusteeType};
#[cfg(windows)]
use windows::Win32::Security::Authorization::TRUSTEE_W;

/// Trait for filesystem operations needed during validation.
///
/// Abstracts filesystem operations to enable testing without
/// touching the real filesystem.
pub trait FileSystem: Send + Sync {
    /// Checks if a path exists (file or directory).
    fn exists(&self, path: &Path) -> bool;

    /// Checks if a path is a directory.
    fn is_dir(&self, path: &Path) -> bool;

    /// Reads the entire contents of a file as a string.
    fn read_to_string(&self, path: &Path) -> std::io::Result<String>;

    /// Returns the parent directory of a path.
    ///
    /// Used to validate that parent directories exist before writing certificate files.
    fn parent(&self, path: &Path) -> Option<PathBuf> {
        path.parent().map(|p| p.to_path_buf())
    }

    /// Writes content to a tmp file in the given parent directory.
    /// Returns the path to the newly created temp file
    fn write_string_to_temp(&self, parent_dir: &Path, content: &str) -> std::io::Result<PathBuf>;

    /// Atomically update the dest file to have the contents of the source file.
    /// The old dest_path contents are clobbered and the source_path location is removed
    ///
    /// Used for updating cert store files from temp files
    fn atomic_rename(&self, source_path: &Path, dest_path: &Path) -> std::io::Result<()>;

    /// Removes the given path
    ///
    /// Used for cleaning up leftover files
    fn remove_file(&self, path: &Path) -> std::io::Result<()>;

    /// Applies file permissions using a platform-specific [`PathPermission`] descriptor.
    ///
    /// # Platform behavior
    /// - **Unix:** Replaces the file's entire permission mode (ignoring umask).
    /// - **Windows:** Appends a GRANT ACE to the file's existing DACL.
    fn grant_permissions(&self, path: &Path, permission: &PathPermission) -> std::io::Result<()>;

    /// Canonicalizes a path, resolving symlinks and `..` components to their real location.
    ///
    /// Returns an error if the path does not exist or cannot be resolved.
    fn canonicalize(&self, path: &Path) -> std::io::Result<PathBuf>;
}

/// Sets the bitmask for the path to mode.
/// Notably, this ignores the process umask as we're directly using std::fs::set_permisisons
/// This overwrites the existing access mask
#[cfg(unix)]
fn set_unix_file_permissions(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode_perms = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, mode_perms)
}
/// Adds an ACE entry (for trustee with dword_access_mask permissions) to the DACL for the path.
/// This appends to the default owner/admin/system tempfile DACL instead of completely overwriting
#[cfg(windows)]
fn grant_windows_file_permissions(
    path: &Path,
    dword_access_mask: u32,
    trustee: &TRUSTEE_W,
) -> std::io::Result<()> {
    use std::ptr;
    use windows::core::PWSTR;
    use windows::Win32::Security::Authorization::{
        GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W,
        GRANT_ACCESS, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::NO_INHERITANCE;
    use windows::Win32::Security::{ACL, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};

    let path_str = path
        .to_str()
        .ok_or(std::io::Error::other("path is not valid UTF-16"))?;
    let wide_path: Vec<u16> = path_str.encode_utf16().chain(std::iter::once(0)).collect();

    // SAFETY: This unsafe block calls Windows security APIs that require raw pointer
    // manipulation. All invariants are upheld as follows:
    // - `wide_path` is a valid null-terminated UTF-16 string that outlives the unsafe block.
    // - `security_descriptor` is freed via `LocalFree` on all code paths (success and error).
    // - `new_acl` is freed via `LocalFree` on all code paths after allocation.
    // - `existing_dacl` points into `security_descriptor` and is not freed independently.
    unsafe {
        // 1. Get the current DACL for the file
        let mut existing_dacl: *mut ACL = ptr::null_mut();
        let mut security_descriptor = PSECURITY_DESCRIPTOR::default();
        let result = GetNamedSecurityInfoW(
            PWSTR(wide_path.as_ptr() as *mut _),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None, // owner
            None, // group
            Some(&mut existing_dacl),
            None, // SACL
            &mut security_descriptor,
        );
        if result.0 != 0 {
            return Err(std::io::Error::from_raw_os_error(result.0 as i32));
        }

        // 2. Build an EXPLICIT_ACCESS entry for the new permission
        let mut ea = EXPLICIT_ACCESS_W::default();
        ea.grfAccessPermissions = dword_access_mask;
        ea.grfAccessMode = GRANT_ACCESS;
        ea.grfInheritance = NO_INHERITANCE;
        ea.Trustee = *trustee;

        // 3. Merge the new entry with the existing ACL
        let mut new_acl: *mut ACL = ptr::null_mut();
        let result = SetEntriesInAclW(Some(&[ea]), Some(existing_dacl as *const ACL), &mut new_acl);
        if result.0 != 0 {
            // SAFETY: `security_descriptor.0` was allocated by `GetNamedSecurityInfoW` and
            // must be freed with `LocalFree` per the Win32 API contract. The cast to
            // `*mut _` is required to match the `HLOCAL` parameter type.
            windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(
                security_descriptor.0 as *mut _,
            )));
            return Err(std::io::Error::from_raw_os_error(result.0 as i32));
        }

        // 4. Apply the merged DACL to the file
        let result = SetNamedSecurityInfoW(
            PWSTR(wide_path.as_ptr() as *mut _),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None, // owner (unchanged)
            None, // group (unchanged)
            Some(new_acl as *const ACL),
            None, // SACL (unchanged)
        );

        // 5. Free allocated resources
        // SAFETY: `new_acl` was allocated by `SetEntriesInAclW` and `security_descriptor.0`
        // was allocated by `GetNamedSecurityInfoW`. Both must be freed with `LocalFree` per
        // the Win32 API contract. The `*mut _` casts convert the pointers to the `HLOCAL`
        // parameter type expected by `LocalFree`.
        windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(
            new_acl as *mut _,
        )));
        windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(
            security_descriptor.0 as *mut _,
        )));

        if result.0 != 0 {
            return Err(std::io::Error::from_raw_os_error(result.0 as i32));
        }

        Ok(())
    }
}

/// Real filesystem implementation.
///
/// Uses standard library filesystem operations to interact with the actual filesystem.
#[derive(Debug, Default)]
pub struct RealFileSystem;

impl FileSystem for RealFileSystem {
    /// Checks if a path exists (file or directory).
    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    /// Checks if a path is a directory.
    fn is_dir(&self, path: &Path) -> bool {
        path.is_dir()
    }

    /// Reads the entire contents of a file as a string.
    fn read_to_string(&self, path: &Path) -> std::io::Result<String> {
        std::fs::read_to_string(path)
    }

    /// Creates a new temp file in parent_dir and writes content to it. Leaves default permissions
    ///
    /// Return path to this tempfile
    fn write_string_to_temp(&self, parent_dir: &Path, content: &str) -> std::io::Result<PathBuf> {
        let mut tmp = NamedTempFile::new_in(parent_dir)?;

        tmp.write_all(content.as_bytes())?;
        tmp.as_file().sync_data()?;
        let (_, temp_path) = tmp.keep()?;

        Ok(temp_path)
    }

    /// Wrapper around std::fs::rename
    fn atomic_rename(&self, source_path: &Path, dest_path: &Path) -> std::io::Result<()> {
        std::fs::rename(source_path, dest_path)
    }

    /// Wrapper around std::fs::remove_file
    fn remove_file(&self, path: &Path) -> std::io::Result<()> {
        std::fs::remove_file(path)
    }

    fn canonicalize(&self, path: &Path) -> std::io::Result<PathBuf> {
        // Use dunce to avoid Windows \\?\ verbatim path prefix that
        // std::fs::canonicalize adds, which would break path comparisons.
        dunce::canonicalize(path)
    }

    /// Grants the specified file permissions using a platform-specific [`PathPermission`] descriptor.
    fn grant_permissions(&self, path: &Path, permission: &PathPermission) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            set_unix_file_permissions(path, permission.mode)
        }
        #[cfg(windows)]
        {
            use windows::core::PWSTR;
            use windows::Win32::Foundation::GENERIC_READ;
            use windows::Win32::Security::Authorization::{
                TRUSTEE_IS_GROUP, TRUSTEE_IS_NAME, TRUSTEE_IS_USER, TRUSTEE_W,
            };
            let wide: Vec<u16> = permission
                .trustee_name
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let mut trustee = TRUSTEE_W::default();
            trustee.TrusteeForm = TRUSTEE_IS_NAME;
            trustee.TrusteeType = match permission.trustee_type {
                TrusteeType::Group => TRUSTEE_IS_GROUP,
                TrusteeType::User => TRUSTEE_IS_USER,
            };
            trustee.ptstrName = PWSTR(wide.as_ptr() as *mut u16);
            let mask = match permission.rights {
                Rights::Read => GENERIC_READ.0,
            };
            grant_windows_file_permissions(path, mask, &trustee)
        }
        #[cfg(not(any(unix, windows)))]
        {
            compile_error!("grant_permissions is not supported on this platform")
        }
    }
}

/// Mock filesystem for testing.
#[derive(Debug, Default)]
pub struct MockFileSystem {
    existing_paths: HashSet<String>,
    directories: HashSet<String>,
}

impl MockFileSystem {
    /// Creates a new empty mock filesystem.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a file path that exists.
    pub fn with_file(mut self, path: &str) -> Self {
        self.existing_paths.insert(path.to_string());
        self
    }

    /// Adds a directory path that exists.
    pub fn with_dir(mut self, path: &str) -> Self {
        self.existing_paths.insert(path.to_string());
        self.directories.insert(path.to_string());
        self
    }
}

impl FileSystem for MockFileSystem {
    /// Checks if a path exists (file or directory).
    fn exists(&self, path: &Path) -> bool {
        self.existing_paths.contains(path.to_str().unwrap_or(""))
    }

    /// Checks if a path is a directory.
    fn is_dir(&self, path: &Path) -> bool {
        self.directories.contains(path.to_str().unwrap_or(""))
    }

    /// Reads the entire contents of a file as a string.
    fn read_to_string(&self, _path: &Path) -> std::io::Result<String> {
        Ok(String::new())
    }

    fn write_string_to_temp(&self, _parent_dir: &Path, _content: &str) -> std::io::Result<PathBuf> {
        Ok(PathBuf::new())
    }

    fn atomic_rename(&self, _source_path: &Path, _dest_path: &Path) -> std::io::Result<()> {
        Ok(())
    }

    fn remove_file(&self, _path: &Path) -> std::io::Result<()> {
        Ok(())
    }

    fn canonicalize(&self, path: &Path) -> std::io::Result<PathBuf> {
        // Mock: registered paths are treated as canonical (no symlinks simulated)
        let path_str = path.to_str().unwrap_or("");
        if self.existing_paths.contains(path_str) {
            Ok(path.to_path_buf())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("mock: path not found: {}", path.display()),
            ))
        }
    }

    fn grant_permissions(&self, _path: &Path, _permission: &PathPermission) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_mock_filesystem_with_file() {
        let fs = MockFileSystem::new().with_file("/path/to/file");
        assert!(fs.exists(Path::new("/path/to/file")));
        assert!(!fs.exists(Path::new("/other/path")));
        assert!(!fs.is_dir(Path::new("/path/to/file")));
    }

    #[test]
    fn test_mock_filesystem_with_dir() {
        let fs = MockFileSystem::new().with_dir("/path/to/dir");
        assert!(fs.exists(Path::new("/path/to/dir")));
        assert!(fs.is_dir(Path::new("/path/to/dir")));
    }

    #[test]
    fn test_mock_filesystem_parent() {
        let fs = MockFileSystem::new();
        assert_eq!(
            fs.parent(Path::new("/path/to/file")),
            Some(PathBuf::from("/path/to"))
        );
        assert_eq!(fs.parent(Path::new("/file")), Some(PathBuf::from("/")));
        assert_eq!(fs.parent(Path::new("/")), None);
    }

    #[test]
    fn test_real_filesystem_exists() {
        let fs = RealFileSystem;
        assert!(fs.exists(Path::new("/")));
        assert!(!fs.exists(Path::new("/nonexistent_path_12345")));
    }

    #[test]
    fn test_real_filesystem_is_dir() {
        let fs = RealFileSystem;
        assert!(fs.is_dir(Path::new("/")));
        assert!(!fs.is_dir(Path::new("/nonexistent_path_12345")));
    }

    #[test]
    fn test_real_filesystem_read_to_string() {
        let fs = RealFileSystem;
        // Test that nonexistent file returns error
        assert!(fs
            .read_to_string(Path::new("/nonexistent_path_12345"))
            .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn test_set_unix_file_permissions_in_custom_temp_dir() {
        use std::os::unix::fs::PermissionsExt;

        let tmp_dir = TempDir::new().expect("failed to create temp dir");
        let file_path = tmp_dir.path().join("test_file.txt");
        std::fs::write(&file_path, "test content").expect("failed to write file");

        set_unix_file_permissions(&file_path, 0o600).expect("failed to set permissions");

        let metadata = std::fs::metadata(&file_path).expect("failed to read metadata");
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0o600, got 0o{:o}", mode);
    }

    #[cfg(unix)]
    #[test]
    fn test_set_unix_file_permissions_readonly_in_custom_temp_dir() {
        use std::os::unix::fs::PermissionsExt;

        let tmp_dir = TempDir::new().expect("failed to create temp dir");
        let file_path = tmp_dir.path().join("readonly_file.txt");
        std::fs::write(&file_path, "readonly content").expect("failed to write file");

        set_unix_file_permissions(&file_path, 0o400).expect("failed to set permissions");

        let metadata = std::fs::metadata(&file_path).expect("failed to read metadata");
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o400, "expected 0o400, got 0o{:o}", mode);
    }

    #[cfg(unix)]
    #[test]
    fn test_set_unix_file_permissions_world_readable_in_custom_temp_dir() {
        use std::os::unix::fs::PermissionsExt;

        let tmp_dir = TempDir::new().expect("failed to create temp dir");
        let file_path = tmp_dir.path().join("world_readable.txt");
        std::fs::write(&file_path, "public content").expect("failed to write file");

        set_unix_file_permissions(&file_path, 0o644).expect("failed to set permissions");

        let metadata = std::fs::metadata(&file_path).expect("failed to read metadata");
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "expected 0o644, got 0o{:o}", mode);
    }

    #[cfg(unix)]
    #[test]
    fn test_set_unix_file_permissions_nonexistent_file() {
        let tmp_dir = TempDir::new().expect("failed to create temp dir");
        let file_path = tmp_dir.path().join("does_not_exist.txt");

        let result = set_unix_file_permissions(&file_path, 0o600);
        assert!(result.is_err(), "expected error for nonexistent file");
    }

    #[test]
    fn test_write_string_to_temp_creates_file_in_custom_dir() {
        let tmp_dir = TempDir::new().expect("failed to create temp dir");
        let fs = RealFileSystem;

        let temp_path = fs
            .write_string_to_temp(tmp_dir.path(), "hello temp")
            .expect("failed to write temp file");

        // File should exist inside the custom temp directory
        assert!(
            temp_path.exists(),
            "temp file should exist at {}",
            temp_path.display()
        );
        assert!(
            temp_path.starts_with(tmp_dir.path()),
            "temp file should be inside the custom temp dir"
        );

        let contents = std::fs::read_to_string(&temp_path).expect("failed to read temp file");
        assert_eq!(contents, "hello temp");
    }

    #[cfg(unix)]
    #[test]
    fn test_write_string_to_temp_and_set_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp_dir = TempDir::new().expect("failed to create temp dir");
        let fs = RealFileSystem;

        let temp_path = fs
            .write_string_to_temp(tmp_dir.path(), "secret data")
            .expect("failed to write temp file");

        set_unix_file_permissions(&temp_path, 0o600).expect("failed to set permissions");

        let metadata = std::fs::metadata(&temp_path).expect("failed to read metadata");
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0o600, got 0o{:o}", mode);

        let contents = std::fs::read_to_string(&temp_path).expect("failed to read temp file");
        assert_eq!(contents, "secret data");
    }

    #[cfg(unix)]
    #[test]
    fn test_write_string_to_temp_and_set_more_permissions() {
        // THis test is confirmation that set_permissions ignores the umask and allows setting all permission bits
        use std::os::unix::fs::PermissionsExt;

        let tmp_dir = TempDir::new().expect("failed to create temp dir");
        let fs = RealFileSystem;

        let temp_path = fs
            .write_string_to_temp(tmp_dir.path(), "secret data")
            .expect("failed to write temp file");

        set_unix_file_permissions(&temp_path, 0o777).expect("failed to set permissions");

        let metadata = std::fs::metadata(&temp_path).expect("failed to read metadata");
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o777, "expected 0o777, got 0o{:o}", mode);

        let contents = std::fs::read_to_string(&temp_path).expect("failed to read temp file");
        assert_eq!(contents, "secret data");
    }

    #[cfg(unix)]
    #[test]
    fn test_atomic_rename_preserves_permissions_in_custom_temp_dir() {
        use std::os::unix::fs::PermissionsExt;

        let tmp_dir = TempDir::new().expect("failed to create temp dir");
        let fs = RealFileSystem;

        // Create source file and set restrictive permissions
        let src_path = fs
            .write_string_to_temp(tmp_dir.path(), "renamed content")
            .expect("failed to write source");
        set_unix_file_permissions(&src_path, 0o600).expect("failed to set source permissions");

        // Rename to destination
        let dest_path = tmp_dir.path().join("destination.txt");
        fs.atomic_rename(&src_path, &dest_path)
            .expect("atomic rename failed");

        // Source should be gone, dest should exist with same permissions
        assert!(!src_path.exists(), "source should no longer exist");
        assert!(dest_path.exists(), "destination should exist");

        let metadata = std::fs::metadata(&dest_path).expect("failed to read metadata");
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "permissions should be preserved after rename");

        let contents = std::fs::read_to_string(&dest_path).expect("failed to read dest");
        assert_eq!(contents, "renamed content");
    }
    // ── Windows permission helper ───────────────────────────────────

    /// Retrieves the effective access mask for a given trustee on the specified file.
    /// Unlike `get_effective_access_mask`, this allows querying permissions for any
    /// trustee (user or group) rather than only the current process user.
    #[cfg(windows)]
    fn get_effective_access_mask_for_trustee(
        path: &Path,
        trustee: &TRUSTEE_W,
    ) -> std::io::Result<u32> {
        use std::ptr;
        use windows::core::PWSTR;
        use windows::Win32::Security::Authorization::{
            GetEffectiveRightsFromAclW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
        };
        use windows::Win32::Security::{ACL, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};

        let path_str = path
            .to_str()
            .ok_or(std::io::Error::other("failed to get path string"))?;

        unsafe {
            // Get the file's DACL
            let wide_path: Vec<u16> = path_str.encode_utf16().chain(std::iter::once(0)).collect();
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
            if result.0 != 0 {
                return Err(std::io::Error::from_raw_os_error(result.0 as i32));
            }

            // Query effective rights for the provided trustee
            let mut access_mask: u32 = 0;
            let result = GetEffectiveRightsFromAclW(p_dacl, trustee, &mut access_mask);

            // Free the security descriptor before checking the result
            windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(
                p_sd.0 as *mut _,
            )));

            if result.0 != 0 {
                return Err(std::io::Error::from_raw_os_error(result.0 as i32));
            }

            Ok(access_mask)
        }
    }

    // ── Windows permission tests ────────────────────────────────────

    #[cfg(windows)]
    use {
        windows::core::PWSTR,
        windows::Win32::Foundation::{CloseHandle, HANDLE},
        windows::Win32::Security::Authorization::{
            TRUSTEE_IS_GROUP, TRUSTEE_IS_NAME, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
        },
        windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER},
        windows::Win32::Storage::FileSystem::{
            FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_READ_DATA,
            FILE_WRITE_DATA, READ_CONTROL,
        },
        windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    /// Creates a `TRUSTEE_W` from a name `&str`.
    ///
    /// Returns the wide-string buffer alongside the trustee so the caller
    /// can keep the buffer alive for as long as the trustee is in use.
    #[cfg(windows)]
    fn trustee_from_name(name: &str, trustee_type: TrusteeType) -> (Vec<u16>, TRUSTEE_W) {
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut trustee = TRUSTEE_W::default();
        trustee.TrusteeForm = TRUSTEE_IS_NAME;
        trustee.TrusteeType = match trustee_type {
            TrusteeType::User => TRUSTEE_IS_USER,
            TrusteeType::Group => TRUSTEE_IS_GROUP,
        };
        trustee.ptstrName = PWSTR(wide.as_ptr() as *mut u16);
        (wide, trustee)
    }

    #[cfg(windows)]
    #[test]
    fn test_set_windows_file_permissions_for_guest_read_only() -> std::io::Result<()> {
        let (_buf, guest_name_trustee) = trustee_from_name("Everyone", TrusteeType::Group);

        let mask = FILE_GENERIC_READ.0 | READ_CONTROL.0;

        let tmp_dir = TempDir::new().expect("failed to create temp dir");
        let file_path = tmp_dir.path().join("trait_ro.txt");
        std::fs::write(&file_path, "trait readonly").expect("failed to write file");

        // get access mask before granting extra guest permissions

        let guest_access_pre =
            get_effective_access_mask_for_trustee(&file_path, &guest_name_trustee)?;
        println!("pre guest access = 0x{:08X}", guest_access_pre);
        assert!(
            guest_access_pre & FILE_WRITE_DATA.0 == 0,
            "expected no FILE_WRITE_DATA (0x{:08X}) access, got 0x{:08X}",
            FILE_WRITE_DATA.0,
            guest_access_pre
        );
        assert!(
            guest_access_pre & FILE_READ_ATTRIBUTES.0 == 0,
            "expected no FILE_READ_ATTRIBUTES access, got 0x{:08X}",
            guest_access_pre
        );
        assert!(
            guest_access_pre & READ_CONTROL.0 == 0,
            "expected no READ_CONTROL access, got 0x{:08X}",
            guest_access_pre
        );
        assert!(
            guest_access_pre & FILE_READ_DATA.0 == 0,
            "expected no FILE_READ_DATA access, got 0x{:08X}",
            guest_access_pre
        );

        // grant guest permission
        let res = grant_windows_file_permissions(&file_path, mask, &guest_name_trustee);
        assert!(
            res.is_ok(),
            "grant_windows_file_permissions method failed: {}",
            res.unwrap_err()
        );

        // get access mask after granting extra guest permissions
        let guest_access_post =
            get_effective_access_mask_for_trustee(&file_path, &guest_name_trustee)?;
        println!("post guest access = 0x{:08X}", guest_access_post);
        assert!(
            guest_access_post & FILE_WRITE_DATA.0 == 0,
            "expected no FILE_WRITE_DATA (0x{:08X}) access, got 0x{:08X}",
            FILE_WRITE_DATA.0,
            guest_access_post
        );
        assert!(
            guest_access_post & FILE_READ_ATTRIBUTES.0 == FILE_READ_ATTRIBUTES.0,
            "expected FILE_READ_ATTRIBUTES access, got 0x{:08X}",
            guest_access_post
        );
        assert!(
            guest_access_post & READ_CONTROL.0 == READ_CONTROL.0,
            "expected READ_CONTROL access, got 0x{:08X}",
            guest_access_post
        );
        assert!(
            guest_access_post & FILE_READ_DATA.0 == FILE_READ_DATA.0,
            "expected FILE_READ_DATA access, got 0x{:08X}",
            guest_access_post
        );
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn test_set_windows_file_permissions_for_nonexistentuser_read_only() -> std::io::Result<()> {
        let (_buf, guest_name_trustee) = trustee_from_name("NONEXISTENTUSER", TrusteeType::User);

        let mask = FILE_GENERIC_READ.0 | READ_CONTROL.0;

        let tmp_dir = TempDir::new().expect("failed to create temp dir");
        let file_path = tmp_dir.path().join("trait_ro.txt");
        std::fs::write(&file_path, "trait readonly").expect("failed to write file");

        // get access mask before granting extra guest permissions

        let result = grant_windows_file_permissions(&file_path, mask, &guest_name_trustee);
        assert!(
            result.is_err(),
            "Expected to fail setting the access mask of an invalid user"
        );
        println!("error encountered: {}", result.unwrap_err());
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn test_set_windows_file_permissions_for_user_read_only() -> std::io::Result<()> {
        unsafe {
            // 1. Get the current process token
            let mut token = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)?;

            // 2. Get the current user's SID from the token
            let mut token_info_len: u32 = 0;
            let _ = GetTokenInformation(token, TokenUser, None, 0, &mut token_info_len);
            let mut buffer = vec![0u8; token_info_len as usize];
            let result = GetTokenInformation(
                token,
                TokenUser,
                Some(buffer.as_mut_ptr() as *mut _),
                token_info_len,
                &mut token_info_len,
            );
            let _ = CloseHandle(token); // close before propogating errors
            result?;
            let token_user = &*(buffer.as_ptr() as *const TOKEN_USER);
            let user_sid = token_user.User.Sid;

            let mut current_user_trustee = TRUSTEE_W::default();
            current_user_trustee.TrusteeForm = TRUSTEE_IS_SID;
            current_user_trustee.TrusteeType = TRUSTEE_IS_USER;
            current_user_trustee.ptstrName = PWSTR(user_sid.0 as *mut u16);

            let mask = FILE_GENERIC_READ.0 | READ_CONTROL.0;

            let tmp_dir = TempDir::new().expect("failed to create temp dir");
            let file_path = tmp_dir.path().join("trait_ro.txt");
            std::fs::write(&file_path, "trait readonly").expect("failed to write file");

            // get access mask before granting extra user permissions
            let user_access_pre =
                get_effective_access_mask_for_trustee(&file_path, &current_user_trustee)?;

            assert!(
                user_access_pre & FILE_GENERIC_WRITE.0 == FILE_GENERIC_WRITE.0,
                "expected FILE_GENERIC_WRITE (0x{:08X}) access, got 0x{:08X}",
                FILE_GENERIC_WRITE.0,
                user_access_pre
            );
            assert!(
                user_access_pre & FILE_GENERIC_READ.0 == FILE_GENERIC_READ.0,
                "expected FILE_GENERIC_READ (0x{:08X}) access, got 0x{:08X}",
                FILE_GENERIC_READ.0,
                user_access_pre
            );
            assert!(
                user_access_pre & READ_CONTROL.0 == READ_CONTROL.0,
                "expected READ_CONTROL (0x{:08X}) access, got 0x{:08X}",
                READ_CONTROL.0,
                user_access_pre
            );

            // grant current user permissions. As we have
            let res = grant_windows_file_permissions(&file_path, mask, &current_user_trustee);
            assert!(
                res.is_ok(),
                "grant_windows_file_permissions method failed: {}",
                res.unwrap_err()
            );

            // get access mask after granting extra user permissions
            let user_access_post =
                get_effective_access_mask_for_trustee(&file_path, &current_user_trustee)?;

            assert!(
                user_access_post & FILE_GENERIC_WRITE.0 == FILE_GENERIC_WRITE.0,
                "expected FILE_GENERIC_WRITE (0x{:08X}) access, got 0x{:08X}",
                FILE_GENERIC_WRITE.0,
                user_access_post
            );
            assert!(
                user_access_post & FILE_GENERIC_READ.0 == FILE_GENERIC_READ.0,
                "expected FILE_GENERIC_READ (0x{:08X}) access, got 0x{:08X}",
                FILE_GENERIC_READ.0,
                user_access_post
            );
            assert!(
                user_access_post & READ_CONTROL.0 == READ_CONTROL.0,
                "expected READ_CONTROL (0x{:08X}) access, got 0x{:08X}",
                READ_CONTROL.0,
                user_access_post
            );
            Ok(())
        }
    }

    #[cfg(windows)]
    #[test]
    fn test_atomic_rename_preserves_windows_permissions() -> std::io::Result<()> {
        let tmp_dir = TempDir::new().expect("failed to create temp dir");
        let fs = RealFileSystem;

        // Create source file and grant Everyone read-only permissions
        let src_path = fs
            .write_string_to_temp(tmp_dir.path(), "renamed content")
            .expect("failed to write source");
        let perm = PathPermission {
            trustee_name: "Everyone".to_owned(),
            rights: Rights::Read,
            trustee_type: TrusteeType::Group,
        };
        fs.grant_permissions(&src_path, &perm)
            .expect("failed to set source permissions");

        // Verify Everyone has read access on the source before rename
        let (_buf, guest_trustee) = trustee_from_name("Everyone", TrusteeType::Group);
        let pre_access = get_effective_access_mask_for_trustee(&src_path, &guest_trustee)?;
        assert!(
            pre_access & FILE_READ_DATA.0 == FILE_READ_DATA.0,
            "expected FILE_READ_DATA on source before rename, got 0x{:08X}",
            pre_access
        );
        assert!(
            pre_access & READ_CONTROL.0 == READ_CONTROL.0,
            "expected READ_CONTROL on source before rename, got 0x{:08X}",
            pre_access
        );

        // Rename to destination
        let dest_path = tmp_dir.path().join("destination.txt");
        fs.atomic_rename(&src_path, &dest_path)
            .expect("atomic rename failed");

        // Source should be gone, dest should exist
        assert!(!src_path.exists(), "source should no longer exist");
        assert!(dest_path.exists(), "destination should exist");

        // Verify content is preserved
        let contents = std::fs::read_to_string(&dest_path).expect("failed to read dest");
        assert_eq!(contents, "renamed content");

        // Verify Everyone permissions are preserved after rename
        let (_buf, guest_trustee) = trustee_from_name("Everyone", TrusteeType::Group);
        let post_access = get_effective_access_mask_for_trustee(&dest_path, &guest_trustee)?;
        assert!(
            post_access & FILE_READ_DATA.0 == FILE_READ_DATA.0,
            "expected FILE_READ_DATA preserved after rename, got 0x{:08X}",
            post_access
        );
        assert!(
            post_access & READ_CONTROL.0 == READ_CONTROL.0,
            "expected READ_CONTROL preserved after rename, got 0x{:08X}",
            post_access
        );
        assert!(
            post_access & FILE_WRITE_DATA.0 == 0,
            "expected no FILE_WRITE_DATA after rename, got 0x{:08X}",
            post_access
        );

        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn test_grant_windows_file_permissions_nonexistent_file() {
        let (_buf, guest_trustee) = trustee_from_name("Everyone", TrusteeType::Group);
        let mask = FILE_GENERIC_READ.0 | READ_CONTROL.0;

        let tmp_dir = TempDir::new().expect("failed to create temp dir");
        let file_path = tmp_dir.path().join("does_not_exist.txt");

        let result = grant_windows_file_permissions(&file_path, mask, &guest_trustee);
        assert!(result.is_err(), "expected error for nonexistent file");
    }

    #[cfg(windows)]
    #[test]
    fn test_write_string_to_temp_and_set_windows_permissions() -> std::io::Result<()> {
        let (_buf, guest_trustee) = trustee_from_name("Everyone", TrusteeType::Group);
        let mask = FILE_GENERIC_READ.0 | READ_CONTROL.0;

        let tmp_dir = TempDir::new().expect("failed to create temp dir");
        let fs = RealFileSystem;

        let temp_path = fs
            .write_string_to_temp(tmp_dir.path(), "secret data")
            .expect("failed to write temp file");

        grant_windows_file_permissions(&temp_path, mask, &guest_trustee)
            .expect("failed to set permissions");

        // Verify Everyone gained read access
        let access = get_effective_access_mask_for_trustee(&temp_path, &guest_trustee)?;
        assert!(
            access & FILE_READ_DATA.0 == FILE_READ_DATA.0,
            "expected FILE_READ_DATA access, got 0x{:08X}",
            access
        );
        assert!(
            access & READ_CONTROL.0 == READ_CONTROL.0,
            "expected READ_CONTROL access, got 0x{:08X}",
            access
        );
        assert!(
            access & FILE_WRITE_DATA.0 == 0,
            "expected no FILE_WRITE_DATA access, got 0x{:08X}",
            access
        );

        // Verify content is intact
        let contents = std::fs::read_to_string(&temp_path).expect("failed to read temp file");
        assert_eq!(contents, "secret data");

        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn test_write_string_to_temp_and_set_more_windows_permissions() -> std::io::Result<()> {
        let (_buf, guest_trustee) = trustee_from_name("Everyone", TrusteeType::Group);
        let mask = FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | READ_CONTROL.0;

        let tmp_dir = TempDir::new().expect("failed to create temp dir");
        let fs = RealFileSystem;

        let temp_path = fs
            .write_string_to_temp(tmp_dir.path(), "secret data")
            .expect("failed to write temp file");

        grant_windows_file_permissions(&temp_path, mask, &guest_trustee)
            .expect("failed to set permissions");

        // Verify Everyone gained both read and write access
        let access = get_effective_access_mask_for_trustee(&temp_path, &guest_trustee)?;
        assert!(
            access & FILE_GENERIC_READ.0 == FILE_GENERIC_READ.0,
            "expected FILE_GENERIC_READ access, got 0x{:08X}",
            access
        );
        assert!(
            access & FILE_GENERIC_WRITE.0 == FILE_GENERIC_WRITE.0,
            "expected FILE_GENERIC_WRITE access, got 0x{:08X}",
            access
        );
        assert!(
            access & READ_CONTROL.0 == READ_CONTROL.0,
            "expected READ_CONTROL access, got 0x{:08X}",
            access
        );

        // Verify content is intact
        let contents = std::fs::read_to_string(&temp_path).expect("failed to read temp file");
        assert_eq!(contents, "secret data");

        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn test_real_filesystem_grant_permissions_windows() -> std::io::Result<()> {
        let tmp_dir = TempDir::new().expect("failed to create temp dir");
        let file_path = tmp_dir.path().join("trait_perm.txt");
        std::fs::write(&file_path, "trait test").expect("failed to write file");

        // Verify Everyone has no access before
        let (_buf, guest_trustee) = trustee_from_name("Everyone", TrusteeType::Group);
        let pre_access = get_effective_access_mask_for_trustee(&file_path, &guest_trustee)?;
        assert!(
            pre_access & FILE_READ_DATA.0 == 0,
            "expected no FILE_READ_DATA before grant, got 0x{:08X}",
            pre_access
        );
        assert!(
            pre_access & READ_CONTROL.0 == 0,
            "expected no READ_CONTROL before grant, got 0x{:08X}",
            pre_access
        );
        assert!(
            pre_access & FILE_WRITE_DATA.0 == 0,
            "expected no FILE_WRITE_DATA before grant, got 0x{:08X}",
            pre_access
        );

        // Use the trait method on RealFileSystem
        let fs = RealFileSystem;
        let perm = PathPermission {
            trustee_name: "Everyone".to_owned(),
            rights: Rights::Read,
            trustee_type: TrusteeType::Group,
        };
        fs.grant_permissions(&file_path, &perm)
            .expect("grant_permissions via trait failed");

        // Verify Everyone gained read access via the trait method
        let (_buf, guest_trustee) = trustee_from_name("Everyone", TrusteeType::Group);
        let post_access = get_effective_access_mask_for_trustee(&file_path, &guest_trustee)?;
        assert!(
            post_access & FILE_READ_DATA.0 == FILE_READ_DATA.0,
            "expected FILE_READ_DATA after grant, got 0x{:08X}",
            post_access
        );
        assert!(
            post_access & READ_CONTROL.0 == READ_CONTROL.0,
            "expected READ_CONTROL after grant, got 0x{:08X}",
            post_access
        );
        assert!(
            post_access & FILE_WRITE_DATA.0 == 0,
            "expected no FILE_WRITE_DATA after grant, got 0x{:08X}",
            post_access
        );
        Ok(())
    }
}
