//! The watcher's identity and directories, resolved from the environment.

use std::path::{Path, PathBuf};
use std::time::Duration;

use aws_workload_credentials_provider_common::refresh_executor::MAX_STARTUP_HOLD;

use log::warn;

use aws_workload_credentials_provider_common::config::watcher_config::WATCHER_CONFIG_FILE_NAME;
use aws_workload_credentials_provider_common::config::{
    validate_watcher_directories, validate_watcher_id, ValidationErrors,
    DEFAULT_WATCHER_CONFIG_DIR, DEFAULT_WATCHER_REQUESTS_DIR,
};
use aws_workload_credentials_provider_common::filesystem::FileSystem;
use aws_workload_credentials_provider_common::watcher_request::inbox_path;

use crate::error::{InboxCheckError, StartupError};

/// The watcher's sibling of `inbox/`. Watcher implementation detail: the ACM
/// provider never uses it.
const WATCHER_PENDING_SUBDIR: &str = "pending";
const WATCHER_OUTBOX_SUBDIR: &str = "outbox";

/// Identity of the watcher this process is.
pub const WATCHER_ID_VAR: &str = "WCP_WATCHER_ID";

/// Overrides the configuration root. See [`WATCHER_ID_VAR`].
pub const CONFIG_DIR_VAR: &str = "WCP_WATCHER_CONFIG_DIR";

/// Overrides the request root. See [`WATCHER_ID_VAR`].
pub const REQUESTS_DIR_VAR: &str = "WCP_WATCHER_REQUESTS_DIR";

/// Overrides the startup hold window, in milliseconds. Default: 30 seconds
///
/// Absent, empty, unparseable or out of range never fails startup — the value
/// is warned about and the default or the clamped bound is used instead.
pub const STARTUP_HOLD_MS_VAR: &str = "WCP_WATCHER_STARTUP_HOLD_MS";

/// Smallest accepted [`STARTUP_HOLD_MS_VAR`]: release held requests
/// immediately, with no startup window at all.
pub const MIN_STARTUP_HOLD: Duration = Duration::from_millis(0);

/// Where this watcher reads its configuration and its requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatcherEnv {
    watcher_id: String,
    config_dir: PathBuf,
    requests_dir: PathBuf,
    startup_hold: Duration,
}

impl WatcherEnv {
    /// Resolves identity and directories through `lookup`.
    ///
    /// Takes a lookup function rather than reading the process environment
    /// directly so that tests never mutate a process-global that the test
    /// harness's other threads are reading at the same time.
    pub fn resolve(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, StartupError> {
        // The identity is required. Guessing it wrong means loading another
        // watcher's configuration and reloading another watcher's
        // certificates, so there is no safe default to fall back to.
        let watcher_id = match lookup(WATCHER_ID_VAR) {
            Some(id) if !id.trim().is_empty() => id,
            _ => {
                return Err(StartupError::MissingWatcherId {
                    var: WATCHER_ID_VAR,
                })
            }
        };

        // Validated BEFORE it is joined into a path, with the ACM provider's
        // own rule: a single path segment, no separators, no `.`/`..`. This is
        // the only traversal guard on the joins in `config_file` and the
        // request directories below.
        validate_watcher_id(WATCHER_ID_VAR, &watcher_id).map_err(|source| {
            StartupError::InvalidEnvValue {
                var: WATCHER_ID_VAR,
                source,
            }
        })?;

        let config_dir = resolve_dir(&lookup, CONFIG_DIR_VAR, DEFAULT_WATCHER_CONFIG_DIR);
        let requests_dir = resolve_dir(&lookup, REQUESTS_DIR_VAR, DEFAULT_WATCHER_REQUESTS_DIR);

        // Resolved here rather than read where it is used, for the same reason
        // the directories are: every `WCP_WATCHER_*` value goes through this
        // one `lookup`, so the loop's tests cannot be perturbed by the variable
        // happening to be set in a developer's shell, and `run()` keeps its
        // signature.
        let startup_hold = resolve_startup_hold(&lookup);

        Ok(Self {
            watcher_id,
            config_dir,
            requests_dir,
            startup_hold,
        })
    }

    /// Resolves from the real process environment.
    pub fn from_process_env() -> Result<Self, StartupError> {
        Self::resolve(|var| std::env::var(var).ok())
    }

    pub fn watcher_id(&self) -> &str {
        &self.watcher_id
    }

    pub fn config_dir(&self) -> &Path {
        &self.config_dir
    }

    pub fn requests_dir(&self) -> &Path {
        &self.requests_dir
    }

    /// How long after startup requests are held instead of run.
    ///
    /// [`crate::run::STARTUP_HOLD_WINDOW`] unless [`STARTUP_HOLD_MS_VAR`]
    /// overrides it.
    pub fn startup_hold_window(&self) -> Duration {
        self.startup_hold
    }

    /// `<config_dir>/<watcher_id>/watcher.config.toml`, the layout the ACM
    /// provider's generator writes.
    pub fn config_file(&self) -> PathBuf {
        self.config_dir
            .join(&self.watcher_id)
            .join(WATCHER_CONFIG_FILE_NAME)
    }

    /// `<requests_dir>/<watcher_id>`, the parent of `inbox/`, `pending/` and
    /// `outbox/`.
    pub fn watcher_requests_dir(&self) -> PathBuf {
        self.requests_dir.join(&self.watcher_id)
    }

    /// `<requests_dir>/<watcher_id>/inbox`, the only directory the ACM
    /// provider writes requests into.
    ///
    /// Created by the watcher at startup if missing.
    pub fn inbox_dir(&self) -> PathBuf {
        inbox_path(&self.requests_dir, &self.watcher_id)
    }

    /// `<requests_dir>/<watcher_id>/outbox`, where the watcher writes status
    /// records for WCP to consume.
    ///
    /// Created and validated by the watcher at startup. The ACM provider reads
    /// and deletes records in this shared directory.
    pub fn outbox_dir(&self) -> PathBuf {
        self.watcher_requests_dir().join(WATCHER_OUTBOX_SUBDIR)
    }

    /// `<requests_dir>/<watcher_id>/pending`, where the watcher keeps the
    /// requests it has claimed from `inbox/` until their reload completes.
    ///
    /// Created by the watcher at startup if missing. Same parent as
    /// [`WatcherEnv::inbox_dir`], so a claim is a rename within one
    /// filesystem.
    pub fn pending_dir(&self) -> PathBuf {
        self.watcher_requests_dir().join(WATCHER_PENDING_SUBDIR)
    }

    /// The startup directory check on both roots.
    ///
    /// Logs each distinct warning from the check with `warn!`, once, and
    /// returns the logged messages in order. On Windows, a mount mode that
    /// cannot be read passes with one warning per directory. This is the only
    /// caller that logs them: [`WatcherEnv::verify_inbox`] repeats the check
    /// on every scan and drops them, so a periodic scan does not log the same
    /// warning again. Call it after the logger is initialized.
    pub fn verify_roots_present(
        &self,
        filesystem: &impl FileSystem,
    ) -> Result<Vec<String>, StartupError> {
        let warnings = self
            .check_roots(filesystem)
            .map_err(|source| StartupError::DirectoriesInvalid { source })?;

        let mut logged: Vec<String> = Vec::new();
        for warning in warnings {
            if !logged.contains(&warning) {
                warn!("{warning}");
                logged.push(warning);
            }
        }
        Ok(logged)
    }

    /// The shared directory check on both roots, as [`ValidationErrors`].
    ///
    /// Startup ([`WatcherEnv::verify_roots_present`]) and every scan
    /// ([`WatcherEnv::verify_inbox`]) both go through this, so the two cannot
    /// drift apart. Returns the check's warnings without logging them; each
    /// caller decides whether to log.
    fn check_roots(&self, filesystem: &impl FileSystem) -> Result<Vec<String>, ValidationErrors> {
        // Lossless: `resolve_dir` builds both paths from `String`s.
        validate_watcher_directories(
            filesystem,
            // Watcher validates that its config is mounted read-only
            true,
            CONFIG_DIR_VAR,
            Some(&self.config_dir.to_string_lossy()),
            REQUESTS_DIR_VAR,
            Some(&self.requests_dir.to_string_lossy()),
        )
        .map(|directories| directories.warnings)
        .map_err(ValidationErrors::from_vec)
    }

    /// The check that runs before every scan of the inbox directory, and
    /// before every attempt to re-establish its watch.
    ///
    /// The root check startup runs, then [`WatcherEnv::verify_inbox_leaf`]
    /// and [`WatcherEnv::verify_pending_leaf`]: a scan claims files from one
    /// into the other, so both must be the directories they are named as.
    ///
    /// The root check's warnings are dropped here.
    /// [`WatcherEnv::verify_roots_present`] logged them at startup, and the
    /// real filesystem reports the same unreadable mount mode on every scan,
    /// so logging them here would repeat the same lines every scan.
    pub fn verify_inbox(&self, filesystem: &impl FileSystem) -> Result<(), InboxCheckError> {
        let _logged_at_startup = self
            .check_roots(filesystem)
            .map_err(|source| InboxCheckError::Roots { source })?;
        self.verify_inbox_leaf(filesystem)?;
        self.verify_pending_leaf(filesystem)
    }

    /// The same checks on `<requests_dir>/<watcher_id>`, so that creating
    /// `inbox/` or `pending/` in it cannot follow a symlink out of the
    /// requests root. See [`check_leaf`].
    pub fn verify_watcher_requests_dir(
        &self,
        filesystem: &impl FileSystem,
    ) -> Result<(), InboxCheckError> {
        check_leaf(filesystem, self.watcher_requests_dir())
    }

    /// The checks on `<requests_dir>/<watcher_id>/inbox` itself, which the
    /// root check cannot see. See [`check_leaf`].
    pub fn verify_inbox_leaf(&self, filesystem: &impl FileSystem) -> Result<(), InboxCheckError> {
        check_leaf(filesystem, self.inbox_dir())
    }

    /// The same checks on `<requests_dir>/<watcher_id>/pending`.
    pub fn verify_pending_leaf(&self, filesystem: &impl FileSystem) -> Result<(), InboxCheckError> {
        check_leaf(filesystem, self.pending_dir())
    }

    /// The checks on `<requests_dir>/<watcher_id>/outbox`, which the watcher
    /// writes and the ACM provider consumes.
    pub fn verify_outbox_leaf(&self, filesystem: &impl FileSystem) -> Result<(), InboxCheckError> {
        check_leaf(filesystem, self.outbox_dir())
    }
}

/// Checks `<requests_dir>/<watcher_id>` or one `<watcher_id>/<subdir>`
/// directory under it:
///
/// - it resolves to itself. The requests root is already canonical, so this
///   also proves no component below the root is a symlink.
/// - it is a directory.
fn check_leaf(filesystem: &impl FileSystem, path: PathBuf) -> Result<(), InboxCheckError> {
    match filesystem.canonicalize(&path) {
        Ok(resolved) if resolved == path => {}
        Ok(resolved) => return Err(InboxCheckError::NotCanonical { path, resolved }),
        Err(source) => return Err(InboxCheckError::Unresolvable { path, source }),
    }

    if !filesystem.is_dir(&path) {
        return Err(InboxCheckError::NotADirectory { path });
    }

    Ok(())
}

/// What the event loop checks before it lists the inbox directory or
/// re-establishes the watch on it.
///
/// A seam so that the loop's tests can script pass and fail sequences.
/// Production uses [`FileSystemValidator`] over the real filesystem.
pub trait InboxValidator {
    fn validate(&self, env: &WatcherEnv) -> Result<(), InboxCheckError>;
}

/// [`WatcherEnv::verify_inbox`] against `F`.
pub struct FileSystemValidator<'a, F>(pub &'a F);

impl<F: FileSystem> InboxValidator for FileSystemValidator<'_, F> {
    fn validate(&self, env: &WatcherEnv) -> Result<(), InboxCheckError> {
        env.verify_inbox(self.0)
    }
}

/// Reads one directory override, or falls back to the landed default.
///
/// The defaults are the cfg-split constants in `common`, so Linux gets
/// `/shared/wcp-watchers/...` and Windows `C:\shared\wcp-watchers\...` with no
/// platform code here.
///
/// This function reads the override from the environment
/// (or takes the default) and returns it as a `PathBuf` unchanged —
///  it does no validation.
fn resolve_dir(
    lookup: &impl Fn(&str) -> Option<String>,
    var: &'static str,
    default: &str,
) -> PathBuf {
    match lookup(var) {
        Some(value) if !value.trim().is_empty() => PathBuf::from(value),
        _ => PathBuf::from(default),
    }
}

/// Reads [`STARTUP_HOLD_MS_VAR`], or falls back to the production default.
///
/// Never fails: a bad value is a warning and the default, an out-of-range
/// value is a warning and the nearest bound.
fn resolve_startup_hold(lookup: &impl Fn(&str) -> Option<String>) -> Duration {
    let default = crate::run::STARTUP_HOLD_WINDOW;

    let Some(raw) = lookup(STARTUP_HOLD_MS_VAR) else {
        return default;
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return default;
    }

    // `u64` milliseconds, so a negative or fractional value is unparseable and
    // takes the warn-and-default path rather than silently becoming zero.
    let Ok(millis) = trimmed.parse::<u64>() else {
        warn!(
            "Ignoring {}='{}': expected a whole number of milliseconds. Using {:?}.",
            STARTUP_HOLD_MS_VAR, raw, default
        );
        return default;
    };

    let requested = Duration::from_millis(millis);
    if requested < MIN_STARTUP_HOLD || requested > MAX_STARTUP_HOLD {
        let clamped = requested.clamp(MIN_STARTUP_HOLD, MAX_STARTUP_HOLD);
        warn!(
            "{}={:?} is outside [{:?}, {:?}]; using {:?}.",
            STARTUP_HOLD_MS_VAR, requested, MIN_STARTUP_HOLD, MAX_STARTUP_HOLD, clamped
        );
        return clamped;
    }

    requested
}

/// Constructors for the other modules' tests.
///
/// Lives here rather than in each test module so that every test resolves its
/// environment through [`WatcherEnv::resolve`], the same path production takes,
/// instead of building the struct's private fields directly.
#[cfg(test)]
pub mod tests_support {
    use super::*;

    use std::io;

    use aws_workload_credentials_provider_common::filesystem::RealFileSystem;
    use aws_workload_credentials_provider_common::fs_permissions::PathPermission;

    /// The valid watcher identity every in-crate unit test uses.
    ///
    /// Shared so a test's identity reads as an identity rather than as a
    /// plausible-looking service name. The `env`, `main` and `run` tests
    /// use it; `tests/e2e_startup.rs` keeps its own copy, because an
    /// integration test is a separate compilation unit and cannot see a
    /// `#[cfg(test)]` item.
    pub const TEST_WATCHER_ID: &str = "watcher_id_1";

    /// The real filesystem, except that the config root it was built with
    /// reports a read-only mount.
    ///
    /// Tests put both roots under one read-write temp directory, while
    /// [`WatcherEnv::verify_roots_present`] requires the config root to be on
    /// a read-only mount. Only the mount mode of that one exact path is faked:
    /// existence, `is_dir`, canonicalization, the requests root's mount mode
    /// and every read and write still go to the real disk, so the rest of the
    /// directory check runs for real.
    ///
    /// `#[cfg(test)]`, like this whole module: it is compiled into the unit
    /// test harness only and never into the `wcp-watcher` binary.
    pub struct ReadOnlyConfigFileSystem {
        real: RealFileSystem,
        config_dir: PathBuf,
    }

    impl ReadOnlyConfigFileSystem {
        pub fn new(config_dir: &Path) -> Self {
            Self {
                real: RealFileSystem,
                config_dir: config_dir.to_path_buf(),
            }
        }

        /// Fakes a read-only mount for `env`'s config root.
        pub fn for_env(env: &WatcherEnv) -> Self {
            Self::new(env.config_dir())
        }
    }

    impl FileSystem for ReadOnlyConfigFileSystem {
        fn exists(&self, path: &Path) -> bool {
            self.real.exists(path)
        }

        fn is_dir(&self, path: &Path) -> bool {
            self.real.is_dir(path)
        }

        fn read_to_string(&self, path: &Path) -> io::Result<String> {
            self.real.read_to_string(path)
        }

        fn parent(&self, path: &Path) -> Option<PathBuf> {
            self.real.parent(path)
        }

        fn write_string_to_temp(&self, parent_dir: &Path, content: &str) -> io::Result<PathBuf> {
            self.real.write_string_to_temp(parent_dir, content)
        }

        fn atomic_rename(&self, source_path: &Path, dest_path: &Path) -> io::Result<()> {
            self.real.atomic_rename(source_path, dest_path)
        }

        fn remove_file(&self, path: &Path) -> io::Result<()> {
            self.real.remove_file(path)
        }

        fn grant_permissions(&self, path: &Path, permission: &PathPermission) -> io::Result<()> {
            self.real.grant_permissions(path, permission)
        }

        fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
            self.real.canonicalize(path)
        }

        fn is_read_only_mount(&self, path: &Path) -> io::Result<bool> {
            // Real lookup first, so a vanished root still fails as
            // `WatcherDirectoryMountUnknown` (and Windows still reports
            // `Unsupported`, the gap common accepts with a warning).
            let real = self.real.is_read_only_mount(path)?;
            Ok(real || path == self.config_dir)
        }
    }

    /// Canonicalizes a temp root so every path derived from it passes the
    /// directory check's `canonicalize(dir) == dir` rule.
    ///
    /// A symlinked `TMPDIR` would otherwise fail the caller for a reason
    /// unrelated to what it covers.
    #[cfg(unix)]
    pub fn canonical_root(path: &Path) -> PathBuf {
        std::fs::canonicalize(path).expect("the temp root should canonicalize")
    }

    /// Canonicalizes a temp root, stripping the Windows verbatim prefix.
    ///
    /// `std::fs::canonicalize` returns an extended-length `\\?\` path on
    /// Windows, while the directory check canonicalizes through `dunce`, which
    /// yields the non-verbatim form for an ordinary local-drive path like the
    /// CI temp directory. Stripping also removes the `?`, which the Windows
    /// reload-command character class forbids.
    #[cfg(windows)]
    pub fn canonical_root(path: &Path) -> PathBuf {
        let canonical = std::fs::canonicalize(path).expect("the temp root should canonicalize");
        let stripped = canonical
            .to_str()
            .and_then(|s| s.strip_prefix(r"\\?\"))
            .map(PathBuf::from);
        stripped.unwrap_or(canonical)
    }

    /// A `WatcherEnv` whose config and request roots are both `root`.
    ///
    /// `root` must exist. It is canonicalized with [`canonical_root`], so the
    /// roots match the directory check's canonical form on every platform.
    /// One shared root is a `ConflictingPaths` refusal in
    /// [`WatcherEnv::verify_roots_present`]; tests that run it use
    /// [`split_env`].
    pub fn env_at(root: &Path, watcher_id: &str) -> WatcherEnv {
        let root = canonical_root(root);
        let root = root.to_string_lossy().into_owned();
        WatcherEnv::resolve(|var| match var {
            WATCHER_ID_VAR => Some(watcher_id.to_string()),
            CONFIG_DIR_VAR | REQUESTS_DIR_VAR => Some(root.clone()),
            _ => None,
        })
        .expect("a temp-directory environment should resolve")
    }

    /// A `WatcherEnv` with separate `<root>/config` and `<root>/requests`
    /// roots, both created, and the startup hold window overridden when
    /// `hold_ms` is given.
    ///
    /// The layout [`WatcherEnv::verify_inbox`] accepts when paired with
    /// [`ReadOnlyConfigFileSystem::for_env`], for tests that run the real
    /// per-scan check. `<watcher_id>/inbox` and `<watcher_id>/pending` are
    /// not created.
    pub fn split_env(root: &Path, watcher_id: &str, hold_ms: Option<u64>) -> WatcherEnv {
        let root = canonical_root(root);
        let config = root.join("config");
        let requests = root.join("requests");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::create_dir_all(&requests).unwrap();

        let config = config.to_string_lossy().into_owned();
        let requests = requests.to_string_lossy().into_owned();
        let hold = hold_ms.map(|ms| ms.to_string());
        WatcherEnv::resolve(|var| match var {
            WATCHER_ID_VAR => Some(watcher_id.to_string()),
            CONFIG_DIR_VAR => Some(config.clone()),
            REQUESTS_DIR_VAR => Some(requests.clone()),
            STARTUP_HOLD_MS_VAR => hold.clone(),
            _ => None,
        })
        .expect("a temp-directory environment should resolve")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tests_support::TEST_WATCHER_ID;

    use aws_workload_credentials_provider_common::config::{ValidationError, ValidationErrorCode};
    use aws_workload_credentials_provider_common::filesystem::{MockFileSystem, RealFileSystem};
    use tempfile::TempDir;

    /// Builds a lookup over a fixed list of pairs.
    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let owned: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |var: &str| {
            owned
                .iter()
                .find(|(k, _)| k.as_str() == var)
                .map(|(_, v)| v.clone())
        }
    }

    fn resolved(watcher_id: &str) -> Result<WatcherEnv, StartupError> {
        WatcherEnv::resolve(env(&[(WATCHER_ID_VAR, watcher_id)]))
    }

    #[test]
    fn missing_watcher_id_is_refused() {
        let err = WatcherEnv::resolve(|_| None).unwrap_err();
        assert!(matches!(err, StartupError::MissingWatcherId { .. }));
        assert!(err.to_string().contains(WATCHER_ID_VAR), "{err}");
    }

    #[test]
    fn empty_watcher_id_is_refused() {
        let err = resolved("   ").unwrap_err();
        assert!(matches!(err, StartupError::MissingWatcherId { .. }));
    }

    #[test]
    fn traversal_watcher_id_is_refused() {
        let err = resolved("../escape").unwrap_err();
        assert!(matches!(err, StartupError::InvalidEnvValue { .. }));
    }

    #[test]
    fn separator_in_watcher_id_is_refused() {
        let err = resolved("nginx/inner").unwrap_err();
        assert!(matches!(err, StartupError::InvalidEnvValue { .. }));
    }

    #[test]
    fn overlong_watcher_id_is_refused() {
        let err = resolved(&"a".repeat(65)).unwrap_err();
        assert!(matches!(err, StartupError::InvalidEnvValue { .. }));
    }

    /// Without overrides, the roots are common's defaults, the same constants
    /// the ACM provider provisions and validates.
    #[test]
    fn defaults_are_commons_constants() {
        use aws_workload_credentials_provider_common::config as common;

        let resolved = resolved(TEST_WATCHER_ID).unwrap();
        assert_eq!(
            resolved.config_dir(),
            Path::new(common::DEFAULT_WATCHER_CONFIG_DIR)
        );
        assert_eq!(
            resolved.requests_dir(),
            Path::new(common::DEFAULT_WATCHER_REQUESTS_DIR)
        );
    }

    #[test]
    fn env_overrides_are_honoured() {
        #[cfg(unix)]
        let (config, requests) = ("/mnt/config", "/mnt/requests");
        #[cfg(windows)]
        let (config, requests) = (r"C:\mnt\config", r"C:\mnt\requests");

        let resolved = WatcherEnv::resolve(env(&[
            (WATCHER_ID_VAR, TEST_WATCHER_ID),
            (CONFIG_DIR_VAR, config),
            (REQUESTS_DIR_VAR, requests),
        ]))
        .unwrap();

        assert_eq!(resolved.config_dir(), Path::new(config));
        assert_eq!(resolved.requests_dir(), Path::new(requests));
    }

    // -- directory refusals: `resolve` only reads the paths; the directory
    // check in `verify_roots_present` is what refuses a bad one. Each test
    // keeps the other root a real canonical directory, so exactly one error
    // is expected. --

    /// Unwraps `DirectoriesInvalid`, panicking with the actual error otherwise.
    fn directory_errors(err: StartupError) -> Vec<ValidationError> {
        match err {
            StartupError::DirectoriesInvalid { source } => source.errors,
            other => panic!("expected StartupError::DirectoriesInvalid, got {other:?}"),
        }
    }

    /// `err` is `DirectoriesInvalid` holding exactly one error, with this
    /// field and code.
    fn assert_single_directory_error(err: StartupError, field: &str, code: ValidationErrorCode) {
        let errors = directory_errors(err);
        assert_eq!(errors.len(), 1, "expected one directory error: {errors:?}");
        assert_eq!(errors[0].field, field, "{errors:?}");
        assert_eq!(errors[0].code, code, "{errors:?}");
    }

    /// Resolves with both directory overrides; `resolve` must accept any shape.
    fn resolve_with_dirs(config: &Path, requests: &Path) -> WatcherEnv {
        WatcherEnv::resolve(env(&[
            (WATCHER_ID_VAR, TEST_WATCHER_ID),
            (CONFIG_DIR_VAR, &config.to_string_lossy()),
            (REQUESTS_DIR_VAR, &requests.to_string_lossy()),
        ]))
        .expect("resolve no longer checks directory shape")
    }

    /// Creates `<root>/<name>` and returns it.
    fn real_dir(root: &Path, name: &str) -> PathBuf {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn relative_config_dir_is_refused() {
        let tmp = TempDir::new().unwrap();
        let root = tests_support::canonical_root(tmp.path());
        let requests = real_dir(&root, "requests");

        let err = resolve_with_dirs(Path::new("relative/path"), &requests)
            .verify_roots_present(&RealFileSystem)
            .expect_err("a relative config root must be refused");

        // Rejected as relative before the filesystem is touched.
        assert_single_directory_error(err, CONFIG_DIR_VAR, ValidationErrorCode::RelativePath);
    }

    #[test]
    fn traversal_requests_dir_is_refused() {
        let tmp = TempDir::new().unwrap();
        let root = tests_support::canonical_root(tmp.path());
        real_dir(&root, "a");
        real_dir(&root, "b");
        let config = real_dir(&root, "config");
        // Joined component by component so the `..` survives on both
        // platforms, and both ends exist so the refusal is the traversal.
        let traversal = root.join("a").join("..").join("b");

        let err = resolve_with_dirs(&config, &traversal)
            .verify_roots_present(&RealFileSystem)
            .expect_err("a request root with '..' must be refused");

        assert_single_directory_error(err, REQUESTS_DIR_VAR, ValidationErrorCode::UnsafePath);
    }

    #[test]
    fn paths_are_assembled_per_the_landed_layout() {
        let resolved = resolved(TEST_WATCHER_ID).unwrap();

        assert_eq!(
            resolved.config_file(),
            Path::new(DEFAULT_WATCHER_CONFIG_DIR)
                .join(TEST_WATCHER_ID)
                .join(WATCHER_CONFIG_FILE_NAME)
        );
        assert_eq!(
            resolved.inbox_dir(),
            Path::new(DEFAULT_WATCHER_REQUESTS_DIR)
                .join(TEST_WATCHER_ID)
                .join("inbox")
        );
        assert_eq!(
            resolved.pending_dir(),
            Path::new(DEFAULT_WATCHER_REQUESTS_DIR)
                .join(TEST_WATCHER_ID)
                .join("pending")
        );
        assert_eq!(
            resolved.outbox_dir(),
            Path::new(DEFAULT_WATCHER_REQUESTS_DIR)
                .join(TEST_WATCHER_ID)
                .join("outbox")
        );
    }

    /// `inbox/` and `pending/` are siblings, so a claim is a rename within
    /// one directory tree.
    #[test]
    fn the_inbox_and_pending_directories_share_a_parent() {
        let resolved = resolved(TEST_WATCHER_ID).unwrap();

        assert_eq!(
            resolved.inbox_dir().parent(),
            Some(resolved.watcher_requests_dir().as_path())
        );
        assert_eq!(
            resolved.pending_dir().parent(),
            Some(resolved.watcher_requests_dir().as_path())
        );
    }

    // -- the startup hold window override --

    fn hold(value: &str) -> Duration {
        WatcherEnv::resolve(env(&[
            (WATCHER_ID_VAR, TEST_WATCHER_ID),
            (STARTUP_HOLD_MS_VAR, value),
        ]))
        .unwrap()
        .startup_hold_window()
    }

    /// The production default, which is what every deployment gets: the
    /// variable exists for tests and must change nothing when it is unset.
    #[test]
    fn startup_hold_defaults_to_the_production_window() {
        assert_eq!(
            resolved(TEST_WATCHER_ID).unwrap().startup_hold_window(),
            crate::run::STARTUP_HOLD_WINDOW
        );
    }

    #[test]
    fn startup_hold_is_read_as_milliseconds() {
        assert_eq!(hold("250"), Duration::from_millis(250));
    }

    /// Zero is a legitimate value — release immediately — and not a bad value
    /// to be replaced by the default.
    #[test]
    fn startup_hold_accepts_zero() {
        assert_eq!(hold("0"), MIN_STARTUP_HOLD);
        assert_eq!(hold("0"), Duration::ZERO);
    }

    #[test]
    fn unparseable_startup_hold_falls_back_to_the_default() {
        for value in ["abc", "-5", "  ", "1.5", "250ms", ""] {
            assert_eq!(
                hold(value),
                crate::run::STARTUP_HOLD_WINDOW,
                "'{value}' should have been ignored"
            );
        }
    }

    #[test]
    fn overlong_startup_hold_is_clamped() {
        let over = MAX_STARTUP_HOLD.as_millis() as u64 + 1;
        assert_eq!(hold(&over.to_string()), MAX_STARTUP_HOLD);
        assert_eq!(hold(&u64::MAX.to_string()), MAX_STARTUP_HOLD);
    }

    /// The watcher-startup part of the symlink-free root check.
    #[cfg(unix)]
    #[test]
    fn symlinked_requests_dir_is_refused_at_startup() {
        let tmp = TempDir::new().unwrap();
        let root = tests_support::canonical_root(tmp.path());
        std::fs::create_dir(root.join("real")).unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(root.join("real"), &link).unwrap();
        let config = real_dir(&root, "config");

        let err = resolve_with_dirs(&config, &link)
            .verify_roots_present(&RealFileSystem)
            .expect_err("a symlinked request root must be refused");

        assert_single_directory_error(err, REQUESTS_DIR_VAR, ValidationErrorCode::UnsafePath);
    }

    /// Enforcement is not conditional on the directory being an override: a
    /// symlinked *default* mount is refused too.
    #[cfg(unix)]
    #[test]
    fn symlinked_config_dir_is_refused_at_startup() {
        let tmp = TempDir::new().unwrap();
        let root = tests_support::canonical_root(tmp.path());
        std::fs::create_dir(root.join("real")).unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(root.join("real"), &link).unwrap();
        let requests = real_dir(&root, "requests");

        let err = resolve_with_dirs(&link, &requests)
            .verify_roots_present(&RealFileSystem)
            .expect_err("a symlinked config root must be refused");

        assert_single_directory_error(err, CONFIG_DIR_VAR, ValidationErrorCode::UnsafePath);
    }

    /// The limitation, pinned: a root that is not mounted yet cannot be
    /// canonicalized, so `resolve` accepts it. `verify_roots_present` is what
    /// refuses it a moment later — see the test below.
    #[test]
    fn not_yet_mounted_requests_dir_is_accepted_by_resolve() {
        use tempfile::TempDir;

        let tmp = TempDir::new().unwrap();
        let absent = tmp.path().join("not-mounted-yet");

        WatcherEnv::resolve(env(&[
            (WATCHER_ID_VAR, TEST_WATCHER_ID),
            (REQUESTS_DIR_VAR, &absent.to_string_lossy()),
        ]))
        .expect("a not-yet-mounted volume must not fail the shape check");
    }

    // -- verify_roots_present: where the watcher-side check is guaranteed --

    /// Two distinct real directories pass when the config root is read-only
    /// and the requests root read-write.
    ///
    /// Both live under one read-write temp directory, so the config root is
    /// faked read-only by [`tests_support::ReadOnlyConfigFileSystem`]; every
    /// other part of the check runs against the real disk. The test below pins
    /// that the real filesystem refuses this same layout.
    #[test]
    fn verify_roots_present_accepts_two_real_directories() {
        let tmp = TempDir::new().unwrap();
        let root = tests_support::canonical_root(tmp.path());
        let config = real_dir(&root, "config");
        let requests = real_dir(&root, "requests");
        let env = resolve_with_dirs(&config, &requests);

        env.verify_roots_present(&tests_support::ReadOnlyConfigFileSystem::for_env(&env))
            .expect("a read-only config root and a writable requests root must pass");
    }

    /// The production filesystem enforces the read-only config rule: the
    /// layout the test above accepts through the fake is refused for real.
    ///
    /// `cfg(unix)`: on Windows the real mount-mode lookup is `Unsupported`,
    /// which the check accepts with a warning.
    #[cfg(unix)]
    #[test]
    fn verify_roots_present_refuses_a_writable_real_config_mount() {
        let tmp = TempDir::new().unwrap();
        let root = tests_support::canonical_root(tmp.path());
        let config = real_dir(&root, "config");
        let requests = real_dir(&root, "requests");

        let err = resolve_with_dirs(&config, &requests)
            .verify_roots_present(&RealFileSystem)
            .expect_err("a config root on a read-write mount must be refused");

        assert_single_directory_error(
            err,
            CONFIG_DIR_VAR,
            ValidationErrorCode::WatcherDirectoryWrongMountMode,
        );
    }

    // -- mount mode, through `MockFileSystem`: both modes of both roots,
    // without needing a real read-only mount. --

    /// Absolute paths the mock registers; it never touches the disk.
    #[cfg(unix)]
    const MOCK_CONFIG: &str = "/mnt/config";
    #[cfg(unix)]
    const MOCK_REQUESTS: &str = "/mnt/requests";
    #[cfg(windows)]
    const MOCK_CONFIG: &str = r"C:\mnt\config";
    #[cfg(windows)]
    const MOCK_REQUESTS: &str = r"C:\mnt\requests";

    fn mock_env() -> WatcherEnv {
        resolve_with_dirs(Path::new(MOCK_CONFIG), Path::new(MOCK_REQUESTS))
    }

    #[test]
    fn verify_roots_present_accepts_read_only_config_and_writable_requests() {
        let fs = MockFileSystem::new()
            .with_read_only_dir(MOCK_CONFIG)
            .with_dir(MOCK_REQUESTS);

        let logged = mock_env()
            .verify_roots_present(&fs)
            .expect("read-only config and read-write requests must pass");
        assert!(logged.is_empty(), "verified modes warn nothing: {logged:?}");
    }

    /// A mock that mimics `RealFileSystem` on Windows: the mount-mode lookup
    /// of both roots fails with `Unsupported`. The inbox and pending leaves
    /// exist, so `verify_inbox` reaches its leaf checks.
    fn unsupported_mount_mode_fs(env: &WatcherEnv) -> MockFileSystem {
        MockFileSystem::new()
            .with_dir_mount_mode_error(MOCK_CONFIG, std::io::ErrorKind::Unsupported)
            .with_dir_mount_mode_error(MOCK_REQUESTS, std::io::ErrorKind::Unsupported)
            .with_dir(&env.inbox_dir().to_string_lossy())
            .with_dir(&env.pending_dir().to_string_lossy())
    }

    /// The Windows gap: startup accepts an unreadable mount mode and logs one
    /// warning per root; the per-scan check accepts it and logs nothing.
    #[cfg(windows)]
    #[test]
    fn unsupported_mount_mode_is_warned_once_at_startup_on_windows() {
        let env = mock_env();
        let fs = unsupported_mount_mode_fs(&env);

        let logged = env
            .verify_roots_present(&fs)
            .expect("Windows accepts an unreadable mount mode");
        assert_eq!(logged.len(), 2, "{logged:?}");
        assert!(logged[0].contains(CONFIG_DIR_VAR), "{logged:?}");
        assert!(logged[1].contains(REQUESTS_DIR_VAR), "{logged:?}");

        // Returns `()`: the scan check has no warnings to surface.
        env.verify_inbox(&fs)
            .expect("every scan accepts the same unreadable mount mode");
    }

    /// Off Windows, `Unsupported` is no gap: both roots fail closed.
    #[cfg(unix)]
    #[test]
    fn unsupported_mount_mode_is_refused_off_windows() {
        let env = mock_env();
        let fs = unsupported_mount_mode_fs(&env);

        let errors = directory_errors(
            env.verify_roots_present(&fs)
                .expect_err("an unreadable mount mode must be refused"),
        );
        let fields: Vec<_> = errors.iter().map(|e| e.field.as_str()).collect();
        assert_eq!(fields, [CONFIG_DIR_VAR, REQUESTS_DIR_VAR], "{errors:?}");
        for error in &errors {
            assert_eq!(
                error.code,
                ValidationErrorCode::WatcherDirectoryMountUnknown,
                "{errors:?}"
            );
        }

        let err = env
            .verify_inbox(&fs)
            .expect_err("an unreadable mount mode must fail the scan check");
        assert!(matches!(err, InboxCheckError::Roots { .. }), "{err:?}");
    }

    #[test]
    fn verify_roots_present_refuses_a_writable_config_mount() {
        let fs = MockFileSystem::new()
            .with_dir(MOCK_CONFIG)
            .with_dir(MOCK_REQUESTS);

        let err = mock_env()
            .verify_roots_present(&fs)
            .expect_err("a writable config mount must be refused");

        assert_single_directory_error(
            err,
            CONFIG_DIR_VAR,
            ValidationErrorCode::WatcherDirectoryWrongMountMode,
        );
    }

    #[test]
    fn verify_roots_present_refuses_a_read_only_requests_mount() {
        let fs = MockFileSystem::new()
            .with_read_only_dir(MOCK_CONFIG)
            .with_read_only_dir(MOCK_REQUESTS);

        let err = mock_env()
            .verify_roots_present(&fs)
            .expect_err("a read-only requests mount must be refused");

        assert_single_directory_error(
            err,
            REQUESTS_DIR_VAR,
            ValidationErrorCode::WatcherDirectoryWrongMountMode,
        );
    }

    #[test]
    fn verify_roots_present_refuses_an_unknown_mount_mode() {
        let fs = MockFileSystem::new()
            .with_read_only_dir(MOCK_CONFIG)
            .with_dir_mount_mode_unknown(MOCK_REQUESTS);

        let err = mock_env()
            .verify_roots_present(&fs)
            .expect_err("an unreadable mount mode must be refused");

        assert_single_directory_error(
            err,
            REQUESTS_DIR_VAR,
            ValidationErrorCode::WatcherDirectoryMountUnknown,
        );
    }

    /// Every scan enforces the mount modes, not just startup.
    #[test]
    fn verify_inbox_refuses_a_read_only_requests_mount() {
        let fs = MockFileSystem::new()
            .with_read_only_dir(MOCK_CONFIG)
            .with_read_only_dir(MOCK_REQUESTS);

        let err = mock_env()
            .verify_inbox(&fs)
            .expect_err("a read-only requests mount must fail the scan check");

        let InboxCheckError::Roots { source } = err else {
            panic!("expected Roots, got {err:?}");
        };
        assert_eq!(source.errors.len(), 1, "{:?}", source.errors);
        assert_eq!(source.errors[0].field, REQUESTS_DIR_VAR);
        assert_eq!(
            source.errors[0].code,
            ValidationErrorCode::WatcherDirectoryWrongMountMode
        );
    }

    /// The gap `resolve` alone leaves open: an absent root is accepted there
    /// and must be refused here, because `canonicalize` cannot have run on it.
    #[test]
    fn verify_roots_present_refuses_a_missing_root() {
        let tmp = TempDir::new().unwrap();
        let root = tests_support::canonical_root(tmp.path());
        let absent = root.join("not-mounted-yet");

        let err = resolve_with_dirs(&root, &absent)
            .verify_roots_present(&RealFileSystem)
            .expect_err("a missing request root must be refused at startup");

        assert_single_directory_error(
            err,
            REQUESTS_DIR_VAR,
            ValidationErrorCode::WatcherDirectoryNotFound,
        );
    }

    /// `resolve` accepts a relative root; this check refuses it as relative.
    ///
    /// `src` is a relative spelling of a directory that exists: cargo runs a
    /// package's unit tests with the package root as the cwd. So the refusal
    /// is the relative shape, independent of the cwd, not a missing directory.
    #[test]
    fn verify_roots_present_refuses_a_relative_root() {
        let tmp = TempDir::new().unwrap();
        let root = tests_support::canonical_root(tmp.path());
        let config = real_dir(&root, "config");

        let err = resolve_with_dirs(&config, Path::new("src"))
            .verify_roots_present(&RealFileSystem)
            .expect_err("a relative root must be refused");

        assert_single_directory_error(err, REQUESTS_DIR_VAR, ValidationErrorCode::RelativePath);
    }

    /// The symlink check, guaranteed rather than best-effort: the root exists
    /// here, so `canonicalize` runs and the symlink is caught.
    #[cfg(unix)]
    #[test]
    fn verify_roots_present_refuses_a_symlinked_root() {
        let tmp = TempDir::new().unwrap();
        let root = tests_support::canonical_root(tmp.path());
        std::fs::create_dir(root.join("real")).unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(root.join("real"), &link).unwrap();

        // Built directly rather than through `resolve`: this pins that the
        // check does not depend on anything `resolve` does.
        let resolved = WatcherEnv {
            watcher_id: TEST_WATCHER_ID.to_string(),
            config_dir: root.clone(),
            requests_dir: link,
            startup_hold: crate::run::STARTUP_HOLD_WINDOW,
        };

        let err = resolved
            .verify_roots_present(&RealFileSystem)
            .expect_err("a symlinked request root must be refused");

        assert_single_directory_error(err, REQUESTS_DIR_VAR, ValidationErrorCode::UnsafePath);
    }

    // -- the read-only-config test filesystem itself --

    /// `cfg(unix)`: on Windows the real mount-mode lookup, which the fake
    /// calls first, is `Unsupported` for every path.
    #[cfg(unix)]
    #[test]
    fn read_only_config_filesystem_fakes_only_the_config_root() {
        use tests_support::ReadOnlyConfigFileSystem;

        let tmp = TempDir::new().unwrap();
        let root = tests_support::canonical_root(tmp.path());
        let config = real_dir(&root, "config");
        let requests = real_dir(&root, "requests");
        let other = real_dir(&root, "other");
        let missing = root.join("missing");

        let fs = ReadOnlyConfigFileSystem::new(&config);

        assert!(fs.is_read_only_mount(&config).unwrap());
        for path in [&requests, &other] {
            assert_eq!(
                fs.is_read_only_mount(path).unwrap(),
                RealFileSystem.is_read_only_mount(path).unwrap(),
                "a path that is not the config root reports its real mode: {path:?}"
            );
            assert!(!fs.is_read_only_mount(path).unwrap(), "{path:?}");
        }
        assert!(
            fs.is_read_only_mount(&missing).is_err(),
            "a missing path must still fail the mount-mode lookup"
        );

        for path in [&config, &requests, &other, &missing] {
            assert_eq!(fs.is_dir(path), RealFileSystem.is_dir(path), "{path:?}");
            assert_eq!(
                fs.canonicalize(path).ok(),
                RealFileSystem.canonicalize(path).ok(),
                "{path:?}"
            );
        }
    }

    // -- verify_inbox: the per-scan check --

    /// A split-root environment and its read-only-config filesystem, with the
    /// inbox and pending directories created.
    fn inbox_env(tmp: &TempDir) -> (WatcherEnv, tests_support::ReadOnlyConfigFileSystem) {
        let env = tests_support::split_env(tmp.path(), TEST_WATCHER_ID, None);
        std::fs::create_dir_all(env.inbox_dir()).unwrap();
        std::fs::create_dir_all(env.pending_dir()).unwrap();
        let fs = tests_support::ReadOnlyConfigFileSystem::for_env(&env);
        (env, fs)
    }

    #[test]
    fn verify_inbox_refuses_a_missing_pending_directory() {
        let tmp = TempDir::new().unwrap();
        let (env, fs) = inbox_env(&tmp);
        std::fs::remove_dir(env.pending_dir()).unwrap();

        let err = env
            .verify_inbox(&fs)
            .expect_err("a missing pending directory must fail");
        assert!(
            matches!(&err, InboxCheckError::Unresolvable { path, .. } if *path == env.pending_dir()),
            "{err:?}"
        );
    }

    #[test]
    fn verify_inbox_refuses_a_file_in_place_of_the_pending_directory() {
        let tmp = TempDir::new().unwrap();
        let (env, fs) = inbox_env(&tmp);
        std::fs::remove_dir(env.pending_dir()).unwrap();
        std::fs::write(env.pending_dir(), "not a directory").unwrap();

        let err = env.verify_inbox(&fs).expect_err("a file must fail");
        assert!(
            matches!(&err, InboxCheckError::NotADirectory { path } if *path == env.pending_dir()),
            "{err:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn verify_inbox_refuses_a_symlinked_pending_directory() {
        let tmp = TempDir::new().unwrap();
        let (env, fs) = inbox_env(&tmp);
        let elsewhere = env.requests_dir().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::remove_dir(env.pending_dir()).unwrap();
        std::os::unix::fs::symlink(&elsewhere, env.pending_dir()).unwrap();

        let err = env
            .verify_inbox(&fs)
            .expect_err("a symlinked pending directory must fail");
        assert!(
            matches!(&err, InboxCheckError::NotCanonical { resolved, .. } if *resolved == elsewhere),
            "{err:?}"
        );
    }

    #[test]
    fn verify_inbox_accepts_a_real_inbox_directory() {
        let tmp = TempDir::new().unwrap();
        let (env, fs) = inbox_env(&tmp);

        env.verify_inbox(&fs).expect("a real inbox must pass");
        FileSystemValidator(&fs)
            .validate(&env)
            .expect("the production validator is verify_inbox");
    }

    /// The roots are checked first, with the same check startup runs.
    #[cfg(unix)]
    #[test]
    fn verify_inbox_runs_the_root_check() {
        let tmp = TempDir::new().unwrap();
        let (env, _) = inbox_env(&tmp);

        // The real filesystem: the config root is on a read-write mount.
        let err = env
            .verify_inbox(&RealFileSystem)
            .expect_err("a writable config mount must be refused");
        let InboxCheckError::Roots { source } = err else {
            panic!("expected Roots, got {err:?}");
        };
        assert_eq!(source.errors[0].field, CONFIG_DIR_VAR);
        assert_eq!(
            source.errors[0].code,
            ValidationErrorCode::WatcherDirectoryWrongMountMode
        );
    }

    #[test]
    fn verify_inbox_refuses_a_missing_inbox() {
        let tmp = TempDir::new().unwrap();
        let (env, fs) = inbox_env(&tmp);
        std::fs::remove_dir(env.inbox_dir()).unwrap();

        let err = env
            .verify_inbox(&fs)
            .expect_err("a missing inbox must fail");
        assert!(
            matches!(&err, InboxCheckError::Unresolvable { path, .. } if *path == env.inbox_dir()),
            "{err:?}"
        );
    }

    #[test]
    fn verify_inbox_refuses_a_file_in_place_of_the_inbox() {
        let tmp = TempDir::new().unwrap();
        let (env, fs) = inbox_env(&tmp);
        std::fs::remove_dir(env.inbox_dir()).unwrap();
        std::fs::write(env.inbox_dir(), "not a directory").unwrap();

        let err = env.verify_inbox(&fs).expect_err("a file must fail");
        assert!(
            matches!(err, InboxCheckError::NotADirectory { .. }),
            "{err:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn verify_inbox_refuses_a_symlinked_inbox() {
        let tmp = TempDir::new().unwrap();
        let (env, fs) = inbox_env(&tmp);
        let elsewhere = env.requests_dir().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::remove_dir(env.inbox_dir()).unwrap();
        std::os::unix::fs::symlink(&elsewhere, env.inbox_dir()).unwrap();

        let err = env
            .verify_inbox(&fs)
            .expect_err("a symlinked inbox must fail");
        assert!(
            matches!(&err, InboxCheckError::NotCanonical { resolved, .. } if *resolved == elsewhere),
            "{err:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn verify_inbox_refuses_a_symlinked_watcher_directory() {
        let tmp = TempDir::new().unwrap();
        let (env, fs) = inbox_env(&tmp);
        let watcher_dir = env.inbox_dir().parent().unwrap().to_path_buf();
        let moved = env.requests_dir().join("moved");
        std::fs::rename(&watcher_dir, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &watcher_dir).unwrap();

        let err = env
            .verify_inbox(&fs)
            .expect_err("a symlinked <watcher_id> must fail");
        assert!(
            matches!(err, InboxCheckError::NotCanonical { .. }),
            "{err:?}"
        );
    }
}
