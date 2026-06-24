use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwapOption;
use aws_config::profile::ProfileFileCredentialsProvider;
use aws_credential_types::provider::{error::CredentialsError, future, ProvideCredentials};
use aws_credential_types::Credentials;
use aws_runtime::env_config::file::{EnvConfigFileKind, EnvConfigFiles};
use tokio::task::JoinHandle;

/// How often the background task checks for updated credentials on disk.
fn reload_delay() -> Duration {
    #[cfg(debug_assertions)]
    if let Ok(secs) = std::env::var("SMA_CREDENTIALS_RELOAD_SECS") {
        if let Ok(val) = secs.parse() {
            return Duration::from_secs(val);
        }
    }
    Duration::from_secs(5 * 60)
}

/// How long the SDK considers the credentials valid before asking the provider again.
const SDK_CREDENTIALS_TTL: Duration = Duration::from_secs(10 * 60);

/// A credentials provider that reads AWS credentials from a file and
/// automatically reloads them on a configurable interval.
///
/// Enforces a session token gate: credentials without an `aws_session_token`
/// are rejected to prevent use of long-term IAM User credentials.
#[derive(Debug, Clone)]
pub struct FileBasedCredentialsProvider {
    cached: Arc<ArcSwapOption<Credentials>>,
    _reload_handle: Arc<ReloadHandle>,
}

#[derive(Debug)]
struct ReloadHandle(JoinHandle<()>);

impl Drop for ReloadHandle {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl FileBasedCredentialsProvider {
    /// Create a new provider that reads credentials from the given path.
    ///
    /// Attempts an initial load but does not fail if the file is missing or
    /// malformed — the background reload task will pick up valid credentials
    /// when they appear.
    pub async fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let cached = Arc::new(ArcSwapOption::new(None));

        match Self::load_and_validate(&path).await {
            Ok(creds) => {
                cached.store(Some(Arc::new(creds)));
                Self::warn_if_broad_permissions(&path);
                log::info!("Loaded file-based credentials from: {}", path.display());
            }
            Err(e) => {
                log::warn!(
                    "Could not load credentials from {}: {}. \
                     The agent will retry every {} seconds.",
                    path.display(),
                    e,
                    reload_delay().as_secs()
                );
            }
        }

        let reload_cached = cached.clone();
        let handle = tokio::spawn(async move {
            let mut last_modified = Self::file_modified_time(&path);
            let mut interval = tokio::time::interval(reload_delay());
            interval.tick().await; // skip immediate first tick
            loop {
                interval.tick().await;

                let current_modified = Self::file_modified_time(&path);
                if current_modified == last_modified {
                    continue;
                }

                match Self::load_and_validate(&path).await {
                    Ok(creds) => {
                        reload_cached.store(Some(Arc::new(creds)));
                        last_modified = current_modified;
                        Self::warn_if_broad_permissions(&path);
                        log::debug!("Successfully reloaded credentials from {}", path.display());
                    }
                    Err(e) => {
                        log::warn!(
                            "Failed to reload credentials from {}: {}",
                            path.display(),
                            e
                        );
                    }
                }
            }
        });

        Self {
            cached,
            _reload_handle: Arc::new(ReloadHandle(handle)),
        }
    }

    async fn load_and_validate<P: Into<PathBuf>>(path: P) -> Result<Credentials, CredentialsError> {
        let env_config_files = EnvConfigFiles::builder()
            .with_file(EnvConfigFileKind::Credentials, path)
            .build();

        let creds = ProfileFileCredentialsProvider::builder()
            .profile_files(env_config_files)
            .build()
            .provide_credentials()
            .await?;

        if creds.session_token().is_none() {
            return Err(CredentialsError::provider_error(
                "Security Policy Violation: Long-term IAM User credentials are not permitted. \
                 The credentials file must contain temporary credentials with an aws_session_token.",
            ));
        }

        Ok(creds)
    }

    /// Wrap credentials with an SDK expiry so the SDK knows when to ask again.
    fn with_expiry(creds: Credentials) -> Credentials {
        Credentials::new(
            creds.access_key_id(),
            creds.secret_access_key(),
            creds.session_token().map(|s| s.to_string()),
            Some(SystemTime::now() + SDK_CREDENTIALS_TTL),
            "FileBasedCredentialsProvider",
        )
    }

    fn file_modified_time(path: &Path) -> Option<SystemTime> {
        std::fs::metadata(path).and_then(|m| m.modified()).ok()
    }

    #[cfg(unix)]
    fn warn_if_broad_permissions(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(path) {
            let mode = metadata.permissions().mode();
            if mode & 0o077 != 0 {
                log::warn!(
                    "Credentials file {} has broad permissions ({:o}). \
                 Consider restricting to owner-only (chmod 600).",
                    path.display(),
                    mode & 0o777
                );
            }
        }
    }

    #[cfg(not(unix))]
    fn warn_if_broad_permissions(_path: &Path) {}
}

impl ProvideCredentials for FileBasedCredentialsProvider {
    fn provide_credentials<'a>(&'a self) -> future::ProvideCredentials<'a>
    where
        Self: 'a,
    {
        future::ProvideCredentials::new(async {
            self.cached
                .load()
                .as_ref()
                .map(|c| Self::with_expiry((**c).clone()))
                .ok_or_else(|| CredentialsError::not_loaded("No credentials available"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_valid_credentials(file: &mut NamedTempFile) {
        writeln!(
            file,
            "[default]\naws_access_key_id=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=wJalrXUtnFEMI\naws_session_token=FwoGZX"
        )
        .unwrap();
    }

    fn write_long_term_credentials(file: &mut NamedTempFile) {
        writeln!(
            file,
            "[default]\naws_access_key_id=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=wJalrXUtnFEMI"
        )
        .unwrap();
    }

    #[tokio::test]
    async fn test_load_valid_credentials() {
        let mut tmp = NamedTempFile::new().unwrap();
        write_valid_credentials(&mut tmp);

        let provider = FileBasedCredentialsProvider::new(tmp.path()).await;
        let creds = provider.provide_credentials().await.unwrap();

        assert_eq!(creds.access_key_id(), "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(creds.secret_access_key(), "wJalrXUtnFEMI");
        assert_eq!(creds.session_token(), Some("FwoGZX"));
    }

    #[tokio::test]
    async fn test_rejects_long_term_credentials() {
        let mut tmp = NamedTempFile::new().unwrap();
        write_long_term_credentials(&mut tmp);

        let provider = FileBasedCredentialsProvider::new(tmp.path()).await;
        let result = provider.provide_credentials().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_missing_file_starts_with_empty_cache() {
        let provider = FileBasedCredentialsProvider::new("/nonexistent/path").await;
        let result = provider.provide_credentials().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_empty_file_starts_with_empty_cache() {
        let tmp = NamedTempFile::new().unwrap();
        let provider = FileBasedCredentialsProvider::new(tmp.path()).await;
        let result = provider.provide_credentials().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_credential_reload() {
        let mut tmp = NamedTempFile::new().unwrap();
        write_valid_credentials(&mut tmp);

        let provider = FileBasedCredentialsProvider::new(tmp.path()).await;
        assert_eq!(
            provider
                .provide_credentials()
                .await
                .unwrap()
                .access_key_id(),
            "AKIAIOSFODNN7EXAMPLE"
        );

        tokio::time::sleep(Duration::from_secs(1)).await;

        std::fs::write(
            tmp.path(),
            "[default]\naws_access_key_id=ROTATED_KEY\naws_secret_access_key=secret\naws_session_token=token",
        )
        .unwrap();

        tmp.as_file()
            .set_modified(SystemTime::now() + Duration::from_secs(60))
            .unwrap();

        tokio::time::pause();
        tokio::time::advance(reload_delay()).await;
        tokio::time::resume();
        tokio::time::sleep(Duration::from_secs(1)).await;

        assert_eq!(
            provider
                .provide_credentials()
                .await
                .unwrap()
                .access_key_id(),
            "ROTATED_KEY"
        );
    }

    #[tokio::test]
    async fn test_reload_rejects_long_term_retains_cached() {
        let mut tmp = NamedTempFile::new().unwrap();
        write_valid_credentials(&mut tmp);

        let provider = FileBasedCredentialsProvider::new(tmp.path()).await;
        assert_eq!(
            provider
                .provide_credentials()
                .await
                .unwrap()
                .access_key_id(),
            "AKIAIOSFODNN7EXAMPLE"
        );

        tokio::time::sleep(Duration::from_secs(1)).await;

        // Write long-term creds (no session token) — should be rejected
        std::fs::write(
            tmp.path(),
            "[default]\naws_access_key_id=LONGTERM\naws_secret_access_key=secret",
        )
        .unwrap();
        tmp.as_file()
            .set_modified(SystemTime::now() + Duration::from_secs(60))
            .unwrap();

        tokio::time::pause();
        tokio::time::advance(reload_delay()).await;
        tokio::time::resume();
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Should still have the original valid credentials
        assert_eq!(
            provider
                .provide_credentials()
                .await
                .unwrap()
                .access_key_id(),
            "AKIAIOSFODNN7EXAMPLE"
        );
    }
}
