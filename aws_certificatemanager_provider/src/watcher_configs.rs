//! Generates each watcher's `watcher.config.toml` from the provider's
//! certificate config, once at startup.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{self, Write};
use std::path::Path;

use aws_workload_credentials_provider_common::config::types::CertificateConfig;
use aws_workload_credentials_provider_common::config::watcher_config::{
    is_valid_watcher_id, split_command, ReloadEntry, WatcherConfig, MAX_WATCHER_CONFIG_BYTES,
    WATCHER_CONFIG_FILE_NAME, WATCHER_CONFIG_SCHEMA_VERSION,
};
use log::warn;

/// Builds one config per `watcher_id`. Certificates whose split commands are
/// identical share a `[[reload]]` entry, so spacing differences don't split
/// them. Output is sorted, so the same input always writes the same file.
pub(crate) fn build(certificates: &HashMap<String, CertificateConfig>) -> Vec<WatcherConfig> {
    let mut grouped: BTreeMap<&str, BTreeMap<Vec<String>, BTreeSet<&str>>> = BTreeMap::new();
    for cert in certificates.values() {
        let (Some(watcher_id), Some(command)) = (&cert.watcher_id, &cert.refresh_command) else {
            continue;
        };
        let command = split_command(command);
        grouped
            .entry(watcher_id)
            .or_default()
            .entry(command)
            .or_default()
            .insert(&cert.certificate_arn);
    }
    grouped
        .into_iter()
        .map(|(watcher_id, reloads)| WatcherConfig {
            schema_version: WATCHER_CONFIG_SCHEMA_VERSION,
            watcher_id: watcher_id.to_string(),
            reloads: reloads
                .into_iter()
                .map(|(command, arns)| ReloadEntry {
                    command,
                    certificate_arns: arns.into_iter().map(str::to_string).collect(),
                })
                .collect(),
        })
        .collect()
}

/// Validates and writes every watcher's config under `config_dir`, and
/// returns how many it wrote. Writes nothing when no certificate has a
/// watcher.
pub(crate) fn generate(
    config_dir: &Path,
    certificates: &HashMap<String, CertificateConfig>,
) -> io::Result<usize> {
    let configs = build(certificates);
    // Validate every config before writing any, so a bad one writes nothing.
    let mut files = Vec::with_capacity(configs.len());
    for config in &configs {
        if let Err(errors) = config.validate(&config.watcher_id) {
            let details: Vec<String> = errors
                .iter()
                .map(|e| format!("{}: {}", e.field, e.message))
                .collect();
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "invalid config for watcher {}: {}",
                    config.watcher_id,
                    details.join("; ")
                ),
            ));
        }
        let toml = config.to_toml().map_err(io::Error::other)?;
        if toml.len() as u64 > MAX_WATCHER_CONFIG_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "the config for watcher {} is {} bytes, over the {MAX_WATCHER_CONFIG_BYTES} a watcher reads",
                    config.watcher_id,
                    toml.len()
                ),
            ));
        }
        files.push((config.watcher_id.as_str(), toml));
    }
    // A write can fail after earlier watchers' configs were written. That's
    // safe: each written config matches the provider's config, the error stops
    // startup so no requests are sent, and the next start rewrites every one.
    for (watcher_id, toml) in &files {
        let dir = config_dir.join(watcher_id);
        write_atomically(&dir, toml.as_bytes()).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "writing the config for watcher {watcher_id} in {}: {e}",
                    dir.display()
                ),
            )
        })?;
    }
    let stale = stale_watcher_ids(config_dir, &configs);
    if !stale.is_empty() {
        warn!(
            "Watcher config(s) in {} for {} are no longer in the provider's config. A watcher that restarts would load them, so remove them once those watchers are gone.",
            config_dir.display(),
            stale.join(", ")
        );
    }
    Ok(configs.len())
}

/// Watcher IDs that have a config under `config_dir` but are no longer
/// configured. They're only reported: deleting one would stop its watcher
/// from starting.
fn stale_watcher_ids(config_dir: &Path, configs: &[WatcherConfig]) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(config_dir) else {
        return Vec::new();
    };
    let mut stale: Vec<String> = entries
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|id| is_valid_watcher_id(id) && !configs.iter().any(|c| c.watcher_id == *id))
        .filter(|id| config_dir.join(id).join(WATCHER_CONFIG_FILE_NAME).is_file())
        .collect();
    stale.sort();
    stale
}

/// Temp file then rename, so the watcher never reads a partial config. The
/// config volume is read-only for the TLS container, so plain paths are safe.
fn write_atomically(dir: &Path, body: &[u8]) -> io::Result<()> {
    // The config directory itself was checked at startup, so only the
    // watcher's own directory may be created.
    match std::fs::create_dir(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    // Refuse a symlink here too, and set the mode on every start so one
    // failed attempt doesn't leave the directory unreadable.
    if !std::fs::symlink_metadata(dir)?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            "not a directory",
        ));
    }
    set_mode(dir, 0o755)?;
    let temp = dir.join(format!(".{WATCHER_CONFIG_FILE_NAME}.tmp"));
    // A temp file left by a crash would make `create_new` fail on every start.
    match std::fs::remove_file(&temp) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    // `create_new` refuses an existing name, symlinks included (O_EXCL).
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)?;
    // The watcher may run as another user, so don't leave this to the umask.
    let written = set_file_mode(&file, 0o644)
        .and_then(|()| file.write_all(body))
        .and_then(|()| file.sync_all())
        .and_then(|()| {
            drop(file);
            std::fs::rename(&temp, dir.join(WATCHER_CONFIG_FILE_NAME))
        });
    if written.is_err() {
        let _ = std::fs::remove_file(&temp);
        return written;
    }
    // The config is in place now; a failed sync only risks losing it in a
    // crash, and the next start rewrites it.
    sync_dir(dir);
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(unix)]
fn set_file_mode(file: &std::fs::File, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(mode))
}

// Windows files and directories inherit the config directory's ACL.
#[cfg(windows)]
fn set_mode(_path: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}

#[cfg(windows)]
fn set_file_mode(_file: &std::fs::File, _mode: u32) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_dir(dir: &Path) {
    let _ = std::fs::File::open(dir).and_then(|d| d.sync_all());
}

#[cfg(windows)]
fn sync_dir(_dir: &Path) {}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn arn(n: u32) -> String {
        format!(
            "arn:aws:acm:us-west-2:123456789012:certificate/0000000{n}-1234-1234-1234-123456789012"
        )
    }

    fn cert(n: u32, watcher_id: Option<&str>, command: &str) -> (String, CertificateConfig) {
        let arn = arn(n);
        (
            arn.clone(),
            CertificateConfig {
                certificate_arn: arn,
                certificate_path: PathBuf::from(format!("/certs/{n}.pem")),
                private_key_path: PathBuf::from(format!("/certs/{n}.key")),
                chain_path: None,
                role_arn: "arn:aws:iam::123456789012:role/r".into(),
                refresh_command: Some(command.into()),
                cert_and_chain_permission: None,
                key_permission: None,
                watcher_id: watcher_id.map(str::to_string),
            },
        )
    }

    #[test]
    fn groups_by_watcher_and_by_split_command() {
        let certs = HashMap::from([
            cert(1, Some("nginx"), "/usr/sbin/nginx -s reload"),
            cert(2, Some("nginx"), "/usr/sbin/nginx  -s   reload"),
            cert(3, Some("nginx"), "/usr/sbin/apachectl -k graceful"),
            cert(4, Some("haproxy"), "/usr/sbin/haproxy-reload"),
            cert(5, None, "/usr/bin/systemctl reload nginx"),
        ]);

        let configs = build(&certs);

        let ids: Vec<&str> = configs.iter().map(|c| c.watcher_id.as_str()).collect();
        assert_eq!(ids, ["haproxy", "nginx"]);
        let nginx = &configs[1];
        assert_eq!(nginx.reloads.len(), 2);
        assert_eq!(
            nginx.reloads[0].command,
            ["/usr/sbin/apachectl", "-k", "graceful"]
        );
        assert_eq!(
            nginx.reloads[1].command,
            ["/usr/sbin/nginx", "-s", "reload"]
        );
        assert_eq!(nginx.reloads[1].certificate_arns, [arn(1), arn(2)]);
        assert!(configs.iter().all(|c| c.validate(&c.watcher_id).is_ok()));
    }

    #[test]
    fn writes_one_file_per_watcher_that_reads_back() {
        let dir = tempfile::tempdir().unwrap();
        let certs = HashMap::from([
            cert(1, Some("nginx"), "/usr/sbin/nginx -s reload"),
            cert(2, Some("haproxy"), "/usr/sbin/haproxy-reload"),
        ]);

        assert_eq!(generate(dir.path(), &certs).unwrap(), 2);

        for id in ["nginx", "haproxy"] {
            let watcher_dir = dir.path().join(id);
            let names: Vec<_> = std::fs::read_dir(&watcher_dir)
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect();
            assert_eq!(
                names,
                [WATCHER_CONFIG_FILE_NAME],
                "no temp file left in {id}"
            );
            let toml = std::fs::read_to_string(watcher_dir.join(WATCHER_CONFIG_FILE_NAME)).unwrap();
            assert!(WatcherConfig::from_toml(&toml)
                .unwrap()
                .validate(id)
                .is_ok());
        }
    }

    #[test]
    fn rewriting_replaces_the_previous_config() {
        let dir = tempfile::tempdir().unwrap();
        generate(
            dir.path(),
            &HashMap::from([cert(1, Some("nginx"), "/usr/sbin/nginx -s reload")]),
        )
        .unwrap();
        generate(
            dir.path(),
            &HashMap::from([cert(2, Some("nginx"), "/usr/sbin/nginx -s reopen")]),
        )
        .unwrap();

        let toml = std::fs::read_to_string(dir.path().join("nginx").join(WATCHER_CONFIG_FILE_NAME))
            .unwrap();
        let config = WatcherConfig::from_toml(&toml).unwrap();
        assert_eq!(config.reloads.len(), 1);
        assert_eq!(
            config.reloads[0].command,
            ["/usr/sbin/nginx", "-s", "reopen"]
        );
    }

    #[test]
    fn no_watcher_certificates_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("not-mounted");

        let certs = HashMap::from([cert(1, None, "/usr/sbin/nginx -s reload")]);
        assert_eq!(generate(&missing, &certs).unwrap(), 0);
        assert!(!missing.exists());
    }

    #[test]
    fn invalid_command_fails_before_anything_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let certs = HashMap::from([
            cert(1, Some("apache"), "/usr/sbin/apachectl -k graceful"),
            cert(2, Some("nginx"), "nginx -s reload"),
        ]);

        let err = generate(dir.path(), &certs).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("watcher nginx"), "{err}");
        // apache sorts first and is valid, but nothing is written.
        assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
    }

    #[test]
    fn a_failed_write_names_the_watcher_and_stops() {
        let dir = tempfile::tempdir().unwrap();
        // A file where nginx's directory should be makes its write fail.
        std::fs::write(dir.path().join("nginx"), b"").unwrap();
        let certs = HashMap::from([
            cert(1, Some("apache"), "/usr/sbin/apachectl -k graceful"),
            cert(2, Some("nginx"), "/usr/sbin/nginx -s reload"),
            cert(3, Some("zeus"), "/usr/sbin/zeus-reload"),
        ]);

        let err = generate(dir.path(), &certs).unwrap_err();

        assert!(
            err.to_string().contains(&format!(
                "watcher nginx in {}",
                dir.path().join("nginx").display()
            )),
            "{err}"
        );
        // Written in order: apache before the failure, zeus never.
        assert!(dir
            .path()
            .join("apache")
            .join(WATCHER_CONFIG_FILE_NAME)
            .exists());
        assert!(!dir.path().join("zeus").exists());
    }

    #[test]
    fn a_config_over_the_watcher_limit_fails_before_anything_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let long = format!(
            "/usr/sbin/{}",
            "a".repeat(MAX_WATCHER_CONFIG_BYTES as usize)
        );
        let certs = HashMap::from([
            cert(1, Some("apache"), "/usr/sbin/apachectl -k graceful"),
            cert(2, Some("nginx"), &long),
        ]);

        let err = generate(dir.path(), &certs).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("watcher nginx is"), "{err}");
        assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
    }

    #[test]
    fn config_and_directory_modes_are_set_explicitly() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let certs = HashMap::from([cert(1, Some("nginx"), "/usr/sbin/nginx -s reload")]);

        generate(dir.path(), &certs).unwrap();

        let mode = |p: PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let watcher_dir = dir.path().join("nginx");
        assert_eq!(mode(watcher_dir.clone()), 0o755);
        assert_eq!(mode(watcher_dir.join(WATCHER_CONFIG_FILE_NAME)), 0o644);
    }

    #[test]
    fn a_temp_file_left_by_a_crash_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let watcher_dir = dir.path().join("nginx");
        std::fs::create_dir(&watcher_dir).unwrap();
        std::fs::write(
            watcher_dir.join(format!(".{WATCHER_CONFIG_FILE_NAME}.tmp")),
            b"partial",
        )
        .unwrap();
        let certs = HashMap::from([cert(1, Some("nginx"), "/usr/sbin/nginx -s reload")]);

        generate(dir.path(), &certs).unwrap();

        let names: Vec<_> = std::fs::read_dir(&watcher_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, [WATCHER_CONFIG_FILE_NAME]);
    }

    #[test]
    fn an_existing_directory_gets_its_mode_fixed() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let watcher_dir = dir.path().join("nginx");
        std::fs::create_dir(&watcher_dir).unwrap();
        std::fs::set_permissions(&watcher_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let certs = HashMap::from([cert(1, Some("nginx"), "/usr/sbin/nginx -s reload")]);

        generate(dir.path(), &certs).unwrap();

        let mode = std::fs::metadata(&watcher_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o755);
    }

    #[test]
    fn a_symlinked_watcher_directory_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        let config_dir = dir.path().join("config");
        std::fs::create_dir(&config_dir).unwrap();
        std::os::unix::fs::symlink(&elsewhere, config_dir.join("nginx")).unwrap();
        let certs = HashMap::from([cert(1, Some("nginx"), "/usr/sbin/nginx -s reload")]);

        let err = generate(&config_dir, &certs).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::NotADirectory, "{err}");
        assert!(std::fs::read_dir(&elsewhere).unwrap().next().is_none());
    }

    #[test]
    fn a_symlink_at_the_temp_name_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        std::fs::write(&outside, b"untouched").unwrap();
        let config_dir = dir.path().join("config");
        let watcher_dir = config_dir.join("nginx");
        std::fs::create_dir_all(&watcher_dir).unwrap();
        std::os::unix::fs::symlink(
            &outside,
            watcher_dir.join(format!(".{WATCHER_CONFIG_FILE_NAME}.tmp")),
        )
        .unwrap();
        let certs = HashMap::from([cert(1, Some("nginx"), "/usr/sbin/nginx -s reload")]);

        generate(&config_dir, &certs).unwrap();

        assert_eq!(std::fs::read(&outside).unwrap(), b"untouched");
        assert!(watcher_dir.join(WATCHER_CONFIG_FILE_NAME).is_file());
    }

    #[test]
    fn configs_of_unconfigured_watchers_are_reported_not_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let old = HashMap::from([
            cert(1, Some("apache"), "/usr/sbin/apachectl -k graceful"),
            cert(2, Some("nginx"), "/usr/sbin/nginx -s reload"),
        ]);
        generate(dir.path(), &old).unwrap();
        // Neither is reported: one has no config, the other isn't a watcher ID.
        std::fs::create_dir(dir.path().join("empty")).unwrap();
        std::fs::create_dir(dir.path().join("not a watcher")).unwrap();
        std::fs::write(
            dir.path()
                .join("not a watcher")
                .join(WATCHER_CONFIG_FILE_NAME),
            b"",
        )
        .unwrap();

        let now = build(&HashMap::from([cert(
            2,
            Some("nginx"),
            "/usr/sbin/nginx -s reload",
        )]));
        assert_eq!(stale_watcher_ids(dir.path(), &now), ["apache"]);
        assert_eq!(stale_watcher_ids(dir.path(), &[]), ["apache", "nginx"]);
        assert!(dir
            .path()
            .join("apache")
            .join(WATCHER_CONFIG_FILE_NAME)
            .exists());
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use std::path::PathBuf;

    const ARN: &str =
        "arn:aws:acm:us-west-2:123456789012:certificate/00000001-1234-1234-1234-123456789012";

    fn certs(command: &str) -> HashMap<String, CertificateConfig> {
        HashMap::from([(
            ARN.to_string(),
            CertificateConfig {
                certificate_arn: ARN.into(),
                certificate_path: PathBuf::from(r"C:\certs\1.pem"),
                private_key_path: PathBuf::from(r"C:\certs\1.key"),
                chain_path: None,
                role_arn: "arn:aws:iam::123456789012:role/r".into(),
                refresh_command: Some(command.into()),
                cert_and_chain_permission: None,
                key_permission: None,
                watcher_id: Some("nginx".into()),
            },
        )])
    }

    #[test]
    fn writes_a_config_that_reads_back_and_replaces_a_leftover_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let watcher_dir = dir.path().join("nginx");
        std::fs::create_dir(&watcher_dir).unwrap();
        std::fs::write(
            watcher_dir.join(format!(".{WATCHER_CONFIG_FILE_NAME}.tmp")),
            b"partial",
        )
        .unwrap();

        generate(dir.path(), &certs(r"C:\nginx\nginx.exe -s reload")).unwrap();
        // A second start replaces the file the first one wrote.
        generate(dir.path(), &certs(r"C:\nginx\nginx.exe -s reopen")).unwrap();

        let names: Vec<_> = std::fs::read_dir(&watcher_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, [WATCHER_CONFIG_FILE_NAME]);
        let toml = std::fs::read_to_string(watcher_dir.join(WATCHER_CONFIG_FILE_NAME)).unwrap();
        let config = WatcherConfig::from_toml(&toml).unwrap();
        assert_eq!(
            config.reloads[0].command,
            [r"C:\nginx\nginx.exe", "-s", "reopen"]
        );
    }

    #[test]
    fn a_config_over_the_watcher_limit_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let long = format!(r"C:\{}.exe", "a".repeat(MAX_WATCHER_CONFIG_BYTES as usize));

        let err = generate(dir.path(), &certs(&long)).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
    }

    #[test]
    fn a_file_in_place_of_the_watcher_directory_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("nginx"), b"").unwrap();

        let err = generate(dir.path(), &certs(r"C:\nginx\nginx.exe -s reload")).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::NotADirectory, "{err}");
    }
}
