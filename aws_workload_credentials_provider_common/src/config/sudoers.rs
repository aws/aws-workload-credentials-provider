//! Sudoers file generation for ACM config
//!
//! Generates `/etc/sudoers.d/aws-workload-credentials-provider` from config
//! to allow the provider user to execute TLS software reload commands as root.

use std::collections::HashSet;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use chrono::Utc;

use super::types::AcmConfig;
use crate::constants::{PROVIDER_NAME, PROVIDER_USER, SUDOERS_PATH};
use crate::filesystem::{FileSystem, RealFileSystem};

/// Generates the sudoers file from ACM configuration.
///
/// This is the main entry point — handles the full lifecycle:
/// 1. Generate sudoers content from certificate refresh commands
/// 2. Atomically write to `/etc/sudoers.d/aws-workload-credentials-provider` with 0440 permissions
pub fn generate_and_install(acm_config: &AcmConfig, config_path: Option<&str>) -> io::Result<()> {
    let content = generate_sudoers_content(acm_config, PROVIDER_USER, config_path);
    let fs = RealFileSystem;
    let sudoers_path = Path::new(SUDOERS_PATH);
    let parent = fs
        .parent(sudoers_path)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid sudoers path"))?;
    let tmp_path = fs.write_string_to_temp(&parent, &content)?;

    let result = (|| {
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o440))?;
        validate_with_visudo(&tmp_path)?;
        fs.atomic_rename(&tmp_path, sudoers_path)
    })();

    if result.is_err() {
        let _ = fs.remove_file(&tmp_path);
    }
    result
}

/// Validates a sudoers file using `visudo -c` before installation.
/// Skips validation if visudo is not found (graceful degradation).
fn validate_with_visudo(path: &Path) -> io::Result<()> {
    match std::process::Command::new("visudo")
        .args(["-c", "-f"])
        .arg(path)
        .output()
    {
        Ok(output) if !output.status.success() => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("visudo validation failed: {}", stderr.trim()),
            ))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            eprintln!("Warning: visudo not found, skipping sudoers validation");
            Ok(())
        }
        Err(e) => Err(e),
        _ => Ok(()),
    }
}

/// Generates sudoers file content from ACM configuration.
fn generate_sudoers_content(
    acm_config: &AcmConfig,
    provider_user: &str,
    config_path: Option<&str>,
) -> String {
    let timestamp = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let mut lines = vec![
        format!("# {}", SUDOERS_PATH),
        format!("# Generated: {}", timestamp),
    ];
    if let Some(path) = config_path {
        lines.push(format!("# Generated from: {}", path));
    }
    lines.push(format!(
        "# DO NOT EDIT MANUALLY - Regenerate with: {} setup-config-based-permissions",
        PROVIDER_NAME
    ));
    lines.push(String::new());

    let mut seen = HashSet::new();
    for cert_config in acm_config.certificates.values() {
        if let Some(ref cmd) = cert_config.refresh_command {
            let trimmed_cmd = cmd.trim();
            if !trimmed_cmd.is_empty() && seen.insert(trimmed_cmd.to_string()) {
                lines.push(format!(
                    "{} ALL=(ALL) NOPASSWD: {}",
                    provider_user, trimmed_cmd
                ));
            }
        }
    }

    lines.join("\n") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::CertificateConfig;
    use std::collections::HashMap;

    fn make_cert(refresh_command: Option<&str>) -> CertificateConfig {
        CertificateConfig {
            certificate_arn: "arn:aws:acm:us-west-2:123456789012:certificate/abc".to_string(),
            certificate_path: PathBuf::from("/etc/ssl/cert.pem"),
            private_key_path: PathBuf::from("/etc/ssl/key.pem"),
            chain_path: Some(PathBuf::from("/etc/ssl/chain.pem")),
            refresh_command: refresh_command.map(String::from),
            role_arn: "arn:aws:iam::123456789012:role/TestRole".to_string(),
            cert_and_chain_permission: None,
            key_permission: None,
        }
    }

    fn make_acm(certs: Vec<(&str, Option<&str>)>) -> AcmConfig {
        let mut certificates = HashMap::new();
        for (name, cmd) in certs {
            certificates.insert(name.to_string(), make_cert(cmd));
        }
        AcmConfig {
            enabled: true,
            certificates,
        }
    }

    #[test]
    fn test_single_command() {
        let acm = make_acm(vec![("c1", Some("/usr/sbin/nginx -s reload"))]);
        let content = generate_sudoers_content(
            &acm,
            "aws-workload-credentials-provider",
            Some("/etc/config.toml"),
        );
        assert!(content.contains(
            "aws-workload-credentials-provider ALL=(ALL) NOPASSWD: /usr/sbin/nginx -s reload"
        ));
        assert!(content.contains("# Generated from: /etc/config.toml"));
    }

    #[test]
    fn test_multiple_commands() {
        let acm = make_acm(vec![
            ("c1", Some("/usr/sbin/nginx -s reload")),
            ("c2", Some("/bin/systemctl reload apache2")),
        ]);
        let content = generate_sudoers_content(
            &acm,
            "aws-workload-credentials-provider",
            Some("/etc/config.toml"),
        );
        assert!(content.contains("NOPASSWD: /usr/sbin/nginx -s reload"));
        assert!(content.contains("NOPASSWD: /bin/systemctl reload apache2"));
    }

    #[test]
    fn test_deduplicates() {
        let acm = make_acm(vec![
            ("c1", Some("/usr/sbin/nginx -s reload")),
            ("c2", Some("/usr/sbin/nginx -s reload")),
        ]);
        let content = generate_sudoers_content(
            &acm,
            "aws-workload-credentials-provider",
            Some("/etc/config.toml"),
        );
        assert_eq!(content.matches("/usr/sbin/nginx -s reload").count(), 1);
    }

    #[test]
    fn test_skips_none() {
        let acm = make_acm(vec![
            ("c1", None),
            ("c2", Some("/usr/sbin/nginx -s reload")),
        ]);
        let content = generate_sudoers_content(
            &acm,
            "aws-workload-credentials-provider",
            Some("/etc/config.toml"),
        );
        assert_eq!(content.matches("NOPASSWD:").count(), 1);
    }

    #[test]
    fn test_skips_empty() {
        let acm = make_acm(vec![
            ("c1", Some("  ")),
            ("c2", Some("/usr/sbin/nginx -s reload")),
        ]);
        let content = generate_sudoers_content(
            &acm,
            "aws-workload-credentials-provider",
            Some("/etc/config.toml"),
        );
        assert_eq!(content.matches("NOPASSWD:").count(), 1);
    }

    #[test]
    fn test_empty_config() {
        let acm = AcmConfig::default();
        let content = generate_sudoers_content(
            &acm,
            "aws-workload-credentials-provider",
            Some("/etc/config.toml"),
        );
        assert!(!content.contains("NOPASSWD:"));
        assert!(content.contains("# DO NOT EDIT MANUALLY"));
    }

    #[test]
    fn test_no_config_path_omits_source_line() {
        let acm = make_acm(vec![("c1", Some("/usr/sbin/nginx -s reload"))]);
        let content = generate_sudoers_content(&acm, "aws-workload-credentials-provider", None);
        assert!(!content.contains("# Generated from:"));
        assert!(content.contains("NOPASSWD:"));
    }
}
