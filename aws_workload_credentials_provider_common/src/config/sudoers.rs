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

/// Program used to check a generated sudoers file before it is installed.
const VISUDO: &str = "visudo";

/// Generates the sudoers file from ACM configuration.
///
/// This is the main entry point — handles the full lifecycle:
/// 1. Generate sudoers content from certificate refresh commands
/// 2. Check it with `visudo -c`, when `visudo` is available
/// 3. Atomically write to `/etc/sudoers.d/aws-workload-credentials-provider` with 0440 permissions
pub fn generate_and_install(acm_config: &AcmConfig, config_path: Option<&str>) -> io::Result<()> {
    let content = generate_sudoers_content(acm_config, PROVIDER_USER, config_path)?;
    let fs = RealFileSystem;
    let sudoers_path = Path::new(SUDOERS_PATH);
    let parent = fs
        .parent(sudoers_path)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid sudoers path"))?;
    let tmp_path = fs.write_string_to_temp(&parent, &content)?;

    let result = (|| {
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o440))?;
        validate_with(VISUDO, &tmp_path)?;
        fs.atomic_rename(&tmp_path, sudoers_path)
    })();

    if result.is_err() {
        let _ = fs.remove_file(&tmp_path);
    }
    result
}

/// Removes the generated sudoers file, if present.
pub fn remove() -> io::Result<()> {
    match std::fs::remove_file(SUDOERS_PATH) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Checks a sudoers file with `<visudo> -c -f <path>`.
/// Skips validation if visudo is not found (graceful degradation).
fn validate_with(visudo: &str, path: &Path) -> io::Result<()> {
    match std::process::Command::new(visudo)
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

/// Encodes a refresh command as a sudoers `Cmnd`.
///
/// The provider runs `sudo -n <program> <args...>` with the command split on
/// whitespace, so the arguments are rejoined with single spaces. Characters
/// sudoers treats as syntax inside a command are backslash-escaped. A command
/// with no arguments gets `""`, which sudoers reads as "no arguments"; without
/// it the rule would allow the program with any arguments.
fn sudoers_command(command: &str) -> io::Result<String> {
    if command.chars().any(char::is_control) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("refresh command {command:?} contains a control character"),
        ));
    }
    if command.contains('"') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("refresh command {command:?} contains a double quote"),
        ));
    }
    let mut words = command.split_whitespace().map(|word| {
        let mut escaped = String::with_capacity(word.len());
        for c in word.chars() {
            if matches!(
                c,
                '\\' | ',' | ':' | '=' | '!' | '#' | '*' | '?' | '[' | ']'
            ) {
                escaped.push('\\');
            }
            escaped.push(c);
        }
        escaped
    });
    let program = words
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "refresh command is empty"))?;
    let args: Vec<String> = words.collect();
    Ok(if args.is_empty() {
        format!("{program} \"\"")
    } else {
        format!("{program} {}", args.join(" "))
    })
}

/// Generates sudoers file content from ACM configuration.
fn generate_sudoers_content(
    acm_config: &AcmConfig,
    provider_user: &str,
    config_path: Option<&str>,
) -> io::Result<String> {
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
            if !cmd.trim().is_empty() {
                let cmd = sudoers_command(cmd.trim())?;
                if seen.insert(cmd.clone()) {
                    lines.push(format!("{} ALL=(root) NOPASSWD: {}", provider_user, cmd));
                }
            }
        }
    }

    Ok(lines.join("\n") + "\n")
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
            watcher_id: None,
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
            discovery: None,
            ..Default::default()
        }
    }

    #[test]
    fn test_single_command() {
        let acm = make_acm(vec![("c1", Some("/usr/sbin/nginx -s reload"))]);
        let content = generate_sudoers_content(
            &acm,
            "aws-workload-credentials-provider",
            Some("/etc/config.toml"),
        )
        .unwrap();
        assert!(content.contains(
            "aws-workload-credentials-provider ALL=(root) NOPASSWD: /usr/sbin/nginx -s reload"
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
        )
        .unwrap();
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
        )
        .unwrap();
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
        )
        .unwrap();
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
        )
        .unwrap();
        assert_eq!(content.matches("NOPASSWD:").count(), 1);
    }

    #[test]
    fn test_empty_config() {
        let acm = AcmConfig::default();
        let content = generate_sudoers_content(
            &acm,
            "aws-workload-credentials-provider",
            Some("/etc/config.toml"),
        )
        .unwrap();
        assert!(!content.contains("NOPASSWD:"));
        assert!(content.contains("# DO NOT EDIT MANUALLY"));
    }

    #[test]
    fn test_no_config_path_omits_source_line() {
        let acm = make_acm(vec![("c1", Some("/usr/sbin/nginx -s reload"))]);
        let content =
            generate_sudoers_content(&acm, "aws-workload-credentials-provider", None).unwrap();
        assert!(!content.contains("# Generated from:"));
        assert!(content.contains("NOPASSWD:"));
    }

    #[test]
    fn test_no_arg_command_forbids_arguments() {
        let acm = make_acm(vec![("c1", Some("/usr/bin/systemctl"))]);
        let content = generate_sudoers_content(&acm, "aws-wcp", None).unwrap();
        assert!(
            content.contains("aws-wcp ALL=(root) NOPASSWD: /usr/bin/systemctl \"\"\n"),
            "{content}"
        );
    }

    #[test]
    fn test_rejects_tab() {
        let acm = make_acm(vec![("c1", Some("/usr/sbin/nginx   -s\treload"))]);
        let content = generate_sudoers_content(&acm, "aws-wcp", None);
        assert_eq!(content.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_collapses_repeated_spaces() {
        let acm = make_acm(vec![("c1", Some("/usr/sbin/nginx   -s  reload"))]);
        let content = generate_sudoers_content(&acm, "aws-wcp", None).unwrap();
        assert!(
            content.contains("NOPASSWD: /usr/sbin/nginx -s reload\n"),
            "{content}"
        );
    }

    #[test]
    fn test_rejects_whitespace_only_command() {
        let err = sudoers_command("   ").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn test_escapes_sudoers_special_characters() {
        let cases = [
            ("/usr/bin/app --mode=reload", "/usr/bin/app --mode\\=reload"),
            ("/usr/bin/app a,b", "/usr/bin/app a\\,b"),
            ("/usr/bin/app host:1", "/usr/bin/app host\\:1"),
            ("/usr/bin/app a\\b", "/usr/bin/app a\\\\b"),
            ("/usr/bin/app (x)!#", "/usr/bin/app (x)\\!\\#"),
            (
                "/usr/bin/app *.pem [ab]?",
                "/usr/bin/app \\*.pem \\[ab\\]\\?",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(sudoers_command(input).unwrap(), expected, "input {input:?}");
        }
    }

    #[test]
    fn test_rejects_control_characters() {
        for cmd in ["/bin/a\nroot ALL=(ALL) ALL", "/bin/a\rb", "/bin/a\0b"] {
            let acm = make_acm(vec![("c1", Some(cmd))]);
            let err = generate_sudoers_content(&acm, "aws-wcp", None).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "cmd {cmd:?}");
        }
    }

    #[test]
    fn test_rejects_double_quotes() {
        let acm = make_acm(vec![("c1", Some("/bin/foo --value=\"a b\""))]);
        let err = generate_sudoers_content(&acm, "aws-wcp", None).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("double quote"));
    }

    #[test]
    fn test_validate_skips_when_visudo_missing() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("sudoers");
        std::fs::write(&file, "# empty\n").unwrap();
        validate_with("/nonexistent/visudo-12345", &file).unwrap();
    }

    #[test]
    fn test_validate_reports_checker_failure() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("sudoers");
        std::fs::write(&file, "x\n").unwrap();
        // `false` exits non-zero whatever its arguments, standing in for a
        // visudo that rejects the file.
        let err = validate_with("false", &file).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_validate_accepts_checker_success() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("sudoers");
        std::fs::write(&file, "x\n").unwrap();
        validate_with("true", &file).unwrap();
    }
}
