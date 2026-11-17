//! The watcher's configuration, loaded once at startup.
//!
//! Parsing and validation are entirely `common`'s [`WatcherConfig`]
//! (`common::config::watcher_config`): this module adds no second parser and
//! no second validator, so the rule set — schema version, identity match, at
//! least one `[[reload]]` entry, non-empty argv, element 0 absolute on Unix
//! (Windows also accepts a bare name or cmdlet, resolved by PowerShell),
//! per-element charset, at least one well-formed ARN per entry, each ARN in
//! exactly one entry — has exactly one implementation, the same one the ACM
//! provider validates its output against.
//!
//! What this module adds is the lookup the event loop needs: certificate ARN to
//! the command that reloads it, with identical commands collapsed onto one id.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::Path;

use aws_workload_credentials_provider_common::config::watcher_config::WatcherConfig;
use aws_workload_credentials_provider_common::config::{ValidationErrorCode, ValidationErrors};

use crate::error::StartupError;

/// Largest watcher configuration file that will be read.
///
/// The configuration volume is read-only to this container but it is still a
/// shared mount, and an unbounded read of a file on a shared volume is free to
/// bound.
///
/// Sizing: the WCP config allows at most `MAX_CERTIFICATES` (50) certificates
/// (`common::config::validator`), each ARN in one `[[reload]]` entry. The
/// largest file puts all 50 on this watcher with 50 distinct commands; shared
/// commands merge entries and only shrink it. As `to_toml` writes it:
///
/// - header: `schema_version` + `watcher_id` (<= 64, `WATCHER_ID_RE`) = 99 B
/// - entry: 49 B of keys and punctuation + ARN + command
/// - ARN: `arn:` + partition + `:acm:` + region + 12-digit account +
///   `:certificate/` + 36-char UUID ~= 100 B
/// - command of L bytes in k elements: L + 3k - 1 B, k <= (L + 1) / 2, so
///   <= 2.5 L (Unix charset, no TOML escapes)
///
/// With L = 256: 99 + 50 x (49 + 100 + 640) ~= 39 KiB, ~6.6x headroom. The
/// limit holds every such config whose commands are under ~2 KiB.
///
/// Neither ARN nor command length is enforced: `CERTIFICATE_ARN_RE`,
/// `REFRESH_COMMAND_RE` and `COMMAND_ELEMENT_RE` check characters only. A
/// valid config with much longer commands is refused here.
pub const MAX_CONFIG_BYTES: u64 = 256 * 1024;

/// Index into the plan's list of distinct reload commands.
pub type CommandId = usize;

/// Which command reloads which certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloadPlan {
    /// Distinct argv arrays, indexed by [`CommandId`].
    commands: Vec<Vec<String>>,
    by_arn: HashMap<String, CommandId>,
}

impl ReloadPlan {
    /// Reads and validates `path` as the configuration for `watcher_id`.
    pub fn load(path: &Path, watcher_id: &str) -> Result<Self, StartupError> {
        let metadata = fs::metadata(path).map_err(|source| StartupError::ConfigRead {
            path: path.to_path_buf(),
            source,
        })?;

        if metadata.len() > MAX_CONFIG_BYTES {
            return Err(StartupError::ConfigTooLarge {
                path: path.to_path_buf(),
                size: metadata.len(),
                limit: MAX_CONFIG_BYTES,
            });
        }

        let text = fs::read_to_string(path).map_err(|source| StartupError::ConfigRead {
            path: path.to_path_buf(),
            source,
        })?;

        Self::parse(&text, watcher_id, path)
    }

    /// Parses and validates configuration text.
    ///
    /// Kept pure over `&str`, with [`load`](Self::load) as the thin IO wrapper,
    /// following the split `config::systemd` uses: it makes every validation
    /// case testable without touching a filesystem.
    pub fn parse(text: &str, watcher_id: &str, path: &Path) -> Result<Self, StartupError> {
        // `from_toml` reads `schema_version` before the full parse, so a file
        // from a newer ACM provider fails with the version error rather than
        // an unknown-field error. That error is the only one it returns: the
        // rest of a newer file can't be checked against this schema.
        let file = WatcherConfig::from_toml(text).map_err(|source| {
            if source.code == ValidationErrorCode::TomlSyntaxError {
                StartupError::ConfigParse {
                    path: path.to_path_buf(),
                    source,
                }
            } else {
                StartupError::ConfigInvalid {
                    path: path.to_path_buf(),
                    source: ValidationErrors::from_error(source),
                }
            }
        })?;

        // The identity this file was loaded for is the watcher's own id, so a
        // mis-mounted or misplaced file is refused here instead of causing
        // this watcher to reload another watcher's certificates. `validate`
        // collects every error, and all of them are reported.
        file.validate(watcher_id)
            .map_err(|errors| StartupError::ConfigInvalid {
                path: path.to_path_buf(),
                source: ValidationErrors::from_vec(errors),
            })?;

        // MERGE BY COMMAND, STRUCTURALLY. Two `[[reload]]` groups whose argv
        // arrays are identical collapse onto one CommandId here, which is what
        // makes "run each distinct command once" expressible downstream.
        // `validate` forbids a duplicate ARN, not a duplicate command, so this
        // case is reachable from a valid file. See `run::PendingReloads` for
        // the decision this supports and what it gives up.
        let mut commands: Vec<Vec<String>> = Vec::new();
        let mut command_ids: BTreeMap<Vec<String>, CommandId> = BTreeMap::new();
        let mut by_arn: HashMap<String, CommandId> = HashMap::new();

        for group in file.reloads {
            let id = *command_ids.entry(group.command.clone()).or_insert_with(|| {
                commands.push(group.command);
                commands.len() - 1
            });

            for arn in group.certificate_arns {
                // Cannot collide: `validate` guarantees each ARN appears in
                // exactly one group.
                by_arn.insert(arn, id);
            }
        }

        Ok(Self { commands, by_arn })
    }

    /// The command that reloads `certificate_arn`, if the config has one.
    ///
    /// `None` means the certificate is not this watcher's business. The caller
    /// must reject the request.
    pub fn command_for(&self, certificate_arn: &str) -> Option<CommandId> {
        self.by_arn.get(certificate_arn).copied()
    }

    pub fn command(&self, id: CommandId) -> &[String] {
        &self.commands[id]
    }

    pub fn command_count(&self) -> usize {
        self.commands.len()
    }

    pub fn certificate_count(&self) -> usize {
        self.by_arn.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    const ARN_A: &str = "arn:aws:acm:us-west-2:123456789012:certificate/aaaa";
    const ARN_B: &str = "arn:aws:acm:us-west-2:123456789012:certificate/bbbb";
    const ARN_C: &str = "arn:aws:acm:us-west-2:123456789012:certificate/cccc";
    const ARN_UNKNOWN: &str = "arn:aws:acm:us-west-2:123456789012:certificate/zzzz";

    #[cfg(unix)]
    const NGINX: &str = "/usr/sbin/nginx";
    #[cfg(unix)]
    const APACHE: &str = "/usr/sbin/apachectl";
    #[cfg(windows)]
    const NGINX: &str = r"C:\nginx\nginx.exe";
    #[cfg(windows)]
    const APACHE: &str = r"C:\apache\bin\httpd.exe";

    fn fake_path() -> PathBuf {
        PathBuf::from("watcher.config.toml")
    }

    fn parse(text: &str) -> Result<ReloadPlan, StartupError> {
        ReloadPlan::parse(text, "nginx", &fake_path())
    }

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    /// Two groups, three certificates.
    ///
    /// Backslashes in the Windows program paths are escaped by
    /// `escape_default`, because a TOML basic string treats `\` as an escape
    /// introducer and `C:\nginx` would otherwise be a parse error.
    fn two_group_config(first: &str, second: &str) -> String {
        format!(
            "schema_version = 1\n\
             watcher_id = \"nginx\"\n\
             \n\
             [[reload]]\n\
             command = [\"{}\", \"-s\", \"reload\"]\n\
             certificate_arns = [\"{}\", \"{}\"]\n\
             \n\
             [[reload]]\n\
             command = [\"{}\", \"-k\", \"graceful\"]\n\
             certificate_arns = [\"{}\"]\n",
            first.escape_default(),
            ARN_A,
            ARN_B,
            second.escape_default(),
            ARN_C,
        )
    }

    #[test]
    fn two_group_config_parses_and_validates() {
        let plan = parse(&two_group_config(NGINX, APACHE)).unwrap();
        assert_eq!(plan.command_count(), 2);
        assert_eq!(plan.certificate_count(), 3);
    }

    #[test]
    fn arn_maps_to_its_own_groups_command() {
        let plan = parse(&two_group_config(NGINX, APACHE)).unwrap();

        let a = plan.command_for(ARN_A).unwrap();
        let b = plan.command_for(ARN_B).unwrap();
        let c = plan.command_for(ARN_C).unwrap();

        assert_eq!(a, b, "two certificates in one group share a command");
        assert_ne!(a, c);
        assert_eq!(plan.command(a).to_vec(), argv(&[NGINX, "-s", "reload"]));
        assert_eq!(plan.command(c).to_vec(), argv(&[APACHE, "-k", "graceful"]));
    }

    #[test]
    fn unknown_arn_has_no_command() {
        let plan = parse(&two_group_config(NGINX, APACHE)).unwrap();
        assert!(plan.command_for(ARN_UNKNOWN).is_none());
    }

    /// The merge-by-command collapse, at config level: two groups whose argv
    /// arrays are identical share one id, so the command runs once.
    ///
    /// Reachable from a valid file — `validate` forbids a duplicate ARN, not a
    /// duplicate command.
    #[test]
    fn identical_commands_in_two_groups_collapse() {
        let text = format!(
            "schema_version = 1\n\
             watcher_id = \"nginx\"\n\
             \n\
             [[reload]]\n\
             command = [\"{program}\", \"-s\", \"reload\"]\n\
             certificate_arns = [\"{a}\"]\n\
             \n\
             [[reload]]\n\
             command = [\"{program}\", \"-s\", \"reload\"]\n\
             certificate_arns = [\"{b}\"]\n",
            program = NGINX.escape_default(),
            a = ARN_A,
            b = ARN_B,
        );

        let plan = parse(&text).unwrap();

        assert_eq!(plan.command_count(), 1);
        assert_eq!(plan.certificate_count(), 2);
        assert_eq!(plan.command_for(ARN_A), plan.command_for(ARN_B));
    }

    /// The collapse is on the whole argv array, not on the program: the same
    /// binary with different arguments is a different command.
    #[test]
    fn groups_sharing_a_program_but_not_arguments_stay_distinct() {
        let plan = parse(&two_group_config(NGINX, NGINX)).unwrap();

        assert_eq!(plan.command_count(), 2);
        assert_ne!(plan.command_for(ARN_A), plan.command_for(ARN_C));
    }

    /// Each argv element reaches the reload sink exactly as configured: a space
    /// in the program path and a run of spaces inside an argument are kept,
    /// and no element is split or trimmed. On Windows this argv is the source
    /// of the PowerShell script (`reload::powershell_script`).
    #[test]
    fn command_elements_reach_the_plan_unchanged() {
        #[cfg(unix)]
        const PROGRAM: &str = "/opt/my app/reload";
        #[cfg(windows)]
        const PROGRAM: &str = r"C:\Program Files\App\reload.exe";
        let text = format!(
            "schema_version = 1\n\
             watcher_id = \"nginx\"\n\
             \n\
             [[reload]]\n\
             command = [\"{program}\", \"--msg=a  b\", \" x \"]\n\
             certificate_arns = [\"{a}\"]\n",
            program = PROGRAM.escape_default(),
            a = ARN_A,
        );

        let plan = parse(&text).unwrap();

        let id = plan.command_for(ARN_A).unwrap();
        assert_eq!(
            plan.command(id).to_vec(),
            argv(&[PROGRAM, "--msg=a  b", " x "])
        );
    }

    /// The `(field, code)` of every error in a [`StartupError::ConfigInvalid`],
    /// in the order `common`'s `WatcherConfig::validate` reports them.
    fn invalid(text: &str) -> Vec<(String, ValidationErrorCode)> {
        match parse(text).unwrap_err() {
            StartupError::ConfigInvalid { source, .. } => source
                .errors
                .into_iter()
                .map(|e| (e.field, e.code))
                .collect(),
            other => panic!("expected ConfigInvalid, got: {other}"),
        }
    }

    fn one_error(field: &str, code: ValidationErrorCode) -> Vec<(String, ValidationErrorCode)> {
        vec![(field.to_string(), code)]
    }

    /// The code of a [`StartupError::ConfigParse`].
    fn parse_error_code(text: &str) -> ValidationErrorCode {
        match parse(text).unwrap_err() {
            StartupError::ConfigParse { source, .. } => source.code,
            other => panic!("expected ConfigParse, got: {other}"),
        }
    }

    #[test]
    fn identity_mismatch_is_rejected() {
        let err = ReloadPlan::parse(&two_group_config(NGINX, APACHE), "apache", &fake_path())
            .unwrap_err();

        let StartupError::ConfigInvalid { source, .. } = &err else {
            panic!("expected ConfigInvalid, got: {err}");
        };
        assert_eq!(source.errors.len(), 1, "{err}");
        assert_eq!(source.errors[0].field, "watcher_id");
        assert_eq!(source.errors[0].code, ValidationErrorCode::InvalidWatcherId);
        let message = err.to_string();
        assert!(message.contains("apache"), "{message}");
        assert!(message.contains("nginx"), "{message}");
    }

    #[test]
    fn wrong_schema_version_is_rejected() {
        let text =
            two_group_config(NGINX, APACHE).replace("schema_version = 1", "schema_version = 2");
        assert_eq!(
            invalid(&text),
            one_error("schema_version", ValidationErrorCode::ValueOutOfRange)
        );
    }

    /// `from_toml` reads the version first, so a newer file that also adds a
    /// field is reported as a version mismatch, not as malformed TOML.
    #[test]
    fn newer_schema_with_a_new_field_gets_the_version_error() {
        let text = two_group_config(NGINX, APACHE)
            .replace("schema_version = 1", "schema_version = 2\nnew_field = true");
        assert_eq!(
            invalid(&text),
            one_error("schema_version", ValidationErrorCode::ValueOutOfRange)
        );
    }

    #[test]
    fn unknown_field_is_rejected() {
        let text = two_group_config(NGINX, APACHE).replace(
            "watcher_id = \"nginx\"",
            "watcher_id = \"nginx\"\nsurprise = true",
        );
        assert_eq!(
            parse_error_code(&text),
            ValidationErrorCode::TomlSyntaxError
        );
    }

    #[test]
    fn malformed_toml_is_rejected() {
        assert_eq!(
            parse_error_code("schema_version = "),
            ValidationErrorCode::TomlSyntaxError
        );
    }

    #[cfg(unix)]
    #[test]
    fn relative_program_is_rejected() {
        let text =
            two_group_config(NGINX, APACHE).replace(&NGINX.escape_default().to_string(), "nginx");
        assert_eq!(
            invalid(&text),
            one_error("reload[0].command[0]", ValidationErrorCode::InvalidCommand)
        );
    }

    /// Windows accepts any program a Windows install accepts, absolute or
    /// not; PowerShell resolves a bare name.
    #[cfg(windows)]
    #[test]
    fn relative_program_is_accepted_on_windows() {
        for program in ["nginx", "relative/nginx"] {
            let text = two_group_config(NGINX, APACHE)
                .replace(&NGINX.escape_default().to_string(), program);
            let plan = parse(&text).unwrap();
            let id = plan.command_for(ARN_A).unwrap();
            assert_eq!(plan.command(id)[0], program);
        }
    }

    #[test]
    fn empty_command_is_rejected() {
        let text = format!(
            "schema_version = 1\n\
             watcher_id = \"nginx\"\n\
             \n\
             [[reload]]\n\
             command = []\n\
             certificate_arns = [\"{ARN_A}\"]\n"
        );
        assert_eq!(
            invalid(&text),
            one_error("reload[0].command", ValidationErrorCode::EmptyCommand)
        );
    }

    /// Every error in the file comes back in one `ConfigInvalid`, not just the
    /// first.
    #[test]
    fn every_validation_error_is_reported_together() {
        let text = &format!(
            "schema_version = 1\n\
             watcher_id = \"apache\"\n\
             \n\
             [[reload]]\n\
             command = [\"nginx;id\"]\n\
             certificate_arns = [\"not-an-arn\"]\n\
             \n\
             [[reload]]\n\
             command = [\"{}\"]\n\
             certificate_arns = []\n",
            APACHE.escape_default()
        );

        assert_eq!(
            invalid(text),
            vec![
                (
                    "watcher_id".to_string(),
                    ValidationErrorCode::InvalidWatcherId
                ),
                (
                    "reload[0].command[0]".to_string(),
                    ValidationErrorCode::InvalidCommand
                ),
                (
                    "reload[0].certificate_arns[0]".to_string(),
                    ValidationErrorCode::InvalidCertificateArn
                ),
                (
                    "reload[1].certificate_arns".to_string(),
                    ValidationErrorCode::MissingRequiredField
                ),
            ]
        );

        let message = parse(text).unwrap_err().to_string();
        assert!(message.contains("4 error(s)"), "{message}");
    }

    /// A watcher must not start with no mappings.
    #[test]
    fn empty_reload_list_is_rejected() {
        assert_eq!(
            invalid("schema_version = 1\nwatcher_id = \"nginx\"\n"),
            one_error("reload", ValidationErrorCode::MissingRequiredField)
        );
    }

    #[test]
    fn reload_entry_without_certificates_is_rejected() {
        let text = format!(
            "schema_version = 1\n\
             watcher_id = \"nginx\"\n\
             \n\
             [[reload]]\n\
             command = [\"{}\"]\n\
             certificate_arns = []\n",
            NGINX.escape_default()
        );
        assert_eq!(
            invalid(&text),
            one_error(
                "reload[0].certificate_arns",
                ValidationErrorCode::MissingRequiredField
            )
        );
    }

    #[test]
    fn an_arn_in_two_entries_is_rejected() {
        let text = format!(
            "schema_version = 1\n\
             watcher_id = \"nginx\"\n\
             \n\
             [[reload]]\n\
             command = [\"{nginx}\"]\n\
             certificate_arns = [\"{ARN_A}\"]\n\
             \n\
             [[reload]]\n\
             command = [\"{apache}\"]\n\
             certificate_arns = [\"{ARN_B}\", \"{ARN_A}\"]\n",
            nginx = NGINX.escape_default(),
            apache = APACHE.escape_default(),
        );
        assert_eq!(
            invalid(&text),
            one_error(
                "reload[1].certificate_arns[1]",
                ValidationErrorCode::DuplicateCertificateArn
            )
        );
    }

    /// One group running `command` for `arn`. Each string is rendered by
    /// `toml` itself, so any element, including one with a quote or a control
    /// character, reaches the parser verbatim.
    fn one_group_config(command: &[&str], arn: &str) -> String {
        let toml_string = |s: &str| toml::Value::String(s.to_string()).to_string();
        let elements: Vec<String> = command.iter().map(|e| toml_string(e)).collect();
        format!(
            "schema_version = 1\n\
             watcher_id = \"nginx\"\n\
             \n\
             [[reload]]\n\
             command = [{}]\n\
             certificate_arns = [{}]\n",
            elements.join(", "),
            toml_string(arn),
        )
    }

    #[test]
    fn command_elements_inside_the_charset_are_accepted() {
        let plan = parse(&one_group_config(
            &[NGINX, "-s", "reload", "a=b+c@d"],
            ARN_A,
        ))
        .unwrap();
        assert_eq!(plan.command_count(), 1);
    }

    /// `common`'s `COMMAND_ELEMENT_RE` includes the space, so an element made
    /// only of spaces is accepted. The removed placeholder rejected it.
    #[test]
    fn whitespace_only_command_elements_are_accepted() {
        let plan = parse(&one_group_config(&[NGINX, " "], ARN_A)).unwrap();
        assert_eq!(plan.command(0).to_vec(), argv(&[NGINX, " "]));
    }

    #[test]
    fn command_elements_outside_the_charset_are_rejected() {
        for element in [
            "reload;id",
            "$(id)",
            "`id`",
            "a|b",
            "a&b",
            "a>b",
            "it's",
            "\"quoted\"",
            "a*",
            "a\nb",
            "a\rb",
            "a\0b",
            "a\tb",
            "%PATH%",
            "",
        ] {
            let text = one_group_config(&[NGINX, element], ARN_A);
            assert_eq!(
                invalid(&text),
                one_error("reload[0].command[1]", ValidationErrorCode::InvalidCommand),
                "{element:?}"
            );
        }
    }

    #[test]
    fn program_outside_the_charset_is_rejected() {
        let program = format!("{NGINX};id");
        assert_eq!(
            invalid(&one_group_config(&[&program, "-s", "reload"], ARN_A)),
            one_error("reload[0].command[0]", ValidationErrorCode::InvalidCommand)
        );
    }

    #[test]
    fn well_formed_arns_in_other_partitions_are_accepted() {
        for arn in [
            "arn:aws-cn:acm:cn-north-1:123456789012:certificate/1234abcd-12ab-34cd-56ef-1234567890ab",
            "arn:aws-us-gov:acm:us-gov-west-1:123456789012:certificate/a_b+c=d,e.f@g/h-i",
        ] {
            parse(&one_group_config(&[NGINX], arn)).unwrap();
        }
    }

    #[test]
    fn malformed_arns_are_rejected() {
        for arn in [
            "not-an-arn",
            "arn:x:acm:r:a:certificate/id",
            "arn:aws:acm:us-west-2:12345678901:certificate/id",
            "arn:aws:acm:us-west-2:1234567890123:certificate/id",
            "arn:aws:acm:us-west-2:12345678901a:certificate/id",
            "arn::acm:us-west-2:123456789012:certificate/id",
            "arn:a$ws:acm:us-west-2:123456789012:certificate/id",
            "arn:aws:iam:us-west-2:123456789012:certificate/id",
            "arn:aws:acm::123456789012:certificate/id",
            "arn:aws:acm:us-west-2:123456789012:certificate/",
            "arn:aws:acm:us-west-2:123456789012:role/id",
            "arn:aws:acm:us-west-2:123456789012:certificate/id:extra",
            "arn:aws:acm:us-west-2:123456789012:certificate/i d",
            "arn:aws:acm:us-west-2:123456789012:certificate/id;x",
        ] {
            assert_eq!(
                invalid(&one_group_config(&[NGINX], arn)),
                one_error(
                    "reload[0].certificate_arns[0]",
                    ValidationErrorCode::InvalidCertificateArn
                ),
                "{arn}"
            );
        }
    }

    // -- load() --

    #[test]
    fn loads_from_disk() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("watcher.config.toml");
        fs::write(&path, two_group_config(NGINX, APACHE)).unwrap();

        let plan = ReloadPlan::load(&path, "nginx").unwrap();

        assert_eq!(plan.command_count(), 2);
    }

    #[test]
    fn missing_file_names_the_path() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("nginx").join("watcher.config.toml");

        let err = ReloadPlan::load(&path, "nginx").unwrap_err();

        assert!(matches!(err, StartupError::ConfigRead { .. }));
        assert!(err.to_string().contains("watcher.config.toml"), "{err}");
    }

    #[test]
    fn oversized_file_is_rejected() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("watcher.config.toml");
        let mut text = two_group_config(NGINX, APACHE);
        text.push_str(&format!("# {}\n", "x".repeat(MAX_CONFIG_BYTES as usize)));
        fs::write(&path, text).unwrap();

        let err = ReloadPlan::load(&path, "nginx").unwrap_err();

        assert!(matches!(err, StartupError::ConfigTooLarge { .. }));
    }
}
