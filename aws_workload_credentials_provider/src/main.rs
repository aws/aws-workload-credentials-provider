mod cli;

use aws_workload_credentials_provider_common::config::validator::ConfigValidator;
#[cfg(windows)]
use aws_workload_credentials_provider_common::constants::RELOAD_SCRIPT_NAME;
use clap::Parser;
use cli::{AcmAction, Cli, Commands, SmAction};
#[cfg(windows)]
use std::path::PathBuf;

#[cfg(unix)]
use aws_workload_credentials_provider_common::{
    config::{sudoers, systemd},
    constants::{DEFAULT_CONFIG_PATH, SUDOERS_PATH},
    logging::{init_logger, log_dir},
};

#[cfg(windows)]
use aws_workload_credentials_provider_common::{
    config::types::ValidatedConfig, logging::default_config_path,
};

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        #[cfg(unix)]
        Commands::SetupConfigBasedPermissions { config, sudoers } => {
            setup_config_based_permissions(config, sudoers)
        }
        #[cfg(windows)]
        Commands::SetupConfigBasedPermissions { config } => setup_config_based_permissions(config),

        Commands::Acm { action } => match action {
            AcmAction::Start { config } => acm_start(config),
            #[cfg(unix)]
            AcmAction::Reload { config, sudoers } => acm_reload(config, sudoers),
            #[cfg(windows)]
            AcmAction::Reload { config } => acm_reload(config),
        },
        Commands::Sm { action } => match action {
            SmAction::Start { config } => sm_start(config),
        },
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn acm_start(config_path: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = resolve_config_path(config_path)?;
    let validated = ConfigValidator::new().validate(config_path.as_deref())?;

    let acm_config = match validated.acm {
        None => {
            eprintln!("ACM is not configured");
            return Ok(());
        }
        Some(config) if !config.enabled => {
            eprintln!("ACM is explicitly disabled");
            return Ok(());
        }
        Some(config) => config,
    };

    #[cfg(unix)]
    {
        let log_dir = log_dir()?;
        init_logger(
            validated.logging.log_level,
            validated.logging.log_to_file,
            "acm_provider",
            &log_dir,
        )?;
        aws_certificatemanager_provider::run_acm(acm_config)
    }

    #[cfg(windows)]
    {
        use aws_workload_credentials_provider_common::constants::ACM_SERVICE_NAME;
        use aws_workload_credentials_provider_common::win_service::{self, ServiceKind};
        use tokio_util::sync::CancellationToken;

        let token = CancellationToken::new();
        let token_for_workload = token.clone();
        win_service::run_service(ServiceKind::Acm, validated.logging, token, move || {
            aws_certificatemanager_provider::acm_workload(acm_config, token_for_workload)
        })
        .map_err(|e| -> Box<dyn std::error::Error> { e })
    }
}

fn sm_start(config_path: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = resolve_config_path(config_path)?;
    let validated = ConfigValidator::new().validate(config_path.as_deref())?;

    if !validated.secrets_manager.enabled {
        eprintln!("Secrets Manager is not enabled");
        return Ok(());
    }

    #[cfg(unix)]
    {
        let log_dir = log_dir()?;
        init_logger(
            validated.logging.log_level,
            validated.logging.log_to_file,
            "secrets_manager_provider",
            &log_dir,
        )?;
        aws_secretsmanager_provider::run_sm(validated)
    }

    #[cfg(windows)]
    {
        use aws_workload_credentials_provider_common::win_service::{self, ServiceKind};
        use tokio_util::sync::CancellationToken;

        let token = CancellationToken::new();
        let token_for_workload = token.clone();
        let logging = validated.logging.clone();
        win_service::run_service(ServiceKind::Sm, logging, token, move || {
            aws_secretsmanager_provider::sm_workload(validated, token_for_workload)
        })
        .map_err(|e| -> Box<dyn std::error::Error> { e })
    }
}

#[cfg(unix)]
fn acm_reload(
    config_path: Option<String>,
    sudoers: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use aws_workload_credentials_provider_common::constants::{
        ACM_SERVICE_NAME_LINUX, PROVIDER_GROUP,
    };
    use std::os::unix::fs::PermissionsExt;

    // SAFETY: geteuid() is a simple read-only syscall with no side effects.
    if unsafe { libc::geteuid() } != 0 {
        return Err("This command must be run as root".into());
    }

    if let Some(ref config) = config_path {
        // Validate before overwriting the live config
        ConfigValidator::new().validate(Some(config.as_str()))?;

        std::fs::copy(config, DEFAULT_CONFIG_PATH)?;
        std::fs::set_permissions(DEFAULT_CONFIG_PATH, std::fs::Permissions::from_mode(0o440))?;

        let status = std::process::Command::new("chown")
            .arg(format!("root:{PROVIDER_GROUP}"))
            .arg(DEFAULT_CONFIG_PATH)
            .status()?;
        if !status.success() {
            return Err(format!("chown failed with {status}").into());
        }
    }

    // Re-generate sudoers from the (possibly new) config at the standard path
    setup_config_based_permissions(None, sudoers)?;

    // Reload systemd to pick up any changes to the drop-in override
    let status = std::process::Command::new("systemctl")
        .arg("daemon-reload")
        .status()?;
    if !status.success() {
        return Err(format!("systemctl daemon-reload failed with {status}").into());
    }

    let status = std::process::Command::new("systemctl")
        .args(["restart", ACM_SERVICE_NAME_LINUX])
        .status()?;

    if !status.success() {
        return Err(format!("systemctl restart failed with {status}").into());
    }

    Ok(())
}

#[cfg(windows)]
fn acm_reload(config_path: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let current_exec_path = std::env::current_exe()?;
    let reload_script_path = current_exec_path
        .parent()
        .ok_or("Unable to parse current executable path")?
        .join(RELOAD_SCRIPT_NAME);
    let reload_script_path_str = reload_script_path
        .to_str()
        .ok_or("Unable to parse reload script path to valid unicode str")?;

    let status = match config_path {
        None => std::process::Command::new("PowerShell")
            .args(["-File", reload_script_path_str])
            .status()?,
        Some(cfg) => std::process::Command::new("PowerShell")
            .args(["-File", reload_script_path_str, "-Config", &cfg])
            .status()?,
    };

    if !status.success() {
        return Err(format!("reload failed with {status}").into());
    }

    Ok(())
}

#[cfg(unix)]
fn setup_config_based_permissions(
    config_path: Option<String>,
    sudoers: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // SAFETY: geteuid() is a simple read-only syscall with no side effects.
    if unsafe { libc::geteuid() } != 0 {
        return Err("This command must be run as root".into());
    }

    let config_path = resolve_config_path(config_path)?;
    let validated = ConfigValidator::new().validate(config_path.as_deref())?;
    let acm_config = match validated.acm {
        Some(acm) if acm.enabled => acm,
        _ => {
            println!("No ACM configuration found or ACM is disabled, skipping permissions setup");
            return Ok(());
        }
    };

    if sudoers {
        println!("Generating sudoers file");
        sudoers::generate_and_install(&acm_config, config_path.as_deref())?;
        println!("Sudoers file written to {}", SUDOERS_PATH);
    } else {
        println!("Skipping sudoers file generation");
    }

    // Generate systemd drop-in override with ReadWriteDirectories for cert paths
    systemd::generate_and_install(&acm_config)?;
    println!(
        "Systemd override written to {}",
        systemd::override_path().display()
    );

    Ok(())
}

#[cfg(windows)]
/// Validates the provider config and outputs a JSON object describing the capabilities
/// the Windows installer (install.ps1) should enable, plus any ACM certificate
/// permissions it needs to apply.
fn setup_config_based_permissions(
    config_path: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = config_path
        .or_else(|| {
            default_config_path()
                .ok()
                .and_then(|p| p.to_str().map(String::from))
        })
        .ok_or("PROGRAMDATA environment variable is not set")?;
    let validator = ConfigValidator::new();
    let validated = validator.validate(Some(config_path.as_str()))?;

    println!("{}", generate_installer_json(&validated));
    Ok(())
}

#[cfg(windows)]
/// Serializes the validated config into JSON for the PowerShell installer.
fn generate_installer_json(validated: &ValidatedConfig) -> String {
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct InstallerOutput {
        enabled_capabilities: Vec<&'static str>,
        certificates: Vec<CertEntry>,
    }

    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct CertEntry {
        certificate_arn: String,
        certificate_path: PathBuf,
        private_key_path: PathBuf,
        chain_path: Option<PathBuf>,
        refresh_command: String,
    }

    let mut enabled_capabilities: Vec<&'static str> = Vec::new();
    if validated.secrets_manager.enabled {
        enabled_capabilities.push("secrets-manager");
    }

    let certificates: Vec<CertEntry> = match &validated.acm {
        Some(acm) if acm.enabled => {
            enabled_capabilities.push("acm");
            acm.certificates
                .values()
                .map(|cert| CertEntry {
                    certificate_arn: cert.certificate_arn.clone(),
                    certificate_path: cert.certificate_path.clone(),
                    private_key_path: cert.private_key_path.clone(),
                    chain_path: cert.chain_path.clone(),
                    refresh_command: cert.refresh_command.clone().unwrap_or_default(),
                })
                .collect()
        }
        _ => Vec::new(),
    };

    serde_json::to_string(&InstallerOutput {
        enabled_capabilities,
        certificates,
    })
    .unwrap()
}

/// Resolves the config file path: uses the given path if provided,
/// falls back to the default path if it exists on disk, or None for defaults.
fn resolve_config_path(path: Option<String>) -> Result<Option<String>, Box<dyn std::error::Error>> {
    if let Some(p) = path {
        return Ok(Some(p));
    }

    #[cfg(unix)]
    {
        if std::path::Path::new(DEFAULT_CONFIG_PATH).exists() {
            return Ok(Some(DEFAULT_CONFIG_PATH.to_string()));
        }
    }

    #[cfg(windows)]
    {
        let default = default_config_path()?;
        if default.exists() {
            return Ok(default.to_str().map(String::from));
        }
    }

    Ok(None)
}
