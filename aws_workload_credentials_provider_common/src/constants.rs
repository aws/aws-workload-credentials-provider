//! Common constants for the AWS Workload Credentials Provider.

/// Name of the provider binary.
pub const PROVIDER_NAME: &str = "aws-workload-credentials-provider";

/// System user the provider runs as.
pub const PROVIDER_USER: &str = "aws-workload-credentials-provider";

/// Primary group for provider-created files.
pub const PROVIDER_GROUP: &str = "awscreds";

/// Provider installation directory (Linux).
#[cfg(unix)]
pub const PROVIDER_HOME_DIR: &str = "/opt/aws/workload-credentials-provider";

/// Linux systemd service name for the ACM provider.
#[cfg(unix)]
pub const ACM_SERVICE_NAME_LINUX: &str = "aws-workload-credentials-provider-acm";

/// Path to the generated sudoers file for ACM reload commands.
/// Must be kept in sync with PROVIDER_NAME.
pub const SUDOERS_PATH: &str = "/etc/sudoers.d/aws-workload-credentials-provider";

/// Systemd drop-in override directory for the ACM service.
/// Used to dynamically add ReadWriteDirectories based on customer cert paths.
pub const ACM_SERVICE_OVERRIDE_DIR: &str =
    "/etc/systemd/system/aws-workload-credentials-provider-acm.service.d";

/// Filename for the generated ReadWriteDirectories drop-in.
pub const ACM_SERVICE_OVERRIDE_FILE: &str = "cert-paths.conf";

/// Default configuration file path (Linux).
#[cfg(unix)]
pub const DEFAULT_CONFIG_PATH: &str = "/etc/aws-workload-credentials-provider/config.toml";

/// Default configuration directory (Linux). Parent of DEFAULT_CONFIG_PATH.
#[cfg(unix)]
pub const CONFIG_DIR: &str = "/etc/aws-workload-credentials-provider/";

/// Windows Service name for the Secrets Manager HTTP server. Must match
/// the name used with `sc.exe create` in the Windows installer.
pub const SM_SERVICE_NAME: &str = "AWSWorkloadCredentialsProvider-SecretsManager";

/// Windows Service name for the ACM certificate refresher. Must match
/// the name used with `sc.exe create` in the Windows installer.
pub const ACM_SERVICE_NAME: &str = "AWSWorkloadCredentialsProvider-ACM";

/// Path for powershell script used to execute acm config reload
/// Can be called standalone or with provider_exe acm reload [-ConfigFile] [file path]
#[cfg(windows)]
pub const RELOAD_SCRIPT_NAME: &str = "acmReloadConfig.ps1";
