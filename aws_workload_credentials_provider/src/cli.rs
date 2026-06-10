use clap::{Parser, Subcommand};

use aws_workload_credentials_provider_common::constants::PROVIDER_NAME;

#[derive(Parser)]
#[command(name = PROVIDER_NAME)]
#[command(about = "AWS Workload Credentials Provider", version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Setup config-based permissions (sudoers, windows ACLs etc.)
    SetupConfigBasedPermissions {
        /// Path to the configuration file
        #[arg(short, long)]
        config: Option<String>,
        /// Skip sudoers file generation
        #[cfg(unix)]
        #[arg(long = "no-sudoers", action = clap::ArgAction::SetFalse, default_value_t = true)]
        sudoers: bool,
    },
    /// ACM certificate management
    Acm {
        #[command(subcommand)]
        action: AcmAction,
    },
    /// Secrets Manager HTTP server
    Sm {
        #[command(subcommand)]
        action: SmAction,
    },
}

#[derive(Subcommand)]
pub enum AcmAction {
    /// Start the ACM certificate sync service
    Start {
        /// Path to the configuration file
        #[arg(short, long)]
        config: Option<String>,
    },
    /// Reload the ACM certificate sync service (re-applies permissions and restarts)
    Reload {
        /// Path to the configuration file
        #[cfg_attr(not(windows), arg(short, long))]
        #[cfg_attr(windows, arg(short = 'C', long = "Config"))]
        config: Option<String>,
        /// Skip sudoers file generation
        #[cfg(unix)]
        #[arg(long = "no-sudoers", action = clap::ArgAction::SetFalse, default_value_t = true)]
        sudoers: bool,
    },
}

#[derive(Subcommand)]
pub enum SmAction {
    /// Start the Secrets Manager HTTP server service
    Start {
        /// Path to the configuration file
        #[arg(short, long)]
        config: Option<String>,
    },
}
