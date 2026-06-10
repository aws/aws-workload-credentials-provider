<#
.SYNOPSIS
    Reloads the ACM certificate configuration for the AWS Workload Credentials Provider on Windows.

.DESCRIPTION
    Performs a reload of the ACM certificate config without a full reinstall
    Leaves binary and Windows service in place:
    1. Parse the old config to identify existing certificate tasks and permissions
    2. Validate and load the new config
    3. Stop the ACM provider service
    4. Unregister old certificate scheduled tasks
    5. Remove ACM service account permissions from old certificate files
    6. Grant ACM service account permissions on new certificate files
    7. Register new certificate scheduled tasks
    8. Restart the ACM provider service

.PARAMETER Config
    Path to the new config.toml file. If omitted, re-validates and re-applies
    the existing config in place.

.EXAMPLE
    .\acmReloadConfig.ps1
    .\acmReloadConfig.ps1 -Config .\config.toml
#>

param(
    [string]$Config
)

$ErrorActionPreference = "Stop"
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path

. "$SCRIPT_DIR\common.ps1"

Assert-Administrator

$providerBin = "$BIN_DIR\$PROVIDER_EXE"
$configPath = "$PROVIDER_DIR\$CONFIG_FILE_NAME"

if (-not (Test-Path $providerBin)) {
    Write-Error "Provider binary not found at $providerBin. Is the provider installed?"
}

# --- Step 1: Parse old config to capture existing certificate state ---

Write-Step "Parse current config"

$oldConfig = Get-Config -Config $configPath -ProviderBinary $providerBin

# --- Step 2: Validate and load new config ---

Write-Step "Parse new config"

if ($Config) {
    $newConfig = Confirm-Config -Config $Config -ProviderBinary $providerBin
    # Verify ACM is enabled in the new config
    if ($newConfig.enabledCapabilities -notcontains "acm") {
        Write-Error "ACM is not enabled in the new config. This script only reloads ACM certificate configuration."
    }
    # Copy new config into place
    Copy-Item -Path $Config -Destination $configPath -Force
    Write-Host "  New config copied to $configPath"
} else {
    if (-not (Test-Path $configPath)) {
        Write-Error "No config found at $configPath. Pass -Config to provide one."
    }
    $newConfig = Confirm-Config -Config $configPath -ProviderBinary $providerBin
}


# --- Step 3: Apply config file ACLs ---

Write-Step "Configure config file permissions"

# Apply config file ACLs so an edited-by-hand config gets re-locked on reinstall
icacls $configPath /inheritance:r /Q | Out-Null
icacls $configPath /grant "SYSTEM:F" /Q | Out-Null
icacls $configPath /grant "BUILTIN\Administrators:F" /Q | Out-Null
icacls $configPath /grant "${ACM_SERVICE_ACCOUNT}:R" /Q | Out-Null
# Also grant SM service account read if secrets-manager is enabled
if ($newConfig.enabledCapabilities -contains "secrets-manager") {
    icacls $configPath /grant "${ASM_SERVICE_ACCOUNT}:R" /Q | Out-Null
}
Write-Host "  Locked down ACLs on $configPath"

# --- Step 4: Stop ACM service ---

Write-Step "Stop ACM service"

if (Stop-ProviderService -Name $ACM_SERVICE) {
    Write-Host "  Stopped $ACM_SERVICE"
} else {
    Write-Host "  Service $ACM_SERVICE not found (skipped)"
}

# --- Step 5: Remove old certificate scheduled tasks and permissions ---

Remove-CertificateTasksPermissions $oldConfig

# --- Step 6: Add new certificate permissions and scheduled tasks ---

Add-CertificateTasksPermissions $newConfig

# --- Step 7: Restart ACM service ---

Write-Step "Start ACM service"

& sc.exe start $ACM_SERVICE | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Error "sc.exe start failed for $ACM_SERVICE (exit $LASTEXITCODE)"
}
Write-Host "  Started $ACM_SERVICE"

Write-Host "`n ACM certificate config reload complete." -ForegroundColor Green
