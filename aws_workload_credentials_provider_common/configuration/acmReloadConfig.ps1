<#
.SYNOPSIS
    Reloads the ACM certificate configuration for the AWS Workload Credentials Provider on Windows.

.DESCRIPTION
    Performs a reload of the ACM certificate config without a full reinstall
    Leaves binary and Windows service in place:
    1. Validate the new or existing config and verify ACM is enabled
    2. Stop the ACM provider service
    3. Remove old certificate tasks and permissions while the old config is on disk
    4. Replace the config with the validated copy when -Config is provided
    5. Apply config file ACLs
    6. Grant ACM service account permissions and register scheduled tasks
    7. Restart the ACM provider service, also when steps 3-6 fail

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

# Trust the provider folder, and without -Config the existing config, by the same
# rule as install.ps1
Assert-AdminControlledProviderDir -NoCreate
$oldConfigProblem = $null
if (Test-ExistingConfig) {
    if ($Config) {
        # The new config replaces it below
        $oldConfigProblem = Get-ExistingConfigProblem -Path $configPath
    } else {
        Assert-AdminControlledConfig -Path $configPath
    }
}

# --- Step 1: Validate and load config ---

if ($Config) {
    $newConfig = Confirm-Config -Config $Config -ProviderBinary $providerBin
} else {
    if (-not (Test-Path $configPath)) {
        Write-Error "No config found at $configPath. Pass -Config to provide one."
    }
    $newConfig = Confirm-Config -Config $configPath -ProviderBinary $providerBin
}

# Verify ACM is enabled in the config before stopping the running ACM service.
if ($newConfig.enabledCapabilities -notcontains "acm") {
    Write-Error "ACM is not enabled in the new config. This script only reloads ACM certificate configuration."
}

# Parse the trusted old config after validation so failed new configs leave the
# running service and its permissions untouched.
$oldConfig = if ($oldConfigProblem) { $null } else { Get-Config -Config $configPath -ProviderBinary $providerBin }

# --- Step 2: Stop ACM service ---

Write-Step "Stop ACM service"

if (Stop-ProviderService -Name $ACM_SERVICE) {
    Write-Host "  Stopped $ACM_SERVICE"
} else {
    Write-Host "  Service $ACM_SERVICE not found (skipped)"
}

# --- Steps 3-6: Replace the config, certificate tasks and permissions ---

# A failure in these steps still restarts ACM below rather than leaving
# certificate serving down.
$applyError = $null
try {
    # --- Step 3: Remove old certificate tasks and permissions ---

    # Remove them while the old config is still on disk: if this fails, the
    # config is not replaced, so a rerun finds the same grants and tasks. A
    # failure after the replacement is fixed by rerunning, which re-applies the
    # new config. Until then the new config's certificates may have no grants.
    if (-not $oldConfigProblem) {
        Remove-CertificateTasksPermissions $oldConfig
    }

    # --- Step 4: Replace config with validated copy when requested ---

    if ($Config) {
        Copy-ConfigIntoPlace -Source $Config -Destination $configPath -ReplaceUntrusted:([bool]$oldConfigProblem)
        Write-Host "  New config copied to $configPath"
        if ($oldConfigProblem) {
            # Cleanup was intentionally skipped because the previous config was untrusted.
            Write-Warning "Replaced the old ${configPath}, which administrators didn't control: $oldConfigProblem. Renewal tasks from it (AWSWorkloadCredentialsProvider-Reload-*) and the permissions it granted on certificate files were not removed. The tasks run as SYSTEM, so remove the ones the new config doesn't need."
        }
    }

    # --- Step 5: Apply config file ACLs ---

    Write-Step "Configure config file permissions"

    # Apply config file ACLs so an edited-by-hand config gets re-locked on reinstall
    # A new config is owned by whoever ran this, who may be an administrator only
    # through a domain group, which a later trust check would refuse
    Invoke-Icacls $configPath /setowner "*S-1-5-32-544" /Q
    Invoke-Icacls $configPath /inheritance:r /Q
    Invoke-Icacls $configPath /grant "SYSTEM:F" /Q
    Invoke-Icacls $configPath /grant "BUILTIN\Administrators:F" /Q
    Invoke-Icacls $configPath /grant "${ACM_SERVICE_ACCOUNT}:R" /Q
    # Also grant SM service account read if secrets-manager is enabled
    if ($newConfig.enabledCapabilities -contains "secrets-manager") {
        Invoke-Icacls $configPath /grant "${ASM_SERVICE_ACCOUNT}:R" /Q
    }
    Write-Host "  Locked down ACLs on $configPath"

    # --- Step 6: Grant new certificate permissions and register scheduled tasks ---

    Add-CertificateTasksPermissions $newConfig
} catch {
    $applyError = $_
}

# --- Step 7: Restart ACM service ---

Write-Step "Start ACM service"

& sc.exe start $ACM_SERVICE | Out-Null
if ($LASTEXITCODE -ne 0) {
    $startError = "sc.exe start failed for $ACM_SERVICE (exit $LASTEXITCODE); $ACM_SERVICE is stopped."
    if ($applyError) {
        Write-Error "Applying the new config failed: $applyError. $startError Fix the errors and rerun this script."
    }
    Write-Error $startError
}
Write-Host "  Started $ACM_SERVICE"

# This script only restarts ACM, so Secrets Manager may still run with the old settings
if ($oldConfigProblem -and (Get-Service -Name $ASM_SERVICE -ErrorAction SilentlyContinue | Where-Object Status -ne 'Stopped')) {
    Write-Warning "$ASM_SERVICE may still use settings from the old config. Restart it."
}

if ($applyError) {
    Write-Error "Restarted $ACM_SERVICE, but applying the new config failed: $applyError. The config, certificate permissions or scheduled tasks may be incomplete; fix the error and rerun this script."
}

Write-Host "`n ACM certificate config reload complete." -ForegroundColor Green
