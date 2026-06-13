<#
.SYNOPSIS
    Uninstalls the AWS Workload Credentials Provider from Windows.

.DESCRIPTION
    Reverses install.ps1:
    1. Stop and remove services via sc.exe
    2. Remove install directory (binary and configs)
    3. Preserve provider data directory (config and logs) by default

.PARAMETER RemoveAll
    Also remove C:\ProgramData\AWS\WorkloadCredentialsProvider\ (config and logs).
    By default, data is preserved for record keeping.

.EXAMPLE
    .\uninstall.ps1
    .\uninstall.ps1 -RemoveAll
#>

param(
    [switch]$RemoveAll
)

$ErrorActionPreference = "Stop"
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path

. "$SCRIPT_DIR\common.ps1"

Assert-Administrator

$configPath = "$PROVIDER_DIR\$CONFIG_FILE_NAME"
$providerBin = "$BIN_DIR\$PROVIDER_EXE"

# Parse config before stopping services (needs the binary which lives in the
# install directory that gets removed later).
$jsonOutput = $null
if ((Test-Path $configPath) -and (Test-Path $providerBin)) {
    try {
        $jsonOutput = & $providerBin setup-config-based-permissions --config $configPath 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Config parsing failed (exit code $LASTEXITCODE) - skipping ACM cleanup"
            $jsonOutput = $null
        }
    } catch {
        Write-Warning "Failed to run config parser: $_"
        $jsonOutput = $null
    }
}

Write-Step "Stop and remove services"

foreach ($svc in @($ACM_SERVICE, $ASM_SERVICE)) {
    try {
        if (-not (Stop-ProviderService -Name $svc)) {
            Write-Host "  Service not found: $svc (skipped)"
            continue
        }
        sc.exe delete $svc | Out-Null
        Write-Host "  Removed service: $svc"
    } catch {
        Write-Warning "Failed to remove service ${svc}: $_"
    }
}

if ($jsonOutput) {
    Write-Step "Remove config-based permissions"

    $acmConfig = ($jsonOutput -join "`n") | ConvertFrom-Json
    foreach ($cert in $acmConfig.certificates) {
        try {
            Remove-CertificatePermissions $cert
        } catch {
            Write-Warning "Failed to clean up permissions for $($cert.certificateArn): $_"
        }
    }
} elseif (-not (Test-Path $configPath) -or -not (Test-Path $providerBin)) {
    Write-Host "  No config or binary found - skipping ACM permission cleanup"
}

Write-Step "Remove scheduled tasks"

if (Get-ScheduledTask -TaskName $SEED_TOKEN_TASK -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $SEED_TOKEN_TASK -Confirm:$false
    Write-Host "  Removed scheduled task: $SEED_TOKEN_TASK"
} else {
    Write-Host "  Scheduled task not found: $SEED_TOKEN_TASK (skipped)"
}

Write-Step "Remove SSRF token"

if (Test-Path $SSRF_TOKEN_FILE) {
    Remove-Item -Path $SSRF_TOKEN_FILE -Force
    Write-Host "  Removed SSRF token file: $SSRF_TOKEN_FILE"
} else {
    Write-Host "  Not found: $SSRF_TOKEN_FILE (skipped)"
}

Write-Step "Remove install directory"

if (Test-Path $INSTALL_DIR) {
    Remove-Item -Path $INSTALL_DIR -Recurse -Force
    Write-Host "  Removed $INSTALL_DIR"
} else {
    Write-Host "  Not found: $INSTALL_DIR (skipped)"
}

Write-Step "Remove provider directory"

if (-not (Test-Path $PROVIDER_DIR)) {
    Write-Host "  Not found: $PROVIDER_DIR (skipped)"
} elseif ($RemoveAll) {
    Remove-Item -Path $PROVIDER_DIR -Recurse -Force
    Write-Host "  Removed $PROVIDER_DIR"
} else {
    Write-Host "  Kept $PROVIDER_DIR (config and logs preserved)"
    Write-Host "  Use -RemoveAll to delete"
}

Write-Host ""
Write-Host "Uninstall complete." -ForegroundColor Green
