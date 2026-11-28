<#
.SYNOPSIS
    Uninstalls the AWS Workload Credentials Provider from Windows.

.DESCRIPTION
    Reverses install.ps1:
    1. Stop services
    2. Remove certificate ACLs from the previous config when it can be parsed; always remove reload scheduled tasks and warn when certificate cleanup may be needed
    3. Remove services via sc.exe, skipping any service that did not stop
    4. Remove the install directory when all service stops succeeded
    5. Preserve provider data directory (config and logs) by default

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
if ((Test-Path $configPath) -and (Test-Path $providerBin) -and (Test-AdminControlledConfig -Path $configPath)) {
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

Write-Step "Stop services"

$stopSucceeded = @{}
$serviceDeleteSkipped = $false
foreach ($svc in @($ACM_SERVICE, $ASM_SERVICE)) {
    try {
        if (-not (Stop-ProviderService -Name $svc)) {
            $stopSucceeded[$svc] = $true
            Write-Host "  Service not found: $svc (skipped)"
        } elseif ((Get-Service -Name $svc -ErrorAction SilentlyContinue).Status -eq 'Stopped') {
            $stopSucceeded[$svc] = $true
            Write-Host "  Stopped service: $svc"
        } else {
            $stopSucceeded[$svc] = $false
            Write-Warning "Service $svc did not stop; it will not be deleted."
        }
    } catch {
        $stopSucceeded[$svc] = $false
        Write-Warning "Failed to stop service ${svc}: $_. The service will not be deleted."
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
} elseif (-not (Test-Path $configPath)) {
    Write-Host "  No config found - skipping ACM permission cleanup"
} elseif (-not (Test-Path $providerBin)) {
    # Uninstall removes the binary only after this cleanup, so a missing
    # binary usually means an earlier uninstall already ran it.
    Write-Host "  Provider binary not found at $providerBin - skipping ACM permission cleanup"
} else {
    Write-Warning "ACM cleanup was skipped because the previous config is untrusted or could not be parsed. Certificate permissions may remain; review and remove them manually."
}

Write-Step "Remove services"

foreach ($svc in @($ACM_SERVICE, $ASM_SERVICE)) {
    try {
        if (-not (Get-Service -Name $svc -ErrorAction SilentlyContinue)) {
            Write-Host "  Service not found: $svc (skipped)"
            continue
        }
        if (-not $stopSucceeded[$svc]) {
            $serviceDeleteSkipped = $true
            Write-Warning "Skipping deletion of $svc because it was not stopped."
            continue
        }
        sc.exe delete $svc | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "sc.exe delete failed (exit $LASTEXITCODE)"
        }
        Write-Host "  Removed service: $svc"
    } catch {
        $serviceDeleteSkipped = $true
        Write-Warning "Failed to remove service ${svc}: $_"
    }
}

Write-Step "Remove scheduled tasks"

if (Get-ScheduledTask -TaskName $SEED_TOKEN_TASK -ErrorAction SilentlyContinue) {
    try {
        Unregister-ScheduledTask -TaskName $SEED_TOKEN_TASK -Confirm:$false
        Write-Host "  Removed scheduled task: $SEED_TOKEN_TASK"
    } catch {
        Write-Warning "Failed to remove scheduled task ${SEED_TOKEN_TASK}: $_"
    }
} else {
    Write-Host "  Scheduled task not found: $SEED_TOKEN_TASK (skipped)"
}

$reloadTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    $_.TaskName.StartsWith($RELOAD_TASK_PREFIX, [StringComparison]::Ordinal)
})
foreach ($task in $reloadTasks) {
    try {
        Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false
        Write-Host "  Removed scheduled task: $($task.TaskName)"
    } catch {
        Write-Warning "Failed to remove scheduled task $($task.TaskName): $_"
    }
}

Write-Step "Remove SSRF token"

if (Test-Path $SSRF_TOKEN_FILE) {
    Remove-Item -Path $SSRF_TOKEN_FILE -Force
    Write-Host "  Removed SSRF token file: $SSRF_TOKEN_FILE"
} else {
    Write-Host "  Not found: $SSRF_TOKEN_FILE (skipped)"
}

Write-Step "Remove install directory"

if ($serviceDeleteSkipped) {
    Write-Warning "Skipping removal of $INSTALL_DIR because a service could not be stopped or deleted. Fix the service and rerun uninstall."
} elseif (Test-Path $INSTALL_DIR) {
    Remove-Item -Path $INSTALL_DIR -Recurse -Force
    Write-Host "  Removed $INSTALL_DIR"
} else {
    Write-Host "  Not found: $INSTALL_DIR (skipped)"
}

Write-Step "Remove provider directory"

if (-not (Test-Path $PROVIDER_DIR)) {
    Write-Host "  Not found: $PROVIDER_DIR (skipped)"
} elseif ($RemoveAll -and $serviceDeleteSkipped) {
    # A rerun needs the config to remove the certificate permissions it granted.
    Write-Warning "Skipping removal of $PROVIDER_DIR because a service could not be stopped or deleted. Fix the service and rerun uninstall -RemoveAll."
} elseif ($RemoveAll) {
    Remove-Item -Path $PROVIDER_DIR -Recurse -Force
    Write-Host "  Removed $PROVIDER_DIR"
} else {
    Write-Host "  Kept $PROVIDER_DIR (config and logs preserved)"
    Write-Host "  Use -RemoveAll to delete"
}

Write-Host ""
Write-Host "Uninstall complete." -ForegroundColor Green
