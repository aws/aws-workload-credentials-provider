<#
.SYNOPSIS
    Installs the AWS Workload Credentials Provider on Windows.

.DESCRIPTION
    Steps:
    1. Install provider binary
    2. Create provider data directory
    3. Register services via sc.exe, switch to Virtual Service Accounts
    4. Configure provider directory ACLs
    5. Start services (unless -NoStart)

    If the provider services are already running, the installer exits without
    making changes to avoid dropping in-flight requests. Use the config
    reload path (ACM) to apply config updates.

    The provider binary self-registers with the Windows Service Control
    Manager via the `windows-service` crate; no external wrapper is used.

.PARAMETER NoStart
    Install and register services but don't start them.

.EXAMPLE
    .\install.ps1
    .\install.ps1 -Config .\config.toml
    .\install.ps1 -Config .\config.toml -NoStart
#>

param(
    [string]$Config,
    [switch]$NoStart
)

$ErrorActionPreference = "Stop"
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path

. "$SCRIPT_DIR\common.ps1"

$PROVIDER_SOURCE_DIR = Join-Path $SCRIPT_DIR "..\..\target\release"

function Test-ServicesRunning {
    $running = @($ACM_SERVICE, $ASM_SERVICE) | Where-Object {
        $svc = Get-Service -Name $_ -ErrorAction SilentlyContinue
        $svc -and $svc.Status -eq 'Running'
    }
    return $running
}

function Register-SeedTokenTask {
    param(
        [Parameter(Mandatory)][string]$TaskName,
        [Parameter(Mandatory)][string]$ScriptPath
    )

    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }

    $action = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-NoProfile -NonInteractive -File `"$ScriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
}

function Register-ProviderService {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][string]$Account,
        [Parameter(Mandatory)][string]$BinPath
    )

    # sc.exe uses `key= value` pairs (space after `=`).
    if (Get-Service -Name $Name -ErrorAction SilentlyContinue) {
        Stop-ProviderService -Name $Name | Out-Null
        & sc.exe delete $Name | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Error "sc.exe delete failed for $Name (exit $LASTEXITCODE)"
        }
        # Wait for service to be fully removed (up to 5 seconds)
        $retries = 0
        while ((Get-Service -Name $Name -ErrorAction SilentlyContinue) -and $retries -lt 5) {
            Start-Sleep -Seconds 1
            $retries++
        }
        if (Get-Service -Name $Name -ErrorAction SilentlyContinue) {
            Write-Error "Service $Name still exists after deletion. Close any open service handles and retry."
        }
    }

    & sc.exe create $Name binPath= $BinPath start= delayed-auto obj= $Account displayname= $DisplayName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Error "sc.exe create failed for $Name (exit $LASTEXITCODE)"
    }

    & sc.exe description $Name $Description | Out-Null
    & sc.exe failure $Name actions= restart/5000 | Out-Null

    # Verify the service account was applied - rollback if not
    $svcAccount = (Get-CimInstance Win32_Service -Filter "Name='$Name'").StartName
    if ($svcAccount -ne $Account) {
        & sc.exe delete $Name | Out-Null
        Write-Error "Service $Name account is '$svcAccount', expected '$Account'. Service removed."
    }

    Write-Host "  Registered service: $Name (account: $Account)"
}

Assert-Administrator

$runningServices = Test-ServicesRunning
if ($runningServices) {
    Write-Host "`n Provider services are already running: $($runningServices -join ', ')" -ForegroundColor Yellow
    Write-Host " The installer will not modify a running provider to avoid dropping in-flight requests."
    Write-Host " Use the config reload path (ACM) to apply config updates."
    Write-Host " To update the binary, stop the services first and re-run the installer."
    exit 0
}

$providerBinary = Join-Path $PROVIDER_SOURCE_DIR $PROVIDER_EXE

if (-not (Test-Path $providerBinary)) {
    Write-Error "Cannot read $providerBinary"
}

# Ensure provider data directory exists before config validation/copy.
New-Item -ItemType Directory -Path $PROVIDER_DIR -Force | Out-Null

# Copy over a new config if one was provided (first install, or reinstall with
# updated config). On reinstalls without -Config, validate the config left
# in place by the previous install.
# On fresh install without -Config, start the SecretsManager provider with no config, don't start ACM provider
$defaultConfigPath = "$PROVIDER_DIR\$CONFIG_FILE_NAME"
if ($Config) {
    # Validate the provided config before overwriting the existing one
    $validatedConfig = Confirm-Config -Config $Config -ProviderBinary $providerBinary
    $secretsManagerEnabled = $validatedConfig.enabledCapabilities -contains "secrets-manager"
    $acmEnabled = $validatedConfig.enabledCapabilities -contains "acm"
    Copy-Item -Path $Config -Destination $defaultConfigPath -Force
} else {
    if (-not (Test-Path $defaultConfigPath)) {
        $secretsManagerEnabled = $true
        $acmEnabled = $false
        Write-Host "No config found at $defaultConfigPath. Installing in default SecretsManager only mode."
    } else {
        $validatedConfig = Confirm-Config -Config $defaultConfigPath -ProviderBinary $providerBinary
        $secretsManagerEnabled = $validatedConfig.enabledCapabilities -contains "secrets-manager"
        $acmEnabled = $validatedConfig.enabledCapabilities -contains "acm"
    }
}


Write-Step "Install files"

New-Item -ItemType Directory -Path $BIN_DIR -Force | Out-Null
Copy-Item -Path $providerBinary -Destination "$BIN_DIR\$PROVIDER_EXE" -Force
Copy-Item -Path (Join-Path $SCRIPT_DIR "aws-workload-credentials-provider-token.ps1") -Destination "$BIN_DIR\aws-workload-credentials-provider-token.ps1" -Force
Copy-Item -Path (Join-Path $SCRIPT_DIR "common.ps1") -Destination "$BIN_DIR\common.ps1" -Force
Copy-Item -Path (Join-Path $SCRIPT_DIR "acmReloadConfig.ps1") -Destination "$BIN_DIR\acmReloadConfig.ps1" -Force
Write-Host "  Installed $BIN_DIR\$PROVIDER_EXE"

Write-Step "Register Windows Services"

$providerExePath = "$BIN_DIR\$PROVIDER_EXE"

# Always Register ACM_SERVICE and create ACM_SERVICE_ACCOUNT
Register-ProviderService `
    -Name $ACM_SERVICE `
    -DisplayName "AWS Workload Credentials Provider - ACM" `
    -Description "AWS Workload Credentials Provider - ACM certificate refresher" `
    -Account $ACM_SERVICE_ACCOUNT `
    -BinPath "$providerExePath acm start"

# Always Register ASM_SERVICE and create ASM_SERVICE_ACCOUNT
Register-ProviderService `
    -Name $ASM_SERVICE `
    -DisplayName "AWS Workload Credentials Provider - Secrets Manager" `
    -Description "AWS Workload Credentials Provider - Secrets Manager HTTP server" `
    -Account $ASM_SERVICE_ACCOUNT `
    -BinPath "$providerExePath sm start"

if ($secretsManagerEnabled) {
    # Set the SSRF token env var for the service process so it can locate the token file.
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ASM_SERVICE"
    New-ItemProperty -Path $regPath -Name "Environment" -Value "AWS_TOKEN=file://$SSRF_TOKEN_FILE" -PropertyType MultiString -Force | Out-Null
    Write-Host "  Set AWS_TOKEN env var for $ASM_SERVICE"

    Write-Step "Create SSRF token file"

    # Create the token file with locked-down ACLs. The seed token service
    # (running as SYSTEM) writes the value at boot. The ASM service account
    # gets read-only access — only SYSTEM can write the token.
    New-Item -ItemType File -Path $SSRF_TOKEN_FILE -Force | Out-Null

    icacls $SSRF_TOKEN_FILE /inheritance:r /Q | Out-Null
    icacls $SSRF_TOKEN_FILE /grant "SYSTEM:F" /Q | Out-Null
    icacls $SSRF_TOKEN_FILE /grant "BUILTIN\Administrators:F" /Q | Out-Null
    icacls $SSRF_TOKEN_FILE /grant "${ASM_SERVICE_ACCOUNT}:R" /Q | Out-Null
    Write-Host "  Created $SSRF_TOKEN_FILE (read-only for $ASM_SERVICE_ACCOUNT)"

    # Generate the initial token value. Install proceeds only if this succeeds.
    & powershell.exe -NoProfile -NonInteractive -File $SEED_TOKEN_SCRIPT_PATH
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $SSRF_TOKEN_FILE) -or (Get-Item $SSRF_TOKEN_FILE).Length -eq 0) {
        Write-Error "Failed to generate initial SSRF token."
    }
    Write-Host "  Seeded $SSRF_TOKEN_FILE"

    Register-SeedTokenTask -TaskName $SEED_TOKEN_TASK -ScriptPath $SEED_TOKEN_SCRIPT_PATH
    Write-Host "  Registered boot-time seed task: $SEED_TOKEN_TASK"
}

Write-Step "Configure provider directory ACLs"

# Remove inherited ACLs (e.g., Users read access from ProgramData) so only
# SYSTEM, Administrators, and the two service accounts can access this directory.
# Take ownership first to neutralize pre-creation attacks via implicit owner DACL-write.
takeown /f $PROVIDER_DIR /r /d y | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Error "Failed to take ownership of $PROVIDER_DIR" }

# Reset wipes all explicit ACEs and re-enables inheritance, then /inheritance:r
# strips the inherited ones, leaving a blank DACL to rebuild from scratch.
icacls $PROVIDER_DIR /reset /T /Q | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Error "Failed to reset ACLs on $PROVIDER_DIR" }
icacls $PROVIDER_DIR /inheritance:r /Q | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Error "Failed to remove inherited ACLs on $PROVIDER_DIR" }
icacls $PROVIDER_DIR /grant "SYSTEM:(OI)(CI)F" /T /Q | Out-Null
icacls $PROVIDER_DIR /grant "BUILTIN\Administrators:(OI)(CI)F" /T /Q | Out-Null

icacls $PROVIDER_DIR /grant "${ASM_SERVICE_ACCOUNT}:(OI)(CI)RX" /T /Q | Out-Null
Write-Host "  Granted Read+Execute ACL to $ASM_SERVICE_ACCOUNT on $PROVIDER_DIR"

icacls $PROVIDER_DIR /grant "${ACM_SERVICE_ACCOUNT}:(OI)(CI)RX" /T /Q | Out-Null
Write-Host "  Granted Read+Execute ACL to $ACM_SERVICE_ACCOUNT on $PROVIDER_DIR"


$LOGS_DIR = "$PROVIDER_DIR\logs"
New-Item -ItemType Directory -Path $LOGS_DIR -Force | Out-Null

icacls $LOGS_DIR /grant "${ASM_SERVICE_ACCOUNT}:(OI)(CI)M" /T /Q | Out-Null
Write-Host "  Granted Modify ACL to $ASM_SERVICE_ACCOUNT on $LOGS_DIR"

icacls $LOGS_DIR /grant "${ACM_SERVICE_ACCOUNT}:(OI)(CI)M" /T /Q | Out-Null
Write-Host "  Granted Modify ACL to $ACM_SERVICE_ACCOUNT on $LOGS_DIR"


Write-Step "Configure file permissions"

if (Test-Path $defaultConfigPath) {
    # Apply config file ACLs so an edited-by-hand config gets re-locked on reinstall
    icacls $defaultConfigPath /inheritance:r /Q | Out-Null
    icacls $defaultConfigPath /grant "SYSTEM:F" /Q | Out-Null
    icacls $defaultConfigPath /grant "BUILTIN\Administrators:F" /Q | Out-Null

    icacls $defaultConfigPath /grant "${ASM_SERVICE_ACCOUNT}:R" /Q | Out-Null

    icacls $defaultConfigPath /grant "${ACM_SERVICE_ACCOUNT}:R" /Q | Out-Null

    Write-Host "  Locked down ACLs on $defaultConfigPath"
} else {
    Write-Host "  Config file doesn't exist - skipping config file permission setup"
}

if ($acmEnabled) {
    Add-CertificateTasksPermissions $validatedConfig
} else {
    Write-Host "  ACM not enabled - skipping ACM permission setup"
}

if (-not $NoStart) {
    Write-Step "Start services"

    if ($secretsManagerEnabled) {
        & sc.exe start $ASM_SERVICE | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Error "sc.exe start failed for $ASM_SERVICE (exit $LASTEXITCODE)"
        }
        Write-Host "  Starting $ASM_SERVICE"
    }

    if ($acmEnabled) {
        & sc.exe start $ACM_SERVICE | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Error "sc.exe start failed for $ACM_SERVICE (exit $LASTEXITCODE)"
        }
        Write-Host "  Starting $ACM_SERVICE"
    }
} else {
    Write-Host "`nServices registered but not started (-NoStart specified)."
}

Write-Host "`n Installation complete." -ForegroundColor Green
Write-Host "  Binary:     $BIN_DIR\$PROVIDER_EXE"
Write-Host "  Provider Dir:  $PROVIDER_DIR"
$installedServices = @()
if ($acmEnabled) { $installedServices += $ACM_SERVICE }
if ($secretsManagerEnabled) { $installedServices += $ASM_SERVICE }
if ($installedServices) {
    Write-Host "  Services:   $($installedServices -join ', ')"
}
