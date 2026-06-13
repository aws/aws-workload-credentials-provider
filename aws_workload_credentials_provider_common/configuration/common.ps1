# Common variables for install/uninstall scripts

$INSTALL_DIR = "$env:ProgramFiles\AWS\WorkloadCredentialsProvider"
$BIN_DIR = "$INSTALL_DIR\bin"
$PROVIDER_DIR = "$env:ProgramData\AWS\WorkloadCredentialsProvider"
$SSRF_TOKEN_FILE = "$PROVIDER_DIR\awssmatoken"
$CONFIG_FILE_NAME = "config.toml"

$PROVIDER_EXE = "aws-workload-credentials-provider.exe"

$ASM_SERVICE = "AWSWorkloadCredentialsProvider-SecretsManager"
$ACM_SERVICE = "AWSWorkloadCredentialsProvider-ACM"
$ASM_SERVICE_ACCOUNT = "NT SERVICE\$ASM_SERVICE"
$ACM_SERVICE_ACCOUNT = "NT SERVICE\$ACM_SERVICE"

$SEED_TOKEN_TASK = "AWSWorkloadCredentialsProvider-SeedToken"
$SEED_TOKEN_SCRIPT_PATH = "$BIN_DIR\aws-workload-credentials-provider-token.ps1"

function Assert-Administrator {
    $current = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $current.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must be run as Administrator."
    }
}

function Write-Step {
    param([string]$Message)
    Write-Host "`n=== $Message ===" -ForegroundColor Cyan
}

function Stop-ProviderService {
    param([string]$Name)
    if (-not (Get-Service -Name $Name -ErrorAction SilentlyContinue)) { return $false }
    $svcPid = (Get-CimInstance Win32_Service -Filter "Name='$Name'").ProcessId
    $proc = if ($svcPid -and $svcPid -ne 0) { Get-Process -Id $svcPid -ErrorAction SilentlyContinue }
    Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
    if ($proc -and -not $proc.WaitForExit(30000)) {
        throw "Service $Name process (PID $svcPid) did not exit within 30 seconds."
    }
    return $true
}

function Construct-TaskName($certificate) {
    $arnSuffix = $certificate.certificateArn -replace '[^a-zA-Z0-9\-]', '-'
    return "AWSWorkloadCredentialsProvider-Reload-$arnSuffix"
}

<#
.DESCRIPTION
    Validates the Config exists and passes validation implemented by the ProviderBinary

.PARAMETER Config
    Path to the config file to be validated
.PARAMETER ProviderBinary
    Path to the installed provider binary. Has exposed cli config validation and parsing
#>
function Confirm-Config {
    param(
        [Parameter(Mandatory)][string]$Config,
        [Parameter(Mandatory)][string]$ProviderBinary
    )

    if (-not (Test-Path $Config)) {
        Write-Error "Config file not found: $Config"
    }

    Write-Step "Validate config"
    $ErrorActionPreference = "Continue"
    $output = @(& $ProviderBinary setup-config-based-permissions --config $Config 2>&1)
    $ErrorActionPreference = "Stop"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "`n Config validation failed. Please fix the errors and re-run." -ForegroundColor Red
        foreach ($line in $output) {
            Write-Host " $($line.Exception.Message)" -ForegroundColor Red
        }
        exit 1
    }
    $validatedConfig = ($output -join "`n") | ConvertFrom-Json
    Write-Host " Config validated successfully"
    return $validatedConfig
}

<#
.DESCRIPTION
    Removes ACLs and scheduled tasks associated with a certificate configuration

.PARAMETER cert
    Position 0. Certificate object containing certificateArn, certificatePath, privateKeyPath, and chainPath
#>
function Remove-CertificatePermissions($cert) {
    Write-Host "  Certificate: $($cert.certificateArn)"

    # Remove Scheduled Task
    $taskName = Construct-TaskName $cert

    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        Write-Host "    Removed Scheduled Task: $taskName"
    }

    # Remove certificate file and parent directory ACLs
    $certPaths = @($cert.certificatePath, $cert.privateKeyPath, $cert.chainPath) | Where-Object { $_ }

    $parentDirs = @($certPaths | ForEach-Object { Split-Path -Parent $_ }) | Select-Object -Unique
    foreach ($dir in $parentDirs) {
        if (Test-Path $dir) {
            icacls $dir /remove "${ACM_SERVICE_ACCOUNT}" /Q | Out-Null
            Write-Host "    Removed ACL for $ACM_SERVICE_ACCOUNT on $dir"
        }
    }

    foreach ($filePath in $certPaths) {
        if (Test-Path $filePath) {
            icacls $filePath /remove "${ACM_SERVICE_ACCOUNT}" /Q | Out-Null
            Write-Host "    Removed ACL for $ACM_SERVICE_ACCOUNT on $filePath"
        }
    }
}

<#
.DESCRIPTION
    Grants ACLs and creates scheduled tasks for certificate renewal

.PARAMETER cert
    Position 0. Certificate object containing certificateArn, certificatePath, privateKeyPath, chainPath, and optionally refreshCommand
#>
function Add-CertificatePermissions($cert) {
    Write-Host "  Certificate: $($cert.certificateArn)"

    # Grant ACM VSA Modify on specific certificate files only
    $certPaths = @($cert.certificatePath, $cert.privateKeyPath, $cert.chainPath) | Where-Object { $_ }

    # Grant file-create permission on parent directories so the provider can
    # write temp files for atomic renames.
    # Grant read permission on parent directories so the provider can
    # read contents of directory
    $parentDirs = @($certPaths | ForEach-Object { Split-Path -Parent $_ }) | Select-Object -Unique
    foreach ($dir in $parentDirs) {
        if (-not (Test-Path $dir)) {
            Write-Warning "Parent directory not found, skipping ACL: $dir"
            continue
        }
        icacls $dir /grant "${ACM_SERVICE_ACCOUNT}:(WD,R)" /Q | Out-Null
        Write-Host "    Granted file-create and read ACL to $ACM_SERVICE_ACCOUNT on $dir"
    }

    foreach ($filePath in $certPaths) {
        if (-not (Test-Path $filePath)) {
            Write-Warning "Certificate file not found, skipping ACL: $filePath"
            continue
        }
        icacls $filePath /grant "${ACM_SERVICE_ACCOUNT}:M" /Q | Out-Null
        Write-Host "    Granted Modify ACL to $ACM_SERVICE_ACCOUNT on $filePath"
    }

    # Setup reload mechanism - Scheduled Task running as SYSTEM.
    # ACM VSA gets execute-only rights on the task; Administrators/SYSTEM
    # retain their inherited full control.
    if (-not $cert.refreshCommand) { return }

    $taskName = Construct-TaskName $cert

    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }

    $encodedCmd = [Convert]::ToBase64String(
        [System.Text.Encoding]::Unicode.GetBytes($cert.refreshCommand))
    $action = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-NoProfile -NonInteractive -EncodedCommand $encodedCmd"
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 5)

    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings | Out-Null

    # Grant ACM VSA execute rights on the task (GRGX = Generic Read + Generic Execute).
    # Required because SYSTEM-principal tasks deny triggering to non-admins by default.
    # Pass DACL_SECURITY_INFORMATION to both Get and Set so we only
    # touch the DACL and leave owner/group/SACL alone.
    $acmSid = (New-Object System.Security.Principal.NTAccount($ACM_SERVICE_ACCOUNT)).Translate(
        [System.Security.Principal.SecurityIdentifier]).Value
    $scheduler = New-Object -ComObject "Schedule.Service"
    $scheduler.Connect()
    $task = $scheduler.GetFolder("\").GetTask($taskName)
    $sddl = $task.GetSecurityDescriptor(4)
    $ace = "(A;;GRGX;;;$acmSid)"
    if (-not $sddl.Contains($ace)) {
        $task.SetSecurityDescriptor($sddl + $ace, 0)
    }
    Write-Host "    Scheduled Task: $taskName (runs as SYSTEM, $ACM_SERVICE_ACCOUNT has execute)"
}

function Remove-CertificateTasksPermissions($config) {
    if ($config -and $config.certificates) {
        Write-Step "Remove old certificate tasks and permissions"

        foreach ($cert in $config.certificates) {
            Remove-CertificatePermissions $cert
        }
    } else {
        Write-Host "`n  No old certificate config to clean up"
    }
}

function Add-CertificateTasksPermissions($config) {
    Write-Step "Add new certificate permissions and tasks"

    foreach ($cert in $config.certificates) {
        Add-CertificatePermissions $cert
    }
}

<#
.DESCRIPTION
    Validates the Config exists and passes validation implemented by the ProviderBinary
    Return $null if the file doesn't exist or validation fails

.PARAMETER Config
    Path to the config file to be validated
.PARAMETER ProviderBinary
    Path to the installed provider binary. Has exposed cli config validation and parsing
#>
function Get-Config {
    param(
        [Parameter(Mandatory)][string]$Config,
        [Parameter(Mandatory)][string]$ProviderBinary
    )
    if (-not (Test-Path $Config)) {
        Write-Host "  No config found at $Config"
        return $null
    }
    try {
        $jsonOutput = & $ProviderBinary setup-config-based-permissions --config $Config 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "config parsing failed (exit code $LASTEXITCODE) - will skip permission cleanup"
            return $null
        }
        $validatedConfig = ($jsonOutput -join "`n") | ConvertFrom-Json
        Write-Host "  Parsed config successfully"
        return $validatedConfig
    } catch {
        Write-Warning "Failed to parse config: $_ - will skip permission cleanup"
        return $null
    }
}