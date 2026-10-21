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

# SYSTEM, BUILTIN\Administrators, TrustedInstaller
$ADMIN_SIDS = @(
    "S-1-5-18",
    "S-1-5-32-544",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
)
# OWNER RIGHTS (applies to the owner, checked separately) and CREATOR OWNER (grants nothing on a file)
$OWNER_PLACEHOLDER_SIDS = @("S-1-3-4", "S-1-3-0")
# FILE_WRITE_DATA, FILE_APPEND_DATA, FILE_WRITE_EA, FILE_DELETE_CHILD, FILE_WRITE_ATTRIBUTES,
# DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_ALL, GENERIC_WRITE
$WRITE_RIGHTS_MASK = 0x500D0156
$ADMIN_DESCRIPTION = "SYSTEM, TrustedInstaller, the Administrators group, the current user, or a direct member of the local Administrators group"
$script:LocalAdministratorMembers = $null
$script:CurrentUserSid = $null

<#
.DESCRIPTION
    Prints why the existing config is not used and how to continue, then exits 1

.PARAMETER Path
    Path to the existing config file
.PARAMETER Reason
    Why the existing config is not used
#>
function Write-ConfigRefusal {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Reason
    )

    $dir = Split-Path -Parent $Path
    Write-Host "`n Not using the existing config at ${Path}: $Reason." -ForegroundColor Red
    Write-Host " Without -Config, an existing config is only used if an administrator owns it and no account other than an" -ForegroundColor Red
    Write-Host " administrator has a write grant on it." -ForegroundColor Red
    Write-Host " To continue:" -ForegroundColor Red
    Write-Host "   1. Stop the $ACM_SERVICE and $ASM_SERVICE services if" -ForegroundColor Red
    Write-Host "      they are running." -ForegroundColor Red
    Write-Host "   2. Copy $Path to a folder only administrators can write to, and review it, including every refresh_command." -ForegroundColor Red
    Write-Host "   3. Delete ${dir}:  cmd /c rmdir /s /q `"$dir`"" -ForegroundColor Red
    Write-Host "   4. Re-run the installer with -Config <path to the reviewed copy>." -ForegroundColor Red
    Write-Host " Do steps 3 and 4 one right after the other, without restarting the computer in between." -ForegroundColor Red
    exit 1
}

<#
.DESCRIPTION
    Returns $true if the provider data directory contains a config file. Lists the
    directory rather than probing the path, so the result does not depend on the
    file's own permissions. Exits 1 if the directory cannot be listed.
#>
function Test-ExistingConfig {
    try {
        # -eq is case-insensitive, matching NTFS file names
        $entries = @(Get-ChildItem -LiteralPath $PROVIDER_DIR -Force -ErrorAction Stop |
            Where-Object { $_.Name -eq $CONFIG_FILE_NAME })
    } catch {
        Write-ConfigRefusal -Path "$PROVIDER_DIR\$CONFIG_FILE_NAME" -Reason "the folder $PROVIDER_DIR could not be listed"
    }
    return $entries.Count -gt 0
}

<#
.DESCRIPTION
    Returns "Member", "NotMember", or "Unknown" for whether Sid is a direct member of
    the local Administrators group. The group is read once per run.

.PARAMETER Sid
    SID string to look up
#>
function Get-LocalAdministratorMembership {
    param([Parameter(Mandatory)][string]$Sid)

    if ($null -eq $script:LocalAdministratorMembers) {
        $members = @{ Readable = $false; Complete = $true; Sids = @() }
        try {
            # The group name is localised; drop the domain part (also localised)
            $groupName = (New-Object Security.Principal.SecurityIdentifier "S-1-5-32-544").Translate(
                [Security.Principal.NTAccount]).Value
            $groupName = $groupName.Substring($groupName.LastIndexOf('\') + 1)
            $group = [ADSI]"WinNT://./$groupName,group"
            $groupMembers = @($group.Invoke("Members"))
            $members.Readable = $true
            foreach ($m in $groupMembers) {
                try {
                    $bytes = $m.GetType().InvokeMember("objectSid", "GetProperty", $null, $m, $null)
                    $members.Sids += (New-Object Security.Principal.SecurityIdentifier -ArgumentList $bytes, 0).Value
                } catch {
                    $members.Complete = $false
                }
            }
        } catch {
            $members.Readable = $false
        }
        $script:LocalAdministratorMembers = $members
    }

    $members = $script:LocalAdministratorMembers
    if (-not $members.Readable) { return "Unknown" }
    if ($members.Sids -contains $Sid) { return "Member" }
    if (-not $members.Complete) { return "Unknown" }
    return "NotMember"
}

<#
.DESCRIPTION
    Returns "Admin", "NotAdmin", or "Unknown" for a SID. Only looks up the local
    Administrators group for SIDs outside the fixed administrator set.

.PARAMETER Sid
    SID string to check
#>
function Get-AdministratorStatus {
    param([Parameter(Mandatory)][string]$Sid)

    if ($ADMIN_SIDS -contains $Sid) { return "Admin" }
    if ($null -eq $script:CurrentUserSid) {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        try { $script:CurrentUserSid = $identity.User.Value } finally { $identity.Dispose() }
    }
    if ($Sid -eq $script:CurrentUserSid) { return "Admin" }
    switch (Get-LocalAdministratorMembership -Sid $Sid) {
        "Member" { return "Admin" }
        "NotMember" { return "NotAdmin" }
        default { return "Unknown" }
    }
}

<#
.DESCRIPTION
    Returns the account name for a SID, or the SID string if it does not resolve

.PARAMETER Sid
    SID string to translate
#>
function Get-PrincipalName {
    param([Parameter(Mandatory)][string]$Sid)

    try {
        return (New-Object Security.Principal.SecurityIdentifier $Sid).Translate(
            [Security.Principal.NTAccount]).Value
    } catch {
        return $Sid
    }
}

<#
.DESCRIPTION
    Returns why the file at Path is not controlled by administrators, or $null if it is

.PARAMETER Path
    Path to the config file to check
#>
function Get-ConfigControlProblem {
    param([Parameter(Mandatory)][string]$Path)

    $acl = $null
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    } catch {
        $acl = $null
    }
    if (-not $acl) { return "its permissions could not be read" }

    # GetAccessRules only returns plain allow and deny entries, so refuse any other kind
    # (for example conditional entries) rather than skip it
    $raw = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $acl.GetSecurityDescriptorBinaryForm(), 0
    foreach ($ace in @($raw.DiscretionaryAcl)) {
        if ($ace -and $ace.AceType -ne [Security.AccessControl.AceType]::AccessAllowed -and
                $ace.AceType -ne [Security.AccessControl.AceType]::AccessDenied) {
            return "it has an access entry of type $($ace.AceType), which this check does not support"
        }
    }

    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier])
    if (-not $owner) { return "its owner could not be read" }
    $status = Get-AdministratorStatus -Sid $owner.Value
    if ($status -eq "NotAdmin") { return "its owner $(Get-PrincipalName $owner.Value) is not $ADMIN_DESCRIPTION" }
    if ($status -eq "Unknown") {
        return "could not check whether its owner $(Get-PrincipalName $owner.Value) is a member of the local Administrators group"
    }

    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        if ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
        $sid = $rule.IdentityReference.Value
        if ($OWNER_PLACEHOLDER_SIDS -contains $sid) { continue }
        if (([int]$rule.FileSystemRights -band $WRITE_RIGHTS_MASK) -eq 0) { continue }

        $status = Get-AdministratorStatus -Sid $sid
        if ($status -eq "NotAdmin") {
            return "$(Get-PrincipalName $sid) has a write grant on it, and is not $ADMIN_DESCRIPTION"
        }
        if ($status -eq "Unknown") {
            return "could not check whether $(Get-PrincipalName $sid), which has a write grant on it, is a member of the local Administrators group"
        }
    }
    return $null
}

<#
.DESCRIPTION
    Exits 1 with recovery steps unless the config at Path is owned by an administrator
    and no account other than an administrator has a write grant on it

.PARAMETER Path
    Path to the existing config file
#>
function Assert-AdminControlledConfig {
    param([Parameter(Mandatory)][string]$Path)

    try {
        $reason = Get-ConfigControlProblem -Path $Path
    } catch {
        $reason = "its permissions could not be checked: $($_.Exception.Message.Trim().TrimEnd('.'))"
    }
    if ($reason) {
        Write-ConfigRefusal -Path $Path -Reason $reason
    }
}