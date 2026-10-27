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
        exit $EXIT_CONFIG_INVALID
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
    Return $null if the file doesn't exist or validation fails. The caller checks that
    administrators control it first.

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
# For C:\ProgramData\AWS: FILE_DELETE_CHILD, DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_ALL, GENERIC_WRITE.
# Adding files and subfolders is allowed, since ProgramData grants that to Users by default.
$PARENT_WRITE_RIGHTS_MASK = 0x500D0040
# Exit code when the provider folder, its parent, or an existing config is not used
$EXIT_CONFIG_NOT_TRUSTED = 2
# Exit code when a config fails validation
$EXIT_CONFIG_INVALID = 3
$ADMIN_DESCRIPTION = "SYSTEM, TrustedInstaller, the Administrators group, the current user, or a direct member of the local Administrators group"
$script:LocalAdministratorMembers = $null
$script:CurrentUserSid = $null

<#
.DESCRIPTION
    Prints why the provider folder or the existing config in it is not used and how
    to continue, then exits $EXIT_CONFIG_NOT_TRUSTED

.PARAMETER Path
    Path to the provider folder or the existing config file
.PARAMETER Reason
    Why it is not used
#>
function Write-ConfigRefusal {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Reason
    )

    Write-Host "`n Not using ${Path}: $Reason." -ForegroundColor Red
    # The scripts that would fix it refuse first, so they can't stop the services
    Write-Host " Only administrators should control it. Stop both provider services; they start again after a restart." -ForegroundColor Red
    # A config that another account could edit may have its own refresh_command, and
    # may have left renewal tasks behind. Both run as SYSTEM.
    $tasks = "remove renewal tasks (AWSWorkloadCredentialsProvider-Reload-*) it no longer needs"
    if ($Path -ne $PROVIDER_DIR) {
        Write-Host " If you can't open it, take ownership of it and give administrators access first. Review it, including every refresh_command, and $tasks." -ForegroundColor Red
        Write-Host " Then run this again with -Config and the reviewed copy, and start both services again if they are not running." -ForegroundColor Red
    } else {
        # Fixing it in place would keep whatever another account put in it, and
        # deleting through a junction deletes what it points to
        Write-Host " If you can't open the folder, take ownership of it and give administrators access first. Back up the logs, and the config if there is one," -ForegroundColor Red
        Write-Host " then delete the folder. If it, or anything in it, is a junction or symbolic link, delete only the link." -ForegroundColor Red
        Write-Host " If there was a config, review it, including every refresh_command, and $tasks." -ForegroundColor Red
        Write-Host " Then run the installer again, with -Config and the reviewed config if there was one." -ForegroundColor Red
    }
    exit $EXIT_CONFIG_NOT_TRUSTED
}

<#
.DESCRIPTION
    Prints why the folder that holds the provider folder is not used and how to
    continue, then exits $EXIT_CONFIG_NOT_TRUSTED

.PARAMETER Path
    Path to the parent folder
.PARAMETER Reason
    Why it is not used
#>
function Write-ParentRefusal {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Reason
    )

    Write-Host "`n Not using ${Path}: $Reason." -ForegroundColor Red
    Write-Host " $Path must be a folder, not a junction or symbolic link. An administrator must own it, and no account" -ForegroundColor Red
    Write-Host " other than an administrator may delete, rename, change permissions on, or take ownership of what is in it." -ForegroundColor Red
    Write-Host " Stop both provider services; they start again after a restart." -ForegroundColor Red
    # Changing the permissions of a junction or symbolic link changes its target instead,
    # so unless it is known to be a real folder, replacing it is the safe advice
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if (-not $item -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or -not $item.PSIsContainer) {
        Write-Host " Replace it with a real folder that only administrators control." -ForegroundColor Red
    } else {
        Write-Host " Fix its owner and permissions." -ForegroundColor Red
    }
    Write-Host " Then run this again, and start both services again if they are not running." -ForegroundColor Red
    exit $EXIT_CONFIG_NOT_TRUSTED
}

<#
.DESCRIPTION
    Returns $true if the provider data directory contains a config file. Lists the
    directory rather than probing the path, so the result does not depend on the
    file's own permissions. Exits $EXIT_CONFIG_NOT_TRUSTED if the directory cannot be listed.
#>
function Test-ExistingConfig {
    try {
        # -eq is case-insensitive, matching NTFS file names
        $entries = @(Get-ChildItem -LiteralPath $PROVIDER_DIR -Force -ErrorAction Stop |
            Where-Object { $_.Name -eq $CONFIG_FILE_NAME })
    } catch {
        Write-ConfigRefusal -Path $PROVIDER_DIR -Reason "it could not be listed"
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
    Returns why the file or folder at Path is not controlled by administrators, or $null if it is

.PARAMETER Path
    Path to the config file or folder to check
.PARAMETER WriteRightsMask
    Rights that count as a write grant
.PARAMETER CountInheritOnly
    Also count grants that only pass down to new files and folders, for the provider
    folder, so the files the installer creates in it can't get them
#>
function Get-ConfigControlProblem {
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$WriteRightsMask = $WRITE_RIGHTS_MASK,
        [switch]$CountInheritOnly
    )

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
    # With no access list at all, Windows gives everyone full access
    if ($null -eq $raw.DiscretionaryAcl) { return "it has no access list, so every account has full access" }
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
        if (-not $CountInheritOnly -and
                ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) { continue }
        $sid = $rule.IdentityReference.Value
        if ($OWNER_PLACEHOLDER_SIDS -contains $sid) { continue }
        if (([int]$rule.FileSystemRights -band $WriteRightsMask) -eq 0) { continue }

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
    Exits $EXIT_CONFIG_NOT_TRUSTED unless the config at Path is owned
    by an administrator and no account other than an administrator has a write grant on it

.PARAMETER Path
    Path to the existing config file
#>
function Assert-AdminControlledConfig {
    param([Parameter(Mandatory)][string]$Path)

    $reason = Get-ExistingConfigProblem -Path $Path
    if ($reason) {
        Write-ConfigRefusal -Path $Path -Reason $reason
    }
}

<#
.DESCRIPTION
    Returns why the existing config at Path is not controlled by administrators, or
    $null if it is

.PARAMETER Path
    Path to the existing config file
#>
function Get-ExistingConfigProblem {
    param([Parameter(Mandatory)][string]$Path)

    try {
        return Get-ConfigControlProblem -Path $Path
    } catch {
        return "its permissions could not be checked: $($_.Exception.Message.Trim().TrimEnd('.'))"
    }
}

<#
.DESCRIPTION
    Returns $true if the config at Path is controlled by administrators. Otherwise
    warns and returns $false.

.PARAMETER Path
    Path to the existing config file
#>
function Test-AdminControlledConfig {
    param([Parameter(Mandatory)][string]$Path)

    $reason = Get-ExistingConfigProblem -Path $Path
    if ($reason) {
        Write-Warning "Not using ${Path}: $reason - will skip permission cleanup"
        return $false
    }
    return $true
}

<#
.DESCRIPTION
    Writes a validated config to Destination as a new file, so no owner or explicit
    ACE of an existing one is kept. Exits $EXIT_CONFIG_NOT_TRUSTED if Source is the
    untrusted Destination under any path, or the untrusted Destination can't be opened
    or moved.

.PARAMETER Source
    Path to the validated config
.PARAMETER Destination
    Path the config is installed to
.PARAMETER ReplaceUntrusted
    Destination exists and administrators don't control it
#>
function Copy-ConfigIntoPlace {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination,
        [switch]$ReplaceUntrusted
    )

    $sourcePath = (Resolve-Path -LiteralPath $Source).ProviderPath
    # The folder is admin-only, so nobody else can make these names
    $newPath = "$Destination.new"
    $oldPath = "$Destination.old"
    $cantUse = {
        param($Action, $Err)
        Write-Host "`n Could not $Action ${Destination}, which administrators don't control: $($Err.Exception.GetBaseException().Message.Trim())" -ForegroundColor Red
        Write-Host " If you can't open it, take ownership of it and give administrators access first. If another program has it open, close that program. Then run this again." -ForegroundColor Red
        exit $EXIT_CONFIG_NOT_TRUSTED
    }
    if ($ReplaceUntrusted) {
        # While the untrusted file is held open with no sharing, opening it by any
        # other path (a short name, a share or a link) fails. Opening it fails if its
        # owner gave administrators no access to it, or another program has it open.
        try {
            $held = [IO.File]::Open($Destination, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
        } catch {
            & $cantUse "open" $_
        }
        try {
            $bytes = [IO.File]::ReadAllBytes($sourcePath)
        } catch [IO.IOException] {
            # ERROR_SHARING_VIOLATION
            if ($_.Exception.GetBaseException().HResult -ne -2147024864) { throw }
            Write-Host "`n -Config is the existing $CONFIG_FILE_NAME, which administrators don't control, or another program has it open. Pass a reviewed copy that only administrators can change." -ForegroundColor Red
            exit $EXIT_CONFIG_NOT_TRUSTED
        } finally {
            $held.Dispose()
        }
    } else {
        $bytes = [IO.File]::ReadAllBytes($sourcePath)
    }
    # Cleared only once Source is read, in case it is a leftover one
    Remove-Item -LiteralPath $newPath, $oldPath -Force -ErrorAction SilentlyContinue
    # Written as a new file and then renamed, so no owner or explicit ACE of the old
    # one is kept
    [IO.File]::WriteAllBytes($newPath, $bytes)
    if (Test-Path -LiteralPath $Destination) {
        try {
            [IO.File]::Move($Destination, $oldPath)
        } catch {
            Remove-Item -LiteralPath $newPath -Force -ErrorAction SilentlyContinue
            if (-not $ReplaceUntrusted) { throw }
            & $cantUse "move aside" $_
        }
    }
    try {
        [IO.File]::Move($newPath, $Destination)
    } catch {
        # Without a config, later runs would install in Secrets Manager only mode
        if (Test-Path -LiteralPath $oldPath) {
            [IO.File]::Move($oldPath, $Destination)
        }
        throw
    }
    # -Force also deletes a read-only one
    Remove-Item -LiteralPath $oldPath -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $oldPath) {
        Write-Warning "Could not delete the old config, $oldPath. Delete it."
    }
}

<#
.DESCRIPTION
    Returns why the folder at Path is not controlled by administrators, or $null if it is

.PARAMETER Path
    Path to the folder to check
.PARAMETER WriteRightsMask
    Rights that count as a write grant
.PARAMETER CountInheritOnly
    Also count grants that only pass down to new files and folders
#>
function Get-FolderControlProblem {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][int]$WriteRightsMask,
        [switch]$CountInheritOnly
    )

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { return "it is a junction or symbolic link" }
    if (-not $item.PSIsContainer) { return "it is not a folder" }
    return Get-ConfigControlProblem -Path $Path -WriteRightsMask $WriteRightsMask -CountInheritOnly:$CountInheritOnly
}

<#
.DESCRIPTION
    Returns a protected access list that gives only SYSTEM and Administrators access,
    passed down to everything in the folder

.PARAMETER UsersRead
    Also let Users read, for C:\ProgramData\AWS, which other tools may share
#>
function New-AdminOnlyDirectorySecurity {
    param([switch]$UsersRead)

    $security = New-Object Security.AccessControl.DirectorySecurity
    $security.SetAccessRuleProtection($true, $false)
    foreach ($sid in @("S-1-5-18", "S-1-5-32-544")) {
        $security.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule -ArgumentList `
            (New-Object Security.Principal.SecurityIdentifier $sid), "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow"))
    }
    if ($UsersRead) {
        $security.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule -ArgumentList `
            (New-Object Security.Principal.SecurityIdentifier "S-1-5-32-545"), "ReadAndExecute", "ContainerInherit, ObjectInherit", "None", "Allow"))
    }
    return $security
}

<#
.DESCRIPTION
    Replaces the whole access list of an existing folder with the admin-only one, in
    one step, so no entry from before is left and it never inherits from its parent

.PARAMETER Path
    Path to the folder
#>
function Set-AdminOnlyDirectoryAcl {
    param([Parameter(Mandatory)][string]$Path)

    # Only the access list is written, the owner is left as is
    $security = New-AdminOnlyDirectorySecurity
    $dir = New-Object IO.DirectoryInfo $Path
    if ($PSVersionTable.PSEdition -eq "Core") {
        [IO.FileSystemAclExtensions]::SetAccessControl($dir, $security)
    } else {
        $dir.SetAccessControl($security)
    }
}

<#
.DESCRIPTION
    Creates a folder owned by Administrators that only SYSTEM and Administrators can
    access (and Users read, with -UsersRead), in one step, so no other account can use
    it before its permissions are set

.PARAMETER Path
    Path to the folder to create
.PARAMETER UsersRead
    Also let Users read the folder, for C:\ProgramData\AWS, which other tools may share
#>
function New-AdminOnlyDirectory {
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$UsersRead
    )

    $security = New-AdminOnlyDirectorySecurity -UsersRead:$UsersRead
    $security.SetOwner((New-Object Security.Principal.SecurityIdentifier "S-1-5-32-544"))
    if ($PSVersionTable.PSEdition -eq "Core") {
        # PowerShell 7 has no Directory.CreateDirectory overload that takes security
        [IO.FileSystemAclExtensions]::Create((New-Object IO.DirectoryInfo $Path), $security)
    } else {
        [IO.Directory]::CreateDirectory($Path, $security) | Out-Null
    }
}

<#
.DESCRIPTION
    Creates the provider data directory admin-only if it is missing. Then exits
    $EXIT_CONFIG_NOT_TRUSTED unless both it and its parent are
    real folders owned by an administrator, the provider folder has no write grant
    for other accounts, and the parent gives other accounts no delete, delete-child,
    WRITE_DAC or WRITE_OWNER rights, so nobody else can rename the provider folder
    away and put their own in its place.

.PARAMETER NoCreate
    Only check, for scripts that need an installed provider
#>
function Assert-AdminControlledProviderDir {
    param([switch]$NoCreate)

    $parent = Split-Path -Parent $PROVIDER_DIR
    if (-not $NoCreate) {
        if (-not (Test-Path -LiteralPath $parent)) {
            # Owned by Administrators, and Users can't add folders, so nobody else
            # can put their own provider folder in it later, after uninstall -RemoveAll
            New-AdminOnlyDirectory -Path $parent -UsersRead
        } else {
            # Nothing is created in an existing parent before it is checked
            Assert-AdminControlledFolder -Path $parent -Parent
        }
        if (-not (Test-Path -LiteralPath $PROVIDER_DIR)) {
            New-AdminOnlyDirectory -Path $PROVIDER_DIR
        }
    }

    # The parent is checked (again) once the provider folder is in it, since an empty
    # folder that Users can add files to can be turned into a junction
    Assert-AdminControlledFolder -Path $parent -Parent
    Assert-AdminControlledFolder -Path $PROVIDER_DIR
}

<#
.DESCRIPTION
    Exits $EXIT_CONFIG_NOT_TRUSTED unless the folder at Path is a
    real folder controlled by administrators

.PARAMETER Path
    Path to the folder to check
.PARAMETER Parent
    Path is the folder that holds the provider folder, so its own rights mask and
    message are used
#>
function Assert-AdminControlledFolder {
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Parent
    )

    $mask = if ($Parent) { $PARENT_WRITE_RIGHTS_MASK } else { $WRITE_RIGHTS_MASK }
    try {
        # The parent's grants only reach the provider folder if it inherits, and the
        # installer turns that off
        $reason = Get-FolderControlProblem -Path $Path -WriteRightsMask $mask -CountInheritOnly:(-not $Parent)
    } catch {
        $reason = "its permissions could not be checked: $($_.Exception.Message.Trim().TrimEnd('.'))"
    }
    if (-not $reason) { return }
    if ($Parent) {
        Write-ParentRefusal -Path $Path -Reason $reason
    }
    Write-ConfigRefusal -Path $Path -Reason $reason
}