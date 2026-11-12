<#
.SYNOPSIS
    Bootstrap installer for the AWS Workload Credentials Provider on Windows.

.DESCRIPTION
    Downloads the release binary and the matching configuration directory, then
    runs install.ps1 from it.

    The version is explicit: the binary comes from the artifact host and the
    service units and install scripts come from the repository at tag v<Version>,
    so both halves are pinned to the same release.

    The binary's Authenticode signature is verified before anything is
    installed. It covers the binary only: the service registration and install
    scripts come from the tag archive over TLS, with no signature of their own.

.PARAMETER Version
    Version to install, in the pattern x.y.z. Defaults to $env:AWCP_VERSION.

.PARAMETER Config
    Bootstrap config passed through to install.ps1.

.PARAMETER NoStart
    Install and register services but don't start them.

.PARAMETER Force
    Stop running provider services before installing.

.PARAMETER DryRun
    Download and verify, then stop without installing.

.EXAMPLE
    $installer = Join-Path $env:TEMP "awcp-install.ps1"
    Invoke-WebRequest -UseBasicParsing https://raw.githubusercontent.com/aws/aws-workload-credentials-provider/HEAD/install.ps1 -OutFile $installer
    & $installer -Version 3.1.2 -Config C:\path\to\config.toml

    Downloaded to a file rather than run from the response, because
    [scriptblock]::Create() on an empty body silently does nothing and reports
    success, so a failed download would read as a completed install.
#>

# CmdletBinding, so an unknown switch is an error rather than being collected
# into $args: without it a mistyped -DryRun binds to nothing, $DryRun stays
# false, and what the operator meant as a rehearsal is a real install.
[CmdletBinding()]
param(
    [string]$Version = $env:AWCP_VERSION,
    [string]$Config,
    [switch]$NoStart,
    [switch]$Force,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
# Invoke-WebRequest's progress bar costs an order of magnitude on Windows
# PowerShell 5.1.
$ProgressPreference = "SilentlyContinue"

$BASE_URL = if ($env:AWCP_BASE_URL) { $env:AWCP_BASE_URL } else { "https://artifacts.awcp.global.on.aws" }
$REPO_URL = if ($env:AWCP_REPO_URL) { $env:AWCP_REPO_URL } else { "https://github.com/aws/aws-workload-credentials-provider" }
$TARGET = "x86_64-pc-windows-msvc"
$EXE = "aws-workload-credentials-provider.exe"
# Compared against the decoded CN rather than a substring of Subject: .NET
# quotes any attribute value containing a comma, so a pattern written against
# the unquoted form silently never matches.
$SIGNER_CN = "Amazon Web Services, Inc."

# Checked at runtime rather than with #Requires, which applies to scripts and is
# ignored when this is run as a script block, as the documented one-liner does.
# Expand-Archive needs 5.0; Windows Server 2012 R2 ships 4.0.
if ($PSVersionTable.PSVersion.Major -lt 5) {
    throw "PowerShell 5.0 or newer is required; this session is $($PSVersionTable.PSVersion)."
}

# The tag ships install.ps1, common.ps1 and the seed-token script as unsigned
# .ps1 files, and they are run from disk: the delegate through the call operator,
# the seed script through powershell.exe -File. A policy that refuses those fails
# the install after the binary and the archive have been downloaded, and after the
# services have been registered, so it is checked before any of that happens.
$policy = Get-ExecutionPolicy
if ($policy -in @("Restricted", "AllSigned")) {
    throw "PowerShell execution policy is $policy, which blocks the unsigned install scripts this downloads."
}

$current = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $current.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script must be run as Administrator."
}

if (-not $Version) {
    throw "Pass -Version (or set AWCP_VERSION) to the version to install, as in -Version 3.1.2"
}
# \z, not $: .NET's $ also matches before a trailing newline, so a version with
# one on the end would pass and then be interpolated into the download URLs.
if ($Version -notmatch '^\d+\.\d+\.\d+\z') {
    throw "Not a valid version: $Version"
}

# PROCESSOR_ARCHITEW6432 is set only in a 32-bit process on a 64-bit OS. Refused
# rather than translated: that same process gets a ProgramFiles pointing at the
# x86 tree, and common.ps1 builds the install directory from it, so the install
# would land in "Program Files (x86)" and the services would be registered there.
if ($env:PROCESSOR_ARCHITEW6432) {
    throw "Running under 32-bit PowerShell on a 64-bit OS, which would install into ${env:ProgramFiles}. Re-run with $env:SystemRoot\sysnative\WindowsPowerShell\v1.0\powershell.exe, or the 64-bit powershell.exe."
}
if ($env:PROCESSOR_ARCHITECTURE -ne "AMD64") {
    throw "Unsupported architecture: $env:PROCESSOR_ARCHITECTURE. Only $TARGET is published."
}

# A random name, created without -Force, so a pre-created directory in a
# world-writable TEMP (C:\Windows\Temp when running as SYSTEM) cannot be reused
# with its own ACL while this script writes the binary it is about to trust.
$tmp = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ("awcp-install-" + [IO.Path]::GetRandomFileName()))

$previousProtocol = [Net.ServicePointManager]::SecurityProtocol
$stoppedServices = @()
$installed = $false
$keepStaging = $false
$delegateRan = $false
$configRefused = $false
try {
    & icacls $tmp.FullName /inheritance:r /grant "*S-1-5-18:(OI)(CI)F" /grant "*S-1-5-32-544:(OI)(CI)F" /Q | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to restrict the ACL on $($tmp.FullName) (icacls exit $LASTEXITCODE)"
    }

    # The repository archive is extracted alongside, never into, the directory
    # holding the verified binary, so an archive member can't replace it.
    $binDir = New-Item -ItemType Directory -Path (Join-Path $tmp "bin")
    $repoDir = New-Item -ItemType Directory -Path (Join-Path $tmp "repo")

    # Windows PowerShell 5.1 defaults to protocols older than TLS 1.2 on
    # unpatched hosts. Restored in the finally block so the caller's session
    # keeps whatever it had.
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    Write-Host "Installing $EXE $Version ($TARGET)"

    $exePath = Join-Path $binDir $EXE
    Invoke-WebRequest -UseBasicParsing "$BASE_URL/$Version/$TARGET/$EXE" -OutFile $exePath

    $sig = Get-AuthenticodeSignature $exePath
    if ($sig.Status -ne "Valid") {
        throw "Authenticode signature for $EXE $Version is $($sig.Status)"
    }
    $signerCn = $sig.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
    if ($signerCn -ne $SIGNER_CN) {
        throw "Unexpected signer for $EXE $Version : $signerCn"
    }
    Write-Host "  Signature valid: $($sig.SignerCertificate.Subject)"

    # The tag is what ties the units and scripts to the release. A missing tag
    # means the version was published without being tagged.
    $archive = "$REPO_URL/archive/refs/tags/v$Version.zip"
    $archivePath = Join-Path $tmp "repo.zip"
    try {
        Invoke-WebRequest -UseBasicParsing $archive -OutFile $archivePath
    } catch {
        throw "Cannot fetch $archive; is v$Version tagged? $($_.Exception.Message)"
    }
    Expand-Archive -Path $archivePath -DestinationPath $repoDir -Force

    $configurationDir = Get-ChildItem -Path $repoDir -Recurse -Directory -Filter configuration |
        Where-Object { $_.Parent.Name -eq "aws_workload_credentials_provider_common" } |
        Select-Object -First 1
    if (-not $configurationDir) {
        throw "No configuration directory in $archive"
    }
    $installScript = Join-Path $configurationDir.FullName "install.ps1"
    if (-not (Test-Path $installScript)) {
        throw "No install.ps1 in $($configurationDir.FullName)"
    }
    # Service names, paths, and Stop-ProviderService come from the same tag, so
    # this wrapper can't drift from the version it is installing.
    . (Join-Path $configurationDir.FullName "common.ps1")

    $running = @(Get-Service -Name $ASM_SERVICE, $ACM_SERVICE -ErrorAction SilentlyContinue |
        Where-Object { $_.Status -ne "Stopped" })

    if ($DryRun) {
        # Kept, so the operator can read the scripts and check the binary before
        # committing to an install. Theirs to remove afterwards.
        $keepStaging = $true
        Write-Host "Downloaded $EXE $Version and the v$Version configuration to $($tmp.FullName)"
        Write-Host "Install skipped (-DryRun). Remove $($tmp.FullName) when you are done."
        if ($running) {
            Write-Host "  Note: $($running.Name -join ', ') running; a real install needs -Force."
        }
        return
    }

    # The bundled installer refuses to touch a running provider, so stop the
    # services here first, with consent, since it drops in-flight requests.
    if ($running -and -not $Force) {
        throw "Provider services are running: $($running.Name -join ', '). Re-run with -Force to stop them and upgrade."
    }

    foreach ($svc in $running) {
        # Recorded before the attempt: Stop-ProviderService throws if the process
        # outlives its 30 second grace period, by which point the service has
        # already been told to stop, so the restore below still has to run it.
        $stoppedServices += $svc.Name
        # Waits for the process to exit, not just for the service control
        # manager to report Stopped, so the binary is no longer locked.
        Stop-ProviderService -Name $svc.Name | Out-Null
        Write-Host "  Stopped $($svc.Name)"
    }

    $installArgs = @{}
    if ($Config) { $installArgs.Config = $Config }
    if ($NoStart) { $installArgs.NoStart = $true }

    # install.ps1 looks for the binary at ..\..\target\release relative to
    # itself, which is where a source build leaves it, so put the downloaded one
    # there. Written after the archive is extracted, so no archive member can
    # stand in for it.
    $sourceDir = New-Item -ItemType Directory -Force -Path `
        (Join-Path $configurationDir.FullName "..\..\target\release")
    Copy-Item -Path $exePath -Destination (Join-Path $sourceDir $EXE) -Force

    $global:LASTEXITCODE = 0
    $delegateRan = $true
    & $installScript @installArgs
    # Not a verdict on its own, except for a refused or invalid config, which
    # have their own exit codes from tags that define them. Older tags report a
    # rejected config by way of Confirm-Config's `exit 1`, but also end with
    # unchecked `icacls` calls, and icacls exits nonzero over a single
    # unresolvable principal, so a completed install can leave this set. What the
    # install did is checked on disk below; this only sharpens the message.
    $delegateExit = $LASTEXITCODE
    if ($EXIT_CONFIG_NOT_TRUSTED -and $delegateExit -eq $EXIT_CONFIG_NOT_TRUSTED) {
        $configRefused = $true
        throw "configuration\install.ps1 did not use $(Split-Path -Parent $PROVIDER_DIR), the provider folder in it, or its config; see the message above. The binary was not changed."
    }
    if ($EXIT_CONFIG_INVALID -and $delegateExit -eq $EXIT_CONFIG_INVALID) {
        $configRefused = $true
        throw "configuration\install.ps1 did not use the config because it failed validation; see the errors above. The binary was not changed."
    }
    $detail = if ($delegateExit -ne 0) { " (it exited $delegateExit)" } else { "" }

    # The delegate also exits 0 when it decides not to touch a running provider,
    # so the binary on disk has to be the one just verified.
    $installedExe = Join-Path $BIN_DIR $PROVIDER_EXE
    if (-not (Test-Path $installedExe)) {
        throw "configuration\install.ps1 did not install $installedExe$detail"
    }
    if ((Get-FileHash $installedExe -Algorithm SHA256).Hash -ne (Get-FileHash $exePath -Algorithm SHA256).Hash) {
        throw "$installedExe is not the $Version binary$detail; stop the services and re-run"
    }
    # A config rejected on a re-install of the version already present would
    # leave the binary matching, so compare what was asked for with what landed.
    if ($Config) {
        $installedConfig = Join-Path $PROVIDER_DIR $CONFIG_FILE_NAME
        if (-not (Test-Path $installedConfig) -or
            (Get-FileHash $installedConfig -Algorithm SHA256).Hash -ne (Get-FileHash $Config -Algorithm SHA256).Hash) {
            throw "$Config was not installed to $installedConfig$detail"
        }
    }
    if ($delegateExit -ne 0) {
        Write-Warning "configuration\install.ps1 exited $delegateExit but installed $Version; check its output above."
    }
    $installed = $true
    Write-Host "Installed $EXE $Version"
} finally {
    # Services stopped for an install that then failed would otherwise stay
    # down until reboot: they are registered delayed-auto, not on-demand.
    #
    # Starting them is not a rollback. Once the delegate is running it replaces
    # the binary and re-registers the services early on, and truncates the SSRF
    # token before seeding it, so what starts here may be the new binary against
    # a half-configured host.
    if (-not $installed) {
        # A refusal happens before the delegate installs anything
        if ($delegateRan -and -not $configRefused) {
            Write-Warning "configuration\install.ps1 had already started, so this host may be partially installed: re-run to finish, or download the v$Version source and run aws_workload_credentials_provider_common\configuration\uninstall.ps1 from it to remove it."
        }
        foreach ($name in $stoppedServices) {
            try {
                Start-Service -Name $name
                Write-Warning "Install failed; started $name again."
            } catch {
                Write-Warning "Install failed and $name could not be restarted: $($_.Exception.Message)"
            }
        }
    }
    [Net.ServicePointManager]::SecurityProtocol = $previousProtocol
    if (-not $keepStaging) {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }
}
