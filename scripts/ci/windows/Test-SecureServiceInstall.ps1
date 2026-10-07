# GATE: reproduces the daemon's SECURE service install, without the CI escape hatch.
#
# Usage:
#   Test-SecureServiceInstall.ps1 -PackagedDirectory <...\release\win-unpacked> `
#                                 -ProbeDirectory "C:\Program Files\sing-box-ci-probe" `
#                                 -WorkingDirectory "C:\ProgramData\sing-box-daemon" `
#                                 -RecordPath <file>
#
# # Why this gate exists, and why it is separate from gate 5
#
# Gate 5 runs `service install --allow-unsafe-installation-directory-permissions`, which is
# legitimate for a CI workspace but skips part of what the product's installer does. The
# NSIS installer runs `service install` with NO such flag under C:\Program Files, so it
# exercises code that gate 5 never reaches:
#
#   resolveWindowsServiceWorkingDirectory(path, false)
#       validateFixedNTFSVolume + validateInstallationAncestors on the working directory's
#       parent chain, where each ancestor must be owned by SYSTEM, Administrators or
#       TrustedInstaller, and no non-inherited ALLOW ACE to any other principal may carry
#       DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_WRITE, GENERIC_ALL or FILE_DELETE_CHILD
#   secureWindowsInstallation(path, false)
#       the same ancestor rules for the installation directory, a reparse-point walk of the
#       whole tree, and applyProtectedTree with an explicit owner and DACL
#
# The installer's customInstall aborts and rolls the installation back when that fails, so
# the whole product fails with it - and the installer does not surface the daemon's stderr,
# which is why this gate runs the exact command itself and prints what it said.
#
# This is the production configuration. Nothing here weakens the check to make it pass: the
# working directory is the daemon's own default, the installation directory is under
# Program Files like a real install, and the command has no flags.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PackagedDirectory,
    [Parameter(Mandatory = $true)][string]$ProbeDirectory,
    [Parameter(Mandatory = $true)][string]$WorkingDirectory,
    [Parameter(Mandatory = $true)][string]$RecordPath
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "GateHelpers.ps1")

$serviceName = "sing-box-daemon"

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("windows secure daemon service install (the installer's own path, no flags)")
$lines.Add("packaged directory $PackagedDirectory")
$lines.Add("probe directory    $ProbeDirectory")
$lines.Add("working directory  $WorkingDirectory")
$lines.Add("")

function Save-Record {
    $directory = Split-Path -Parent $RecordPath
    if (-not [string]::IsNullOrWhiteSpace($directory) -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    [System.IO.File]::WriteAllLines($RecordPath, $lines)
}

function Write-SecurityFacts {
    param([string]$Path)
    $lines.Add("-- $Path --")
    if (-not (Test-Path -LiteralPath $Path)) {
        $lines.Add("   (does not exist)")
        return
    }
    $acl = Get-Acl -LiteralPath $Path
    $lines.Add("   owner: $($acl.Owner)")
    foreach ($rule in $acl.Access) {
        $lines.Add("   $($rule.IdentityReference) $($rule.AccessControlType) $($rule.FileSystemRights) inherited=$($rule.IsInherited)")
    }
}

function Fail-Gate {
    param([string]$Message)
    $lines.Add("")
    $lines.Add("FAIL: $Message")
    Write-Host ""
    Write-Host "== filesystem security facts =="
    foreach ($path in @("C:\", "C:\Program Files", "C:\ProgramData", $ProbeDirectory, $WorkingDirectory, (Split-Path -Parent $WorkingDirectory))) {
        $output = ""
        try { $output = (Get-Acl -LiteralPath $path -ErrorAction Stop | Format-List Owner, AccessToString | Out-String) } catch { $output = "  (unavailable: $($_.Exception.Message))" }
        Write-Host "-- $path --"
        Write-Host $output
        $lines.Add("security facts: $path")
        $lines.Add($output)
    }
    Write-Host "== sc.exe query =="
    $query = Invoke-NativeCommand { sc.exe query $serviceName }
    Write-Host $query.Output
    $lines.Add("sc.exe query exit $($query.ExitCode)")
    $lines.Add($query.Output)
    Save-Record
    Write-Error "secure service install gate failed: $Message"
    exit 1
}

# --- preconditions -----------------------------------------------------------
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail-Gate "this gate needs an elevated process (running as $($identity.Name))"
}
if (-not (Test-Path -LiteralPath $PackagedDirectory -PathType Container)) {
    Fail-Gate "the packaged directory does not exist: $PackagedDirectory"
}

foreach ($path in @($ProbeDirectory, $WorkingDirectory)) {
    if (Test-Path -LiteralPath $path) {
        Write-Host "removing a pre-existing $path so this gate starts clean"
        Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
    }
}
$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($null -ne $existing) {
    $uninstall = Invoke-NativeCommand { & (Join-Path $PackagedDirectory "resources\daemon\sing-box-daemon.exe") service uninstall }
    Start-Sleep -Seconds 3
    if ($null -ne (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
        Fail-Gate "a pre-existing $serviceName service could not be removed"
    }
}

# --- stage the packaged application where a real install lives ---------------
# Under Program Files, because the ancestor rules are the point: the ones that apply to a
# CI workspace directory are exactly the ones the installer does not skip.
Write-Host "staging $PackagedDirectory -> $ProbeDirectory"
New-Item -ItemType Directory -Path $ProbeDirectory -Force | Out-Null
try {
    Copy-Item -Path (Join-Path $PackagedDirectory "*") -Destination $ProbeDirectory -Recurse -Force -ErrorAction Stop
} catch {
    Fail-Gate "could not stage the packaged application into $ProbeDirectory`: $($_.Exception.Message)"
}
$daemonPath = Join-Path $ProbeDirectory "resources\daemon\sing-box-daemon.exe"
if (-not (Test-Path -LiteralPath $daemonPath -PathType Leaf)) {
    Fail-Gate "$daemonPath is missing after staging"
}
if (-not (Test-Path -LiteralPath (Join-Path $ProbeDirectory "sing-box.exe") -PathType Leaf)) {
    Fail-Gate "<probe>\sing-box.exe is missing; the daemon authenticates the application by that exact path"
}
$lines.Add("staged: $(Test-Path -LiteralPath $daemonPath) daemon, $(Test-Path -LiteralPath (Join-Path $ProbeDirectory 'sing-box.exe')) application")
$lines.Add("")

# --- the command the installer runs, with no flags ---------------------------
$lines.Add("[1/2] service install --working-directory <default>   (no unsafe flag)")
Write-Host "  > $daemonPath service install --working-directory $WorkingDirectory"
$install = Invoke-NativeCommand { & $daemonPath service install --working-directory $WorkingDirectory }
$lines.Add("  exit code $($install.ExitCode)")
$output = $install.Output.Trim()
if (-not [string]::IsNullOrWhiteSpace($output)) {
    Write-Host "  daemon output:"
    foreach ($line in ($output -split "`r?`n")) {
        if (-not [string]::IsNullOrWhiteSpace($line)) { Write-Host "    $line" }
    }
    $lines.Add("  daemon output:")
    foreach ($line in ($output -split "`r?`n")) {
        if (-not [string]::IsNullOrWhiteSpace($line)) { $lines.Add("    $line") }
    }
} else {
    $lines.Add("  daemon output: (none)")
    Write-Host "  daemon output: (none)"
}
if ($install.ExitCode -ne 0) {
    Fail-Gate "the daemon's secure service install exited $($install.ExitCode). This is the exact command clients/desktop/build/installer.nsh runs during customInstall, with no --allow-unsafe-installation-directory-permissions, so the installer would abort and roll back."
}

$state = (Get-Service -Name $serviceName -ErrorAction SilentlyContinue).Status
$lines.Add("  service state: $state")
if ($state -ne "Running") {
    Fail-Gate "the service is '$state' after a successful install, expected Running"
}
$lines.Add("  PASS")
$lines.Add("")

# --- teardown ---------------------------------------------------------------
$lines.Add("[2/2] teardown")
$uninstall = Invoke-NativeCommand { & $daemonPath service uninstall }
$lines.Add("  service uninstall exit code $($uninstall.ExitCode)")
if ($uninstall.ExitCode -ne 0) {
    Fail-Gate "service uninstall exited $($uninstall.ExitCode)"
}
$null = Wait-Until -Description "the service to disappear" -TimeoutSeconds 120 -Condition {
    $null -eq (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)
}
if ($null -ne (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
    Fail-Gate "the service is still registered after uninstall"
}
foreach ($path in @($ProbeDirectory, $WorkingDirectory)) {
    Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
}
$lines.Add("  PASS")

$lines.Add("")
$lines.Add("PASS: the daemon registers, starts and removes its service under")
$lines.Add("      C:\Program Files with no relaxed permissions, which is the path the")
$lines.Add("      installer takes and the path a real installation takes.")
Save-Record
foreach ($line in $lines) { Write-Host $line }
Complete-Gate
