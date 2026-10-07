# GATE: installs, starts, inspects and uninstalls the real Windows daemon service.
#
# Usage:
#   Test-DaemonService.ps1 -DaemonPath <...\resources\daemon\sing-box-daemon.exe> `
#                          -WorkingDirectory <dir> -RecordPath <file>
#
# # Why this gate exists
#
# "the daemon compiled" and "the daemon registers as a service" are different claims, and
# only the second one is a product. The core's service registration is where the
# Authenticode policy actually bites: serviceInstall() refuses to register unless the
# daemon and the installed application are signed by the same certificate, and unless the
# daemon sits in an <install>/resources/daemon/ layout with <install>/sing-box.exe beside
# it. None of that is visible from a successful compile, and none of it was ever run in CI.
#
# # The one flag this uses, and what it does not do
#
# --allow-unsafe-installation-directory-permissions. It is needed because the daemon
# secures its installation directory for SYSTEM/Administrators with an ACL that a CI
# workspace does not have, and because the CI workspace is not where a real installation
# lives. The flag is the daemon's own, and reading security_windows.go shows it is
# consulted AFTER the Authenticode comparison:
#
#     daemonSigner, err := authenticodeSigner(daemonPath, daemonExecutable)      // enforced
#     applicationSigner, err := authenticodeSigner(applicationFinalPath, ...)    // enforced
#     if !bytes.Equal(daemonSigner, applicationSigner) { return error }          // enforced
#     if allowUnsafeInstallation { return daemonPath, nil }                      // skipped
#
# So it relaxes directory permissions and nothing else. Authenticode, the layout check,
# the service configuration, SCM registration and the signer comparison are all still
# enforced, and this gate proves it by requiring the signed build to pass. There is no
# flag, environment variable or CI bypass that disables the signature check, and none is
# invented here.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$DaemonPath,
    [Parameter(Mandatory = $true)][string]$WorkingDirectory,
    [Parameter(Mandatory = $true)][string]$RecordPath
)

$ErrorActionPreference = "Stop"
$serviceName = "sing-box-daemon"

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("windows daemon service smoke test")
$lines.Add("daemon            $DaemonPath")
$lines.Add("working directory $WorkingDirectory")
$lines.Add("")

function Save-Record {
    $directory = Split-Path -Parent $RecordPath
    if (-not [string]::IsNullOrWhiteSpace($directory) -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    [System.IO.File]::WriteAllLines($RecordPath, $lines)
}

function Fail-Gate {
    param([string]$Message)
    $lines.Add("")
    $lines.Add("FAIL: $Message")
    Write-Host ""
    Write-Host "== diagnostics =="
    foreach ($diagnostic in @(
        @{ Name = "sc.exe query $serviceName"; Command = { sc.exe query $serviceName 2>&1 | Out-String } },
        @{ Name = "Get-Service $serviceName"; Command = { Get-Service -Name $serviceName -ErrorAction SilentlyContinue | Format-List * | Out-String } },
        @{ Name = "Get-Process sing-box-daemon"; Command = { Get-Process -Name "sing-box-daemon" -ErrorAction SilentlyContinue | Format-Table Id, ProcessName, Path -AutoSize | Out-String } },
        @{ Name = "System log (sing-box sources)"; Command = { Get-EventLog -LogName System -Newest 60 -ErrorAction SilentlyContinue | Where-Object { $_.Source -match 'sing-box' } | Format-List TimeGenerated, Source, EntryType, Message | Out-String } },
        @{ Name = "Application log (sing-box sources)"; Command = { Get-EventLog -LogName Application -Newest 60 -ErrorAction SilentlyContinue | Where-Object { $_.Source -match 'sing-box' } | Format-List TimeGenerated, Source, EntryType, Message | Out-String } }
    )) {
        Write-Host "-- $($diagnostic.Name) --"
        $output = ""
        try { $output = & $diagnostic.Command } catch { $output = "diagnostic failed: $($_.Exception.Message)" }
        if ([string]::IsNullOrWhiteSpace($output)) { $output = "(no output)" }
        Write-Host $output
        $lines.Add("diagnostic: $($diagnostic.Name)")
        $lines.Add($output)
    }
    Save-Record
    Write-Error "daemon service smoke test failed: $Message"
    exit 1
}

function Invoke-Daemon {
    param([string[]]$Arguments)
    Write-Host "  > sing-box-daemon $($Arguments -join ' ')"
    $output = & $DaemonPath @Arguments 2>&1 | Out-String
    $exitCode = $LASTEXITCODE
    if (-not [string]::IsNullOrWhiteSpace($output)) {
        foreach ($line in ($output -split "`r?`n")) {
            if (-not [string]::IsNullOrWhiteSpace($line)) { Write-Host "    $line" }
        }
    }
    return @{ Output = $output; ExitCode = $exitCode }
}

function Get-ServiceState {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($null -eq $service) { return "absent" }
    return $service.Status.ToString()
}

# --- preconditions -----------------------------------------------------------
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail-Gate "this gate needs an elevated process to create a Windows service (running as $($identity.Name))"
}
if (-not (Test-Path -LiteralPath $DaemonPath -PathType Leaf)) {
    Fail-Gate "the daemon does not exist: $DaemonPath"
}

# The gate must start from a clean machine state, and says so rather than assuming it.
$preExisting = Get-ServiceState
if ($preExisting -ne "absent") {
    $lines.Add("pre-existing service state: $preExisting (removing so the test starts clean)")
    $cleanup = Invoke-Daemon @("service", "uninstall")
    if ((Get-ServiceState) -ne "absent") {
        Fail-Gate "a '$serviceName' service was already present and could not be removed"
    }
}
$lines.Add("preconditions       elevated=YES service=absent")
$lines.Add("")

# --- 1. install -------------------------------------------------------------
$lines.Add("[1/6] service install")
if (Test-Path -LiteralPath $WorkingDirectory) {
    Remove-Item -LiteralPath $WorkingDirectory -Recurse -Force
}
$result = Invoke-Daemon @(
    "service", "install",
    "--working-directory", $WorkingDirectory,
    "--allow-unsafe-installation-directory-permissions"
)
$lines.Add("  exit code $($result.ExitCode)")
if ($result.ExitCode -ne 0) {
    Fail-Gate "service install exited $($result.ExitCode). The daemon authenticates the installed application against its own signer before registering, so this is where a missing, unsigned or differently-signed sing-box.exe fails."
}
$lines.Add("  PASS")

# --- 2. the service exists in the SCM ---------------------------------------
$lines.Add("[2/6] service is registered with the SCM")
$query = sc.exe query $serviceName 2>&1 | Out-String
Write-Host $query.Trim()
if ($LASTEXITCODE -ne 0) {
    Fail-Gate "sc.exe query $serviceName exited $LASTEXITCODE after a successful install"
}
if ($query -notmatch [regex]::Escape($serviceName)) {
    Fail-Gate "sc.exe query did not report $serviceName"
}
$state = Get-ServiceState
$lines.Add("  status: $state")
if ($state -eq "absent") { Fail-Gate "the service is not visible to Get-Service" }
$lines.Add("  PASS")

# --- 3. running -------------------------------------------------------------
$lines.Add("[3/6] service is Running")
if ($state -ne "Running") {
    Fail-Gate "the service state is '$state', expected Running"
}
$lines.Add("  PASS")

# --- 4. the daemon reports its own version ----------------------------------
$lines.Add("[4/6] daemon status command")
$statusResult = Invoke-Daemon @("service", "status")
$statusText = $statusResult.Output.Trim()
$lines.Add("  status output: $statusText (exit code $($statusResult.ExitCode))")
if ($statusResult.ExitCode -ne 0 -or $statusText -notmatch "running") {
    Fail-Gate "the daemon's own status command reported '$statusText' with exit code $($statusResult.ExitCode), expected 'running' with exit code 0"
}
$lines.Add("  PASS")

# --- 5. stop ----------------------------------------------------------------
$lines.Add("[5/6] service stop")
$stopResult = Invoke-Daemon @("service", "stop")
$lines.Add("  exit code $($stopResult.ExitCode)")
if ($stopResult.ExitCode -ne 0) { Fail-Gate "service stop exited $($stopResult.ExitCode)" }
$state = Get-ServiceState
$lines.Add("  status: $state")
if ($state -ne "Stopped") { Fail-Gate "the service state is '$state' after stop, expected Stopped" }
$lines.Add("  PASS")

# --- 6. uninstall -----------------------------------------------------------
$lines.Add("[6/6] service uninstall")
$uninstallResult = Invoke-Daemon @("service", "uninstall")
$lines.Add("  exit code $($uninstallResult.ExitCode)")
if ($uninstallResult.ExitCode -ne 0) { Fail-Gate "service uninstall exited $($uninstallResult.ExitCode)" }
$state = Get-ServiceState
$lines.Add("  status: $state")
if ($state -ne "absent") { Fail-Gate "the service is still '$state' after uninstall" }

# A deleted service that is still "marked for deletion" blocks the next install, which is
# exactly the residue this gate exists to catch.
$queryAfter = sc.exe query $serviceName 2>&1 | Out-String
if ($queryAfter -match "marked for deletion") {
    Fail-Gate "the service is marked for deletion after uninstall; the next install would fail"
}
$lines.Add("  service registry entry: absent, not marked for deletion")
$lines.Add("  PASS")

# --- leftovers --------------------------------------------------------------
$daemonProcesses = @(Get-Process -Name "sing-box-daemon" -ErrorAction SilentlyContinue)
$lines.Add("")
$lines.Add("orphan daemon processes: $($daemonProcesses.Count)")
if ($daemonProcesses.Count -gt 0) {
    Fail-Gate "a sing-box-daemon process survived service uninstall"
}

$lines.Add("")
$lines.Add("PASS: install, SCM registration, Running, status, stop and uninstall all verified")
Save-Record
foreach ($line in $lines) { Write-Host $line }
