# GATE: installs, reinstalls and uninstalls the real NSIS installer, silently.
#
# Usage:
#   Test-InstallerLifecycle.ps1 -InstallerPath <...\Jiejiebox-v0.1.5-windows-x64.exe> `
#                               -ExpectedVersion 0.1.5 -RecordPath <file>
#
# # Why this gate exists
#
# Extracting the installer and auditing its payload proves what is inside the file. It
# does not prove the file installs. The installer's own customInstall runs
# `sing-box-daemon.exe service install` and, on any non-zero exit, runs the uninstaller
# and aborts - so a signed-build regression, a layout mistake or a service that cannot
# start turns the installer into a rollback, and only running it shows that.
#
# # What is covered
#
#   install            silent, default per-machine location, no /D override
#   files              sing-box.exe, the daemon, the native module and the drivers exist
#   version            the installed daemon reports the expected version
#   service            registered and Running, and the app layout registry key written
#   reinstall          the same version over itself, which is where a service that is
#                      left stopped, StopPending or marked for deletion shows up
#   uninstall          files removed, service removed, no orphan process
#   clean reinstall    install again after a full uninstall and tear it down again
#
# Silent mode is used deliberately rather than GUI automation. The installer has custom
# pages, and in a default per-machine install none of them raise a prompt that /S cannot
# answer - the pages with a MessageBox are the unsafe-installation and repair paths, which
# a secure Program Files installation does not enter. A timeout guards the case where that
# reasoning is wrong: a prompt nobody can answer fails the gate instead of hanging the job.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$InstallerPath,
    [Parameter(Mandatory = $true)][string]$ExpectedVersion,
    [Parameter(Mandatory = $true)][string]$RecordPath,
    [int]$OperationTimeoutSeconds = 900,
    # The installer's CI-only diagnostic channel: an absolute path OUTSIDE $PLUGINSDIR and
    # $INSTDIR that survives customInstall's rollback. Without it a failure leaves nothing
    # but "exited 2", because the installer deletes its own evidence. Empty means the
    # installer runs exactly as it does for a user, with no diagnostic option at all.
    [string]$DiagnosticPath = ""
)

$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "GateHelpers.ps1")

# Native commands here are expected to exit non-zero in normal operation - `sc.exe query`
# on a service that should be absent returns 1060 - so a non-zero exit must not become a
# terminating error. Each call checks $LASTEXITCODE where the result matters.
$PSNativeCommandUseErrorActionPreference = $false

$serviceName = "sing-box-daemon"
$productDisplayName = "Jiejiebox"
$installationLayoutKey = "HKLM:\SOFTWARE\SagerNet\sing-box"

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("windows NSIS installer lifecycle smoke test")
$lines.Add("installer         $InstallerPath")
$lines.Add("expected version  $ExpectedVersion")
$lines.Add("")

function Save-Record {
    $directory = Split-Path -Parent $RecordPath
    if (-not [string]::IsNullOrWhiteSpace($directory) -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    [System.IO.File]::WriteAllLines($RecordPath, $lines)
}

function Get-UninstallEntry {
    $roots = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    foreach ($root in $roots) {
        $entries = Get-ItemProperty -Path $root -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -eq $productDisplayName }
        if ($null -ne $entries) {
            $first = @($entries)[0]
            if ($null -ne $first) { return $first }
        }
    }
    return $null
}

function Get-InstallationDirectory {
    $entry = Get-UninstallEntry
    if ($null -eq $entry) { return $null }
    if (-not [string]::IsNullOrWhiteSpace($entry.InstallLocation)) {
        return $entry.InstallLocation.Trim('"')
    }
    if (-not [string]::IsNullOrWhiteSpace($entry.UninstallString)) {
        $match = [regex]::Match($entry.UninstallString, '^\s*"([^"]+)"')
        if ($match.Success) { return (Split-Path -Parent $match.Groups[1].Value) }
    }
    return $null
}

function Get-ServiceState {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($null -eq $service) { return "absent" }
    return $service.Status.ToString()
}

function Get-InstallArguments {
    $arguments = @("/S")
    if (-not [string]::IsNullOrWhiteSpace($DiagnosticPath)) {
        $arguments += "/CI-DIAGNOSTIC-PATH=$DiagnosticPath"
    }
    return $arguments
}

function Show-InstallerDiagnostic {
    if ([string]::IsNullOrWhiteSpace($DiagnosticPath)) {
        Write-Host "-- installer diagnostic channel --"
        Write-Host "   (not requested for this run)"
        $lines.Add("installer diagnostic channel: not requested")
        return
    }
    Write-Host "-- installer diagnostic channel ($DiagnosticPath) --"
    if (-not (Test-Path -LiteralPath $DiagnosticPath)) {
        Write-Host "   (the installer did not create it, so it failed before customInit or could not write)"
        $lines.Add("installer diagnostic channel: file not created at $DiagnosticPath")
        return
    }
    $content = Get-Content -LiteralPath $DiagnosticPath -Raw -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($content)) { $content = "(empty)" }
    Write-Host $content
    $lines.Add("installer diagnostic channel:")
    foreach ($line in ($content -split "`r?`n")) { $lines.Add("  $line") }
    # Preserved beside the record so it reaches the artifact.
    $preserved = Join-Path (Split-Path -Parent $RecordPath) "installer-diagnostic.txt"
    try {
        Copy-Item -LiteralPath $DiagnosticPath -Destination $preserved -Force -ErrorAction Stop
        Write-Host "   preserved as $preserved"
    } catch {
        Write-Host "   could not preserve it: $($_.Exception.Message)"
    }
}

function Show-Diagnostics {
    Show-InstallerDiagnostic
    foreach ($diagnostic in @(
        @{ Name = "uninstall registry entry"; Command = { Get-UninstallEntry | Format-List DisplayName, DisplayVersion, InstallLocation, UninstallString | Out-String } },
        @{ Name = "$installationLayoutKey"; Command = { Get-ItemProperty -Path $installationLayoutKey -ErrorAction SilentlyContinue | Format-List | Out-String } },
        @{ Name = "sc.exe query $serviceName"; Command = { sc.exe query $serviceName 2>&1 | Out-String } },
        @{ Name = "service config"; Command = { sc.exe qc $serviceName 2>&1 | Out-String } },
        @{ Name = "install directory"; Command = { $d = Get-InstallationDirectory; if ($d -and (Test-Path -LiteralPath $d)) { Get-ChildItem -LiteralPath $d -Recurse -File | Select-Object -First 60 FullName, Length | Format-Table -AutoSize | Out-String } else { "(not present)" } } },
        @{ Name = "sing-box-daemon processes"; Command = { Get-Process -Name "sing-box-daemon" -ErrorAction SilentlyContinue | Format-Table Id, ProcessName, Path -AutoSize | Out-String } },
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
}

function Fail-Gate {
    param([string]$Message)
    $lines.Add("")
    $lines.Add("FAIL: $Message")
    Write-Host ""
    Write-Host "== diagnostics =="
    Show-Diagnostics
    Save-Record
    Write-Error "installer lifecycle smoke test failed: $Message"
    exit 1
}

function Invoke-Silently {
    param([string]$FilePath, [string[]]$Arguments, [string]$What)
    Write-Host "  > $what $FilePath $($Arguments -join ' ')"
    $process = Start-Process -FilePath $FilePath -ArgumentList $Arguments -PassThru
    $null = $process | Wait-Process -Timeout $OperationTimeoutSeconds -ErrorAction SilentlyContinue
    if (-not $process.HasExited) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        Fail-Gate "$What did not finish within $OperationTimeoutSeconds seconds; in silent mode that means a prompt appeared that /S could not answer"
    }
    Write-Host "    exit code $($process.ExitCode)"
    return $process.ExitCode
}

function Assert-Installed {
    param([string]$Phase)
    $null = Wait-Until -Description "$Phase uninstall registry entry to appear" -TimeoutSeconds 180 -Condition {
        $null -ne (Get-UninstallEntry)
    }
    $installationDirectory = Get-InstallationDirectory
    if ([string]::IsNullOrWhiteSpace($installationDirectory)) {
        Fail-Gate "$Phase`: no $productDisplayName uninstall registry entry, so the install did not complete"
    }
    if (-not (Test-Path -LiteralPath $installationDirectory -PathType Container)) {
        Fail-Gate "$Phase`: the registry names '$installationDirectory', which does not exist"
    }
    $lines.Add("  installation directory: $installationDirectory")

    $required = [ordered]@{
        "sing-box.exe"                                = (Join-Path $installationDirectory "sing-box.exe")
        "resources\daemon\sing-box-daemon.exe"         = (Join-Path $installationDirectory "resources\daemon\sing-box-daemon.exe")
        "resources\daemon\libcronet.dll"              = (Join-Path $installationDirectory "resources\daemon\libcronet.dll")
        "resources\daemon\WinDivert64.sys"            = (Join-Path $installationDirectory "resources\daemon\WinDivert64.sys")
        "resources\native\windows_share.node"         = (Join-Path $installationDirectory "resources\native\windows_share.node")
    }
    foreach ($name in $required.Keys) {
        $path = $required[$name]
        $exists = Test-Path -LiteralPath $path -PathType Leaf
        $lines.Add("  $name : $(if ($exists) { 'present' } else { 'MISSING' })")
        if (-not $exists) { Fail-Gate "$Phase`: $name is missing at $path" }
    }

    # The application executable must keep the name the daemon authenticates it by. If a
    # future branding change renames it, the service registration fails and this says why
    # rather than reporting a mysterious service error.
    if (-not (Test-Path -LiteralPath (Join-Path $installationDirectory "sing-box.exe") -PathType Leaf)) {
        Fail-Gate "$Phase`: <install>/sing-box.exe is absent; experimental/boxdd authenticates the application by exactly that path"
    }

    $daemonPath = $required["resources\daemon\sing-box-daemon.exe"]
    $version = Invoke-NativeCommand { & $daemonPath version }
    $versionExit = $version.ExitCode
    $versionOutput = $version.Output.Trim()
    $lines.Add("  daemon version: $versionOutput (exit code $versionExit)")
    if ($versionExit -ne 0) { Fail-Gate "$Phase`: the installed daemon's version command exited $versionExit" }
    if ($versionOutput -notmatch [regex]::Escape("version $ExpectedVersion")) {
        Fail-Gate "$Phase`: the installed daemon reports '$versionOutput', expected version $ExpectedVersion"
    }

    $state = Get-ServiceState
    $lines.Add("  service: $state")
    if ($state -ne "Running") {
        Fail-Gate "$Phase`: the $serviceName service is '$state', expected Running"
    }

    $layout = Get-ItemProperty -Path $installationLayoutKey -ErrorAction SilentlyContinue
    $layoutVersion = $null
    if ($null -ne $layout) { $layoutVersion = $layout.LayoutVersion }
    $lines.Add("  installation layout version: $(if ($null -ne $layoutVersion) { $layoutVersion } else { '(absent)' })")
    if ($null -eq $layoutVersion -or [int]$layoutVersion -ne 2) {
        Fail-Gate "$Phase`: $installationLayoutKey does not record LayoutVersion 2; clients/desktop reads that key at startup"
    }

    return $installationDirectory
}

function Invoke-Uninstall {
    param([string]$Phase)
    $entry = Get-UninstallEntry
    if ($null -eq $entry -or [string]::IsNullOrWhiteSpace($entry.UninstallString)) {
        Fail-Gate "$Phase`: there is no uninstall command to run"
    }
    $match = [regex]::Match($entry.UninstallString, '^\s*"([^"]+)"')
    if (-not $match.Success) {
        Fail-Gate "$Phase`: could not parse the uninstall command '$($entry.UninstallString)'"
    }
    $uninstaller = $match.Groups[1].Value
    if (-not (Test-Path -LiteralPath $uninstaller -PathType Leaf)) {
        Fail-Gate "$Phase`: the uninstaller '$uninstaller' does not exist"
    }
    # The installer's own rollback uses exactly this pair, so it is the supported one.
    $exitCode = Invoke-Silently -FilePath $uninstaller -Arguments @("/S", "/allusers") -What "$Phase uninstall"
    if ($exitCode -ne 0) { Fail-Gate "$Phase`: the uninstaller exited $exitCode" }
    return $uninstaller
}

function Assert-Uninstalled {
    param([string]$Phase)
    $null = Wait-Until -Description "$Phase uninstall to settle (no service, no uninstall entry)" -TimeoutSeconds 300 -Condition {
        ($null -eq (Get-UninstallEntry)) -and ((Get-ServiceState) -eq "absent")
    }
    $state = Get-ServiceState
    $lines.Add("  service after uninstall: $state")
    if ($state -ne "absent") { Fail-Gate "$Phase`: the $serviceName service is still '$state'" }

    # The service must be gone, so a non-zero `sc.exe query` is the expected outcome and
    # is asserted as one rather than tolerated.
    $query = Invoke-NativeCommand { sc.exe query $serviceName }
    if ($query.ExitCode -eq 0) {
        Fail-Gate "$Phase`: sc.exe query still reports $serviceName"
    }
    if ($query.Output -match "marked for deletion") {
        Fail-Gate "$Phase`: the service is marked for deletion; the next install would fail"
    }

    $entry = Get-UninstallEntry
    if ($null -ne $entry) {
        Fail-Gate "$Phase`: the $productDisplayName uninstall registry entry survived uninstall"
    }
    $layout = Get-ItemProperty -Path $installationLayoutKey -ErrorAction SilentlyContinue
    if ($null -ne $layout) {
        Fail-Gate "$Phase`: $installationLayoutKey survived uninstall"
    }

    $remaining = @(Get-Process -Name "sing-box-daemon" -ErrorAction SilentlyContinue)
    $lines.Add("  orphan daemon processes: $($remaining.Count)")
    if ($remaining.Count -gt 0) { Fail-Gate "$Phase`: a sing-box-daemon process survived uninstall" }
}

# --- preconditions -----------------------------------------------------------
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail-Gate "the installer is per-machine and needs an elevated process (running as $($identity.Name))"
}
if (-not (Test-Path -LiteralPath $InstallerPath -PathType Leaf)) {
    Fail-Gate "the installer does not exist: $InstallerPath"
}

# A previous gate may have left a service behind; a clean state is a precondition, and it
# is reported rather than assumed.
if ((Get-ServiceState) -ne "absent" -or $null -ne (Get-UninstallEntry)) {
    $lines.Add("clean state: a previous installation or service was present; removing it first")
    Write-Host "an installation or service was already present; uninstalling before the test"
    if ($null -ne (Get-UninstallEntry)) { Invoke-Uninstall -Phase "precondition" | Out-Null }
    else {
        # Best effort: the service may already be gone, so this exit code is expected to be
        # non-zero sometimes and is captured and cleared rather than inherited.
        $deleted = Invoke-NativeCommand { sc.exe delete $serviceName }
        $lines.Add("precondition: sc.exe delete exited $($deleted.ExitCode)")
    }
    Start-Sleep -Seconds 3
    if ((Get-ServiceState) -ne "absent") { Fail-Gate "could not return the machine to a clean state" }
}
$lines.Add("clean state: no service, no uninstall entry")
$lines.Add("")

# --- first install -----------------------------------------------------------
$lines.Add("[1/5] silent install")
$exitCode = Invoke-Silently -FilePath $InstallerPath -Arguments (Get-InstallArguments) -What "install"
$lines.Add("  exit code $exitCode")
if ($exitCode -ne 0) {
    # Which stage aborted is not inferred from the exit code; the diagnostic channel says.
    Fail-Gate "the installer exited $exitCode. The stage that aborted is recorded in the installer diagnostic channel above."
}
$installationDirectory = Assert-Installed -Phase "after first install"
$lines.Add("  PASS")
$lines.Add("")

# --- same-version reinstall --------------------------------------------------
$lines.Add("[2/5] same-version reinstall")
$exitCode = Invoke-Silently -FilePath $InstallerPath -Arguments (Get-InstallArguments) -What "reinstall"
$lines.Add("  exit code $exitCode")
if ($exitCode -ne 0) { Fail-Gate "the same-version reinstall exited $exitCode" }
$null = Assert-Installed -Phase "after same-version reinstall"
$lines.Add("  PASS (no ERROR_SERVICE_EXISTS, no marked-for-deletion, no StopPending stall)")
$lines.Add("")

# --- uninstall ---------------------------------------------------------------
$lines.Add("[3/5] silent uninstall")
$null = Invoke-Uninstall -Phase "first"
Assert-Uninstalled -Phase "after first uninstall"
$leftover = @(Test-Path -LiteralPath $installationDirectory)
$lines.Add("  installation directory still present: $($leftover[0])")
if ($leftover[0]) {
    $remainingFiles = @(Get-ChildItem -LiteralPath $installationDirectory -Recurse -File -ErrorAction SilentlyContinue)
    $names = ($remainingFiles | Select-Object -First 10 -ExpandProperty Name) -join ", "
    $lines.Add("  remaining files: $($remainingFiles.Count) ($names)")
    $appExecutable = Join-Path $installationDirectory "sing-box.exe"
    if (Test-Path -LiteralPath $appExecutable) {
        Fail-Gate "sing-box.exe survived uninstall at $appExecutable"
    }
    $daemonExecutable = Join-Path $installationDirectory "resources\daemon\sing-box-daemon.exe"
    if (Test-Path -LiteralPath $daemonExecutable) {
        Fail-Gate "the daemon survived uninstall at $daemonExecutable"
    }
}
$lines.Add("  PASS")
$lines.Add("")

# --- clean reinstall ---------------------------------------------------------
$lines.Add("[4/5] clean reinstall after a full uninstall")
$exitCode = Invoke-Silently -FilePath $InstallerPath -Arguments (Get-InstallArguments) -What "reinstall"
$lines.Add("  exit code $exitCode")
if ($exitCode -ne 0) { Fail-Gate "the clean reinstall exited $exitCode" }
$installationDirectory = Assert-Installed -Phase "after clean reinstall"
$lines.Add("  PASS")
$lines.Add("")

# --- final teardown ----------------------------------------------------------
$lines.Add("[5/5] final uninstall")
$null = Invoke-Uninstall -Phase "final"
Assert-Uninstalled -Phase "after final uninstall"
$lines.Add("  PASS")
$lines.Add("")

$lines.Add("PASS: install, verify, same-version reinstall, uninstall, clean reinstall and")
$lines.Add("      final uninstall all completed with no residual service or process state")
Save-Record
foreach ($line in $lines) { Write-Host $line }

Complete-Gate
