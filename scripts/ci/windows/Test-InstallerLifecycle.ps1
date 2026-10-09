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
# Set once per run: the uninstall registry is dumped in full the first time an installation
# is identified, so the record shows what the runner actually has.
$candidateDumpWritten = $false
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


function Get-InstallationState {
    # Identity, in the only order that is a fact rather than a guess: the SCM's own record
    # of the daemon's command line, the layout that implies, the installer's layout
    # registry, and only then the uninstall entry whose InstallLocation IS that root.
    #
    # A display name is recorded as audit metadata and never used to match. It is the
    # product name, while the installation directory and executable are deliberately
    # "sing-box", so the name could legitimately be either - and a name cannot establish
    # identity even when it matches, because the first entry with that name would win.
    $commandLine = Get-DaemonServiceCommandLine
    $daemonPath = Get-CommandExecutablePath $commandLine
    $root = Get-InstallationRootFromDaemonPath $daemonPath
    $layout = Get-InstallationLayoutRegistry
    if ([string]::IsNullOrWhiteSpace($root) -and $null -eq $layout) { return $null }
    $matches = @()
    if (-not [string]::IsNullOrWhiteSpace($root)) {
        $matches = @(Get-UninstallEntriesForInstallation -InstallationRoot $root)
    }
    return [pscustomobject]@{
        ServiceCommandLine   = $commandLine
        DaemonPath           = $daemonPath
        Root                 = $root
        LayoutVersion        = $(if ($null -ne $layout) { $layout.LayoutVersion } else { $null })
        InstallationID       = $(if ($null -ne $layout) { $layout.InstallationID } else { $null })
        DaemonDataDirectory  = $(if ($null -ne $layout) { $layout.DaemonDataDirectory } else { $null })
        UninstallMatches     = $matches
    }
}


function Add-InstallationIdentity {
    param($State)
    if ($null -eq $State) {
        $lines.Add("  installation identity: absent")
        return
    }
    $lines.Add("  service command line: $($State.ServiceCommandLine)")
    $lines.Add("  derived install root: $($State.Root)")
    $lines.Add("  layout version:       $($State.LayoutVersion)")
    $lines.Add("  installation id:      $($State.InstallationID)")
    $lines.Add("  daemon data dir:      $($State.DaemonDataDirectory)")
    $lines.Add("  uninstall matches:    $(@($State.UninstallMatches).Count)")
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
        @{ Name = "installation identity"; Command = { $state = Get-InstallationState; Add-InstallationIdentity $state | Out-Null; ($lines | Select-Object -Last 6) -join [Environment]::NewLine } },
        @{ Name = "uninstall registry candidates"; Command = { (Format-UninstallEntries -Entries @(Get-UninstallRegistryEntries)) -join [Environment]::NewLine } },
        @{ Name = "$installationLayoutKey"; Command = { Get-ItemProperty -Path $installationLayoutKey -ErrorAction SilentlyContinue | Format-List | Out-String } },
        @{ Name = "sc.exe query $serviceName"; Command = { sc.exe query $serviceName 2>&1 | Out-String } },
        @{ Name = "service config"; Command = { sc.exe qc $serviceName 2>&1 | Out-String } },
        @{ Name = "install directory"; Command = { $state = Get-InstallationState; $d = ""; if ($null -ne $state) { $d = $state.Root }; if ($d -and (Test-Path -LiteralPath $d)) { Get-ChildItem -LiteralPath $d -Recurse -File | Select-Object -First 60 FullName, Length | Format-Table -AutoSize | Out-String } else { "(not present)" } } },
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
    $null = Wait-Until -Description "$Phase installation to become identifiable" -TimeoutSeconds 180 -Condition {
        -not [string]::IsNullOrWhiteSpace((Get-InstallationRootFromDaemonPath (Get-CommandExecutablePath (Get-DaemonServiceCommandLine))))
    }
    $state = Get-InstallationState
    if ($null -eq $state -or [string]::IsNullOrWhiteSpace($state.Root)) {
        Add-InstallationIdentity $state
        Fail-Gate "$Phase`: no installation could be identified from the SCM"
    }
    $root = $state.Root
    $lines.Add("  installation root: $root")

    $required = [ordered]@{
        "sing-box.exe"                          = (Join-Path $root "sing-box.exe")
        "resources\daemon\sing-box-daemon.exe" = (Join-Path $root "resources\daemon\sing-box-daemon.exe")
        "resources\daemon\libcronet.dll"       = (Join-Path $root "resources\daemon\libcronet.dll")
        "resources\daemon\WinDivert64.sys"     = (Join-Path $root "resources\daemon\WinDivert64.sys")
        "resources\native\windows_share.node"  = (Join-Path $root "resources\native\windows_share.node")
    }
    foreach ($name in $required.Keys) {
        $exists = Test-Path -LiteralPath $required[$name] -PathType Leaf
        $lines.Add("  $name : $(if ($exists) { 'present' } else { 'MISSING' })")
        if (-not $exists) { Fail-Gate "$Phase`: $name is missing at $($required[$name])" }
    }

    if ($null -eq $state.LayoutVersion -or [int]$state.LayoutVersion -ne 2) {
        Fail-Gate "$Phase`: HKLM SagerNet sing-box does not record LayoutVersion 2 (found '$($state.LayoutVersion)'); clients/desktop reads that key at startup"
    }
    $lines.Add("  layout registry: LayoutVersion 2, InstallationID $($state.InstallationID)")

    # Fail closed on the uninstall entry, and never silently pick the first.
    $matches = @($state.UninstallMatches)
    if ($matches.Count -eq 0) {
        $lines.Add("  uninstall entries: NONE matched $root; every candidate follows")
        foreach ($line in (Format-UninstallEntries -Entries @(Get-UninstallRegistryEntries))) { $lines.Add($line) }
        Fail-Gate "$Phase`: no uninstall registry entry has an InstallLocation - or an uninstaller - inside $root"
    }
    if ($matches.Count -gt 1) {
        $lines.Add("  uninstall entries: $($matches.Count) matched $root")
        foreach ($line in (Format-UninstallEntries -Entries $matches)) { $lines.Add($line) }
        Fail-Gate "$Phase`: $($matches.Count) uninstall registry entries match $root; refusing to choose one"
    }
    if (-not $candidateDumpWritten) {
        $candidateDumpWritten = $true
        $allCandidates = @(Get-UninstallRegistryEntries)
        $lines.Add("  every uninstall registry entry on this machine: $($allCandidates.Count)")
        foreach ($line in (Format-UninstallEntries -Entries $allCandidates)) { $lines.Add($line) }
    }

    $entry = $matches[0].Entry
    $lines.Add("  uninstall entry:    $($entry.PSPath)")
    $lines.Add("  display name:       $($entry.DisplayName)   (audit metadata only, never a key)")
    $lines.Add("  display version:    $($entry.DisplayVersion)")
    $lines.Add("  install location:   $($entry.InstallLocation)")
    $lines.Add("  uninstall string:   $($entry.UninstallString)")
    $lines.Add("  matched by:         $($matches[0].MatchMethod)")
    if ([string]::IsNullOrWhiteSpace($entry.UninstallString)) {
        Fail-Gate "$Phase`: the matched uninstall entry has no UninstallString"
    }

    $daemonPath = $required["resources\daemon\sing-box-daemon.exe"]
    $version = Invoke-NativeCommand { & $daemonPath version }
    $versionOutput = $version.Output.Trim()
    $lines.Add("  daemon version: $versionOutput (exit code $($version.ExitCode))")
    if ($version.ExitCode -ne 0) { Fail-Gate "$Phase`: the installed daemon's version command exited $($version.ExitCode)" }
    if ($versionOutput -notmatch [regex]::Escape("version $ExpectedVersion")) {
        Fail-Gate "$Phase`: the installed daemon reports '$versionOutput', expected version $ExpectedVersion"
    }

    $serviceState = Get-ServiceState
    $lines.Add("  service: $serviceState")
    if ($serviceState -ne "Running") {
        Fail-Gate "$Phase`: the $serviceName service is '$serviceState', expected Running"
    }

    return [pscustomobject]@{ Root = $root; UninstallEntry = $entry }
}


function Invoke-Uninstall {
    param([string]$Phase, [Parameter(Mandatory = $true)]$UninstallEntry, [switch]$DeleteAppData)
    # The uninstaller is the one the discovered entry names. No path is constructed from a
    # product name.
    $uninstallString = [string]$UninstallEntry.UninstallString
    if ([string]::IsNullOrWhiteSpace($uninstallString)) {
        Fail-Gate "$Phase`: the matched uninstall entry has no UninstallString"
    }
    $uninstaller = Get-CommandExecutablePath $uninstallString
    if ([string]::IsNullOrWhiteSpace($uninstaller) -or -not (Test-Path -LiteralPath $uninstaller -PathType Leaf)) {
        Fail-Gate "$Phase`: the uninstaller '$uninstaller' named by $($UninstallEntry.PSPath) does not exist"
    }
    # The installer's own rollback uses /S /allusers, so that pair is the supported one.
    $arguments = @("/S", "/allusers")
    if ($DeleteAppData) {
        # build/installer.nsh: `--delete-app-data` sets $keepUninstallData to unchecked,
        # which is the ONLY path that runs the data-removal branch. Without it the
        # uninstaller keeps the data by design (electron-builder.yml:
        # deleteAppDataOnUninstall: false) and the installer layout registry key is
        # deliberately left behind so a reinstall can reuse the data directories.
        $arguments += "--delete-app-data"
    }
    $exitCode = Invoke-Silently -FilePath $uninstaller -Arguments $arguments -What "$Phase uninstall"
    if ($exitCode -ne 0) { Fail-Gate "$Phase`: the uninstaller exited $exitCode" }
}


function Assert-Uninstalled {
    param([string]$Phase, [string]$InstallationRoot, $UninstallEntry, [switch]$DataPreserved)
    $null = Wait-Until -Description "$Phase uninstall to settle" -TimeoutSeconds 300 -Condition {
        ($null -eq (Get-DaemonServiceCommandLine)) -and ($null -eq (Get-InstallationLayoutRegistry))
    }

    $state = Get-ServiceState
    $lines.Add("  service after uninstall: $state")
    if ($state -ne "absent") { Fail-Gate "$Phase`: the $serviceName service is still '$state'" }
    $query = Invoke-NativeCommand { sc.exe query $serviceName }
    if ($query.ExitCode -eq 0) { Fail-Gate "$Phase`: sc.exe query still reports $serviceName" }
    if ($query.Output -match "marked for deletion") {
        Fail-Gate "$Phase`: the service is marked for deletion; the next install would fail"
    }

    $layout = Get-InstallationLayoutRegistry
    if ($DataPreserved) {
        # The uninstaller keeps the data directories unless it is told not to, and it keeps
        # the layout key with them so a reinstall can reuse them. Asserting the key gone
        # here would be asserting behaviour the product does not have; the next phase runs
        # the uninstall that DOES remove it, so the assertion is still made - just where it
        # is actually about something.
        if ($null -ne $layout) {
            $lines.Add("  layout registry: retained by design (LayoutVersion $($layout.LayoutVersion), InstallationID $($layout.InstallationID))")
            $lines.Add("    the uninstaller preserves data unless --delete-app-data is given; the final phase passes it")
        } else {
            $lines.Add("  layout registry: absent (not retained by this uninstall)")
        }
    } else {
        if ($null -ne $layout) {
            Fail-Gate "$Phase`: the installer layout registry key survived a data-removing uninstall"
        }
        $lines.Add("  layout registry: absent after --delete-app-data")
    }

    if ($null -ne $UninstallEntry) {
        $survivors = @(Get-UninstallRegistryEntries | Where-Object { $_.PSPath -eq $UninstallEntry.PSPath })
        if ($survivors.Count -gt 0) {
            Fail-Gate "$Phase`: the uninstall registry entry $($UninstallEntry.PSPath) survived uninstall"
        }
        $lines.Add("  uninstall entry: absent ($($UninstallEntry.PSPath))")
    }

    if (-not [string]::IsNullOrWhiteSpace($InstallationRoot)) {
        foreach ($relative in @("sing-box.exe", "resources\daemon\sing-box-daemon.exe")) {
            $path = Join-Path $InstallationRoot $relative
            if (Test-Path -LiteralPath $path) {
                Fail-Gate "$Phase`: $relative survived uninstall at $path"
            }
        }
        $lines.Add("  product payload: absent from $InstallationRoot")
        if (Test-Path -LiteralPath $InstallationRoot) {
            # Reported rather than failed: only product payload is asserted absent. A left
            # behind log or an empty directory is not a broken installation.
            $remaining = @(Get-ChildItem -LiteralPath $InstallationRoot -Recurse -File -ErrorAction SilentlyContinue)
            $lines.Add("  note: the installation directory remains with $($remaining.Count) file(s)")
        }
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

# The installer runs its preflight and its service command through Windows PowerShell 5.1
# ($SYSDIR\WindowsPowerShell\v1.0\powershell.exe). Started from PowerShell 7 - which is what
# this gate and the runner use - that child inherits PowerShell 7's PSModulePath, and 5.1
# then resolves Microsoft.PowerShell.Security to PowerShell 7's incompatible copy of the
# module ahead of its own:
#
#     [preflight] exit=30  The 'Get-Acl' command was found in the module
#     'Microsoft.PowerShell.Security', but the module could not be loaded.
#
# Prepending the 5.1 directory is not enough, because PowerShell 7 already appends it:
# the check that looked for it found it, skipped the change, and the failure stayed. The
# child's module path is therefore rebuilt from the 5.1 locations only, so it cannot pick up
# a module built for a different PowerShell. This changes the harness's environment, not the
# product's behaviour: a user double-clicking the installer inherits Explorer's environment.
$windowsPowerShellModules = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\Modules"
if (-not (Test-Path -LiteralPath $windowsPowerShellModules)) {
    Fail-Gate "the Windows PowerShell 5.1 module directory is missing: $windowsPowerShellModules"
}
$installerModulePath = @(
    $windowsPowerShellModules,
    (Join-Path $env:ProgramFiles "WindowsPowerShell\Modules"),
    (Join-Path $env:USERPROFILE "Documents\WindowsPowerShell\Modules")
) -join ";"
$lines.Add("psmodulepath for the installer's Windows PowerShell 5.1 children: $installerModulePath")
Write-Host "setting PSModulePath for the installer to the Windows PowerShell 5.1 module locations"
$env:PSModulePath = $installerModulePath

# A previous gate may have left a service behind; a clean state is a precondition, and it
# is reported rather than assumed.
$preconditionState = Get-InstallationState
$preconditionMatches = @()
if ($null -ne $preconditionState) { $preconditionMatches = @($preconditionState.UninstallMatches) }
if ((Get-ServiceState) -ne "absent" -or $null -ne $preconditionState -or $preconditionMatches.Count -gt 1) {
    $lines.Add("clean state: a previous installation or service was present; removing it first")
    Write-Host "an installation or service was already present; uninstalling before the test"
    Add-InstallationIdentity $preconditionState
    if ($preconditionMatches.Count -gt 1) {
        foreach ($line in (Format-UninstallEntries -Entries $preconditionMatches)) { $lines.Add($line) }
        Fail-Gate "the machine has $($preconditionMatches.Count) installations matching one root; refusing to remove one"
    }
    if ($preconditionMatches.Count -eq 1) {
        # Only this installation's own uninstaller, discovered structurally.
        Invoke-Uninstall -Phase "precondition" -UninstallEntry $preconditionMatches[0].Entry
    } elseif ($null -ne $preconditionState -and -not [string]::IsNullOrWhiteSpace($preconditionState.Root)) {
        # A service without a usable uninstall entry: remove only that service, and say so.
        $lines.Add("precondition: no uninstall entry matched $($preconditionState.Root); deleting the service only")
        $deleted = Invoke-NativeCommand { sc.exe delete $serviceName }
        $lines.Add("precondition: sc.exe delete exited $($deleted.ExitCode)")
    } elseif ((Get-ServiceState) -ne "absent") {
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
$installed = Assert-Installed -Phase "after first install"
$installationRoot = $installed.Root
$uninstallEntry = $installed.UninstallEntry
$lines.Add("  PASS")
$lines.Add("")

# --- same-version reinstall --------------------------------------------------
$lines.Add("[2/5] same-version reinstall")
$exitCode = Invoke-Silently -FilePath $InstallerPath -Arguments (Get-InstallArguments) -What "reinstall"
$lines.Add("  exit code $exitCode")
if ($exitCode -ne 0) { Fail-Gate "the same-version reinstall exited $exitCode" }
$reinstalled = Assert-Installed -Phase "after same-version reinstall"
if ($reinstalled.Root -ne $installationRoot) {
    Fail-Gate "the reinstall moved the installation from $installationRoot to $($reinstalled.Root)"
}
$lines.Add("  PASS (same root, no ERROR_SERVICE_EXISTS, no marked-for-deletion, no StopPending stall)")
$lines.Add("")

# --- uninstall ---------------------------------------------------------------
$lines.Add("[3/5] silent uninstall")
Invoke-Uninstall -Phase "first" -UninstallEntry $uninstallEntry
Assert-Uninstalled -Phase "after first uninstall" -InstallationRoot $installationRoot -UninstallEntry $uninstallEntry -DataPreserved
$lines.Add("  PASS")
$lines.Add("")

# --- clean reinstall ---------------------------------------------------------
$lines.Add("[4/5] clean reinstall after a full uninstall")
$exitCode = Invoke-Silently -FilePath $InstallerPath -Arguments (Get-InstallArguments) -What "reinstall"
$lines.Add("  exit code $exitCode")
if ($exitCode -ne 0) { Fail-Gate "the clean reinstall exited $exitCode" }
$reinstalled = Assert-Installed -Phase "after clean reinstall"
$installationRoot = $reinstalled.Root
$uninstallEntry = $reinstalled.UninstallEntry
$lines.Add("  PASS")
$lines.Add("")

# --- final teardown ----------------------------------------------------------
$lines.Add("[5/5] final uninstall")
Invoke-Uninstall -Phase "final" -UninstallEntry $uninstallEntry -DeleteAppData
Assert-Uninstalled -Phase "after final uninstall" -InstallationRoot $installationRoot -UninstallEntry $uninstallEntry
$lines.Add("  PASS")
$lines.Add("")

$lines.Add("PASS: install, verify, same-version reinstall, uninstall, clean reinstall and")
$lines.Add("      final uninstall all completed with no residual service or process state")
Save-Record
foreach ($line in $lines) { Write-Host $line }

Complete-Gate
