# Shared exit-status handling for the Windows CI gates.
#
# # The problem this exists for
#
# GitHub's pwsh wrapper ends a step with `exit $LASTEXITCODE`. $LASTEXITCODE is whatever
# the last NATIVE command left behind - not what the script decided - and several commands
# in these gates are expected to exit non-zero as part of a PASS:
#
#   sc.exe query <name>            returns 1060 when the service is, correctly, absent
#   signtool verify /kp /c ...     returns non-zero for a driver its catalog does not cover
#
# Left alone, that turns a passing gate into a failed step. Gate 5 did exactly that: it
# printed
#
#   PASS: install, SCM registration, Running, status, stop and uninstall all verified
#
# and the step still reported "Process completed with exit code 1", because the last native
# command to run was the `sc.exe query` that proved the service was gone.
#
# # Why not just `exit 0`
#
# An unconditional `exit 0` at the end of a script also hides a real failure that happened
# to leave a non-zero status, and it makes the exit code say nothing about the verdict. The
# leak is closed at its source instead:
#
#   * Invoke-NativeCommand runs a native command, records its exit code and its output, and
#     clears $LASTEXITCODE immediately. Every caller then judges ExitCode explicitly, so an
#     expected non-zero is a positive assertion rather than something tolerated.
#   * Complete-Gate ends the script. Every failure path reaches Fail-Gate first, which exits
#     1 and writes the record, so reaching Complete-Gate IS the verdict.
#
# Nothing here suppresses a failure: a command whose non-zero exit was not expected still
# fails the gate through the caller's check on ExitCode.

$script:GateFailures = New-Object System.Collections.Generic.List[string]

# Runs a native command and returns its output and exit code, clearing $LASTEXITCODE so the
# value cannot leak into the caller's process exit status. The caller MUST judge ExitCode.
function Invoke-NativeCommand {
    param([Parameter(Mandatory = $true)][scriptblock]$Command)
    $output = & $Command 2>&1 | Out-String
    $exitCode = $LASTEXITCODE
    $global:LASTEXITCODE = 0
    return [pscustomobject]@{ Output = $output; ExitCode = $exitCode }
}

# Clears a leaked native status when a command was invoked directly rather than through
# Invoke-NativeCommand. Prefer Invoke-NativeCommand; this exists for the few places where
# the command is part of a larger expression.
function Clear-NativeExitStatus {
    $global:LASTEXITCODE = 0
}

# Polls a condition until it holds or a deadline passes. NSIS uninstallers commonly copy
# themselves to a temporary directory and hand off, so the process that was waited on can
# exit before the work is finished; post-conditions are waited for rather than sampled.
function Wait-Until {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Condition,
        [Parameter(Mandatory = $true)][string]$Description,
        [int]$TimeoutSeconds = 300
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (& $Condition) { return $true }
        Start-Sleep -Seconds 2
    }
    Write-Host "  timed out after $TimeoutSeconds s waiting for: $Description"
    return $false
}

# Ends the script with the exit code the gate decided, not the one a native command left.
# Fail-Gate exits 1 before this is ever reached, so this line means the gate passed.
function Complete-Gate {
    if ($script:GateFailures.Count -gt 0) {
        Write-Error "gate recorded $($script:GateFailures.Count) failure(s) but reached the end; this is a bug in the gate"
        foreach ($failure in $script:GateFailures) { Write-Error "  - $failure" -ErrorAction Continue }
        exit 1
    }
    exit 0
}

# --- installation identity ---------------------------------------------------
#
# # Why identity is structural and never a display name
#
# The first version of the installer gate matched the uninstall registry entry with
#
#     Where-Object { $_.DisplayName -eq "Jiejiebox" }
#
# That is a fixture bug. A display name is presentation: it is the product name, and the
# executable and installation directory are deliberately NOT the product name (they are
# "sing-box", because experimental/boxdd authenticates the application by that exact path).
# So the entry may legitimately be named either way, and a name cannot establish identity
# even when it happens to match - the first entry with that name would be accepted.
#
# These helpers establish identity from things that are facts:
#
#   1. the SCM's own record of where the daemon runs  (Win32_Service.PathName), which is
#      the daemon's command line, parsed with path APIs rather than string replacement;
#   2. the directory layout that command line implies  (<root>\resources\daemon\...),
#      which is the layout experimental/boxdd itself requires;
#   3. the installer's own layout registry key          (LayoutVersion 2);
#   4. and only then the uninstall entry whose InstallLocation IS that root.
#
# DisplayName is recorded as audit metadata. It is never a key.

function Get-NormalizedPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return "" }
    $trimmed = $Path.Trim().Trim('"')
    $expanded = [System.Environment]::ExpandEnvironmentVariables($trimmed)
    try {
        $full = [System.IO.Path]::GetFullPath($expanded)
    } catch {
        return $expanded.TrimEnd('\').ToLowerInvariant()
    }
    return $full.TrimEnd('\').ToLowerInvariant()
}

# The executable out of a command line, honouring a quoted path and otherwise splitting on
# the first space. Used for both Win32_Service.PathName and UninstallString.
function Get-CommandExecutablePath {
    param([string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return "" }
    $value = $CommandLine.Trim()
    if ($value.StartsWith('"')) {
        $end = $value.IndexOf('"', 1)
        if ($end -lt 0) { return "" }
        return $value.Substring(1, $end - 1)
    }
    return ($value -split ' ')[0]
}

# The daemon's command line as the SCM has it. Get-CimInstance rather than parsing
# `sc.exe qc` output, which is localised.
function Get-DaemonServiceCommandLine {
    param([string]$ServiceName = "sing-box-daemon")
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
    if ($null -eq $service) { return "" }
    return [string]$service.PathName
}

# <root>\resources\daemon\sing-box-daemon.exe -> <root>, using path APIs and checking each
# component, so a path that merely contains the string "resources" is not accepted.
function Get-InstallationRootFromDaemonPath {
    param([string]$DaemonPath)
    if ([string]::IsNullOrWhiteSpace($DaemonPath)) { return "" }
    if (-not (Test-Path -LiteralPath $DaemonPath -PathType Leaf)) { return "" }
    $daemonDirectory = Split-Path -Parent $DaemonPath
    $resourcesDirectory = Split-Path -Parent $daemonDirectory
    $root = Split-Path -Parent $resourcesDirectory
    if ([string]::IsNullOrWhiteSpace($root)) { return "" }
    if ((Split-Path -Leaf $DaemonPath) -ine "sing-box-daemon.exe") { return "" }
    if ((Split-Path -Leaf $daemonDirectory) -ine "daemon") { return "" }
    if ((Split-Path -Leaf $resourcesDirectory) -ine "resources") { return "" }
    return (Get-NormalizedPath $root)
}

function Get-InstallationLayoutRegistry {
    param([string]$RegistryPath = "HKLM:\SOFTWARE\SagerNet\sing-box")
    $key = Get-ItemProperty -Path $RegistryPath -ErrorAction SilentlyContinue
    if ($null -eq $key) { return $null }
    return $key
}

function Get-UninstallRegistryEntries {
    $roots = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $entries = New-Object System.Collections.Generic.List[object]
    foreach ($root in $roots) {
        foreach ($entry in @(Get-ItemProperty -Path $root -ErrorAction SilentlyContinue)) {
            if ($null -eq $entry) { continue }
            # Entries with neither an uninstall command nor an install location cannot be
            # matched structurally and are not candidates.
            if ([string]::IsNullOrWhiteSpace($entry.UninstallString) -and [string]::IsNullOrWhiteSpace($entry.InstallLocation)) { continue }
            $entries.Add([pscustomobject]@{
                PSPath              = $entry.PSPath
                Key                 = $entry.PSChildName
                DisplayName         = $entry.DisplayName
                DisplayVersion      = $entry.DisplayVersion
                Publisher           = $entry.Publisher
                InstallLocation     = $entry.InstallLocation
                UninstallString     = $entry.UninstallString
                QuietUninstallString = $entry.QuietUninstallString
            })
        }
    }
    return $entries
}

# Every uninstall entry that IS this installation, by InstallLocation first and by the
# uninstaller's own location second. Returns matches with the method that matched, so a
# fallback is never silent.
function Get-UninstallEntriesForInstallation {
    param([Parameter(Mandatory = $true)][string]$InstallationRoot)
    $normalizedRoot = Get-NormalizedPath $InstallationRoot
    $matches = New-Object System.Collections.Generic.List[object]
    foreach ($entry in Get-UninstallRegistryEntries) {
        $method = ""
        if (-not [string]::IsNullOrWhiteSpace($entry.InstallLocation)) {
            if ((Get-NormalizedPath $entry.InstallLocation) -eq $normalizedRoot) { $method = "InstallLocation" }
        }
        if ([string]::IsNullOrWhiteSpace($method) -and -not [string]::IsNullOrWhiteSpace($entry.UninstallString)) {
            $uninstaller = Get-CommandExecutablePath $entry.UninstallString
            if (-not [string]::IsNullOrWhiteSpace($uninstaller)) {
                $parent = Split-Path -Parent $uninstaller
                if (-not [string]::IsNullOrWhiteSpace($parent) -and (Get-NormalizedPath $parent) -eq $normalizedRoot) {
                    $method = "UninstallString parent"
                }
            }
        }
        if (-not [string]::IsNullOrWhiteSpace($method)) {
            $matches.Add([pscustomobject]@{ Entry = $entry; MatchMethod = $method })
        }
    }
    return $matches
}

function Format-UninstallEntries {
    param([Parameter(Mandatory = $true)]$Entries)
    $lines = New-Object System.Collections.Generic.List[string]
    if (@($Entries).Count -eq 0) {
        $lines.Add("  (none)")
        return $lines
    }
    $index = 0
    foreach ($item in @($Entries)) {
        $index++
        $entry = $item.Entry
        if ($null -eq $entry) { $entry = $item }
        $lines.Add("  [$index] PSPath           $($entry.PSPath)")
        $lines.Add("      DisplayName        $($entry.DisplayName)")
        $lines.Add("      DisplayVersion     $($entry.DisplayVersion)")
        $lines.Add("      Publisher          $($entry.Publisher)")
        $lines.Add("      InstallLocation    $($entry.InstallLocation)")
        $lines.Add("      UninstallString    $($entry.UninstallString)")
        $lines.Add("      QuietUninstall     $($entry.QuietUninstallString)")
        if ($null -ne $item.MatchMethod) { $lines.Add("      matched by         $($item.MatchMethod)") }
    }
    return $lines
}
