# P0-2: turn the historical "Failed to register sing-box daemon (code 1)" into a
# concrete failing stage with the raw error.
#
# `code 1` is the exit status of `sing-box-daemon.exe service install`. Every failure
# path in that command is log.Fatal (experimental/boxdd/cmd_service_windows.go), so the
# stage and the raw error can only be recovered by running the daemon directly with the
# same arguments the NSIS installer uses.
#
# `service install` mutates the machine (creates/updates the sing-box-daemon service,
# is a no-op when the existing layout and inputs are unchanged). Pass -DryRun to only
# record state, or -Uninstall to remove the test daemon and restore the machine.
[CmdletBinding()]
param(
    [string]$InstallRoot = 'C:\src\sfw-test\sing-box',
    [string]$WorkingDirectory = 'C:\ProgramData\sing-box-daemon-test',
    [string]$LogPath = 'C:\src\_toolchain\p0-2-registration.json',
    [switch]$DryRun,
    [switch]$Uninstall,
    [switch]$StatusOnly
)

$ErrorActionPreference = 'Continue'

function Write-Section([string]$title) {
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor Cyan
    Write-Host $title -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor Cyan
}

$daemonPath = Join-Path $InstallRoot 'resources\daemon\sing-box-daemon.exe'
$applicationPath = Join-Path $InstallRoot 'sing-box.exe'

$record = [ordered]@{
    timestamp         = (Get-Date).ToString('o')
    installRoot       = $InstallRoot
    workingDirectory  = $WorkingDirectory
    daemonPath        = $daemonPath
    applicationPath   = $applicationPath
    ancestors         = @()
    preflight         = [ordered]@{}
    attempt           = [ordered]@{}
}

# ---------------------------------------------------------------- ancestor audit
# This mirrors experimental/boxdd/security_windows.go validateInstallationAncestors:
# every ancestor from the install root up to the volume root must be owned by SYSTEM,
# Administrators or TrustedInstaller, and must not grant DELETE/WRITE_DAC/WRITE_OWNER/
# GENERIC_WRITE/GENERIC_ALL/FILE_DELETE_CHILD to any other principal. The walk covers
# the installation DIRECTORY itself, not just its parents.
Write-Section 'ANCESTOR AUDIT (validateInstallationAncestors rule)'
$trusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
$root = [System.IO.Path]::GetPathRoot($InstallRoot)
$current = $InstallRoot.TrimEnd('\')
$ancestorRows = @()
while ($true) {
    $acl = Get-Acl -LiteralPath $current -ErrorAction SilentlyContinue
    if ($null -eq $acl) {
        $ancestorRows += [pscustomobject]@{ path = $current; owner = '(missing)'; verdict = 'MISSING' ; detail = '' }
        break
    }
    $ownerSid = $acl.Owner
    try { $ownerSid = (New-Object System.Security.Principal.NTAccount($acl.Owner)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { }
    $ownerTrusted = $trusted -contains $ownerSid

    $dangerous = 0x00010000 -bor 0x00040000 -bor 0x00080000 -bor 0x40000000 -bor 0x10000000 -bor 0x00000040
    $badAce = @()
    foreach ($ace in $acl.Access) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        if ($ace.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
        $mask = [int]$ace.FileSystemRights
        if (($mask -band $dangerous) -eq 0) { continue }
        $sid = $ace.IdentityReference
        try { $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { }
        if ($trusted -notcontains $sid) { $badAce += "$($ace.IdentityReference) [$sid] mask=0x$('{0:X}' -f $mask)" }
    }

    $verdict = 'OK'
    $detail = ''
    if (-not $ownerTrusted) { $verdict = 'FAIL'; $detail = "owner $($acl.Owner) is not a trusted administrative principal" }
    elseif ($badAce.Count -gt 0) { $verdict = 'FAIL'; $detail = "dangerous ACE: $($badAce -join '; ')" }

    $ancestorRows += [pscustomobject]@{ path = $current; owner = $acl.Owner; ownerSid = $ownerSid; verdict = $verdict; detail = $detail }
    Write-Host ("  [{0,-4}] {1}" -f $verdict, $current) -ForegroundColor $(if ($verdict -eq 'OK') { 'Gray' } else { 'Red' })
    Write-Host ("           owner: {0}" -f $acl.Owner)
    if ($detail) { Write-Host ("           {0}" -f $detail) -ForegroundColor Red }

    if ([string]::Equals($current, $root.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) { break }
    $parent = Split-Path -Parent $current
    if (-not $parent -or $parent -eq $current) { break }
    $current = $parent
}
$record.ancestors = $ancestorRows

Write-Section 'PREFLIGHT'
foreach ($p in @($applicationPath, $daemonPath)) {
    $exists = Test-Path -LiteralPath $p
    Write-Host ("  {0,-6} {1}" -f $(if ($exists) { 'OK' } else { 'MISSING' }), $p) -ForegroundColor $(if ($exists) { 'Gray' } else { 'Red' })
}
$sigDaemon = if (Test-Path $daemonPath) { Get-AuthenticodeSignature $daemonPath } else { $null }
$sigApp = if (Test-Path $applicationPath) { Get-AuthenticodeSignature $applicationPath } else { $null }
$record.preflight = [ordered]@{
    daemonSignature = if ($sigDaemon) { [ordered]@{ status = "$($sigDaemon.Status)"; subject = "$($sigDaemon.SignerCertificate.Subject)"; thumbprint = "$($sigDaemon.SignerCertificate.Thumbprint)"; sha256 = (Get-FileHash $daemonPath -Algorithm SHA256).Hash } } else { $null }
    applicationSignature = if ($sigApp) { [ordered]@{ status = "$($sigApp.Status)"; subject = "$($sigApp.SignerCertificate.Subject)"; thumbprint = "$($sigApp.SignerCertificate.Thumbprint)"; sha256 = (Get-FileHash $applicationPath -Algorithm SHA256).Hash } } else { $null }
}
Write-Host ("  daemon signer : {0}" -f $(if ($sigDaemon.SignerCertificate) { $sigDaemon.SignerCertificate.Subject } else { '(none)' }))
Write-Host ("  app signer    : {0}" -f $(if ($sigApp.SignerCertificate) { $sigApp.SignerCertificate.Subject } else { '(none)' }))

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host ("  user / elevated : {0} / {1}" -f $identity.Name, $isAdmin)
$record.preflight.elevated = $isAdmin
$record.preflight.user = $identity.Name

$svcBefore = Get-CimInstance Win32_Service -Filter "Name='sing-box-daemon'" -ErrorAction SilentlyContinue
$record.preflight.serviceBefore = if ($svcBefore) { "$($svcBefore.State) :: $($svcBefore.PathName)" } else { 'not installed' }
Write-Host ("  service before  : {0}" -f $record.preflight.serviceBefore)

if ($StatusOnly -or $DryRun) {
    if ($StatusOnly) {
        Write-Section 'DAEMON service status'
        & $daemonPath service status 2>&1 | ForEach-Object { "  $_" }
        Write-Host ("  exit code: {0}" -f $LASTEXITCODE)
    }
    $record | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $LogPath -Encoding UTF8
    Write-Host "`nrecord written: $LogPath"
    return
}

# ---------------------------------------------------------------- the attempt
$serviceAction = if ($Uninstall) { 'uninstall' } else { 'install' }
$arguments = @('service', $serviceAction)
if (-not $Uninstall) { $arguments += @('--working-directory', $WorkingDirectory) }

Write-Section "ATTEMPT: sing-box-daemon.exe $($arguments -join ' ')"
Write-Host ("  cwd: {0}" -f (Split-Path -Parent $daemonPath))

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $daemonPath
$psi.Arguments = ($arguments -join ' ')
$psi.WorkingDirectory = Split-Path -Parent $daemonPath
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
$psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8

$process = [System.Diagnostics.Process]::Start($psi)
$stdoutTask = $process.StandardOutput.ReadToEndAsync()
$stderrTask = $process.StandardError.ReadToEndAsync()
$process.WaitForExit()
$stdout = $stdoutTask.Result.TrimEnd()
$stderr = $stderrTask.Result.TrimEnd()
$exitCode = $process.ExitCode
$process.Dispose()

Write-Host '  --- STDOUT ---' -ForegroundColor Yellow
if ($stdout) { $stdout -split "`r?`n" | ForEach-Object { "  $_" } } else { Write-Host '  (empty)' }
Write-Host '  --- STDERR ---' -ForegroundColor Yellow
if ($stderr) { $stderr -split "`r?`n" | ForEach-Object { "  $_" } } else { Write-Host '  (empty)' }
Write-Host ("  EXIT CODE: {0}" -f $exitCode) -ForegroundColor $(if ($exitCode -eq 0) { 'Green' } else { 'Red' })

$record.attempt = [ordered]@{
    command   = "`"$daemonPath`" $($arguments -join ' ')"
    exitCode  = $exitCode
    stdout    = $stdout
    stderr    = $stderr
}

Write-Section 'SERVICE STATE AFTER'
$svcAfter = Get-CimInstance Win32_Service -Filter "Name='sing-box-daemon'" -ErrorAction SilentlyContinue
if ($svcAfter) {
    $svcAfter | Select-Object Name, State, StartName, StartMode, PathName, ProcessId | Format-List
    $record.after = [ordered]@{ state = "$($svcAfter.State)"; startName = "$($svcAfter.StartName)"; pathName = "$($svcAfter.PathName)"; processId = $svcAfter.ProcessId }
} else {
    Write-Host '  not installed'
    $record.after = [ordered]@{ state = 'not installed' }
}

if ($exitCode -ne 0) {
    Write-Section 'STAGE MAPPING'
    $detail = if ($stderr) { $stderr } else { $stdout }
    Write-Host ("  raw error: {0}" -f $detail) -ForegroundColor Red
}

$record | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $LogPath -Encoding UTF8
Write-Host "`nrecord written: $LogPath"
