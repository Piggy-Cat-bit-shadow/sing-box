# Removes everything New-TestSigningCertificate.ps1 created. Runs with `if: always()`.
#
# Usage:
#   Remove-TestSigningCertificate.ps1 -ClientDirectory <desktop client dir> `
#                                     [-Thumbprint <thumbprint>]
#
# Removes:
#   the PFX and the exported .cer under $env:RUNNER_TEMP
#   the PFX password file
#   <client dir>/signing.local.json
#   the certificate from Cert:\CurrentUser\My
#   the certificate from Cert:\LocalMachine Root and TrustedPublisher
#
# # Why this exists even though the runner is thrown away
#
# A hosted runner is ephemeral, but the workspace is not private for the duration of the
# job, and an artifact upload glob is easy to widen later. A private key and its password
# sitting in the checkout while later steps run is the kind of thing that ends up inside a
# published artifact by accident. So they are removed as soon as packaging is done, and the
# step is `if: always()` so a failed build removes them too.
#
# The password and the key are never printed. The thumbprint is a public identifier and is
# printed.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ClientDirectory,
    [string]$Thumbprint = ""
)

$ErrorActionPreference = "Continue"

if ([string]::IsNullOrWhiteSpace($Thumbprint) -and -not [string]::IsNullOrWhiteSpace($env:JJ_SIGNING_THUMBPRINT)) {
    $Thumbprint = $env:JJ_SIGNING_THUMBPRINT
}

$temporaryDirectory = $env:RUNNER_TEMP
if ([string]::IsNullOrWhiteSpace($temporaryDirectory)) {
    $temporaryDirectory = [System.IO.Path]::GetTempPath()
}

Write-Host "== removing CI test signing material =="

foreach ($path in @(
    (Join-Path $temporaryDirectory "jiejiebox-ci-signing.pfx"),
    (Join-Path $temporaryDirectory "jiejiebox-ci-signing.cer"),
    (Join-Path $temporaryDirectory "jiejiebox-ci-signing.password")
)) {
    if (Test-Path -LiteralPath $path) {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        Write-Host "  removed $path"
    }
}

if (-not [string]::IsNullOrWhiteSpace($ClientDirectory)) {
    $signingConfiguration = Join-Path $ClientDirectory "signing.local.json"
    if (Test-Path -LiteralPath $signingConfiguration) {
        Remove-Item -LiteralPath $signingConfiguration -Force -ErrorAction SilentlyContinue
        Write-Host "  removed $signingConfiguration"
    }
}

if (-not [string]::IsNullOrWhiteSpace($Thumbprint)) {
    Write-Host "  certificate thumbprint $Thumbprint"
    foreach ($store in @(
        "Cert:\CurrentUser\My",
        "Cert:\LocalMachine\Root",
        "Cert:\LocalMachine\TrustedPublisher"
    )) {
        $removed = 0
        Get-ChildItem -Path $store -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $Thumbprint } |
            ForEach-Object {
                Remove-Item -Path $_.PSPath -Force -ErrorAction SilentlyContinue
                $removed++
            }
        Write-Host "  removed $removed entr$(if ($removed -eq 1) { 'y' } else { 'ies' }) from $store"
    }
} else {
    Write-Host "  no thumbprint was supplied, so no certificate store entries were removed"
}

# Report what is left, so a failed cleanup is visible rather than assumed.
$remaining = @()
foreach ($path in @(
    (Join-Path $temporaryDirectory "jiejiebox-ci-signing.pfx"),
    (Join-Path $temporaryDirectory "jiejiebox-ci-signing.password")
)) {
    if (Test-Path -LiteralPath $path) { $remaining += $path }
}
if (-not [string]::IsNullOrWhiteSpace($ClientDirectory)) {
    $signingConfiguration = Join-Path $ClientDirectory "signing.local.json"
    if (Test-Path -LiteralPath $signingConfiguration) { $remaining += $signingConfiguration }
}
if ($remaining.Count -gt 0) {
    Write-Error "signing material was not fully removed:" -ErrorAction Continue
    foreach ($path in $remaining) { Write-Error "  $path" -ErrorAction Continue }
    exit 1
}

Write-Host "  PASS: no PFX, password file or signing.local.json remains"

# GitHub's pwsh wrapper ends the step with `exit $LASTEXITCODE`, so a gate that has just
# verified everything can still be reported as a failure if the last native command that
# ran happened to exit non-zero. In this script that is normal, not an error: `sc.exe
# query` on a service that is correctly absent returns 1060. The verdict is decided above,
# so the exit code is set deliberately here.
exit 0
