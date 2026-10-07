# Creates a throwaway Authenticode code-signing certificate for this CI run only.
#
# Usage:
#   New-TestSigningCertificate.ps1 -ClientDirectory <desktop client dir>
#
# Writes, all under $env:RUNNER_TEMP except the last:
#   jiejiebox-ci-signing.pfx        the certificate and private key, for signtool
#   jiejiebox-ci-signing.cer        the public certificate, for the trust stores
#   jiejiebox-ci-signing.password   the PFX password, never printed
#   <client dir>/signing.local.json the file scripts/package.ts already reads
#
# and exports JJ_SIGNING_THUMBPRINT so the signing gate can assert that the files it
# inspects were signed by THIS certificate.
#
# # Why a certificate at all, when the release is unsigned
#
# The unsigned path exists so a development build needs no certificate. It also meant
# nothing ever exercised signing, so a release candidate was never once proven to be
# signable. The core's Windows daemon goes further than that: it authenticates the
# application against the daemon's own signer, and refuses to register the service or
# accept a peer connection if they differ. An unsigned build cannot even install.
#
# So CI signs with a certificate it makes and destroys, which exercises the real path -
# electron-builder's signtool, and the daemon's own Authenticode checks - without any
# long-lived secret. Nothing here is a substitute for a release certificate; it is the
# same code path with a certificate nobody can use afterwards.
#
# # Why the certificate is trusted on this runner
#
# The gate asserts Get-AuthenticodeSignature returns Valid. An untrusted self-signed
# certificate reports UnknownError even when the signature is perfectly good, so the
# certificate is added to this runner's LocalMachine Root and TrustedPublisher stores
# for the duration of the run and removed by Remove-TestSigningCertificate.ps1. That
# makes the gate stricter, not looser: it has to chain, not merely exist.
#
# The daemon does not need this. experimental/boxdd/authenticode_windows.go already
# tolerates CERT_E_UNTRUSTEDROOT for a self-signed certificate whose self-signature,
# code-signing EKU and validity window check out - which is why a throwaway certificate
# is a supported configuration rather than a bypass.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ClientDirectory,
    [int]$ValidDays = 2
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $ClientDirectory -PathType Container)) {
    throw "client directory does not exist: $ClientDirectory"
}
$signingConfigurationPath = Join-Path $ClientDirectory "signing.local.json"
if (Test-Path -LiteralPath $signingConfigurationPath) {
    throw "$signingConfigurationPath already exists; refusing to overwrite it"
}

$temporaryDirectory = $env:RUNNER_TEMP
if ([string]::IsNullOrWhiteSpace($temporaryDirectory)) {
    $temporaryDirectory = [System.IO.Path]::GetTempPath()
}
$pfxPath = Join-Path $temporaryDirectory "jiejiebox-ci-signing.pfx"
$cerPath = Join-Path $temporaryDirectory "jiejiebox-ci-signing.cer"
$passwordPath = Join-Path $temporaryDirectory "jiejiebox-ci-signing.password"

# Random, and only ever written to files that the cleanup step deletes. The password is
# deliberately never passed as an argument (arguments are visible to other processes)
# and never printed.
$password = [System.Guid]::NewGuid().ToString("N") + [System.Guid]::NewGuid().ToString("N")
$securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force

Write-Host "== creating a throwaway code-signing certificate =="
$certificate = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject "CN=Jiejiebox CI Test Code Signing" `
    -KeyUsage DigitalSignature `
    -KeyExportPolicy Exportable `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -NotAfter (Get-Date).AddDays($ValidDays)

if ($null -eq $certificate) {
    throw "New-SelfSignedCertificate produced no certificate"
}
$thumbprint = $certificate.Thumbprint

# The EKU is what experimental/boxdd's validateCodeSigningCertificate requires, so the
# certificate is checked here rather than assumed.
$codeSigningOid = "1.3.6.1.5.5.7.3.3"
$hasCodeSigning = $false
foreach ($extension in $certificate.Extensions) {
    if ($extension.Oid.Value -ne "2.5.29.37") { continue }
    foreach ($usage in $extension.EnhancedKeyUsages) {
        if ($usage.Value -eq $codeSigningOid) { $hasCodeSigning = $true }
    }
}
if (-not $hasCodeSigning) {
    throw "the generated certificate has no code-signing EKU"
}
if ($certificate.NotAfter -le (Get-Date) -or $certificate.NotBefore -gt (Get-Date)) {
    throw "the generated certificate is not currently valid"
}

Export-PfxCertificate -Cert $certificate -FilePath $pfxPath -Password $securePassword | Out-Null
Export-Certificate -Cert $certificate -FilePath $cerPath -Type CERT | Out-Null
[System.IO.File]::WriteAllText($passwordPath, $password, [System.Text.UTF8Encoding]::new($false))

if (-not (Test-Path -LiteralPath $pfxPath)) { throw "the PFX was not written" }

# Temporary trust, removed by the cleanup step.
Import-Certificate -FilePath $cerPath -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
Import-Certificate -FilePath $cerPath -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" | Out-Null

# The exact shape scripts/package.ts reads: windows.certificateFile must be a non-empty
# string that exists, windows.certificatePassword a string.
$configuration = [ordered]@{
    windows = [ordered]@{
        certificateFile     = $pfxPath
        certificatePassword = $password
    }
}
$json = $configuration | ConvertTo-Json -Depth 4
[System.IO.File]::WriteAllText($signingConfigurationPath, $json, [System.Text.UTF8Encoding]::new($false))

Write-Host "  subject:    $($certificate.Subject)"
Write-Host "  thumbprint: $thumbprint"
Write-Host "  expires:    $($certificate.NotAfter.ToString('u'))"
Write-Host "  pfx:        $pfxPath"
Write-Host "  signing.local.json written to the client checkout (removed by cleanup)"
Write-Host "  the PFX password was written only to $passwordPath and is not printed"

if (-not [string]::IsNullOrWhiteSpace($env:GITHUB_ENV)) {
    Add-Content -Path $env:GITHUB_ENV -Value "JJ_SIGNING_THUMBPRINT=$thumbprint"
    Add-Content -Path $env:GITHUB_ENV -Value "JJ_SIGNING_PFX=$pfxPath"
    Add-Content -Path $env:GITHUB_ENV -Value "JJ_SIGNING_CONFIG=$signingConfigurationPath"
}

# GitHub's pwsh wrapper ends the step with `exit $LASTEXITCODE`, so a gate that has just
# verified everything can still be reported as a failure if the last native command that
# ran happened to exit non-zero. In this script that is normal, not an error: `sc.exe
# query` on a service that is correctly absent returns 1060. The verdict is decided above,
# so the exit code is set deliberately here.
exit 0
