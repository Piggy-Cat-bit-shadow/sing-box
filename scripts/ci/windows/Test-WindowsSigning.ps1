# GATE: verifies that the packaged Windows binaries are Authenticode-signed by the
# certificate this CI run created, and by the same one.
#
# Usage:
#   Test-WindowsSigning.ps1 -ExpectedThumbprint <thumbprint> -RecordPath <file> -Files <path>...
#
# # What is actually asserted
#
#   1. every named file carries an Authenticode signature     (signature exists)
#   2. Get-AuthenticodeSignature reports Valid                (the hash is intact and the
#                                                              chain resolves, because the
#                                                              CI certificate is trusted on
#                                                              this runner for the run)
#   3. SignatureType is Authenticode
#   4. SignerCertificate.Thumbprint equals the expected value (it is THIS run's
#                                                              certificate, not any
#                                                              certificate that happens to
#                                                              chain)
#   5. all files share that one thumbprint                    (main app == daemon == native
#                                                              module)
#
# Point 4 is the one that matters most and the one a naive check skips. "Signed by
# something" is not the property the product needs: experimental/boxdd compares the
# daemon's signer with the application's and refuses the service registration and every
# peer handshake when they differ (security_windows.go, peer_windows.go). A build whose
# three binaries are signed by three different certificates installs nothing, and this
# gate is what says so before a user finds out.
#
# Only the thumbprint of the public certificate is printed. No password, no key.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ExpectedThumbprint,
    [Parameter(Mandatory = $true)][string]$RecordPath,
    [Parameter(Mandatory = $true)][string[]]$Files
)

$ErrorActionPreference = "Stop"

$expected = $ExpectedThumbprint.Trim().ToUpperInvariant()
if ($expected.Length -ne 40) {
    throw "expected thumbprint '$ExpectedThumbprint' is not a SHA-1 certificate thumbprint"
}

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("windows signing audit")
$lines.Add("expected signer thumbprint   $expected")
$lines.Add("")

$failures = New-Object System.Collections.Generic.List[string]
$thumbprints = New-Object System.Collections.Generic.List[string]

foreach ($file in $Files) {
    $name = Split-Path -Leaf $file
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        $failures.Add("$file does not exist")
        $lines.Add("$name  MISSING")
        continue
    }

    $signature = Get-AuthenticodeSignature -LiteralPath $file
    $signerThumbprint = ""
    if ($null -ne $signature.SignerCertificate) {
        $signerThumbprint = $signature.SignerCertificate.Thumbprint.ToUpperInvariant()
        $thumbprints.Add($signerThumbprint)
    }

    $lines.Add(("{0}  status={1} type={2} signer={3}" -f $name, $signature.Status, $signature.SignatureType, $(if ($signerThumbprint) { $signerThumbprint } else { "(none)" })))
    if ($null -ne $signature.SignerCertificate) {
        $lines.Add(("    subject={0}" -f $signature.SignerCertificate.Subject))
    }

    if ($null -eq $signature.SignerCertificate -or $signature.SignatureType -ne "Authenticode") {
        $failures.Add("$name carries no Authenticode signature")
        continue
    }
    if ($signature.Status -ne "Valid") {
        $failures.Add("$name signature status is $($signature.Status), expected Valid (message: $($signature.StatusMessage))")
        continue
    }
    if ($signerThumbprint -ne $expected) {
        $failures.Add("$name was signed by $signerThumbprint, not by this run's certificate $expected")
    }
}

$lines.Add("")
if ($thumbprints.Count -gt 0) {
    $distinct = $thumbprints | Sort-Object -Unique
    $lines.Add("distinct signer thumbprints   $($distinct.Count)")
    foreach ($thumbprint in $distinct) {
        $lines.Add("  $thumbprint")
    }
    if ($distinct.Count -ne 1) {
        $failures.Add("the packaged binaries have $($distinct.Count) different signers; the daemon requires one")
    }
    $lines.Add("same signer for every binary  $(if ($distinct.Count -eq 1) { 'YES' } else { 'NO' })")
} else {
    $lines.Add("distinct signer thumbprints   0")
    $failures.Add("none of the named files is signed")
}
$lines.Add("")

$directory = Split-Path -Parent $RecordPath
if (-not [string]::IsNullOrWhiteSpace($directory) -and -not (Test-Path -LiteralPath $directory)) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
}

if ($failures.Count -gt 0) {
    $lines.Add("FAIL")
    foreach ($failure in $failures) { $lines.Add("  - $failure") }
    [System.IO.File]::WriteAllLines($RecordPath, $lines)
    foreach ($line in $lines) { Write-Host $line }
    Write-Error "windows signing audit failed:" -ErrorAction Continue
    foreach ($failure in $failures) { Write-Error "  - $failure" -ErrorAction Continue }
    exit 1
}

$lines.Add("PASS: every binary is Authenticode-signed, Valid, and signed by this run's certificate")
$lines.Add("      and by the same one, which is what the daemon's own checks require")
[System.IO.File]::WriteAllLines($RecordPath, $lines)
foreach ($line in $lines) { Write-Host $line }
