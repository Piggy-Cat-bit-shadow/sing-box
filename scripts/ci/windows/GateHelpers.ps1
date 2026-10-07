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
