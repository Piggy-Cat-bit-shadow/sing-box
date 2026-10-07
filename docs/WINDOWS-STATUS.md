# Windows line status: FROZEN

**Status:** FROZEN
**Version:** v0.1.5
**Frozen at commit:** _(the commit that adds this document)_
**Branch:** `testing`

The Windows client is **buildable, statically validated and runtime-unresolved**, and its
runtime acceptance is frozen. This document records what is established, what is not, and
what has to exist before work resumes. It is not a claim that Windows is complete, and
nothing here should be read as release-ready.

## Why it is frozen

There is no dedicated real Windows x64 development or debugging environment. The primary
development machine is macOS, and a GitHub Actions Windows runner is not a substitute for
a real Windows desktop:

| what CI can establish | what only a real machine can establish |
| --- | --- |
| the build, the package, the payload | UAC and the real elevation flow |
| static integrity, provenance, architecture | the NSIS lifecycle a user experiences |
| hashes, records, signature validity | Windows service behaviour across reinstall |
| a service registration it performs itself | `Program Files` ACLs and enterprise policy |
| driver package signatures | driver loading, TUN, WinDivert interception |
| | the system proxy, DNS through the tunnel |
| | reboot, sleep/wake, network switching |
| | GUI and daemon behaviour over hours |

Continuing to change CI in order to infer a real-machine failure would risk changing the
product's security behaviour to make a test pass. That is the reason for the freeze, and it
is a deliberate engineering decision rather than a statement that the work is finished.

## Established

**Windows x64 build** — PASS. The core builds, the desktop client builds, Electron packages
and NSIS produces an installer (`Jiejiebox-v0.1.5-windows-x64.exe`).

**Static package validation** — PASS. Source-of-record pin verification, `git describe`
version verification, frozen lockfile install, ASAR integrity, the Electron fuse audit,
daemon provenance (core commit, `windows/amd64`, the required build tags, and the daemon's
own reported version), and SHA-256 build records.

**PE architecture audit** — PASS, with no broad exception and no bypass. amd64 is required
by default. Exactly two i386 images are named, each by its exact path and each with its
reason:

| image | reason |
| --- | --- |
| `Jiejiebox-v*-windows-x64.exe` | an NSIS installer is a 32-bit stub whatever it installs |
| `resources/elevate.exe` | electron-builder's NSIS UAC elevation helper, shipped by electron-builder |

Anything else that is i386, ARM or ARM64 fails, in the packaged tree **and** in the payload
extracted from the built installer.

**Signing path** — IDENTIFIED, PARTIALLY VALIDATED. The core's Windows daemon verifies the
application's Authenticode signer against the daemon's own with `WinVerifyTrustEx`
(`experimental/boxdd/authenticode_windows.go`), and `secureWindowsInstallation`
(`security_windows.go`) refuses to register the service when they differ. So a fully
unsigned `sing-box.exe` plus a fully unsigned `sing-box-daemon.exe` cannot satisfy the
production service-install security path. This is not an architecture problem and not a
daemon build problem.

Two consequences, both already reflected in the tooling:

* the installed application executable keeps the name `sing-box.exe`, because the core
  resolves the application by exactly `<install>/sing-box.exe` both when registering the
  service and on every peer handshake. `productName` stays `Jiejiebox` and supplies
  everything a user reads;
* upstream already has the right signing mechanism — electron-builder's signing plus
  `scripts/afterPack.cjs`, which separately signs `resources/daemon/sing-box-daemon.exe`
  and `resources/native/windows_share.node`. **Do not design a second daemon-signing path;
  restore and use upstream's.**

**Ephemeral self-signed code signing** — implemented and exercised. A throwaway code-signing
certificate (code-signing EKU, self-signed, currently valid) is generated per CI run, used
through electron-builder's own signing, verified, and destroyed. The core explicitly
tolerates an untrusted self-signed signer whose self-signature, EKU and validity window
check out, which is why this is a supported development configuration rather than a bypass.
**This is for development and CI only.** A public release requires a trusted Authenticode
signing solution.

**CI service installation** — HAS SUCCEEDED, in a GitHub Actions run, on the strict path:
installer exit `0`, preflight PASS, `service install` exit `0`, `sing-box-daemon` Running,
`LayoutVersion` 2, install root `C:\Program Files\sing-box`, with
`--allow-unsafe-installation-directory-permissions` **absent** from the normal installer
path. That run's gates 1–8 and cleanup all passed
(`actions/runs/37652597854`). CI success is evidence about CI, not about a user's machine.

## Not established

**Real Windows installation** — BLOCKED / FAIL.

**Observed real-machine error:**

```
Failed to register sing-box daemon (code 1)
```

**Exact root cause:** NOT ESTABLISHED.

`code 1` is the installer's own failure code for the daemon service command, and it cannot
be attributed to a stage from that message alone. The failure may be in any of:

```
secureWindowsInstallation          Authenticode validation
same-signer validation             installedApplicationPath
installation directory ACL         working-directory validation
SCM CreateService / UpdateService  service SID configuration
service security descriptor        event log registration
service start                      service startup timeout
pre-existing service state         previous installation residue
Windows version or policy differences
```

No further inference from GitHub Actions behaviour is valid here, which is precisely why the
line is frozen rather than debugged further by CI.

## Do not weaken

While frozen, and when work resumes:

```
Authenticode validation
signer equality
installation path validation
ACL validation
service security policy
```

Do not remove `secureWindowsInstallation`, do not add an unsafe-permission bypass to the
normal installation path, do not relax the ACL or ancestor rules, and do not add
`continue-on-error` or remove a failing gate to produce green.

## Harness problems already found and fixed

These were test-environment defects, not product bugs. They are recorded so they are not
re-investigated as product issues.

| symptom | cause | fix |
| --- | --- | --- |
| a gate printed PASS and the step still failed | GitHub's `pwsh` wrapper ends with `exit $LASTEXITCODE`, inheriting e.g. `sc.exe query`'s 1060 for a service that is correctly absent | one shared helper: capture, judge, clear at the source; each gate ends on its own verdict |
| overlay aborted with `UnicodeDecodeError 0x81` | the installer contains Chinese and Farsi LangStrings; Python's default encoding is cp1252 on Windows | explicit UTF-8 on every read and write |
| every multi-line overlay rule matched nothing | the runner's checkout is CRLF; block-rule literals are LF | normalise on read, write the repository's canonical LF |
| NSIS preflight failed, `Get-Acl ... module could not be loaded` | the installer's Windows PowerShell 5.1 child inherited PowerShell 7's `PSModulePath` and resolved PS7's incompatible module. Prepending was not enough, because PS7 already appends the 5.1 path | rebuild the child's module path from the 5.1 locations only |
| lifecycle gate could not find the installation | it matched the uninstall entry by `DisplayName -eq "Jiejiebox"`, while the actual name is `Jiejiebox 0.1.5` and the identity is `sing-box` | derive the install root from the SCM's daemon command line, validate it by layout and `LayoutVersion`, then match the uninstall entry by `InstallLocation`, with the uninstaller's own parent as a recorded fallback; fail closed on zero or ambiguous matches |

The last one is implemented and passed in CI; it has **not** been validated on a real
machine.

## CI gating after the freeze

Release-blocking: build, package, integrity, provenance, architecture, hashes.

Experimental / **not** release-blocking, and not a substitute for real-machine acceptance:
the full NSIS lifecycle, the real service lifecycle, driver loading, and TUN runtime. Their
scripts and history are kept and must not be deleted — they are the starting point when work
resumes.

## Resuming

Windows work may resume when a **dedicated real Windows x64 test machine** (or a reliable
Windows VM) is available that can do all of:

```
administrator access            UAC
repeated NSIS install/uninstall reboot
run services                    load WinDivert / TUN drivers
inspect Event Viewer            inspect the SCM
inspect the registry            collect ProcMon and PowerShell diagnostics
```

### First step on resuming: diagnose, do not change code

Turn `Failed to register sing-box daemon (code 1)` into a complete diagnostic before
changing anything. Capture:

```
the exact daemon command, its stdout, its stderr and its exit code
Get-AuthenticodeSignature for the main application and for the daemon
the service state before the install
the SCM result
Event Viewer records (System and Application)
the installation directory ACL
the working-directory ACL
uninstall / previous-install residue
```

The installer already has an opt-in CI diagnostic channel for part of this: passing
`/CI-DIAGNOSTIC-PATH=<absolute path>` makes it record the stage, exit code and captured
output to a file outside `$PLUGINSDIR` and `$INSTDIR`, so it survives the rollback. With no
such option it is completely inert.

Useful tools: PowerShell 5.1 and 7, `sc.exe`, `Get-Service`, `Get-CimInstance
Win32_Service`, `Get-AuthenticodeSignature`, `signtool`, Event Viewer, ProcMon, Process
Explorer, `reg.exe`, `icacls`, `wevtutil`.

### Identity facts to keep using

```
core            e70f3d2c8527ca159231f11405be52604008504c   (v0.1.5)
desktop client  32f915ba595601dbc2dd346c33fe9fedd3e72979
dashboard       9c498355c9973187b04c09991e2aca8100fd00ec
```

Do not move the `v0.1.5` tag, do not bump the version, and do not change these pins as part
of resuming.
