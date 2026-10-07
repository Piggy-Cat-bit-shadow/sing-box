# Windows runtime acceptance

`.github/workflows/client-desktop-windows.yml` builds, signs, installs and tears down the
Windows client on a hosted runner. What that run proves and what it cannot are different
things, and this document is the second half.

## What CI already proves

Everything below fails the workflow, so a green run means these are established:

| gate | what it establishes |
| --- | --- |
| source / toolchain | the exact core commit, the desktop pin, and the toolchain versions |
| build | the installer was produced from that source, with a throwaway signing certificate |
| package integrity | `app.asar` hash and all nine Electron fuses are as expected |
| daemon provenance | the packaged daemon is the v0.1.5 core daemon, `windows/amd64`, with the required build tags, and it reports `0.1.5` when run |
| PE architecture | every PE image in the package and in the installer's extracted payload is amd64, except two named exceptions (the 32-bit NSIS stub and electron-builder's `resources/elevate.exe`) |
| signing | `sing-box.exe`, the daemon and `windows_share.node` carry an Authenticode signature, it verifies, it is the certificate the run created, and all three share one signer |
| daemon service | `service install`, SCM registration, Running, the daemon's own `status`, stop, and uninstall |
| installer lifecycle | silent install, file and version and service and layout-registry verification, same-version reinstall, uninstall, clean reinstall, final uninstall |
| driver packages | each `.sys` has an embedded signature or verified catalog coverage |

The signing gate is worth one note here, because it constrains everything else. The core's
Windows daemon authenticates the installed application against the daemon's own signer and
refuses to register the service - and refuses every peer handshake - when the two differ
(`experimental/boxdd/security_windows.go`, `peer_windows.go`). It also resolves the
application by the exact path `<install>/sing-box.exe`. So the installed executable keeps
that file name; `productName` stays `Jiejiebox` and supplies everything a user reads.

## What only a real machine can prove

A hosted runner is not a user's machine and cannot stand in for one. These remain manual,
and this is the runbook for them:

* TUN mode, WinDivert as a loaded kernel driver, and real traffic interception
* DNS resolution through the tunnel
* the system proxy, and whether disabling it restores the previous registry values
* IPC between the GUI and the daemon under real use
* sleep/wake, network switching, and long-running stability

Until a run of this runbook passes end to end, the installer is **not** appended to the
v0.1.5 release and `SHA256SUMS` is **not** updated.

## What is needed

* A Windows 10 x64 or Windows 11 x64 machine. Not a VM without nested virtualisation if
  TUN is to be tested - WinDivert needs to load a driver.
* Administrator rights. The installer is per-machine and the daemon installs a service.
* A working network connection, and preferably a second one to test reconnection.
* The installer from the Windows workflow run, and its recorded SHA256.

x86 and ARM64 are out of scope for this release and are not tested.

## 0. Establish what you are testing

The artifact must be the one the build record names. Download it, and check it against
the SHA256 in that run's `jijiebox-windows-build-records` artifact:

```powershell
Get-FileHash .\Jiejiebox-v0.1.5-windows-x64.exe -Algorithm SHA256
```

Then record, from that run's `BUILD-INFO-WINDOWS.txt`:

| field | value |
| --- | --- |
| core SHA | `e70f3d2c8527ca159231f11405be52604008504c` |
| core version | `0.1.5` |
| desktop client pin | `32f915ba595601dbc2dd346c33fe9fedd3e72979` |
| installer sha256 | |
| machine | |
| Windows build | |
| tester | |
| date | |

If the hash does not match, stop. Do not test a binary whose provenance is unknown, and
do not report a result against one.

## 1. Install

| check | expected | result |
| --- | --- | --- |
| double-click the installer | UAC prompt appears (per-machine install) | |
| accept elevation | install completes without an error dialog | |
| SmartScreen | warns, because the build is unsigned by design | |
| choose "More info" then "Run anyway" | install proceeds | |
| Start Menu | an entry named **Jiejiebox** exists | |
| Add/Remove Programs | lists **Jiejiebox** 0.1.5 | |
| first launch | the window opens and shows the dashboard | |

SmartScreen warning is expected and is not a defect. The absence of one would mean
something changed about signing.

Note the install directory for later steps:

```powershell
Get-ChildItem 'C:\Program Files\Jiejiebox' | Select-Object Name
```

## 2. Daemon

The daemon is an internal component and keeps its own name: `sing-box-daemon.exe`. That
is not a branding defect.

| check | expected | result |
| --- | --- | --- |
| the GUI reaches the daemon | dashboard populates; no "cannot connect to the service" state | |
| daemon version | `0.1.5` | |
| the daemon is a separate process | it survives a GUI restart | |

```powershell
# What the shipped daemon reports about itself.
& 'C:\Program Files\Jiejiebox\resources\daemon\sing-box-daemon.exe' version
# Expect: sing-box-daemon version 0.1.5  /  core api version <n>

Get-Process | Where-Object { $_.ProcessName -match 'jiejiebox|sing-box' } |
  Select-Object ProcessName, Id, Path
```

Then, with the GUI open: quit the GUI entirely, confirm the daemon's behaviour is the one
the design intends (it should not be left orphaned - see step 5), reopen the GUI, and
confirm it reconnects without an error.

Crash and restart behaviour: kill the daemon process from Task Manager while the GUI is
open, and record what the GUI does. Whatever it does is the finding; the point is that it
is observed rather than assumed.

## 3. System proxy

| check | expected | result |
| --- | --- | --- |
| enable the system proxy in the GUI | setting takes effect without a restart | |
| browse to a site | traffic goes through the proxy | |
| the proxy setting is visible to Windows | `ProxyEnable` is 1 | |
| disable the system proxy in the GUI | the previous setting is restored | |
| browse again | direct connection works | |

```powershell
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' |
  Select-Object ProxyEnable, ProxyServer, ProxyOverride
```

Record the values before enabling, while enabled, and after disabling. "Restored" means
the values after disabling are the values from before enabling, not merely that browsing
works.

## 4. TUN

TUN is the check most likely to expose a real problem, because it is the only one that
loads a kernel driver.

| check | expected | result |
| --- | --- | --- |
| enable TUN in the GUI | no error dialog | |
| WinDivert driver | loaded | |
| a TUN adapter appears | present while enabled | |
| DNS resolution | resolves | |
| IPv4 traffic | works | |
| IPv6 | record what happens; both outcomes are useful | |
| disable TUN | driver unloads, adapter disappears | |
| browse after disabling | normal connectivity | |

```powershell
sc.exe query WinDivert
Get-Service | Where-Object { $_.Name -match 'windivert|sing|jiejie' }
Get-NetAdapter | Where-Object { $_.InterfaceDescription -match 'sing|tun|wintun' } |
  Select-Object Name, InterfaceDescription, Status
Get-DnsClientServerAddress -AddressFamily IPv4
```

Logs, when something fails:

```powershell
Get-EventLog -LogName System -Newest 40 |
  Where-Object { $_.Source -match 'WinDivert|Service Control Manager' }
```

## 5. Cleanup

Run this after quitting the GUI normally, with both the system proxy and TUN turned off
before quitting.

| check | expected | result |
| --- | --- | --- |
| no proxy residue | the Internet Settings values are the pre-test ones | |
| no stale routes | no route pointing at a TUN adapter that is gone | |
| no orphan daemon | no `sing-box-daemon` process remains | |
| no unexpected service state | the service is stopped or absent as designed | |
| no leftover adapter | no TUN adapter remains | |

```powershell
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' |
  Select-Object ProxyEnable, ProxyServer
route print -4
Get-Process | Where-Object { $_.ProcessName -match 'jiejiebox|sing-box' }
Get-Service | Where-Object { $_.Name -match 'sing|jiejie' -or $_.DisplayName -match 'Jiejiebox' }
Get-NetAdapter
```

Uninstall is also worth one pass: confirm the installer's uninstaller removes the service
and leaves no adapter and no orphan process, and record whether it removes user settings
(the upstream default is deliberately to keep them).

## 6. Stability

Each of these is a repeat of the steps above; the finding is whether the second, third and
tenth time behaves like the first.

| check | expected | result |
| --- | --- | --- |
| start and stop 10 times | no drift, no leaked process | |
| alternate System Proxy and TUN 5 times | each engages and disengages cleanly | |
| network reconnect: disable Wi-Fi, re-enable | recovers without a restart | |
| switch networks: Wi-Fi to Ethernet | recovers | |
| application restart while connected | reconnects | |
| sleep and wake | reconnects, and the proxy is still correct | |
| reboot, then launch | comes up cleanly | |

## Reporting

Record, for each section, either `PASS` or the observed behaviour. A failure is more
useful than a pass: include the exact dialog text, the command output, and the log lines.

* If everything passes: append `Jiejiebox-v0.1.5-windows-x64.exe` to the existing
  `v0.1.5` release, update `SHA256SUMS` so it lists all three artifacts, and re-download
  and re-verify every hash. The two existing entries must not change.
* If anything fails: the installer is not released. The finding goes back into the build;
  the fix is a new commit and a new workflow run, and the release still gets the installer
  only after a full pass. The v0.1.5 tag is not moved and no `v0.1.6` is created for this -
  it is an additional platform artifact for the same release.
