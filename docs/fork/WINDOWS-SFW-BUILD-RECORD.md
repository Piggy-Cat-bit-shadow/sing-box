# Windows SFW revival - build and verification record

Produced on this machine by the Windows SFW revival round. This file is the human-readable
counterpart of the CI run's `BUILD-INFO-WINDOWS.txt`.

## Final state

| field | value |
| --- | --- |
| `START_SHA` (branch tip at round start) | `47e08ed395cd70e0a4a38bd78470e08329c837d4` |
| branch | `local/windows-sfw-revival` (temporary local branch) |
| `origin/testing` before and after | `47e08ed395cd70e0a4a38bd78470e08329c837d4` |
| pushed | **no** - nothing was pushed; no tag or release was created |
| remote branches created | none |

## Source identity used for this build

| field | value |
| --- | --- |
| core commit the daemon was built from | `61975ca39f3ca59e6b6ae1734036fa1f88c5c7e4` (the restore commit) |
| core `git describe --tags` | `tooling-v0.1.5-237-g61975ca3` |
| core version the daemon reports | `0.1.5` |
| `release/JIEJIE_VERSION` | `0.1.5` (unchanged) |
| desktop client pin | `32f915ba595601dbc2dd346c33fe9fedd3e72979` (unchanged) |
| dashboard pin | `9c498355c9973187b04c09991e2aca8100fd00ec` |
| version stamping | `SING_BOX_BUILD_VERSION=0.1.5`, `SING_BOX_BUILD_COMMIT=47e08ed3...` |

`build_shared.ReadTag()` reads `SING_BOX_BUILD_VERSION` before falling back to
`git describe --tags`. The branch tip is 237 commits past the release tag, so `describe`
cannot yield the release version; the injection is the mechanism CI itself uses and the
tag was **not** moved.

## Toolchain actually used

| tool | version | source |
| --- | --- | --- |
| Go | `go1.26.8 windows/amd64` | matches `clients/desktop/version.json` `go_version` |
| Node | `v26.7.0` | matches `clients/desktop/package.json` `engines.node` |
| pnpm | `11.13.0` | matches `package.json` `packageManager` |
| Rust | `rustc 1.99.0` / `cargo 1.99.0` | `x86_64-pc-windows-msvc`, needed by `native/windows-share` |
| MSVC | `14.44.35207` (`Microsoft.VisualStudio.Component.VC.Tools.x86.x64`) | needed for the static CRT the `cdylib` links |
| Windows SDK | `10.0.26100.0` | PE/signing tooling |
| Electron | `43.4.1` | from the frozen lockfile |
| electron-builder | `26.15.3` | from the frozen lockfile |

`pnpm@11.13.0` is marked deprecated by npm as "a broken version". Its
`pnpm install --frozen-lockfile` was exercised and worked; the pin was **not** deviated
from.

## Artifacts

| artifact | SHA256 |
| --- | --- |
| `Jiejiebox-v0.1.5-windows-x64.exe` (NSIS, 109.5 MB) | `B58592A2FCB75424335915BFC1ECC5CD8E894771758D5D6F893EEA6E12096C6B` |
| `sing-box.exe` (GUI, unsigned staging twin separately hashed) | `B79F7F8B6B4B2E2DFAD5FEDE7C5DF2840C71B09391592371EFD09BF446DF79B7` |
| `resources/daemon/sing-box-daemon.exe` | `EFE9C5CCE300107C4719F42C88E076F15916155C58A0451D4119793A4C042263` |
| `resources/native/windows_share.node` | `B6346FAB48F4E56F5A8A5B43F3841ECA27DFABDAC76CDD44154A6AFAE33FACD8` |

All four carry **one** Authenticode signer, thumbprint
`104972E9F2CE48BD58B6FA19A5FC3C228EFBEF31`, `CN=Jiejiebox CI Test Code Signing` - a
throwaway certificate created for this round. `Get-AuthenticodeSignature` reports
`UnknownError` for all of them, which is the expected status for a self-signed certificate
whose root is not trusted; the daemon's own `authenticodeSigner` tolerates
`CERT_E_UNTRUSTEDROOT` for a self-signed certificate whose self-signature, code-signing EKU
and validity window check out.

## Gate results

| gate | result | evidence |
| --- | --- | --- |
| daemon builds (`build_boxdd`, windows/amd64) | PASS | PE `0x8664`, `version` prints `0.1.5` |
| daemon provenance | PASS | `_toolchain/audit/daemon-provenance.txt` |
| PE architecture | PASS | 18 images amd64, 1 explicitly allowed exception (`resources/elevate.exe`, i386) |
| branding overlay rules | PASS | 22/22 rules matched, no anchor drift |
| signing identity equality | PASS | one thumbprint across GUI, daemon, `windows_share.node` |
| `service install` from a privileged root | PASS | exit 0, SCM registered, Running as LocalSystem |
| `service install` from a user-owned root | FAIL (reproduces `code 1`) | see root cause below |
| real-machine installer run | **NOT RUN** | would uninstall the official install at `C:\Program Files\sing-box` |

## P0-2 root cause

Historical real-machine symptom: `无法注册 sing-box 守护进程（代码 1）`
(`Failed to register sing-box daemon (code 1)`), which is
`clients/desktop/build/installer.nsh` -> `LangString registerServiceFailed`. `code 1` is the
exit status of `sing-box-daemon.exe service install`, whose every failure path is
`log.Fatal` (`experimental/boxdd/cmd_service_windows.go`), so the installer's message alone
cannot name a stage.

**Root cause: `secureWindowsInstallation` -> `validateInstallationAncestors` rejects the
installation path when any ancestor from the install directory up to the volume root is
owned by a principal other than SYSTEM, Administrators or TrustedInstaller.**

- code: `experimental/boxdd/security_windows.go`, `validateInstallationAncestor` line ~418
- raw error: `FATAL[0000] install service: secure installation: installation ancestor is
  owned by an unprivileged principal: <path>`
- exit code: `1`

A/B evidence, same signed daemon, same arguments, only the install root differing:

| install root | ancestor verdict | `service install` |
| --- | --- | --- |
| `C:\src\sfw-test\sing-box` (owner `DESKTOP-0F552P6\Jie`) | FAIL | exit 1, error above |
| `C:\Program Files\sing-box-sfwtest` (owner `BUILTIN\Administrators`; parents TrustedInstaller) | OK | exit 0, service Running |

This is a security property that must **not** be weakened: the check exists so an
unprivileged principal cannot replace the binary a LocalSystem service runs. It is not a
defect to fix in the core. What was missing is diagnosis - the concrete stage was
unobservable without running the daemon directly or using the installer's
`/CI-DIAGNOSTIC-PATH=` channel.

### Instrument added

`scripts/ci/windows/Test-DaemonServiceRegister.ps1` reproduces the installer's exact
`service install` invocation, audits every ancestor under the real rule and records the raw
stdout/stderr/exit code plus before/after SCM state. This is what made the root cause
recoverable instead of inferred.

## Reproduce this build

```powershell
. C:\src\_toolchain\env.ps1
python C:\src\sing-box\scripts\ci\apply-desktop-branding-overlay.py C:\src\sing-box\clients\desktop
cd C:\src\sing-box\clients\desktop
$env:SING_BOX_BUILD_VERSION = '0.1.5'
node node_modules\tsx\dist\cli.mjs scripts\package.ts win x64
```

Two Windows-specific build prerequisites were found and are documented for CI parity:

1. `scripts/package.ts` -> `ensureGenerated()` runs `pnpm -C dashboard generate`, whose
   `buf generate` resolves `protoc-gen-es` by name from `PATH`. On Windows a pnpm-run script
   does not expose `node_modules/.bin` to `buf`, so both `.bin` directories must be on
   `PATH` or buf fails with
   `Failure: plugin protoc-gen-es: exec: "protoc-gen-es": executable file not found in %PATH%`.
2. `native/windows-share` is a `cdylib` built with `-Ctarget-feature=+crt-static`, so it
   needs the MSVC linker **and** the static CRT; a Windows image with only the Windows SDK
   (UCRT) and no Visual C++ Build Tools fails with `error: linker link.exe not found`.

## Not done

- The produced installer was **not** installed on this machine. Doing so would have
  uninstalled the official `sing-box 1.15.0-alpha.11` at `C:\Program Files\sing-box` that
  the machine was actively running, and destroyed a live environment. The installer's
  end-to-end lifecycle therefore remains `BLOCKED`, not `PASS`.
- No CI run was attempted or claimed.
