# §8 pre-work state capture — architecture closure round (agent: arch-closure)

Read-only evidence, taken **before any modification**, in the isolated worktree `/tmp/v16-arch`.
This file is deliberately named `arch-closure-prework-state.md` rather than
`v0.1.6-architecture-closure.md` so it cannot collide with another agent's report.

## 1. Git state

```text
### git status --short
(empty at capture time — clean tree)

### git branch --show-current
fix/arch-closure          (created from detached HEAD 17b176a18 for this round)

### git rev-parse HEAD
17b176a18d6c4e814bef72ff2cd54a5e794ab696

### git rev-parse origin/testing
17b176a18d6c4e814bef72ff2cd54a5e794ab696     (identical: this worktree starts at the tip)

### git remote -v
origin    https://github.com/Piggy-Cat-bit-shadow/sing-box.git (fetch)
origin    https://github.com/Piggy-Cat-bit-shadow/sing-box.git (push)
upstream  https://github.com/SagerNet/sing-box.git (fetch)
upstream  https://github.com/SagerNet/sing-box.git (push)

### git worktree list
/Users/jie/Desktop/其他文件/sing-box   17b176a18 [testing]
/private/tmp/v16-apple                 17b176a18 [fix/apple-screen-state]
/private/tmp/v16-arch                  17b176a18 [fix/arch-closure]      <- this round
/private/tmp/v16-resid                 17b176a18 [fix/residual-sweep]
/private/tmp/v16-sniff                 17b176a18 [fix/sniff-final]

### git submodule status --recursive
-ec61030d3df74f3e7c39ab848c8996008ecd386a clients/android
-5911580a6366da78e6b4b5b4459596e5a2cf1eb4 clients/apple
-32f915ba595601dbc2dd346c33fe9fedd3e72979 clients/desktop
```

All three submodules are **uninitialised** in this worktree (the leading `-`). That is why the hard
constraint "never touch `clients/apple` or `clients/android`" is structurally satisfied here as well
as by discipline: the working directories are empty, and every git operation in this round names
explicit top-level paths only.

## 2. Submodule gitlink vs worktree

```text
### git ls-tree HEAD clients/apple clients/android
160000 commit ec61030d3df74f3e7c39ab848c8996008ecd386a  clients/android
160000 commit 5911580a6366da78e6b4b5b4459596e5a2cf1eb4  clients/apple

### worktree actual
clients/android   (empty directory)
clients/apple     (empty directory)
clients/desktop   (empty directory)
```

Gitlink and worktree therefore agree trivially: neither client submodule is checked out, so no
client revision can be silently advanced by this round.

## 3. Fork pins

`go.mod` carries **34** `replace` directives, all pinned to the `Piggy-Cat-bit-shadow` forks. The
authoritative ones for this round:

| module | fork pin |
|---|---|
| `github.com/sagernet/sing` | `Piggy-Cat-bit-shadow/sing v0.9.6-0.20261008194531-3af46fe99d3b` |
| `github.com/sagernet/sing-tun` | `Piggy-Cat-bit-shadow/sing-tun v0.0.0-20261008172655-8dde9c8cbe27` |
| `github.com/sagernet/quic-go` | `Piggy-Cat-bit-shadow/quic-go v0.61.1-0.20260929231714-9c94b1e90d94` |
| `github.com/sagernet/cronet-go` (+ 31 platform leaves) | `Piggy-Cat-bit-shadow/cronet-go v0.0.1-143.0.7499.109-2.0.20260929202119-8c68ce89873c` |

The replace set is derived from the toolchain by the module-integrity guard rather than by a hand
list, so these 34 are the count the guard expects.

## 4. Workflow status (local tree, not dispatched)

`.github/workflows/`: `android-core-arm64.yml`, `client-apple.yml`, `client-macos.yml`,
`interop-xray.yml`, `release.yml`, `server-linux-amd64.yml`, `verify.yml`,
`windows-core-amd64.yml`.

Only `verify.yml` and the two core builds are locally reproducible in this environment. The Apple /
Android / Windows / Xray workflows need CI runners or a device; per §23 those are recorded as
"not reproduced locally" rather than claimed.

## 5. Parallel writers

Five worktrees share this object database. They are **separate working trees**, so an uncommitted
change in `v16-apple`, `v16-resid` or `v16-sniff` is not visible from here and cannot be swept into
a commit from here. Every commit in this round therefore stages **explicit file paths only**; broad
`git add .` / `git add -A` is not used anywhere (see §8 discipline).

## 6. Toolchain

```text
### go version
go version go1.25.5 darwin/arm64        (GOTOOLCHAIN=go1.25.5)

### release/DEFAULT_BUILD_TAGS
with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale,with_ccm,with_ocm,with_cloudflared,with_naive_outbound,with_usbip,with_openvpn,with_openconnect,with_xhttp,badlinkname
```

## 7. Baseline builds (before any change)

```text
go build -tags "$TAGS" ./...   -> exit 0
go build ./...                 -> exit 0
```

Both are exit 0 at the baseline. They are re-run after every change; a regression in either is a
release blocker for this round.
