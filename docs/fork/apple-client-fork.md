# Apple client fork and the UI language transplant

The Apple client is a git submodule, and until this change its URL pointed at
[SagerNet/sing-box-for-apple](https://github.com/SagerNet/sing-box-for-apple). The pointer now
records a commit on
[Piggy-Cat-bit-shadow/sing-box-for-apple](https://github.com/Piggy-Cat-bit-shadow/sing-box-for-apple),
branch `hako-ui`, based on the previously pinned commit.

## Why a fork rather than a patch overlay

The parent repository already adapts the pinned client at build time —
`scripts/ci/prepare-apple-client.sh` applies compatibility, branding, link, updater and entitlement
overlays — and that is the right mechanism for *small, mechanically verifiable* adaptations: each
overlay anchors on text that must exist, verifies itself afterwards, and fails closed if the client
is repinned.

The presentation work does not fit that shape. It adds a design system and a primary shell, and it
rewrites the composition of the tool, settings and dashboard pages: hundreds of lines of new code
whose correctness is not a text replacement. Expressing it as an overlay would have meant a patch
large enough that its anchors, not its behaviour, became the maintenance problem, and the parent
would have gone on claiming to pin an upstream client it no longer builds.

So the client is a fork, exactly as this repository already forks the dependencies it patches
(`sing`, `cronet-go`, `quic-go`). The overlays are unchanged and still applied on top.

## What the fork changes

Only the presentation layer, under `ApplicationLibrary/Views` plus `SFI/MainView.swift` and
`MacLibrary/SidebarView.swift`. The kernel, `Library/Network`, the extensions, libbox, the tunnel
lifecycle, the profile model, the app name, the icons, the bundle identifiers and the signing layout
are untouched.

## Updating it

1. Work on a branch of the fork based on the submodule commit the parent records.
2. Push it: `git -C clients/apple push <fork-remote> <branch>`.
3. Record the new commit in the parent: `git add clients/apple` and commit the gitlink.
4. Only then may the submodule URL or the pin change: the parent's Apple workflow verifies that the
   checked-out submodule equals the gitlink, and `actions/checkout` fetches that commit from the URL
   in `.gitmodules`, so a gitlink that exists nowhere reachable turns a build into a fetch failure.

Keeping the branch based on the recorded commit makes each update a fast-forward of the pin rather
than a rebase, and keeps the diff against upstream small enough to review.
