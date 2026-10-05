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

## Rounds recorded against it

### Second UI round — secondary destinations (`747143cf0` → `16cacb701`)

The first round built the shell (Home, Tools, More, the tab bar, the bottom dock) and left the
pages behind it on their original presentation. This round took the secondary destinations:

| phase | what changed |
|---|---|
| shell | a child page is applied after its primary has rendered, so a launch on Logs or a deep link can no longer select a page it never shows |
| profile | the picker row leads with the shared icon tile and marks the selected profile at the trailing edge |
| groups | shared canvas, spacing and status badge; the latency grid and segmented shape are left alone as a diagnostic |
| connections | the list is one grouped card with dividers instead of a glass card per row; the row uses the shared language |
| detail | every `FormTextItem` — connections, settings, tools, reports — renders the shared value line |
| reports | the empty and loading states come from the shared empty state |
| remote | the same, for the server list |
| logs | the native log text view sits on the shared surface; the data path and the auto-scroll policy are unchanged |
| macOS | the detail column is centred and inset without touching `NavigationSplitView` or any of its behaviour |

The child commit is `16cacb70101f416f60c5faea12a2e6df0c1ca244` on `hako-ui`. The build-time
compatibility overlay that `scripts/ci/prepare-apple-client.sh` applies to the submodule is not
part of any child commit, and the nine commits touch only `ApplicationLibrary/Views/**`,
`MacLibrary/MainView.swift` and `scripts/dev/`.

Not verified in this round: the runtime behaviour of the shell routing change and every visual
change, because this machine has no simulator runtime and no unit-test target exists to run the
extracted routing mapping — see `scripts/dev/check-hako-primary-route.sh` for the blocker and the
check that is ready to run where one of those exists.


## Updating it

1. Work on a branch of the fork based on the submodule commit the parent records.
2. Push it: `git -C clients/apple push <fork-remote> <branch>`.
3. Record the new commit in the parent: `git add clients/apple` and commit the gitlink.
4. Only then may the submodule URL or the pin change: the parent's Apple workflow verifies that the
   checked-out submodule equals the gitlink, and `actions/checkout` fetches that commit from the URL
   in `.gitmodules`, so a gitlink that exists nowhere reachable turns a build into a fetch failure.

Keeping the branch based on the recorded commit makes each update a fast-forward of the pin rather
than a rebase, and keeps the diff against upstream small enough to review.
