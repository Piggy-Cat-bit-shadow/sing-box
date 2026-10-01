#!/usr/bin/env python3
"""Applies the libbox compatibility overlay to the pinned Apple client.

Invoked by scripts/ci/prepare-apple-client.sh, which performs the anchoring and
verification. This file only performs the edit, kept separate so the rewrite is
readable as code rather than as a shell heredoc.

Read the header of prepare-apple-client.sh for why the overlay exists at all.
"""
import sys

# The two members this fork's libbox generates that the pinned client lacks.
#
# Everything else the Go interface lists already exists in the client under its
# older Swift spelling - `UsePlatformAutoDetectInterfaceControl` arrives as
# `usePlatformAutoDetectControl`, `SendNotification` as `send` - so no shim is
# added for them. Notification delivery in particular is deliberately left alone:
# it keeps its single real UNUserNotificationCenter / UserServiceClient
# implementation instead of gaining a duplicate.
SHIM = '''    // MARK: - libbox compatibility shims (applied by scripts/ci/prepare-apple-client.sh)

    // Two members of LibboxPlatformInterfaceProtocol are absent from this pinned
    // client. The rest of the protocol's requirements already exist below under
    // their older Swift names, including notification delivery, which is
    // deliberately NOT wrapped so it keeps one implementation.

    // Auto-redirect is a Linux capability. Apple platforms route through
    // NetworkExtension instead, so this reports false and creation refuses rather
    // than pretending to succeed. Upstream sing-box-for-apple declares the same
    // members unsupported on Apple platforms.
    public func usePlatformAutoRedirect() -> Bool {
        false
    }

    public func createAutoRedirect(_ options: Data?, handler: LibboxAutoRedirectHandlerProtocol?) throws -> LibboxAutoRedirectSessionProtocol {
        throw NSError(
            domain: "LibboxAutoRedirect",
            code: -1,
            userInfo: [NSLocalizedDescriptionKey: "auto redirect is not supported on Apple platforms"]
        )
    }

'''

TRAILER = '''

// Applied by scripts/ci/prepare-apple-client.sh.
//
// The pinned client calls LibboxPromotePowerReportDraft(), which this libbox
// revision does not generate - and neither does upstream's, whose libbox is
// identical here. The pinned client is simply newer than both. The call discards
// its result and only promotes a previously written draft, so with no draft entry
// point in this revision the correct behaviour is to do nothing. Defining the
// global here keeps the client's call site untouched.
public func LibboxPromotePowerReportDraft() {
}
'''

ANCHOR = "    public func usePlatformAutoDetectControl() -> Bool {"


def main() -> int:
    path = sys.argv[1]
    src = open(path, encoding="utf-8").read()

    if "func usePlatformAutoRedirect() -> Bool" in src:
        print("apply-apple-compat-overlay: already applied", file=sys.stderr)
        return 1

    if ANCHOR not in src:
        print(f"apply-apple-compat-overlay: anchor not found in {path}", file=sys.stderr)
        return 1

    src = src.replace(ANCHOR, SHIM + ANCHOR, 1)
    src = src.rstrip("\n") + TRAILER
    open(path, "w", encoding="utf-8").write(src)
    return 0


if __name__ == "__main__":
    sys.exit(main())
