#!/usr/bin/env python3
"""Static contract check for the libbox compatibility overlay.

Compiling proves the overlay is well-formed. It does NOT prove the shims still
mean what they are supposed to mean, and the tempting future "fix" for a build
break is to replace them with empty stubs. This asserts the intent instead:

  usePlatformAutoRedirect  -> returns false, always
  createAutoRedirect       -> always throws, never returns a session
  PromotePowerReportDraft  -> is a no-op, not a fake success
  send(_:)                 -> still present exactly once (notification untouched)

Run by scripts/ci/prepare-apple-client.sh after the overlay is applied.
"""
import re
import sys


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    path = sys.argv[1]
    src = open(path, encoding="utf-8").read()

    # --- redirect must stay disabled -------------------------------------
    m = re.search(r"func usePlatformAutoRedirect\(\) -> Bool \{\s*([^}]*?)\s*\}", src)
    if not m:
        fail("usePlatformAutoRedirect is missing")
    body = m.group(1).strip()
    if body != "false":
        fail(f"usePlatformAutoRedirect must return false, got: {body!r}")

    # --- creation must stay unsupported ----------------------------------
    m = re.search(
        r"func createAutoRedirect\(.*?\) throws -> [^{]*\{\s*(.*?)\n    \}", src, re.S
    )
    if not m:
        fail("createAutoRedirect is missing")
    body = m.group(1)
    if "throw" not in body:
        fail("createAutoRedirect must throw; a returning implementation would fake support")
    if re.search(r"\breturn\b", body):
        fail("createAutoRedirect must not return a session")

    # --- the promote shim must do nothing --------------------------------
    m = re.search(r"func LibboxPromotePowerReportDraft\(\)\s*\{(.*?)\n\}", src, re.S)
    if not m:
        fail("LibboxPromotePowerReportDraft() is missing")
    if re.search(r"\b(return\s+\w|fatalError|assert|precondition)\b", m.group(1)):
        fail("LibboxPromotePowerReportDraft() must be a no-op")

    # --- notification must keep exactly one implementation ---------------
    send_count = len(re.findall(r"func send\(_ notification: LibboxNotification\?\) throws", src))
    if send_count != 1:
        fail(f"expected exactly one send(_:) implementation, found {send_count}")

    print("  [contract] redirect disabled, creation unsupported, promote no-op, "
          "notification single-implementation")
    return 0


if __name__ == "__main__":
    sys.exit(main())
