#!/usr/bin/env python3
"""Verifies that release-apple.sh's prebuilt arm does not compile Libbox.

Reads release-apple.sh on stdin.

Exit codes are deliberately 0 for the GOOD case, so the caller reads as a plain
`if ...; then PASS`. The point of APPLE_USE_PREBUILT_LIBBOX is that a local publish reuses the
CI-built artifact instead of compiling a fourth copy; a fallback build would defeat that silently.

  0  the prebuilt arm does not build Libbox (correct)
  1  the prebuilt arm builds Libbox (the flag is defeated)
  2  the prebuilt block could not be located (the script changed shape)
"""
import re
import sys

src = sys.stdin.read()
block = re.search(
    r'if \[ "\$\{APPLE_USE_PREBUILT_LIBBOX:-0\}" = "1" \]; then(.*?)\n  fi',
    src,
    re.S,
)
if not block:
    print("could not locate the prebuilt block in release-apple.sh", file=sys.stderr)
    sys.exit(2)

# Everything before the else arm is the prebuilt path.
prebuilt_arm = block.group(1).split("\n  else")[0]
if "build-apple-libbox.sh both" in prebuilt_arm:
    print("the prebuilt arm still calls build-apple-libbox.sh", file=sys.stderr)
    sys.exit(1)
sys.exit(0)
