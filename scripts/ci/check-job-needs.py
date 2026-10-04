#!/usr/bin/env python3
"""Exits 0 when the named workflow job declares `needs: libbox`.

Reads the workflow on stdin.

Deliberately stdlib-only. The first version imported PyYAML, which is present on a macOS
workstation but NOT on the GitHub runner image, so the check failed there for a reason that had
nothing to do with the workflow it was inspecting.

The job graph is still parsed structurally rather than matched by a line range: a `steps:` list
following the key makes a naive range end in the wrong place, which is how an earlier version
passed while proving nothing. Job blocks are found by indentation, which is what YAML uses.
"""
import re
import sys

job = sys.argv[1]
text = sys.stdin.read()

# A top-level job key sits at exactly two spaces of indentation under `jobs:`.
match = re.search(
    r"^  " + re.escape(job) + r":\n(.*?)(?=^  \S|\Z)",
    text,
    re.M | re.S,
)
if not match:
    sys.exit(2)

block = match.group(1)
needs = re.search(r"^    needs:\s*(\S+)\s*$", block, re.M)
sys.exit(0 if needs and needs.group(1) == "libbox" else 1)
