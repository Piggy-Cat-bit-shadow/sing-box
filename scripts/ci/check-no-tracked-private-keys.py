#!/usr/bin/env python3
"""Fails if a tracked file contains what looks like real PEM private key material.

Invoked by scripts/ci/test-apple-signing.sh.

# Why this exists rather than a grep

The check it replaces was:

    ! git grep -lI "BEGIN .*PRIVATE KEY" -- . ":(exclude)scripts/ci/test-apple-signing.sh"

which has two independent problems.

It is too LOOSE. `BEGIN .*PRIVATE KEY` also matches prose that merely describes PEM
handling. `common/physicalpath/status.go` contains, in a comment:

    BEGIN ... PRIVATE KEY     PEM bodies, which are multi-line

and `common/physicalpath/status{,_contract}_test.go` contain redaction fixtures whose key
body is twelve base64 characters - a string that exists precisely to prove the redactor
strips it, and which no real key could be. Both files arrived with the upstream baseline
sync and turned the check red while nothing was leaking.

It is also UNRELIABLE. `git grep -P` in the Git for Windows build used to develop this
accepts the flag and then matches nothing, silently; and `grep -P` there does not honour
`\\n` inside a pattern. A check written against those would pass for the wrong reason - the
same "green but meaningless" failure as the loose pattern, from the other direction.

So the search is done in Python, where the semantics are the same on every host: a PEM
private key header, followed by enough base64 to be key material. A committed key has
kilobytes; a fixture has a dozen bytes; prose has none.
"""
import re
import subprocess
import sys

# A PEM private-key header: five dashes, BEGIN, an optional key type, PRIVATE KEY, dashes.
HEADER = re.compile(rb"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")

# Base64 body characters, including the line breaks real PEM wraps at 64 columns.
BODY = re.compile(rb"[A-Za-z0-9+/=\r\n]")

# How much base64 must follow the header before this is treated as key material rather than
# a fixture. A 2048-bit RSA key is ~1600 base64 characters; the upstream fixtures are 12.
# 80 is well clear of any fixture and far below any real key.
MIN_BODY = 80

# This file names the patterns, so it would match itself.
SELF = "scripts/ci/test-apple-signing.sh"


def tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z", "--", ".", f":(exclude){SELF}"],
        capture_output=True,
        check=True,
    ).stdout
    return [name for name in out.split(b"\0") if name]


def looks_like_key(data: bytes) -> tuple[bool, int]:
    for match in HEADER.finditer(data):
        # Require the body to start immediately after the header's line, then count base64.
        position = match.end()
        while position < len(data) and data[position : position + 1] in (b"\r", b"\n"):
            position += 1
        body = 0
        while position < len(data) and BODY.match(data, position):
            body += 1
            position += 1
        if body >= MIN_BODY:
            return True, body
    return False, 0


def main() -> int:
    findings = []
    for name in tracked_files():
        path = name.decode("utf-8", "surrogateescape")
        try:
            with open(path, "rb") as handle:
                data = handle.read()
        except (OSError, IsADirectoryError):
            continue
        found, body = looks_like_key(data)
        if found:
            findings.append((path, body))

    if findings:
        print("test-apple-signing: private key material is tracked", file=sys.stderr)
        for path, body in findings:
            print(f"  - {path}: {body} base64 characters after a PEM private key header", file=sys.stderr)
        print("  A committed private key must be revoked, not merely deleted.", file=sys.stderr)
        return 1

    print("  PASS: no private key material is tracked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
