#!/usr/bin/env python3
"""Statically verify that client call sites read their bound StringBox result.

# Why this is a real parser and not a bigger grep

The check is "every call site of this method reads the result through an accessor". Three
things make a shell `grep -E` a bad tool for it, and all three produced a wrong answer in the
first revision of this gate:

  1. Receiver classification. `address` is both a libbox method name and an ordinary local
     variable name. The receiver patterns live in the ABI contract and contain a nested
     optional group (`(\\.next\\(\\))?`); GNU and BSD `grep -E` disagreed about whether that
     parsed, and no quoting made both agree.
  2. Grouping. The contract writes the receiver as a bare alternation (`a|b|c`). Interpolated
     into a larger pattern without wrapping, it becomes a TOP-LEVEL alternation, and the
     pattern then matches the `it` inside `Activity` - the shell version reported 4683
     violations on a clean tree.
  3. What follows the call. The verdict depends on the characters after the closing paren,
     which is a property of the match, not of the line.

The first shell version reported PASS on the very call site it exists to catch
(`Wrappers.kt`'s `toIpPrefix`, which calls `address()` on its extension receiver rather than
through a dotted expression).

# Usage

  probe-accessors.py --contract <contract.tsv> --lang kotlin|swift --root <dir>

Prints one JSON object:

  {"scanned": <int>, "violations": [{"file","line","text","call","tail", ...}], "error": ""}

Exit status 0 when the probe ran (regardless of violations), 2 when it could not run. The
caller decides what a violation means.
"""

import argparse
import json
import os
import re
import sys

# A migrated read of the box. Kotlin has the `StringBox?.unwrap` extension as well as `.value`.
ACCESSORS = {
    "kotlin": (".value", ".unwrap"),
    "swift": (".value",),
}
SUFFIXES = {
    "kotlin": (".kt",),
    "swift": (".swift", ".m", ".mm"),
}
# Directories holding build output or tooling caches rather than client source. Copies of the
# generated API can appear in them and are not call sites anyone maintains.
SKIP_DIRS = {".git", "build", ".gradle", ".idea", "DerivedData", "node_modules"}


def load_contract(path):
    records = []
    with open(path, "r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            fields = line.split("\t")
            if len(fields) < 5:
                raise ValueError(
                    "contract row needs 5+ tab-separated fields, got %d: %r"
                    % (len(fields), line)
                )
            records.append(
                {
                    "owner": fields[0],
                    "method": fields[1],
                    "javamethod": fields[2],
                    "kotlin_res": fields[3],
                    "swift_res": fields[4],
                }
            )
    if not records:
        raise ValueError("the contract has no records")
    return records


def collect_sources(root, lang):
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name.endswith(SUFFIXES[lang]):
                found.append(os.path.join(dirpath, name))
    return sorted(found)


def compile_receiver(pattern, owner, method):
    """Compile a receiver pattern anchored so a match ends exactly at the method name.

    The `(?:...)` wrapper is load-bearing: the contract spells the receiver as a bare
    alternation, and without the wrapper that alternation would be top-level and would match
    substrings of unrelated identifiers. The `(?<![A-Za-z0-9_])` on the left rejects a match
    beginning inside an identifier, so the `Address` in `InetAddress` is not a receiver.
    """
    try:
        return re.compile(r"(?<![A-Za-z0-9_])" + r"(?:" + pattern + r")\Z")
    except re.error as exc:
        raise ValueError(
            "receiver pattern for %s.%s does not compile: %s" % (owner, method, exc)
        )


def is_comment(text):
    """True for a line whose content is a comment or a doc-comment continuation.

    There is no Kotlin/Swift lexer here and there will not be one; this covers the shapes that
    occur in these clients and that produced false positives: KDoc `*` continuations, `//`,
    and `/*`.
    """
    return text.lstrip().startswith(("*", "//", "/*"))


def is_declaration(prefix):
    """True when the method name sits in a declaration rather than in a call.

    `fun RoutePrefix.toIpPrefix() = ...` declares the very function whose body calls
    `address()`, and `override fun getName(): String = ...` declares a migrated method. Both
    carry the method name where a call would. Requiring a declaration keyword between the last
    statement boundary and the name is what separates them.
    """
    return (
        re.search(r"\b(fun|func|val|var|let)\s+[A-Za-z_][A-Za-z0-9_.<>,\[\] ]*$", prefix)
        is not None
    )


def receiver_is_bound(compiled, up_to_method):
    """True when a receiver that `compiled` accepts ends exactly where the method name begins.

    `up_to_method` must be the line text UP TO AND INCLUDING the method name, because the
    receiver is the token immediately before the method name: the classifier has to see the
    receiver's own characters to match them. Testing the text before the name instead finds
    nothing at all - which is exactly the bug that made this probe report zero violations on
    the one call site it was written for.

    The receiver is a suffix of that text: `address` for a bare call
    (`getByName(address`), and `expr.` for a qualified one (`prefix.address`). A suffix
    beginning at an identifier character is rejected, otherwise the match could start mid-word.
    """
    window = up_to_method[-200:]
    for start in range(len(window)):
        if window[start].isalnum() or window[start] == "_":
            continue
        if compiled.search(window[start:]):
            return True
    return False


def probe(root, lang, records):
    sources = collect_sources(root, lang)
    if not sources:
        return {
            "scanned": 0,
            "violations": [],
            "error": "no %s source files under %s" % (lang, root),
        }

    tail_alt = "|".join(re.escape(a) for a in ACCESSORS[lang])
    accessor_re = re.compile(r"^[ \t]*[?!]*(?:" + tail_alt + r")(?![A-Za-z0-9_])")
    call_args = r"\(([^()]*(?:\([^()]*\)[^()]*)*)\)"

    violations = []
    for record in records:
        method = record["javamethod"]
        res_pattern = record["kotlin_res"] if lang == "kotlin" else record["swift_res"]
        if not res_pattern:
            continue
        compiled = compile_receiver(res_pattern, record["owner"], record["method"])
        call_re = re.compile(re.escape(method) + r"[ \t]*" + call_args)

        for path in sources:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                for lineno, text in enumerate(handle, 1):
                    if is_comment(text):
                        continue
                    for match in call_re.finditer(text):
                        prefix = text[: match.start()]
                        if is_declaration(prefix):
                            continue
                        head = prefix.rstrip()
                        # A call on the bound object is either a dotted expression, or a bare
                        # call in argument position (an extension receiver's implicit `this`,
                        # or an unqualified call in a scope that holds one). A bare name that
                        # is neither is not attributable to libbox, and guessing there is what
                        # flags the word "name" in prose.
                        qualified = head.endswith(".")
                        argument = bool(re.search(r"[(,]\s*$", head))
                        if not (qualified or argument):
                            continue
                        # Include the method name: the receiver ends where the name begins.
                        if not receiver_is_bound(
                            compiled, text[: match.start() + len(method)]
                        ):
                            continue
                        tail = text[match.end() :]
                        if accessor_re.match(tail):
                            continue
                        violations.append(
                            {
                                "file": path,
                                "line": lineno,
                                "text": text.rstrip("\n"),
                                "call": match.group(0),
                                "tail": tail.rstrip("\n"),
                                "owner": record["owner"],
                                "method": record["method"],
                                "javamethod": method,
                            }
                        )
    return {"scanned": len(sources), "violations": violations, "error": ""}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", required=True)
    parser.add_argument("--lang", required=True, choices=("kotlin", "swift"))
    parser.add_argument("--root", required=True)
    args = parser.parse_args()

    try:
        result = probe(args.root, args.lang, load_contract(args.contract))
    except Exception as exc:  # noqa: BLE001 - the caller reports this as SKIP, not PASS
        json.dump({"scanned": 0, "violations": [], "error": str(exc)}, sys.stdout)
        sys.stdout.write("\n")
        return 2

    json.dump(result, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
