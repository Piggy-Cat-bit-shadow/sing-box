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

It scans two shapes, not one, because the migration has two:

  1. CALL SITES. `kind: "call"` - a call of a migrated method whose result is not read through
     an accessor. This is what the receiver patterns in the contract describe.

  2. IMPLEMENTERS. `kind: "implementer"` - a PLATFORM type that conforms to a bound Go
     interface and re-declares the migrated method with the old result type. A method on a
     bound Go interface is implemented by the platform as well as by Go, and an
     implementation is a DECLARATION, which the call-site scan cannot see at all. Both clients
     shipped this defect once: Android's `RootBridgeSessionWrapper.name(): String` against a
     Go `BridgeSession.Name() *StringBox` (the Kotlin compiler rejected it), and Apple's
     `BridgeServiceSession.name() -> String` against the same declaration (the Swift compiler
     rejects it on the macOS and JAILBREAK configurations the type is compiled under).

# Usage

  probe-accessors.py --contract <contract.tsv> --lang kotlin|swift --root <dir>

Prints one JSON object:

  {"scanned": <int>, "violations": [{"kind","file","line","text", ...}], "error": ""}

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

# ---------------------------------------------------------------------------
# The implementer side
# ---------------------------------------------------------------------------
#
# A record whose `check` column is `interface` declares a method on a bound Go INTERFACE, and a
# bound Go interface is implemented BY THE PLATFORM as well as by Go: libbox hands the platform
# a Go value (NewBridgeService) and the platform hands libbox its own conforming type back.
# The call-site scan above sees neither, because an implementation is a declaration.
#
# The two languages spell the same three things differently and nothing else:
#
#   what a type is declared with   class/struct/actor/extension   class/interface/object
#   what the bound interface is    Libbox<Owner>Protocol          <Owner> (an imported type)
#   what a method returns          `-> T`                         `: T`
#
# A conformance is recognised by the type keyword appearing shortly BEFORE the interface name
# and the body brace opening shortly AFTER it. Both bounds matter: without the first, a
# property annotation (`val s: BridgeSession`) would be read as a conformance, and without the
# second, so would a parameter type in a function whose body happens to open on the same line
# (`func openTun(_ options: LibboxTunOptionsProtocol?) {`), which is exactly how every Apple
# call site reaches `TunOptions` and is not an implementation of it.
IMPL_KEYWORDS = {
    "swift": r"\b(?:class|struct|actor|extension)\b",
    "kotlin": r"\b(?:class|interface|object)\b",
}
IMPL_KEYWORD_WINDOW = 4  # lines above the interface name that may hold the type keyword
IMPL_BRACE_WINDOW = 3  # lines after the interface name that may hold the opening brace
IMPL_SIGNATURE = {
    # The return type stops at the body brace (Swift) or at the expression-body `=` (Kotlin).
    "swift": r"\bfunc\s+{m}\s*\((?:[^()]|\([^()]*\))*\)\s*(?:async\s*)?(?:throws\s*)?(?:->\s*([^\n{{]+))?",
    "kotlin": r"\bfun\s+{m}\s*\((?:[^()]|\([^()]*\))*\)\s*(?::\s*([^\n={{]+))?",
}
# The box type as each client names it. `LibboxStringBox` is the ObjC name gomobile gives
# `*StringBox` for a package named `libbox`; both spellings contain "StringBox".
BOX_MARKER = "StringBox"


def strip_comments(text):
    """Drop a trailing line comment. Block comments are handled by the caller, which skips
    continuation lines outright; there is no lexer here and there will not be one."""
    for marker in ("//",):
        index = text.find(marker)
        if index >= 0:
            text = text[:index]
    return text


def matching_brace_span(lines, start_line, start_col):
    """Return (first_line, last_line_exclusive) of the brace block opening at or after a point.

    Scanning starts at `start_col` on `start_line` and may cross at most `IMPL_BRACE_WINDOW`
    lines before the opening brace; after that it runs to the brace that closes it. Returns
    None when no brace opens inside the window, which is how a non-conformance is rejected.
    """
    depth = 0
    opened = False
    line = start_line
    limit = min(len(lines), start_line + IMPL_BRACE_WINDOW + 1)
    while line < len(lines):
        text = lines[line]
        col = start_col if line == start_line else 0
        for index in range(col, len(text)):
            character = text[index]
            if character == "{":
                depth += 1
                opened = True
            elif character == "}":
                depth -= 1
                if opened and depth == 0:
                    return start_line, line + 1
        line += 1
        if not opened and line >= limit:
            return None
    return None


def implements_method(lines, span, lang, method):
    """Find a declaration of `method` inside a conformance body.

    Returns (line_number, signature, return_type). `return_type` is None when the declaration
    has no written result type (Kotlin's inferred `= expr` body), and the caller must not
    guess in that case: "could not tell" is reported as nothing rather than as a violation.
    """
    start, end = span
    pattern = re.compile(IMPL_SIGNATURE[lang].format(m=re.escape(method)))
    for line in range(start, min(end, len(lines))):
        match = pattern.search(strip_comments(lines[line]))
        if match is None or is_comment(lines[line]):
            continue
        return_type = match.group(1)
        return line + 1, match.group(0).strip(), (return_type.strip() if return_type else None)
    return None


def find_implementers(path, lines, lang, owner, method):
    """Yield a violation dict for every conformance whose `method` is not boxed."""
    if lang == "swift":
        token_re = re.compile(r"\bLibbox" + re.escape(owner) + r"Protocol\b")
        keyword_re = re.compile(IMPL_KEYWORDS[lang])
    else:
        token_re = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(owner) + r"\b")
        keyword_re = re.compile(IMPL_KEYWORDS[lang])

    for line_index, text in enumerate(lines):
        if is_comment(text):
            continue
        for token in token_re.finditer(text):
            # A parameter type, not a conformance: `func openTun(_ options: LibboxTunOptionsProtocol?)`
            # and `fun createBridge(options: BridgeOptions?): BridgeSession` both name a bound
            # interface where a conformance would, and neither implements it.
            before = strip_comments(text[: token.start()])
            if re.search(r"\b(?:fun|func)\b", before):
                continue
            window = "".join(
                strip_comments(lines[index])
                for index in range(max(0, line_index - IMPL_KEYWORD_WINDOW), line_index)
            )
            if not keyword_re.search(window) and not keyword_re.search(before):
                continue
            span = matching_brace_span(lines, line_index, token.end())
            if span is None:
                continue
            found = implements_method(lines, span, lang, method)
            if found is None:
                continue
            decl_line, signature, return_type = found
            if return_type is None or BOX_MARKER in return_type:
                continue
            yield {
                "kind": "implementer",
                "file": path,
                "line": decl_line,
                "text": lines[decl_line - 1].rstrip("\n"),
                "call": signature,
                "tail": "",
                "owner": owner,
                "method": method,
                "javamethod": method,
                "return_type": return_type,
                "conformance_line": line_index + 1,
                "conformance": text.strip(),
            }


def load_contract(path):
    records = []
    with open(path, "r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            fields = line.split("\t")
            if len(fields) < 6:
                raise ValueError(
                    "contract row needs 6+ tab-separated fields, got %d: %r"
                    % (len(fields), line)
                )
            records.append(
                {
                    "owner": fields[0],
                    "method": fields[1],
                    "javamethod": fields[2],
                    "check": fields[3],
                    "kotlin_res": fields[4],
                    "swift_res": fields[5],
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
    # The declared name must be the last token before the `(` - i.e. nothing but an identifier
    # may follow the declaration keyword. Allowing `.` here was wrong and costly: it made
    # `fun f() = Libbox.formatConfig(...)` look like a declaration of `formatConfig`, so the
    # package-level records were skipped in every qualified call and the probe reported zero
    # violations for them. A receiver expression is not part of a function name.
    return (
        re.search(r"\b(fun|func|val|var|let)\s+[A-Za-z_][A-Za-z0-9_<>,\[\] ]*$", prefix)
        is not None
    )


def receiver_is_bound(compiled, prefix, method):
    """True when a receiver `compiled` accepts ends exactly where `method` begins.

    `prefix` is the line text before the method name. The receiver is a suffix of it, and which
    suffix depends on how the call is written:

      * qualified - `Libbox.formatConfig(...)`, `session.name(...)`: the receiver ends one
        character before the name, at the `.`. The slice that must classify is `...Libbox`.
      * bare - `getByName(address())`: there is no dot, so the receiver ends exactly at the name
        and the slice that must classify is `...address`.

    Both candidates are tested, the `.`-terminated one first. An earlier revision fed the text
    UP TO AND INCLUDING the method name to an end-anchored classifier, so no slice ever ended
    at the receiver and every record reported zero violations - a green gate that inspected
    nothing.
    """
    candidates = []
    if prefix.endswith("."):
        candidates.append(prefix[:-1])
    candidates.append(prefix)
    if prefix.endswith("." + method):
        candidates.append(prefix[: -(len(method) + 1)])
    # A bare call on an extension receiver's implicit `this` - `getByName(address())` - has no
    # dotted expression anywhere, and the receiver IS the method name, which appears AFTER the
    # prefix rather than inside it. Without this candidate the bare shape is not detected at
    # all, which is the shape the original migration missed.
    candidates.append(prefix + method)
    for candidate in candidates:
        window = candidate[-200:]
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
                        if not receiver_is_bound(compiled, prefix, method):
                            continue
                        tail = text[match.end() :]
                        if accessor_re.match(tail):
                            continue
                        violations.append(
                            {
                                "kind": "call",
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

    # A record declared on a bound INTERFACE has a second half that the call-site scan above
    # cannot see: the PLATFORM implements that interface too, and its override has to return the
    # box. Both clients shipped this defect (see the module docstring), so it is scanned rather
    # than only counted.
    implementer_sources = [
        path
        for path in sources
        if path.endswith(".swift" if lang == "swift" else ".kt")
    ]
    for record in records:
        if record["check"] != "interface":
            continue
        for path in implementer_sources:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                lines = handle.readlines()
            for violation in find_implementers(
                path, lines, lang, record["owner"], record["javamethod"]
            ):
                violations.append(violation)

    violations.sort(key=lambda v: (v["file"], v["line"], v["kind"]))
    interface_methods = sum(1 for r in records if r["check"] == "interface")
    return {
        "scanned": len(sources),
        "violations": violations,
        "interface_methods": interface_methods,
        "error": "",
    }


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
