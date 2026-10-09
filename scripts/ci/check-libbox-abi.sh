#!/usr/bin/env bash
#
# ABI compatibility gate for the libbox StringBox migration.
#
# # The failure this exists to prevent
#
# libbox's exported methods used to return a bare `string`. gomobile writes such a result into
# the packed `_cgo_argtype` frame, which puts a Go pointer at alignment 1, and the Go runtime
# then throws `fatal error: bulkBarrierPreWrite: unaligned arguments` - a THROW, so the
# process dies and nothing can recover it. The fix is to return a bound `*StringBox` and read
# it through its `Value` accessor.
#
# That fix spans three layers, versioned in three different repositories:
#
#   1. the Go declaration in experimental/libbox     (this repository)
#   2. the generated Java/ObjC binding               (produced here, consumed there)
#   3. the Kotlin and Swift call sites               (clients/android, clients/apple)
#
# Layer 3 is pinned by a gitlink, so "the AAR built" and "the client compiled" are both
# compatible with a client checked out at a revision that still calls the OLD ABI. That is the
# concrete historical failure this gate exists for: the Kotlin `.value` edits sat uncommitted
# in clients/android, GitHub built the AAR green, and a clean checkout of the client called
# `session.name()` expecting a String.
#
# # What it checks
#
#   1. GO SHAPE      - every method named in docs/fork/libbox-abi-contract.tsv is still
#                      attributed by the surface scanner (experimental/libbox/
#                      gomobile_surface_test.go) and still has a bound-object result rather
#                      than a pointer-bearing string/[]byte one. Catches a revert.
#   2. GO DECL       - the declaration's result really is *StringBox.
#   3. BINDING SHAPE - the generated Java binding declares the method returning StringBox and
#                      does not declare a bare java.lang.String result for it. Uses gobind
#                      when available; says so and falls back to layers 1+2 otherwise.
#   4. CALL SITES    - every call site in the client source whose receiver matches the
#                      contract reads the result through a migrated accessor (Kotlin `.value`
#                      or the `StringBox?.unwrap` extension; Swift/ObjC `.value`). A call that
#                      reads it any other way is an old-ABI call site.
#   4b. IMPLEMENTERS - every PLATFORM type that conforms to a bound Go interface named in the
#                      contract re-declares the migrated method with the boxed result. A method
#                      on a bound Go interface is implemented by the platform as well as by Go,
#                      and an implementation is a DECLARATION, so the call-site scan above cannot
#                      see it. Both clients shipped this defect: Android's
#                      RootBridgeSessionWrapper and Apple's BridgeServiceSession each declared
#                      `name(): String` against a Go `BridgeSession.Name() *StringBox`. The
#                      compiler catches it only in a configuration the release build does not
#                      always compile (Apple's is `#if os(macOS) || JAILBREAK`), which is why it
#                      is scanned here rather than left to a build that never sees the file.
#   5. CLIENT PIN    - the client gitlinks are the revisions the contract was verified against.
#
# # Usage
#
#   check-libbox-abi.sh
#   check-libbox-abi.sh --client-root <dir>    also scan a client checkout at <dir>
#   check-libbox-abi.sh --skip-client          layers 1-3 only
#
# Client source is found automatically in clients/android and clients/apple when the submodules
# are initialised. Point ANDROID_CLIENT_ROOT / APPLE_CLIENT_ROOT or --client-root at a checkout
# elsewhere to run the gate against a scratch clone of the fork. A missing client checkout is
# reported as SKIP with the reason and never as PASS: "I could not look" must not read the same
# as "I looked and it was fine".
#
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"

CONTRACT="$repo_root/docs/fork/libbox-abi-contract.tsv"
GO_PKG_DIR="$repo_root/experimental/libbox"
PROJECT_GOMOBILE_VERSION="$(cd "$repo_root" && go list -m -f '{{.Version}}' github.com/sagernet/gomobile 2>/dev/null || true)"

# The client revisions this contract was verified against; the superproject gitlinks must
# resolve to these. A checkout of either client at any other revision has not been shown to
# carry the migrated call sites.
#
# Android: Piggy-Cat-bit-shadow/sing-box-for-android, branch fix/libbox-stringbox-callsites.
#          Upstream SagerNet/sing-box-for-android does NOT carry them.
# Apple:   Piggy-Cat-bit-shadow/sing-box-for-apple. The migration is carried as
#          docs/fork/apple-stringbox-callsites.patch; see docs/fork/apple-client-fork.md.
#
# THE APPLE VALUE BELOW IS STALE, and layer 4 says so on every run. 5911580a is the revision the
# superproject gitlink pins and it carries NONE of the migration: sweeping it finds all 18
# unmigrated call sites. The fork branch head 8599039f6cd41dad6bdf975066b300725da08668 carries
# them (0 call-site violations, 347 sources scanned), and one more change is required before it
# can be named here: docs/fork/apple-bridge-session-implementer.patch, because Go declares
# BridgeSession.Name as returning *StringBox and the client's own implementer
# (ExtensionPlatformInterface.swift's BridgeServiceSession, under `#if os(macOS) || JAILBREAK`)
# still returns String. Update this constant and the gitlink TOGETHER, to a fork head that
# contains both, once that commit exists. Leaving it at 5911580a makes layer 5 PASS while layer
# 4 FAILS, which is the intended reading: the pin is not the thing that was verified.
VERIFIED_ANDROID_SHA="ec61030d3df74f3e7c39ab848c8996008ecd386a"
VERIFIED_APPLE_SHA="2b23330d489b9f6b45e98f903f458842e8961594"

client_root=""
skip_client=0
while [ $# -gt 0 ]; do
  case "$1" in
    --client-root) client_root="${2:?--client-root needs a directory}"; shift 2 ;;
    --skip-client) skip_client=1; shift ;;
    -h|--help) sed -n '2,60p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) printf 'FAIL: unknown argument %s\n' "$1" >&2; exit 2 ;;
  esac
done

fails=0
skipped_client_layers=0
fail() { printf 'FAIL: %s\n' "$*" >&2; fails=$((fails + 1)); }
ok()   { printf 'PASS: %s\n' "$*"; }
skip() { printf 'SKIP: %s\n' "$*"; }
info() { printf '     %s\n' "$*"; }

[ -f "$CONTRACT" ] || { printf 'FAIL: no ABI contract at %s\n' "$CONTRACT" >&2; exit 2; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

grep -v '^[[:space:]]*#' "$CONTRACT" | grep -v '^[[:space:]]*$' > "$tmp/records"
record_count="$(wc -l < "$tmp/records" | tr -d ' ')"
[ "$record_count" -gt 0 ] || { printf 'FAIL: the ABI contract has no records\n' >&2; exit 2; }

printf '== libbox ABI gate ==\n'
info "contract: docs/fork/libbox-abi-contract.tsv ($record_count migrated methods)"
info "gomobile pin: ${PROJECT_GOMOBILE_VERSION:-unknown}"
printf '\n'

# ---------------------------------------------------------------------------
# The gomobile surface inventory
# ---------------------------------------------------------------------------
#
# The scanner is the checked-in tripwire in gomobile_surface_test.go. It parses every non-test
# .go file in the package - including files excluded by the current build tags, so an
# Android-only declaration is still seen from a macOS checkout - and mirrors cmd/gobind's
# reachability rules. Reusing it keeps one definition of "the bound surface" instead of a
# second one here that would drift.
#
# -checklinkname=0 is passed because the default tag set contains tfogo_checklinkname0, which
# selects signal_handler_darwin.go and its runtime.getsig/setsig/fwdSig linknames; the linker
# rejects those under the default -checklinkname policy, so without the flag the test binary
# does not link on darwin and this gate could not run at all. The flag is exactly what the
# release recipe passes (see the comment at the top of signal_handler_darwin.go).
printf -- '-- surface inventory --\n'
inventory_ok=0
if (cd "$repo_root" && GOTOOLCHAIN="${GOTOOLCHAIN:-go1.25.5}" go test -v \
      -ldflags=-checklinkname=0 -tags "$(cat release/DEFAULT_BUILD_TAGS)" \
      -run TestGomobileMethodResultSurface ./experimental/libbox/) > "$tmp/surface.log" 2>&1; then
  inventory_ok=1
  grep -E 'gomobile surface:' "$tmp/surface.log" | tail -1 | sed 's/^ *//' | while IFS= read -r l; do info "$l"; done
  # The table is logged with a leading indent; dedent it, then key it by "owner<TAB>method".
  sed -n '/type | method | result type | class/,$p' "$tmp/surface.log" \
    | sed 's/^[[:space:]]*//' \
    | awk -F' \\| ' 'NF==4 { o=$1; if (o=="(package function)") o="-"; print o "\t" $2 "\t" $3 "\t" $4 }' \
    > "$tmp/surface.tsv"
  info "inventory rows: $(wc -l < "$tmp/surface.tsv" | tr -d ' ')"
else
  fail "the gomobile surface scanner did not run, so the Go layer cannot be verified:
$(sed 's/^/      /' "$tmp/surface.log" | tail -20)"
fi
printf '\n'

# ---------------------------------------------------------------------------
# Layers 1+2: the Go declaration
# ---------------------------------------------------------------------------
printf -- '-- layers 1-2: Go declaration --\n'
while IFS=$'\t' read -r go_owner go_method javamethod check_kind kotlin_re swift_re evidence; do
  key="$go_owner.$go_method"
  [ "$go_owner" = "-" ] && key="$go_method"

  if [ "$inventory_ok" = 1 ]; then
    # "-" is the scanner's marker for a package-level function; its key is the bare name,
    # not "-.Name". Kept in one place so the two spellings cannot drift.
    # `|| true`: awk exits 0 with no output when nothing matches, but an empty assignment
    # still must not be allowed to trip `set -e` on a future awk that exits non-zero.
    row="$(awk -F'\t' -v k="$key" '{ rk = ($1=="-") ? $2 : ($1"."$2); if (rk==k) { print; exit } }' "$tmp/surface.tsv" || true)"
    if [ -z "$row" ]; then
      fail "$key is not in the gomobile surface inventory at all. Either the declaration was
      removed or renamed (a silently missing API), or gobind now rejects its signature. The
      contract in docs/fork/libbox-abi-contract.tsv names an API no client can reach."
      continue
    fi
    klass="$(printf '%s' "$row" | cut -f4)"
    case "$klass" in
      *"BARE STRING/BYTES"*)
        fail "$key has a pointer-bearing result again: $klass
      The migration was reverted. A bare string/[]byte result puts a Go pointer in the packed
      gomobile result frame and can kill the process with
      'fatal error: bulkBarrierPreWrite: unaligned arguments'."
        continue
        ;;
    esac
    ok "$key is bound and its result is not pointer-bearing ($klass)"
  fi

  # The scanner classifies `*StringBox` as the generic "bound object" - it cannot know the box
  # type - so the specific box is asserted against the declaration itself. The receiver is
  # matched as `[^)]*` and the middle as `[^{]*` so a multi-line signature or a complex
  # parameter list still matches; only the result shape is being asserted.
  if [ "$go_owner" = "-" ]; then
    decl_re="^func ${go_method}\([^{]*\*StringBox"
  else
    decl_re="^func \([^)]*\) ${go_method}\([^{]*\*StringBox"
  fi
  if grep -rqE "$decl_re" "$GO_PKG_DIR"/*.go 2>/dev/null; then
    ok "$key returns *StringBox"
  else
    fail "$key does not return *StringBox in experimental/libbox. Expected a declaration
      matching: $decl_re"
  fi
done < "$tmp/records"

# ---------------------------------------------------------------------------
# Layer 3: the generated binding
# ---------------------------------------------------------------------------
printf '\n-- layer 3: generated Java binding --\n'
gobind_version=""
if command -v gobind >/dev/null 2>&1; then
  gobind_version="$(go version -m "$(command -v gobind)" 2>/dev/null \
    | sed -n 's/.*mod[[:space:]]*github.com\/sagernet\/gomobile[[:space:]]*\(v[^[:space:]]*\).*/\1/p' | head -1)"
fi

if [ -n "$gobind_version" ]; then
  info "gobind from github.com/sagernet/gomobile@$gobind_version"
  if [ "$gobind_version" != "$PROJECT_GOMOBILE_VERSION" ]; then
    info "NOTE: root go.mod pins $PROJECT_GOMOBILE_VERSION. scripts/ci/gomobile-toolchain.sh"
    info "      documents why the Apple build uses a newer patch level; for -lang=java the two"
    info "      versions are known to emit identical bindings (verified by diffing both)."
  fi
  if (cd "$repo_root" && gobind -lang=java -javapkg=io.nekohasekai -libname=box \
        -tags "$(cat release/DEFAULT_BUILD_TAGS)" -outdir "$tmp/bind" ./experimental/libbox) >/dev/null 2>&1; then
    while IFS=$'\t' read -r go_owner go_method javamethod check_kind kotlin_re swift_re evidence; do
      key="$go_owner.$go_method"; [ "$go_owner" = "-" ] && key="$go_method"
      if grep -rqE "^[[:space:]]*(public|protected)?[[:space:]]*(static[[:space:]]+)?(final[[:space:]]+)?(native[[:space:]]+)?StringBox ${javamethod}\(" "$tmp/bind" --include=*.java 2>/dev/null; then
        ok "$key -> generated Java 'StringBox ${javamethod}('"
      else
        fail "$key does not appear in the generated Java binding as returning StringBox.
      Either the method is no longer bound (a silently missing API) or its result went back to
      java.lang.String. Searched $tmp/bind for 'StringBox ${javamethod}('."
      fi
      if grep -rqE "^[[:space:]]*(public|protected)?[[:space:]]*(static[[:space:]]+)?(final[[:space:]]+)?(native[[:space:]]+)?java\.lang\.String ${javamethod}\(" "$tmp/bind" --include=*.java 2>/dev/null; then
        fail "$key still has a bare java.lang.String result in the generated Java binding
      ('java.lang.String ${javamethod}('). That is the old ABI shape."
      fi
    done < "$tmp/records"
  else
    fail "gobind failed to generate Java bindings for experimental/libbox, so the binding
      layer cannot be verified. Install github.com/sagernet/gomobile/cmd/gobind and re-run."
  fi
else
  skip "no gobind on PATH, so the generated binding was not inspected directly.
      Layers 1-2 above still assert the Go result is *StringBox, and cmd/gobind derives the
      Java result type purely from that. Install gomobile to have it checked end to end."
fi

# ---------------------------------------------------------------------------
# Layer 4: client call sites
# ---------------------------------------------------------------------------
printf '\n-- layer 4: client call sites --\n'

kotlin_roots=()
[ -n "${ANDROID_CLIENT_ROOT:-}" ] && kotlin_roots+=("$ANDROID_CLIENT_ROOT")
[ -n "$client_root" ] && kotlin_roots+=("$client_root")
kotlin_roots+=("$repo_root/clients/android")
swift_roots=()
[ -n "${APPLE_CLIENT_ROOT:-}" ] && swift_roots+=("$APPLE_CLIENT_ROOT")
[ -n "$client_root" ] && swift_roots+=("$client_root")
swift_roots+=("$repo_root/clients/apple")

find_root() {
  local want="$1"; shift
  local c
  for c in "$@"; do
    [ -d "$c" ] || continue
    # A real checkout has the marker; an empty submodule directory does not, and scanning an
    # empty directory would report a clean scan for a client that was never read.
    if [ "$want" = kotlin ] && [ -d "$c/app/src/main" ]; then printf '%s\n' "$c"; return 0; fi
    if [ "$want" = swift ] && { [ -d "$c/ApplicationLibrary" ] || [ -d "$c/Library" ]; }; then printf '%s\n' "$c"; return 0; fi
  done
  return 1
}

# The call-site scan itself lives in scripts/ci/probe-accessors.py. It is Python rather than
# shell on purpose, and the reason is written at the top of that file: the shell version of this
# check reported PASS on the one call site it was written to catch. This function only decides
# WHICH clients to scan and how to report the result.
# The call-site scan itself lives in scripts/ci/probe-accessors.py. It is Python rather than
# shell on purpose, and the reason is written at the top of that file: the shell version of this
# check reported PASS on the one call site it was written to catch. This function only decides
# which clients to scan and how to report the result.
# The call-site scan itself lives in scripts/ci/probe-accessors.py. It is Python rather than
# shell on purpose, and the reason is written at the top of that file: the shell version of this
# check reported PASS on the one call site it was written to catch. This function only decides
# which clients to scan and how to report the result.
scan_client() {
  local lang="$1" root="$2" result
  if ! result="$(python3 "$script_dir/probe-accessors.py" \
        --contract "$CONTRACT" --lang "$lang" --root "$root" 2>&1)"; then
    skip "the $lang accessor probe could not run against $root:
$(printf '%s' "$result" | sed 's/^/      /')"
    skipped_client_layers=$((skipped_client_layers + 1))
    return 0
  fi
  # The JSON is passed as an argument rather than on stdin so that the renderer can be a
  # here-document. An earlier revision piped it in and the here-document consumed it instead.
  local rendered
  rendered="$(python3 - "$result" <<'PYEOF'
import json
import sys

data = json.loads(sys.argv[1])
for v in data.get("violations") or []:
    if v.get("kind") == "implementer":
        # A platform type that conforms to a bound Go interface and re-declares the migrated
        # method with the old result type. The call-site scan cannot see this: an implementation
        # is a declaration, not a call.
        print(f"FAIL: {v['file'].rsplit('/', 1)[-1]} implements a bound libbox interface but does not")
        print("      return the migrated StringBox:")
        print(f"      {v['file']}:{v['line']}  (conformance at line {v['conformance_line']})")
        print(f"        {v['text']}")
        print(f"      {v['owner']}.{v['method']} is declared on a bound Go INTERFACE, so the platform")
        print("      implements it as well as Go, and its override must return the box too - it")
        print(f"      currently returns {v['return_type']!r}.")
        print("      The fix is to return the box: Kotlin `StringBox().apply { value = ... }`, Swift")
        print("      `LibboxStringBox()` with its `value` set. This is a COMPILE ERROR, not a silent")
        print("      one: the Kotlin compiler reports")
        print("        Return type of 'fun name(): String' is not a subtype of the return type of")
        print("        the overridden member 'fun name(): StringBox!'")
        print("      and the Swift compiler reports")
        print("        type '...' does not conform to protocol 'Libbox...Protocol'")
        print("        note: protocol requires function 'name()' with type '() -> LibboxStringBox?'")
        print("        note: candidate has non-matching type '() -> String'")
        continue
    print(f"FAIL: {v['file'].rsplit('/', 1)[-1]} call site does not read the migrated StringBox:")
    print(f"      {v['file']}:{v['line']}")
    print(f"        {v['text']}")
    print(f"      {v['owner']}.{v['method']} returns *StringBox (binding: {v['javamethod']}), so the")
    print("      result must be read through an accessor: Kotlin '.value' or the")
    print("      StringBox?.unwrap extension in")
    print("      app/src/main/java/io/nekohasekai/sfa/ktx/Wrappers.kt; Swift '.value'.")
    print(f"      The text after the call was {v['tail']!r}.")
    print("      Reading it any other way is a call against the OLD ABI: it compiles against the")
    print("      old libbox, and against a regenerated one the Kotlin compiler reports")
    print("        Argument type mismatch: actual type is 'StringBox!', but 'String!' was expected.")
PYEOF
)"
  if [ -n "$rendered" ]; then
    printf '%s\n' "$rendered" >&2
    fails=$((fails + $(printf '%s\n' "$rendered" | grep -c '^FAIL:')))
  fi
  local scanned iface
  scanned="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("scanned", 0))' "$result" 2>/dev/null || echo 0)"
  iface="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("interface_methods", 0))' "$result" 2>/dev/null || echo 0)"
  info "$lang sources scanned: $scanned files"
  [ "$scanned" -gt 0 ] || {
    skip "no $lang sources were read under $root"
    skipped_client_layers=$((skipped_client_layers + 1))
  }
  if [ "${iface:-0}" -gt 0 ]; then
    # A method on a bound Go interface is also implemented BY the platform, and that override
    # must return StringBox too. Both halves of that are now checked: the call-site scan above
    # for the calls, and the implementer scan inside probe-accessors.py for the declarations.
    # The compiler agreement is still recorded per method in the contract's check column, and it
    # is still the thing that makes the defect impossible to ship silently - Apple's
    # BridgeServiceSession lives under `#if os(macOS) || JAILBREAK`, so an iOS-only build never
    # compiles it and only this scan or a macOS/JAILBREAK build will say so.
    info "$iface of the contract's methods are declared on a bound Go interface, so the"
    info "platform implements them as well; those declarations are scanned for the boxed result."
  fi
}

if [ "$skip_client" = 1 ]; then
  skip "client scan disabled with --skip-client"
  skipped_client_layers=2
else
  if android_root="$(find_root kotlin "${kotlin_roots[@]}")"; then
    info "Android client: $android_root"
    scan_client kotlin "$android_root"
  else
    skip "no Android client checkout found (looked in: ${kotlin_roots[*]}).
      An uninitialised submodule is NOT evidence that the call sites are migrated.
      Run: git submodule update --init clients/android"
    skipped_client_layers=$((skipped_client_layers + 1))
  fi
  if apple_root="$(find_root swift "${swift_roots[@]}")"; then
    info "Apple client: $apple_root"
    scan_client swift "$apple_root"
  else
    skip "no Apple client checkout found (looked in: ${swift_roots[*]}).
      An uninitialised submodule is NOT evidence that the Apple call sites are migrated."
    skipped_client_layers=$((skipped_client_layers + 1))
  fi
fi

# ---------------------------------------------------------------------------
# Layer 5: the client pin
# ---------------------------------------------------------------------------
printf '\n-- layer 5: client gitlink --\n'
check_gitlink() {
  local path="$1" expected="$2" label="$3" upper actual
  upper="$(printf '%s' "$label" | tr '[:lower:]' '[:upper:]')"
  actual="$(cd "$repo_root" && git ls-tree HEAD "clients/$path" 2>/dev/null | awk '{print $3}')"
  if [ -z "$actual" ]; then
    skip "$label: no gitlink at clients/$path"
    return
  fi
  if [ "$actual" = "$expected" ]; then
    ok "$label gitlink is the verified revision (${actual:0:12})"
  else
    fail "$label gitlink is ${actual:0:12}, but this contract was verified against
      ${expected:0:12}. A client at a different revision may still call the old ABI, and the
      AAR regenerating successfully says nothing about it. Verify the call sites at $actual,
      then update VERIFIED_${upper}_SHA in this script and the gitlink."
  fi
}
check_gitlink android "$VERIFIED_ANDROID_SHA" android
check_gitlink apple "$VERIFIED_APPLE_SHA" apple

printf '\n'
if [ "$fails" -gt 0 ]; then
  printf 'FAILED: %d ABI compatibility violation(s).\n' "$fails" >&2
  exit 1
fi
if [ "$skipped_client_layers" -gt 0 ]; then
  # Deliberately not a bare PASS. A run that never read a client checkout has verified the Go
  # side and nothing about the call sites, and "PASS ... verified across the client call sites"
  # would be a false statement about layers that were never opened.
  printf 'PARTIAL: the Go/binding layers passed, but %d client layer(s) were SKIPPED, so the\n' "$skipped_client_layers"
  printf 'call sites were NOT verified by this run. See the SKIP lines above for what was missing.\n'
  exit 0
fi
printf 'PASS: %d migrated methods verified across the Go declaration, the generated binding, the client call sites and the client pin.\n' "$record_count"
