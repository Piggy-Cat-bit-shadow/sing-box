package main

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/cmd/internal/applebuildtags"
)

// This file guards the -checklinkname contract.
//
// # The failure it exists to prevent
//
// Some of this fork's code reaches into the Go runtime by symbol name with //go:linkname,
// for symbols that have no linkname "push" in the runtime. The Go linker rejects a pull of a
// symbol that has no push unless the build passes -checklinkname=0:
//
//	link: github.com/sagernet/sing-box/experimental/libbox: invalid reference to runtime.fwdSig
//
// The `tfogo_checklinkname0` tag is this repository's record that -checklinkname=0 IS passed
// (docs/installation/build-from-source.md: "Indicates the build uses the -checklinkname=0
// linker flag. Required together with badlinkname").
//
// # Why the check is computed from the toolchain, not from a list
//
// The set of symbols the linker will accept is not a property of this repository: it is
// whatever the *pinned runtime* declares with a push-form directive:
//
//	//go:linkname fwdSig            <- push:  pulls of runtime.fwdSig become legal
//	//go:linkname fwdSig runtime.fwdSig   <- pull: requires a push somewhere
//
// So the test reads the runtime source of the toolchain it is compiled with, builds the pushed
// set from it, and then requires every FIRST-PARTY pull of a runtime symbol to sit behind
// tfogo_checklinkname0 unless the pull is legal. A new //go:linkname added to any file in this
// repository is judged by the real rule instead of by a list that would have to be maintained.
//
// The second half of the guard is the profile tag files. `go build ./...` and `go test ./...`
// are run against `release/DEFAULT_BUILD_TAGS*` in the workflows, and neither cmd/go invocation
// can inject -checklinkname=0 per package, so a profile that names tfogo_checklinkname0 hands
// those commands a link they cannot complete. The profile files therefore must NOT name it, and
// every shipped mobile variant MUST, because the mobile builders do pass the flag
// (cmd/internal/build_shared.LinkerFlags) and dropping the tag there would silently downgrade
// the shipped crash handler and goroutine report to their stubs.

// checklinknameTag records that the build passes -checklinkname=0.
const checklinknameTag = "tfogo_checklinkname0"

// runtimePackage symbol spelling: `//go:linkname <local> runtime.<Symbol>`.
//
// The target import path is `runtime` EXACTLY. `runtime/pprof` and `runtime/debug` are separate
// packages whose symbols are pushed from their own source trees, and they are legal pulls for a
// different reason; matching them here would make this check test the wrong rule.
var runtimePullRE = regexp.MustCompile(`(?m)^//go:linkname\s+\S+\s+runtime\.([A-Za-z_][A-Za-z0-9_]*)\s*$`)

// push-form directive: `//go:linkname <local>` with no target.
var runtimePushRE = regexp.MustCompile(`(?m)^//go:linkname\s+([A-Za-z_][A-Za-z0-9_]*)\s*$`)

// buildConstraintRE captures the //go:build line of a file, if it has one.
var buildConstraintRE = regexp.MustCompile(`(?m)^//go:build\s+(.+)$`)

// runtimeSourceDir returns the source directory of the runtime package of the toolchain this
// test binary was compiled with.
//
// It FAILS rather than skipping when the directory cannot be found: a silent skip would turn
// this gate into a check that verifies nothing while reporting success, which is the exact
// failure mode the tag-policy tests next door were written against.
func runtimeSourceDir(t *testing.T) string {
	t.Helper()
	goroot := runtime.GOROOT()
	if goroot == "" {
		t.Fatal("runtime.GOROOT() is empty; cannot locate the runtime source, so this gate cannot be evaluated")
	}
	dir := filepath.Join(goroot, "src", "runtime")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read runtime source %s: %v", dir, err)
	}
	found := false
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".go") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no Go files under %s; the runtime source layout changed and this gate must be re-derived", dir)
	}
	return dir
}

// pushedRuntimeSymbols reads the push-form directives out of the runtime source.
func pushedRuntimeSymbols(t *testing.T, dir string) map[string]bool {
	t.Helper()
	pushed := make(map[string]bool)
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// The runtime package is the top directory. Subdirectories (runtime/pprof,
			// runtime/internal/...) push into their OWN packages, not into runtime.
			if path != dir {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, match := range runtimePushRE.FindAllStringSubmatch(string(content), -1) {
			pushed[match[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan runtime source: %v", err)
	}
	// A vacuous pass would make every pull look legal, or every pull look illegal. Both are
	// wrong, so an implausible count is itself a failure. The pinned toolchain pushes a few
	// hundred symbols.
	if len(pushed) < 50 {
		t.Fatalf("only %d push-form //go:linkname directives found in %s; the parse is broken", len(pushed), dir)
	}
	// The two symbols this repository actually depends on must be ABSENT from the pushed set,
	// or this test is no longer measuring what it claims to. They are the pulls that produced
	// the production link failure.
	for _, blocked := range []string{"fwdSig", "allgs"} {
		if pushed[blocked] {
			t.Fatalf("the pinned runtime now pushes %q, so the premise of this gate changed; "+
				"re-derive it and revisit whether %s is still needed", blocked, checklinknameTag)
		}
	}
	return pushed
}

// firstPartyGoFiles lists the Go files of this repository, excluding the VCS directory and any
// vendored tree.
func firstPartyGoFiles(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "vendor" || name == "node_modules" {
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repository: %v", err)
	}
	sort.Strings(files)
	return files
}

// TestRuntimeLinknamePullsAreGatedOnChecklinkname0 is the computed half of the guard.
func TestRuntimeLinknamePullsAreGatedOnChecklinkname0(t *testing.T) {
	root := repoRoot(t)
	pushed := pushedRuntimeSymbols(t, runtimeSourceDir(t))

	files := firstPartyGoFiles(t, root)
	if len(files) < 100 {
		t.Fatalf("only %d Go files found under %s; the walk is broken", len(files), root)
	}

	blockedPulls := 0
	for _, path := range files {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		matches := runtimePullRE.FindAllStringSubmatch(string(content), -1)
		if len(matches) == 0 {
			continue
		}
		constraint := ""
		if constraintMatch := buildConstraintRE.FindStringSubmatch(string(content)); constraintMatch != nil {
			constraint = constraintMatch[1]
		}
		gated := strings.Contains(constraint, checklinknameTag)
		for _, match := range matches {
			symbol := match[1]
			if pushed[symbol] {
				// Legal without the flag: the runtime pushes it.
				continue
			}
			blockedPulls++
			if !gated {
				relative, relErr := filepath.Rel(root, path)
				if relErr != nil {
					relative = path
				}
				t.Errorf("%s pulls runtime.%s, which the pinned runtime does not push, and the file is not gated on %s.\n"+
					"    build constraint: %q\n"+
					"    A build that does not pass -checklinkname=0 cannot link this reference:\n"+
					"      link: ...: invalid reference to runtime.%s\n"+
					"    Gate the file on `%s` (the tag that records the flag) or stop pulling the symbol.",
					relative, symbol, checklinknameTag, constraint, symbol, checklinknameTag)
			}
		}
	}

	// The count is asserted so that a change to the toolchain or to the parse cannot turn this
	// test into a no-op that still passes. Two files carry blocked pulls today:
	// experimental/libbox/signal_handler_darwin.go and
	// experimental/libbox/internal/runtimeinfo/goroutine_badlinkname.go.
	if blockedPulls == 0 {
		t.Fatal("no blocked runtime pulls were found at all; either the pulls were removed (then delete " +
			"this test deliberately) or the scan stopped working")
	}
}

// TestOOMProfileStubIsNotGatedOnTheChecklinknameTag is the REVERSE direction of the split in
// experimental/libbox/internal/oomprofile.
//
// That package reads the runtime's profile buffers through //go:linkname pulls of runtime/pprof,
// which pushes nothing, so the real implementation links only where the builder passes
// -checklinkname=0. It is therefore split: the real files carry tfogo_checklinkname0, and
// oomprofile_stub.go carries its NEGATION and exists so a bare `go build ./...` still links.
//
// The failure this guards against is the tempting edit: "the stub is only for the bare build, and the
// bare build is the one that must link, so tag the stub too". Tagging it would compile it ALONGSIDE
// the real writer in every product build, which is a redeclaration of WriteFile and profileSupport,
// and would break every shipping build rather than the bare one. The stub's whole purpose is to be
// the build that does NOT name the tag.
func TestOOMProfileStubIsNotGatedOnTheChecklinknameTag(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, "experimental", "libbox", "internal", "oomprofile")

	stub := filepath.Join(dir, "oomprofile_stub.go")
	content, err := os.ReadFile(stub)
	if err != nil {
		t.Fatalf("read %s: %v. The link-safe half of the OOM profile package is what keeps a bare "+
			"`go build ./...` working; if it was renamed or removed deliberately, delete this test "+
			"deliberately too", filepath.Join("experimental", "libbox", "internal", "oomprofile",
			"oomprofile_stub.go"), err)
	}
	if hasChecklinknameBuildConstraint(string(content)) {
		t.Errorf("oomprofile_stub.go carries %s in its build constraint.\n"+
			"    It must NOT: it is the file compiled when the tag is ABSENT, and naming the tag would\n"+
			"    compile it alongside the real writer, redeclaring WriteFile and profileSupport in every\n"+
			"    product build. Only the real implementation files may carry %s.",
			checklinknameTag, checklinknameTag)
	}

	// And the other side: at least one file in the package must carry the tag, or the split has
	// collapsed to "the real writer is never compiled" and OOM profiling is silently gone from every
	// shippable build.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	tagged := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if hasChecklinknameBuildConstraint(string(body)) {
			tagged++
		}
	}
	if tagged == 0 {
		t.Errorf("no file in experimental/libbox/internal/oomprofile carries %s in its build "+
			"constraint, so the real OOM profile writer is compiled into NO build at all and the "+
			"capability has been removed rather than gated. Every shipping tag set carries %s because "+
			"its builder passes -checklinkname=0, so this would be a silent capability loss.",
			checklinknameTag, checklinknameTag)
	}
}

// hasChecklinknameBuildConstraint reports whether a file's //go:build line POSITIVELY requires the
// checklinkname tag, i.e. whether the file is compiled only where the flag is passed.
//
// Two things make a naive search wrong, and both were wrong in the first version of this gate:
//
//   - the tag is also NAMED in the prose of both halves of the package - the stub's error message
//     has to tell the reader which tag to add - so the search is anchored on the //go:build line;
//   - the stub's constraint is its NEGATION, `!tfogo_checklinkname0`, so a match preceded by `!` is
//     the opposite of what this asks and must not count.
func hasChecklinknameBuildConstraint(content string) bool {
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "//go:build ") {
			continue
		}
		for i := strings.Index(trimmed, checklinknameTag); i >= 0; {
			negated := i > 0 && trimmed[i-1] == '!'
			if !negated {
				return true
			}
			next := strings.Index(trimmed[i+len(checklinknameTag):], checklinknameTag)
			if next < 0 {
				break
			}
			i += len(checklinknameTag) + next
		}
	}
	return false
}

// TestProfileTagFilesDoNotClaimChecklinkname0 is the other half: the tag must not reach a build
// that cannot pass the flag.
func TestProfileTagFilesDoNotClaimChecklinkname0(t *testing.T) {
	root := repoRoot(t)
	matches, err := filepath.Glob(filepath.Join(root, "release", "DEFAULT_BUILD_TAGS*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatal("no release/DEFAULT_BUILD_TAGS* files found; this test would pass vacuously")
	}
	for _, path := range matches {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(content), checklinknameTag) {
			t.Errorf("release/%s names %s.\n"+
				"    These files are read by callers that link with Go's DEFAULT -checklinkname policy:\n"+
				"      go build -tags \"$(cat release/%s)\" ./...\n"+
				"      go test  -tags \"$(cat release/%s)\" ./...\n"+
				"    cmd/go cannot inject -ldflags=-checklinkname=0 per package, so naming the tag here makes\n"+
				"    experimental/libbox unlinkable in those builds:\n"+
				"      link: github.com/sagernet/sing-box/experimental/libbox: invalid reference to runtime.fwdSig\n"+
				"    The tag belongs only in tag sets whose builder really passes the flag: the mobile set in\n"+
				"    cmd/internal/mobilebuildtags, and cmd/internal/build_boxdd (which appends it itself).",
				filepath.Base(path), checklinknameTag, filepath.Base(path), filepath.Base(path))
		}
	}
}

// TestShippedMobileVariantsKeepChecklinkname0 is the counterweight. Removing the tag everywhere
// would make the link failures disappear by shipping stubs, which is a capability loss, not a fix.
func TestShippedMobileVariantsKeepChecklinkname0(t *testing.T) {
	variants := sortedTagVariants()
	if len(variants) == 0 {
		t.Fatal("no shipped variants; this test would pass vacuously")
	}
	for _, variant := range variants {
		tags := ResolveBuildTags(variant)
		if len(tags) == 0 {
			t.Fatalf("variant %s resolves to no tags at all; the assertion below would be vacuous", variant)
		}
		if !HasBuildTag(variant, checklinknameTag) {
			t.Errorf("variant %s does not carry %s, so its libbox would silently fall back to the stub\n"+
				"    crash-signal handler and the stub goroutine report. The mobile builders pass\n"+
				"    -checklinkname=0 (cmd/internal/build_shared.LinkerFlags), so the tag is true there.",
				variant, checklinknameTag)
		}
	}
	// macOS is built by the same gomobile invocation as the mobile targets, so it carries the
	// tag too. It is asserted separately because `apple` resolves to the common set while the
	// per-platform sets come from applebuildtags.
	for _, platform := range []string{"ios", "macos"} {
		tags := appleTagsForPlatform(t, platform)
		if !containsString(tags, checklinknameTag) {
			t.Errorf("the Apple %s tag set does not carry %s", platform, checklinknameTag)
		}
	}
}

// TestBuildBoxddKeepsChecklinkname0 checks the one profile-file consumer that links libbox into a
// product. The tag cannot live in the profile file (see
// TestProfileTagFilesDoNotClaimChecklinkname0), so the recipe has to add it, and this asserts that
// it does instead of trusting a comment.
func TestBuildBoxddKeepsChecklinkname0(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "cmd", "internal", "build_boxdd", "main.go")
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	appendsTag := false
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.Contains(line, "append(tags,") && strings.Contains(line, `"`+checklinknameTag+`"`) {
			appendsTag = true
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if !appendsTag {
		t.Errorf("cmd/internal/build_boxdd/main.go no longer appends %s to its tag list.\n"+
			"    It links experimental/libbox into the desktop daemon and passes -checklinkname=0, so\n"+
			"    without the tag the daemon silently loses the real crash handler and goroutine report.\n"+
			"    If the daemon is meant to stop linking libbox, remove this expectation deliberately.",
			checklinknameTag)
	}

	// And the flag really is passed, so appending the tag is honest rather than a claim.
	flagsPath := filepath.Join(root, "cmd", "internal", "build_shared", "flags.go")
	flags, err := os.ReadFile(flagsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(flags), "-checklinkname=0") {
		t.Errorf("%s no longer passes -checklinkname=0, so %s does not describe the build it is added to",
			filepath.Join("cmd", "internal", "build_shared", "flags.go"), checklinknameTag)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// appleTagsForPlatform resolves one Apple target's tag set through the same function the Apple
// builder uses (applebuildtags.FullDeploymentTagString), so this is a check on what ships rather
// than on a text file.
func appleTagsForPlatform(t *testing.T, platform string) []string {
	t.Helper()
	known := false
	for _, target := range applebuildtags.ApplePlatforms() {
		if target.Name == platform {
			known = true
			break
		}
	}
	if !known {
		t.Fatalf("platform %q is not a known Apple target", platform)
	}
	resolved := applebuildtags.FullDeploymentTagString(platform)
	if resolved == "" {
		t.Fatalf("the Apple %s tag set resolved empty; the assertion below would be vacuous", platform)
	}
	return strings.Split(resolved, ",")
}
