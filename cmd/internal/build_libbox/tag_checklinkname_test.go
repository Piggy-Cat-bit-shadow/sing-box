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

// linknameDirectiveRE matches both spellings of the directive:
//
//	//go:linkname local                 <- push: this package makes `local` pullable by name
//	//go:linkname local pkg.Symbol      <- pull: legal only if the definition of pkg.Symbol is itself
//	                                      pushed with a linkname
//
// The target is captured as (package path, symbol) because the check is per-DEFINITION.
//
// # Why this is not `runtime.<Symbol>` only
//
// The earlier revision matched the literal package name `runtime` and explained the exclusion like
// this: "runtime/pprof and runtime/debug are separate packages whose symbols are pushed from their
// own source trees, and they are legal pulls for a different reason; matching them here would make
// this check test the wrong rule."
//
// That reasoning was wrong, and it is why this gate passed while the untagged build did not. A pull
// of `runtime/pprof.X` does NOT mean package runtime/pprof defines X. cmd/link allows a pull when
// the DEFINITION carries a push linkname (cmd/link/internal/loader/loader.go, "Allow if the def has
// a linkname"), and for most of these names the definition lives in package runtime:
//
//	runtime/symtab.go    //go:linkname runtime_FrameStartLine runtime/pprof.runtime_FrameStartLine
//	runtime/symtab.go    //go:linkname runtime_FrameSymbolName runtime/pprof.runtime_FrameSymbolName
//	runtime/symtab.go    //go:linkname runtime_expandFinalInlineFrame runtime/pprof.runtime_expandFinalInlineFrame
//	runtime/cpuprof.go   //go:linkname pprof_cyclesPerSecond runtime/pprof.runtime_cyclesPerSecond
//	runtime/sys_darwin.go //go:linkname mach_vm_region runtime/pprof.mach_vm_region
//
// Those are legal pulls and need no flag. The two that genuinely need it are the ones DEFINED in
// runtime/pprof, which pushes nothing at all: parseProcSelfMaps (runtime/pprof/proto.go) and
// elfBuildID (runtime/pprof/elf.go). Measured on the pinned toolchain, a reference to
// parseProcSelfMaps is rejected on every GOOS without -checklinkname=0:
//
//	link: ...: invalid reference to runtime/pprof.parseProcSelfMaps
var linknameDirectiveRE = regexp.MustCompile(`(?m)^//go:linkname\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s+(\S+))?\s*$`)

// stdlibPushSource is one standard library package that pushes symbols: the directory holding its
// source and the import path its linkname targets are spelled with.
type stdlibPushSource struct {
	importPath string
	dir        string
}

// buildConstraintRE captures the //go:build line of a file, if it has one.
var buildConstraintRE = regexp.MustCompile(`(?m)^//go:build\s+(.+)$`)

// stdlibSourceDir returns a standard library package's source directory, FAILING rather than
// skipping when it cannot be found: a silent skip would turn this gate into a check that verifies
// nothing while reporting success, which is the exact failure mode the tag-policy tests next door
// were written against.
func stdlibSourceDir(t *testing.T, elem ...string) string {
	t.Helper()
	goroot := runtime.GOROOT()
	if goroot == "" {
		t.Fatal("runtime.GOROOT() is empty; cannot locate the standard library source, so this gate cannot be evaluated")
	}
	dir := filepath.Join(append([]string{goroot, "src"}, elem...)...)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read standard library source %s: %v", dir, err)
	}
	found := false
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".go") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no Go files under %s; the standard library source layout changed and this gate must be re-derived", dir)
	}
	return dir
}

// runtimeSourceDir returns the source directory of the runtime package.
func runtimeSourceDir(t *testing.T) string {
	t.Helper()
	return stdlibSourceDir(t, "runtime")
}

// pprofSourceDir returns the source directory of runtime/pprof, the one standard library subpackage
// this repository pulls symbols from. Its pushes are collected separately from the runtime's because
// a package pushes only into itself.
func pprofSourceDir(t *testing.T) string {
	t.Helper()
	return stdlibSourceDir(t, "runtime", "pprof")
}

// pushedSymbols reads the linkname directives out of one standard library package's source and
// returns the set of linkname TARGETS that package makes resolvable.
//
// The set is not just the push's local name, because a push can also re-export a name that is
// DECLARED ELSEWHERE IN THE SAME PACKAGE, and Go packages are compiled as a whole:
//
//	//go:linkname pprof_cyclesPerSecond runtime/pprof.runtime_cyclesPerSecond   <- local name pushed
//	//go:linkname mach_vm_region runtime/pprof.mach_vm_region                   <- declared in assembly
//	//go:linkname runtime_FrameStartLine runtime/pprof.runtime_FrameStartLine   <- declared in another
//	                                                                             file of the package
//
// All of these make `runtime/pprof.X` a legal pull, and NONE of them is recognisable from the pull's
// own text - which is why the file-text-only rule this gate used to apply answered the wrong
// question. A re-exported target counts only when the package really declares the local name, so a
// target is never treated as legal merely because a file mentions it.
//
// Subdirectories are NOT descended into: a package's pushes belong to that package, so
// runtime/pprof's must be collected by its own call rather than as part of the runtime's.
func pushedSymbols(t *testing.T, source stdlibPushSource, minimum int) map[string]bool {
	t.Helper()

	type directive struct {
		local  string
		target string
	}
	var found []directive
	// Declarations are collected PACKAGE-wide, not per file: a push and the declaration it
	// re-exports routinely live in different files.
	declared := make(map[string]bool)

	recordDeclarations := func(raw string) {
		for _, re := range declarationREs {
			for _, match := range re.FindAllStringSubmatch(raw, -1) {
				declared[match[1]] = true
			}
		}
	}

	err := filepath.WalkDir(source.dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != source.dir {
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
		raw := string(content)
		recordDeclarations(raw)
		for _, match := range linknameDirectiveRE.FindAllStringSubmatch(raw, -1) {
			found = append(found, directive{local: match[1], target: match[2]})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan %s source: %v", source.importPath, err)
	}

	pushed := make(map[string]bool)
	reExports := 0
	for _, d := range found {
		if d.target == "" {
			// Push form: the local name is the symbol other packages may pull.
			pushed[d.local] = true
			continue
		}
		if !declared[lastIdent(d.local)] {
			// The push names a target but the package does not declare the local name, so it is
			// not a definition this package can supply.
			continue
		}
		dot := strings.LastIndex(d.target, ".")
		if dot < 0 {
			continue
		}
		// The symbol name is what a pull resolves by, and a push that exposes a name into another
		// package's namespace is exactly what makes that name pullable. There is deliberately NO
		// check that the target namespace equals this package's import path: the runtime exposes
		// names INTO runtime/pprof (runtime_FrameStartLine and friends), which it does not own, and
		// that is the form this gate exists to recognise.
		pushed[d.target[dot+1:]] = true
		reExports++
	}
	// A vacuous pass would make every pull look legal, or every pull look illegal. Both are wrong,
	// so an implausible count is itself a failure. The floor is 0 for a package that is legitimately
	// expected to push nothing - runtime/pprof is exactly that case, and asserting a floor there
	// would make this gate fail on a fact rather than on a defect.
	if len(pushed) < minimum {
		t.Fatalf("only %d pushed linkname targets found in %s (%d of them re-exports); the parse is broken",
			len(pushed), source.dir, reExports)
	}
	return pushed
}

// knownTargetPackage reports whether this gate has an opinion about a pull's target package. It
// covers the two packages this repository pulls from and whose sources are scanned above; a pull of
// any other package is outside what this check measures, and saying nothing is better than guessing.
func knownTargetPackage(pkgPath string) bool {
	switch pkgPath {
	case "runtime", "runtime/pprof":
		return true
	default:
		return false
	}
}

// declarationREs match the package-scope declarations that can back a re-export: a function or a
// variable. A name that appears only inside a function body is not a declaration.
var declarationREs = []*regexp.Regexp{
	regexp.MustCompile(`(?m)^func\s+([A-Za-z_][A-Za-z0-9_]*)\s*[\(\[]`),
	regexp.MustCompile(`(?m)^var\s+([A-Za-z_][A-Za-z0-9_]*)[\s=]`),
}

// lastIdent returns the final identifier of a possibly qualified name, which is the name a push
// makes pullable: `//go:linkname a/b.C pkg.D` puts `D` in pkg's namespace.
func lastIdent(name string) string {
	if dot := strings.LastIndex(name, "."); dot >= 0 {
		name = name[dot+1:]
	}
	if slash := strings.LastIndex(name, "/"); slash >= 0 {
		name = name[slash+1:]
	}
	return name
}

// pushedRuntimeSymbols reads the push-form directives out of the runtime source and asserts the
// premise this gate rests on: that the runtime really pushes the symbols the repository relies on,
// and really does not push the two it must gate.
func pushedRuntimeSymbols(t *testing.T, dir string) map[string]bool {
	t.Helper()
	pushed := pushedSymbols(t, stdlibPushSource{importPath: "runtime", dir: dir}, 50)
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
//
// It answers, for every //go:linkname pull in this repository, "is the definition of the target
// pushed with a linkname?". If it is, the pull links under the linker's default policy. If it is
// not, the file must be gated on the tag that records -checklinkname=0.
//
// Both push sources this repository's pulls can reach are collected, `runtime` and `runtime/pprof`,
// because the rule is about the DEFINITION and not about the name's prefix. See
// linknameDirectiveRE for why the earlier `runtime.<Symbol>`-only form of this check was wrong.
func TestRuntimeLinknamePullsAreGatedOnChecklinkname0(t *testing.T) {
	root := repoRoot(t)

	pushedBy := map[string]map[string]bool{
		"runtime":       pushedRuntimeSymbols(t, runtimeSourceDir(t)),
		"runtime/pprof": pushedSymbols(t, stdlibPushSource{importPath: "runtime/pprof", dir: pprofSourceDir(t)}, 0),
	}
	// The two sets are UNIONED rather than consulted per package, because a push declares the
	// namespace it exposes a name INTO, not the package that owns the name. The runtime exposes
	// runtime_FrameStartLine and its neighbours INTO runtime/pprof, so requiring the target's
	// namespace to match the scanning package would reject exactly the legal pulls this gate has to
	// accept. What matters to the linker is only whether SOME definition carries the push.
	pushed := make(map[string]bool)
	for _, set := range pushedBy {
		for symbol := range set {
			pushed[symbol] = true
		}
	}
	// runtime/pprof pushing none of these is a FACT this gate depends on, so it is asserted rather
	// than assumed: if a future toolchain starts pushing them, the gate must be re-derived instead of
	// continuing to demand a flag nobody needs.
	for _, symbol := range []string{"parseProcSelfMaps", "elfBuildID"} {
		if pushedBy["runtime/pprof"][symbol] {
			t.Fatalf("the pinned runtime/pprof now pushes %q, so the premise of this gate changed; "+
				"re-derive it and revisit whether %s is still needed", symbol, checklinknameTag)
		}
	}

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
		constraint := ""
		if constraintMatch := buildConstraintRE.FindStringSubmatch(string(content)); constraintMatch != nil {
			constraint = constraintMatch[1]
		}
		gated := strings.Contains(constraint, checklinknameTag)
		for _, match := range linknameDirectiveRE.FindAllStringSubmatch(string(content), -1) {
			target := match[2]
			if target == "" {
				// Push form; it targets nothing.
				continue
			}
			dot := strings.LastIndex(target, ".")
			if dot < 0 {
				continue
			}
			pkgPath, symbol := target[:dot], target[dot+1:]
			if !knownTargetPackage(pkgPath) {
				continue
			}
			if pushed[symbol] {
				// Legal without the flag: some definition carries a push linkname for this name.
				continue
			}
			blockedPulls++
			if gated {
				continue
			}
			relative, relErr := filepath.Rel(root, path)
			if relErr != nil {
				relative = path
			}
			t.Errorf("%s pulls %s, whose definition is not pushed by a linkname, and the file is not gated on %s.\n"+
				"    build constraint: %q\n"+
				"    A build that does not pass -checklinkname=0 cannot link this reference:\n"+
				"      link: ...: invalid reference to %s\n"+
				"    Gate the file on `%s` (the tag that records the flag) - or, when only SOME of the "+
				"package's pulls need it, move those declarations into a gated file of their own, the way "+
				"experimental/libbox/internal/oomprofile splits linkname_private.go from linkname.go.",
				relative, target, checklinknameTag, constraint, target, checklinknameTag)
		}
	}

	// The count is asserted so that a change to the toolchain or to the parse cannot turn this
	// test into a no-op that still passes. Three files carry blocked pulls today:
	// experimental/libbox/signal_handler_darwin.go,
	// experimental/libbox/internal/runtimeinfo/goroutine_badlinkname.go, and
	// experimental/libbox/internal/oomprofile/linkname.go (gated by its sibling mapping_linux.go).
	if blockedPulls == 0 {
		t.Fatal("no blocked linkname pulls were found at all; either the pulls were removed (then delete " +
			"this test deliberately) or the scan stopped working")
	}
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
