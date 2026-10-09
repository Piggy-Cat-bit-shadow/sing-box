package modlayout

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The module-layout gate. See layout.go for the defect it exists for and the rule it enforces.
//
// It lives under cmd/internal so that `go test -count=1 ./cmd/internal/...` in verify.yml runs it
// on every change, in the same job as the other cmd/internal policy tests.

// TestPackageEnumerationContainsOnlySourceRoots is the gate.
//
// It asserts the SHAPE of `go list ./...`:
//
//   - no enumerated package may live under a generated output root (the deny rule), and
//   - every other enumerated package must live under a checked-in source root (the allow rule).
//
// It does not assert a package count. A count changes whenever anything legitimate is added, so a
// count-based gate is one that gets edited rather than read; and when the generated tree landed
// under build/ the count was the symptom, not the disease.
func TestPackageEnumerationContainsOnlySourceRoots(t *testing.T) {
	root := repoRoot(t)

	packages, err := Enumerate(root)
	if err != nil {
		t.Fatalf("could not enumerate the module's packages: %v", err)
	}
	if len(packages) == 0 {
		t.Fatal("`go list ./...` enumerated no packages at all, so every assertion below would " +
			"pass vacuously")
	}

	var denied []string
	var unexpected []string
	allowed := 0

	for _, pkg := range packages {
		if pkg.Dir == "" {
			// `go list -e` reports a package it could not locate with no directory. That is a
			// broken tree rather than a generated one, and it must not be silently allowed.
			unexpected = append(unexpected, fmt.Sprintf(
				"%s (no directory reported: the package could not be located at all)", pkg.ImportPath))
			continue
		}
		if generated, ok := GeneratedRootOf(pkg.Dir); ok {
			denied = append(denied, fmt.Sprintf("%s\t(%s/, a generated output root)", pkg.ImportPath, generated))
			continue
		}
		if _, ok := SourceRootOf(pkg.Dir); ok {
			allowed++
			continue
		}
		unexpected = append(unexpected, fmt.Sprintf("%s\t(%s/)", pkg.ImportPath, topLevelOf(pkg.Dir)))
	}

	if len(denied) > 0 {
		sort.Strings(denied)
		t.Errorf("generated output is being enumerated as Go source:\n\n  %s\n\n"+
			"These directories are produced by tooling and are not source. The usual cause is a "+
			"libbox build: `gomobile bind` writes its generated Go into the CURRENT WORKING "+
			"DIRECTORY -\n"+
			"    github.com/sagernet/gomobile cmd/gomobile/bind_iosapp.go:106   ./build/<platform>-<arch>/Libbox\n"+
			"    github.com/sagernet/gomobile cmd/gomobile/bind_androidapp.go:373   ./build/<arch>/lib<libname>\n"+
			"- and it has no flag or environment variable that moves either path.\n\n"+
			"Do NOT delete the directory and re-run: the next build recreates it, so the count is "+
			"right and the cause is still there. Either remove cmd/internal/build_libbox's generated "+
			"tree from the module (it runs gomobile with an isolated working directory for exactly "+
			"this reason) or move the directory out of the module and rebuild.\n\n"+
			"Enumerated packages in total: %d", strings.Join(denied, "\n  "), len(packages))
	}

	if len(unexpected) > 0 {
		sort.Strings(unexpected)
		roots := append([]string(nil), SourceRoots...)
		sort.Strings(roots)
		t.Errorf("the package enumeration contains packages outside every checked-in source "+
			"root:\n\n  %s\n\n"+
			"Known source roots:\n  %s\n\n"+
			"If this is generated output, it must not be part of the module at all: move the build "+
			"into a directory the go tool ignores (a leading '.' or '_') or out of the module, and "+
			"add that directory to GeneratedRoots in layout.go so the deny rule names it.\n"+
			"If this is a legitimate new source root, add it to SourceRoots in layout.go - that "+
			"edit is the review checkpoint, not an inconvenience.\n\n"+
			"Enumerated packages in total: %d (deliberately not asserted; see the test comment)",
			strings.Join(unexpected, "\n  "), strings.Join(roots, ", "), len(packages))
	}

	if len(denied) == 0 && len(unexpected) == 0 {
		t.Logf("%d packages enumerated, all of them under a checked-in source root and none under "+
			"a generated output root", len(packages))
		t.Logf("source roots: %s", strings.Join(SourceRoots, ", "))
	}
	if allowed == 0 {
		t.Fatal("no enumerated package was accepted by a source root, so the allow rule matched " +
			"nothing and this test proves nothing")
	}

	reportLeftoverGeneratedRoots(t, root)
}

// TestGeneratedRootsCoverTheRealGomobileOutputPaths pins the deny rule against the strings the
// toolchain actually builds.
//
// A rule that fails to match the real path is worse than no rule, because it reads like coverage.
// These are the two `filepath.Join(".", "build", ...)` expressions from the pinned gomobile,
// transcribed with representative target and architecture values, plus the redirect target
// cmd/internal/build_libbox now uses.
func TestGeneratedRootsCoverTheRealGomobileOutputPaths(t *testing.T) {
	for _, testCase := range []struct {
		dir       string
		generated string
		why       string
	}{
		{"build/ios-arm64/Libbox", "build", "gomobile bind_iosapp.go:106, -target ios"},
		{"build/iossimulator-arm64/Libbox", "build", "gomobile bind_iosapp.go:106, simulator slice"},
		{"build/macos-amd64/Libbox", "build", "gomobile bind_iosapp.go:106, macos slice"},
		{"build/arm64/libbox", "build", "gomobile bind_androidapp.go:373, -libname=box"},
		{"build/amd64/libbox", "build", "gomobile bind_androidapp.go:373, 386/amd64 slice"},
		{"_libbox_build/build/ios-arm64/Libbox", "_libbox_build",
			"the isolated working directory cmd/internal/build_libbox runs gomobile in"},
		{"dist/sing-box", "dist", "release artifacts"},
		{"bin/tools", "bin", "Makefile output"},
	} {
		generated, ok := GeneratedRootOf(testCase.dir)
		if !ok {
			t.Errorf("%s is not denied as generated output (%s); the deny rule does not cover a "+
				"path the toolchain really produces, so the gate would pass while the tree was "+
				"polluted", testCase.dir, testCase.why)
			continue
		}
		if generated != testCase.generated {
			t.Errorf("%s was attributed to the generated root %q, expected %q",
				testCase.dir, generated, testCase.generated)
		}
	}

	// The deny rule must be about whole path elements. A near-miss name must NOT be denied, or the
	// next person adds a real source directory called buildbox and the gate fights them.
	for _, sourceDirectory := range []string{
		"common/buildbox",
		"common/urltest",
		"internal/distribution",
		"experimental/libbox",
	} {
		if generated, ok := GeneratedRootOf(sourceDirectory); ok {
			t.Errorf("%s was denied as generated output under %q; the deny rule matches a path "+
				"prefix instead of whole path elements", sourceDirectory, generated)
		}
	}
}

// TestSourceRootsExist keeps the allow rule honest: a root that has been renamed away would
// otherwise allow nothing while still reading as a rule.
func TestSourceRootsExist(t *testing.T) {
	root := repoRoot(t)
	for _, source := range SourceRoots {
		info, err := os.Stat(filepath.Join(root, filepath.FromSlash(source)))
		if err != nil {
			t.Errorf("source root %q does not exist under the module root: %v", source, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("source root %q is not a directory", source)
		}
	}
}

// reportLeftoverGeneratedRoots names any generated root that is present in the working tree, so a
// build that left one behind is visible in the test output even when it holds no Go files and
// therefore cannot be enumerated.
func reportLeftoverGeneratedRoots(t *testing.T, root string) {
	t.Helper()
	var present []string
	for _, generated := range GeneratedRoots {
		if info, err := os.Stat(filepath.Join(root, filepath.FromSlash(generated))); err == nil && info.IsDir() {
			present = append(present, generated)
		}
	}
	if len(present) > 0 {
		t.Logf("note: generated output directories present in the working tree: %s "+
			"(harmless while they hold no Go packages; reported so a build that left one behind "+
			"is not invisible)", strings.Join(present, ", "))
	}
}

func topLevelOf(dir string) string {
	if index := strings.IndexByte(dir, '/'); index >= 0 {
		return dir[:index]
	}
	return dir
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find the module root above the test directory")
		}
		dir = parent
	}
}
