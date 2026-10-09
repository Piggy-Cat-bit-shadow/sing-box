package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/cmd/internal/modlayout"
)

// The gomobile working-directory contract.
//
// # What is being protected
//
// `gomobile bind` writes generated Go into its current working directory:
//
//	github.com/sagernet/gomobile cmd/gomobile/bind_iosapp.go:106
//	    filepath.Abs(filepath.Join(".", "build", platform+"-"+arch, "Libbox"))
//	github.com/sagernet/gomobile cmd/gomobile/bind_androidapp.go:373
//	    filepath.Abs(filepath.Join(".", "build", arch, "lib"+libName))
//
// There is no flag and no environment variable that moves either path, so the ONLY lever this
// builder has is the working directory of the subprocess. Running gomobile from the module root
// put a generated package tree under <module root>/build, and `go test ./...` then enumerated it.
//
// These tests hold the three properties that make the redirect real:
//
//  1. the subprocess does not run in the module root,
//  2. the directory it does run in cannot be enumerated by the go tool, and
//  3. everything it produces is named by absolute path, so nothing depends on that directory.

// TestGomobileRunsOutsideTheModuleRoot is property 1.
func TestGomobileRunsOutsideTheModuleRoot(t *testing.T) {
	root := repoRoot(t)

	savedRoot := rootDir
	rootDir = root
	defer func() { rootDir = savedRoot }()

	workDir := gomobileWorkDir(root)
	if filepath.Clean(workDir) == filepath.Clean(root) {
		t.Fatalf("gomobile would run in the module root (%s), which is what put the generated "+
			"Go tree under build/ and into `go test ./...` in the first place", root)
	}
	if !strings.HasPrefix(workDir, root+string(filepath.Separator)) {
		t.Fatalf("the gomobile working directory %s is not inside the module root %s; it must be "+
			"inside the module so `go env GOMOD` still resolves and the bound package still loads",
			workDir, root)
	}

	command, err := newGomobileCommand(root, "bind")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(command.Dir) != filepath.Clean(workDir) {
		t.Fatalf("the gomobile subprocess would run in %s, expected %s", command.Dir, workDir)
	}
	// The directory is created on demand, so it must exist by the time the command is returned.
	if info, statErr := os.Stat(workDir); statErr != nil || !info.IsDir() {
		t.Fatalf("the gomobile working directory was not created: %v", statErr)
	}
	// Leave the tree as it was found: the directory is recreated on demand, and removing it only
	// when it is empty cannot discard a real artifact.
	t.Cleanup(func() {
		entries, readErr := os.ReadDir(workDir)
		if readErr == nil && len(entries) == 0 {
			_ = os.Remove(workDir)
		}
	})
}

// TestGomobileWorkingDirectoryIsNotEnumerable is property 2, asserted against the SAME rule the
// module-layout gate uses rather than against a second copy of it.
//
// A leading "." or "_" is what makes the go tool skip a directory when matching "./...". Asking
// modlayout is stronger than checking the prefix here: it is the rule that fails the build.
func TestGomobileWorkingDirectoryIsNotEnumerable(t *testing.T) {
	root := repoRoot(t)
	relative, err := filepath.Rel(root, gomobileWorkDir(root))
	if err != nil {
		t.Fatal(err)
	}

	if first := strings.TrimPrefix(filepath.ToSlash(relative), "./")[0]; first != '.' && first != '_' {
		t.Errorf("the gomobile working directory %q does not begin with '.' or '_', so the go tool "+
			"would match it with \"./...\" and enumerate the generated Go inside it", relative)
	}

	generated, denied := modlayout.GeneratedRootOf(relative)
	if !denied {
		t.Errorf("the gomobile working directory %q is not listed in modlayout.GeneratedRoots; the "+
			"directory the generated Go lands in must be named by the deny rule, so that a future "+
			"change to this builder cannot re-open the hole silently", relative)
	} else if generated != relative {
		t.Errorf("the gomobile working directory %q is denied only as part of %q; list it by name",
			relative, generated)
	}
}

// TestAndroidBindArgumentsAreAbsolute is property 3 for the Android builder.
func TestAndroidBindArgumentsAreAbsolute(t *testing.T) {
	root := repoRoot(t)

	savedRoot := rootDir
	rootDir = root
	defer func() { rootDir = savedRoot }()

	outputPath := filepath.Join(gomobileWorkDir(root), "libbox.aar")
	args := androidBindArguments(AndroidBuildConfig{
		AndroidAPI: 24,
		OutputName: "libbox.aar",
		Tags:       ResolveBuildTags("android-main"),
	}, "android", outputPath)

	requireAbsoluteFlagValue(t, args, "-o", "the Android artifact")
	requireAbsoluteLastArgument(t, args, "the bound package")
}

// TestAppleBindArgumentsAreAbsolute is property 3 for the Apple builder.
func TestAppleBindArgumentsAreAbsolute(t *testing.T) {
	root := repoRoot(t)

	savedRoot := rootDir
	rootDir = root
	defer func() { rootDir = savedRoot }()

	frameworkPath := filepath.Join(gomobileWorkDir(root), "Libbox.xcframework")
	args := appleBindArguments("ios", frameworkPath)

	// gomobile's default output name is relative to its working directory, so an explicit -o is
	// what keeps the framework where this builder looks for it.
	output := requireAbsoluteFlagValue(t, args, "-o", "the Apple framework")
	if filepath.Base(output) != "Libbox.xcframework" {
		t.Errorf("-o names %s, expected the framework to be Libbox.xcframework", output)
	}
	requireAbsoluteLastArgument(t, args, "the bound package")
}

func requireAbsoluteFlagValue(t *testing.T, args []string, flag, what string) string {
	t.Helper()
	for index, arg := range args {
		if arg != flag {
			continue
		}
		if index+1 >= len(args) {
			t.Fatalf("%s is the last argument, so %s has no value", flag, what)
		}
		value := args[index+1]
		if !filepath.IsAbs(value) {
			t.Fatalf("%s is %q; gomobile runs in the isolated working directory, so a relative "+
				"path here would not name %s", flag, value, what)
		}
		return value
	}
	t.Fatalf("no %s argument is passed; %s would land wherever gomobile's default puts it", flag, what)
	return ""
}

func requireAbsoluteLastArgument(t *testing.T, args []string, what string) {
	t.Helper()
	if len(args) == 0 {
		t.Fatalf("no arguments at all, so %s is never passed", what)
	}
	last := args[len(args)-1]
	if !filepath.IsAbs(last) {
		t.Fatalf("the last argument (which names %s) is %q; it must be an absolute path so it "+
			"resolves from the isolated working directory", what, last)
	}
}

// repoRoot is declared in tag_policy_test.go; the tests here use the same one rather than a second
// definition of "the module root".
