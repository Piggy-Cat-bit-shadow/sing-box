// Package modlayout owns the module-layout gate: the rule that says which directories of this
// module may contain Go packages, and the enumeration that rule is asserted against.
//
// # The defect this exists for
//
// `gomobile bind` writes the Go source it generates into the CURRENT WORKING DIRECTORY:
//
//	github.com/sagernet/gomobile  cmd/gomobile/bind_iosapp.go:106
//	    filepath.Abs(filepath.Join(".", "build", platform+"-"+arch, "Libbox"))
//	github.com/sagernet/gomobile  cmd/gomobile/bind_androidapp.go:373
//	    filepath.Abs(filepath.Join(".", "build", arch, "lib"+libName))
//
// Neither path has a flag or an environment variable that moves it, and gomobile is run with the
// module root as its working directory, so a libbox build leaves a generated Go tree under
// <module root>/build.
//
// That tree is real Go source in a real directory of this module, so the next `go test ./...`
// enumerated it: the package count moved and the extra "packages" were not source at all.
// Deleting the directory makes the count right again and fixes nothing - the next build puts it
// back. That is why the durable fix is a rule about the SHAPE of the enumeration rather than a
// cleanup step, and why no package count is written down anywhere in this package: a count is a
// number that has to be edited whenever anything legitimate changes, which is how a gate becomes
// something people update instead of something they read.
//
// # The rule
//
//   - GeneratedRoots may NEVER be enumerated. This is the deny rule. It is checked FIRST, so that
//     a generated path added to SourceRoots by mistake cannot quietly re-open the hole.
//   - Every other enumerated package must live under one of SourceRoots. This is the allow rule.
//     It is a snapshot of the module's source ROOTS, not of its packages, so a new package inside
//     an existing root - the ordinary case, and most commits - needs no change here, while a new
//     top-level directory is a deliberate decision recorded in this file.
package modlayout

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// TagsFile is the build-tag profile the full suite is run with. It is read rather than repeated
// so the gate enumerates the same package set the reported failure was observed on.
const TagsFile = "release/DEFAULT_BUILD_TAGS"

// SourceRoots are the module-relative directories that may contain Go packages.
//
// "." is the module root itself, which is a package (box.go and its neighbours).
//
// A new package under one of these needs no change here. A new top-level directory that holds
// packages does, and that edit is the point: it is where a reviewer sees that the tree gained a
// source root rather than a build artifact.
var SourceRoots = []string{
	".",
	"adapter",
	"cmd",
	"common",
	"constant",
	"daemon",
	"dns",
	"e2e",
	"experimental",
	"include",
	"internal",
	"log",
	"option",
	"protocol",
	"route",
	"schema",
	"scripts",
	"service",
	"transport",
}

// GeneratedRoots are module-relative directories that tooling writes and that are never source.
//
// The first entry is the one this gate exists for. The rest are the other output directories the
// Makefile and the CI scripts write into; listing them costs nothing and means a future build step
// that drops Go into one of them is caught by the same rule rather than needing a new gate.
var GeneratedRoots = []string{
	// github.com/sagernet/gomobile bind_iosapp.go:106 and bind_androidapp.go:373.
	"build",
	// The isolated working directory cmd/internal/build_libbox now runs gomobile in. It is named
	// with a leading underscore, which the go tool already refuses to match with "./..."; it is
	// listed here as well so the rule is explicit rather than a property of a name.
	"_libbox_build",
	"dist",
	"bin",
	"vendor",
}

// Package is one entry of the module's package enumeration.
type Package struct {
	// ImportPath is what `go list` reported, for example
	// github.com/sagernet/sing-box/common/urltest.
	ImportPath string
	// Dir is the module-relative directory of the package, slash-separated, for example
	// common/urltest.
	Dir string
}

// Enumerate runs `go list ./...` from the module root and returns every enumerated package,
// sorted by directory.
//
// It asks the go tool rather than walking the tree, because the property being asserted is what
// `go test ./...` sees, and only the go tool decides that: it skips dot-directories, underscore
// directories and testdata by rules of its own, and those rules are exactly what the gomobile
// output would have to defeat to pollute the enumeration.
func Enumerate(root string) ([]Package, error) {
	tags, err := ReadTags(root)
	if err != nil {
		return nil, err
	}

	arguments := []string{"list", "-e", "-f", "{{.ImportPath}}\t{{.Dir}}"}
	if tags != "" {
		arguments = append(arguments, "-tags", tags)
	}
	arguments = append(arguments, "./...")

	command := exec.Command("go", arguments...)
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		return nil, err
	}

	var packages []Package
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, "\t", 2)
		pkg := Package{ImportPath: fields[0]}
		if len(fields) == 2 && fields[1] != "" {
			relative, relErr := filepath.Rel(root, fields[1])
			if relErr == nil {
				pkg.Dir = filepath.ToSlash(relative)
			}
		}
		packages = append(packages, pkg)
	}
	sort.Slice(packages, func(i, j int) bool { return packages[i].Dir < packages[j].Dir })
	return packages, nil
}

// ReadTags returns the build tags the full suite is run with, or "" when the profile is absent.
func ReadTags(root string) (string, error) {
	data, err := os.ReadFile(filepath.Join(root, TagsFile))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// GeneratedRootOf reports which generated root the module-relative directory belongs to, if any.
//
// The comparison is on whole path elements, so a directory named "buildbox" or "distfiles" is not
// mistaken for output of a generated root called "build" or "dist".
func GeneratedRootOf(dir string) (string, bool) {
	for _, generated := range GeneratedRoots {
		if DirIsWithin(dir, generated) {
			return generated, true
		}
	}
	return "", false
}

// SourceRootOf reports which source root the module-relative directory belongs to, if any.
func SourceRootOf(dir string) (string, bool) {
	for _, source := range SourceRoots {
		if DirIsWithin(dir, source) {
			return source, true
		}
	}
	return "", false
}

// DirIsWithin reports whether dir is root itself or lies below it.
//
// Both are module-relative, slash-separated, with "." meaning the module root. The comparison is
// on whole path elements, so "buildbox" is not inside "build".
func DirIsWithin(dir, root string) bool {
	dir = normalizeDir(dir)
	root = normalizeDir(root)
	if root == "." {
		return dir == "."
	}
	if dir == "." {
		return false
	}
	return dir == root || strings.HasPrefix(dir, root+"/")
}

func normalizeDir(dir string) string {
	dir = strings.Trim(filepath.ToSlash(dir), "/")
	if dir == "" {
		return "."
	}
	return dir
}
