package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The toolchain has ONE source of truth, and this file makes the exceptions declare themselves.
//
// # The failure it exists to prevent
//
// Six of the seven workflows resolve the Go toolchain with `go-version-file: go.mod`, so the
// toolchain a gate runs under IS the language version the module declares. The Windows core workflow
// wrote it by hand instead:
//
//	env:
//	  GO_VERSION: "1.26.8"     go.mod declares go 1.25.5
//
// A hand-written toolchain is the same class of mistake as a hand-written tag list or a hand-written
// replace set: it is a value that already exists in the repository, typed a second time, with nothing
// asserting the two agree. It matters more than most, because the toolchain is an INPUT to two
// contracts this tree already enforces - `tag_checklinkname_test.go` computes the set of legal
// runtime //go:linkname pulls from the RUNTIME SOURCE OF THE TOOLCHAIN IT IS COMPILED WITH, and
// scripts/ci/check-go-module-integrity.sh states that the modules declare 1.25.5, "the same as the
// toolchain the repository pins". A gate that runs under 1.26.8 is answering a question about a
// runtime the other six workflows never see.
//
// # Why an exemption with a reason, and not "make them all equal"
//
// Matching the upstream release toolchain is a legitimate goal for one artifact, and it is the reason
// the Windows workflow gives. That is a deliberate divergence, not a defect, and flattening it here
// would be exactly the cosmetic unification this round forbids. What is a defect is that the
// divergence was SILENT: nothing failed when it appeared and nothing would fail if it grew. So a
// divergence is allowed and must be DECLARED with its reason, and anything undeclared - including a
// new one, or a change to this one - fails here.
//
// # What is asserted mechanically rather than by the list
//
// A literal LOWER than the declared language version is never a divergence, it is a broken build:
// cmd/go refuses "go.mod requires go >= X". That is computed, so no exemption can authorise it.

// toolchainDivergence declares one workflow whose toolchain deliberately differs from go.mod's.
type toolchainDivergence struct {
	// version is the exact literal the workflow sets.
	version string
	// reason is required and must not be empty: an unexplained divergence is what this file exists
	// to stop, so the explanation is part of the contract rather than a comment beside it.
	reason string
}

// toolchainDivergences is the complete set of declared divergences, keyed by workflow file name.
//
// EMPTY-OR-EXPLAINED, and kept explicit rather than derived: this is the one place a divergence is
// allowed to exist, so adding an entry must be a visible decision in a diff.
var toolchainDivergences = map[string]toolchainDivergence{
	"windows-core-amd64.yml": {
		version: "1.26.8",
		reason: "Windows matches the toolchain UPSTREAM builds its core releases with, which is not " +
			"the language version this module declares. The divergence is real and is the reason this " +
			"table exists; scripts/ci/check-go-module-integrity.sh and tag_checklinkname_test.go both " +
			"reason about the toolchain go.mod pins, so this artifact's gates answer a question about " +
			"a different runtime and must be read as such. Raising or lowering this literal is a " +
			"deliberate release decision and fails this test until the table is updated with it.",
	},
}

// workflowGoVersion pins the two shapes a workflow can use to choose a toolchain.
var (
	// goVersionFileRE matches `go-version-file: go.mod`, the derived form.
	goVersionFileRE = regexp.MustCompile(`(?m)^\s*go-version-file:\s*(\S+)\s*$`)
	// explicitGoVersionRE matches a literal in either spelling this tree uses:
	// `go-version: "1.26.8"` or `GO_VERSION: "1.26.8"`.
	explicitGoVersionRE = regexp.MustCompile(`(?m)^\s*(?:GO_VERSION|go-version):\s*["']?(\d+\.\d+(?:\.\d+)?)["']?\s*$`)
	// goDirectiveRE reads the language version out of go.mod.
	goDirectiveRE = regexp.MustCompile(`(?m)^go\s+(\d+\.\d+(?:\.\d+)?)\s*$`)
)

// declaredGoVersion reads the module's own language version.
func declaredGoVersion(t *testing.T, root string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	match := goDirectiveRE.FindStringSubmatch(string(content))
	if match == nil {
		t.Fatal("go.mod has no `go <version>` directive; this test would pass vacuously")
	}
	return match[1]
}

// TestEveryWorkflowToolchainIsDerivedOrDeclared is the gate.
func TestEveryWorkflowToolchainIsDerivedOrDeclared(t *testing.T) {
	root := repoRoot(t)
	declared := declaredGoVersion(t, root)

	workflowDir := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(workflowDir)
	if err != nil {
		t.Fatal(err)
	}
	inspected := 0
	seenDivergences := make(map[string]bool)
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || (!strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml")) {
			continue
		}
		content, err := os.ReadFile(filepath.Join(workflowDir, name))
		if err != nil {
			t.Fatal(err)
		}
		text := string(content)
		derived := goVersionFileRE.FindAllStringSubmatch(text, -1)
		explicit := explicitGoVersionRE.FindAllStringSubmatch(text, -1)
		if len(derived) == 0 && len(explicit) == 0 {
			// A workflow that sets up no Go toolchain at all is not this test's subject.
			continue
		}
		inspected++
		for _, match := range derived {
			if match[1] != "go.mod" {
				t.Fatalf("%s derives its toolchain from %q; every derived workflow in this tree reads "+
					"go.mod, and a second source file is a second source of truth", name, match[1])
			}
		}
		if len(explicit) == 0 {
			continue
		}
		// The workflow sets a literal. It must be declared, and the declared value must be the one
		// actually written - a stale entry is as dangerous as a missing one.
		declaration, declaredHere := toolchainDivergences[name]
		for _, match := range explicit {
			version := match[1]
			if version == declared {
				// Equal to go.mod: nothing to declare, and deriving would be better but is not a
				// source-of-truth defect.
				continue
			}
			if !declaredHere {
				t.Fatalf("%s pins the Go toolchain to %q while go.mod declares %q, and the divergence "+
					"is not declared. Either derive it with `go-version-file: go.mod`, or add an entry "+
					"to toolchainDivergences with the reason - an unexplained divergence is how a "+
					"hand-written toolchain silently becomes a second source of truth.",
					name, version, declared)
			}
			if version != declaration.version {
				t.Fatalf("%s is declared as toolchain %q but sets %q; a stale declaration is worse "+
					"than none, because it reads as reviewed", name, declaration.version, version)
			}
			if strings.TrimSpace(declaration.reason) == "" {
				t.Fatalf("%s declares a toolchain divergence with no reason; the reason is the point",
					name)
			}
			// Computed, not listed: a literal BELOW the declared language version cannot build at
			// all, so no exemption may authorise it.
			if compareGoVersions(version, declared) < 0 {
				t.Fatalf("%s pins the Go toolchain to %q, below the language version go.mod declares "+
					"(%q): cmd/go refuses that build outright", name, version, declared)
			}
			seenDivergences[name] = true
		}
	}

	if inspected == 0 {
		t.Fatal("no workflow was inspected; this test would pass vacuously")
	}
	if len(seenDivergences) != len(toolchainDivergences) {
		var stale []string
		for name := range toolchainDivergences {
			if !seenDivergences[name] {
				stale = append(stale, name)
			}
		}
		sort.Strings(stale)
		t.Fatalf("declared toolchain divergences that no longer describe any workflow: %v. "+
			"Remove them: an exemption nobody exercises is an exemption nobody re-reads.", stale)
	}
}

// TestTheDeclaredToolchainDivergenceIsTheOnlyOne is the human-readable half: it names the single
// divergence in the failure message so the next reader does not have to reconstruct it from the map.
func TestTheDeclaredToolchainDivergenceIsTheOnlyOne(t *testing.T) {
	if len(toolchainDivergences) != 1 {
		t.Fatalf("there are now %d declared toolchain divergences; each one is an artifact whose "+
			"gates answer a question about a runtime the other workflows never see, so the set must "+
			"stay small and deliberate", len(toolchainDivergences))
	}
	declaration, loaded := toolchainDivergences["windows-core-amd64.yml"]
	if !loaded {
		t.Skip("the Windows divergence was removed; deriving its toolchain is the better outcome")
	}
	t.Logf("declared toolchain divergence: windows-core-amd64.yml at %s - %s",
		declaration.version, declaration.reason)
}

// compareGoVersions compares two dotted versions numerically, component by component. It is
// deliberately not a semver library: these are Go language versions, which are at most three
// numeric components with no pre-release syntax.
func compareGoVersions(left, right string) int {
	leftParts := strings.Split(left, ".")
	rightParts := strings.Split(right, ".")
	for index := 0; index < len(leftParts) || index < len(rightParts); index++ {
		var leftValue, rightValue int
		if index < len(leftParts) {
			leftValue = atoiOrZero(leftParts[index])
		}
		if index < len(rightParts) {
			rightValue = atoiOrZero(rightParts[index])
		}
		if leftValue != rightValue {
			if leftValue < rightValue {
				return -1
			}
			return 1
		}
	}
	return 0
}

func atoiOrZero(text string) int {
	value := 0
	for _, char := range text {
		if char < '0' || char > '9' {
			return 0
		}
		value = value*10 + int(char-'0')
	}
	return value
}
