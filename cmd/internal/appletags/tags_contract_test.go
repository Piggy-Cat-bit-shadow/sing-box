package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Contract test: this command's tag set must equal the builder's.
//
// # Why this test exists rather than a shared import
//
// The builder lives in cmd/internal/build_libbox, which is package main and cannot be
// imported. The two lists could therefore drift silently, which is exactly the problem this
// work removed at the CI level - so it must not be reintroduced one level down.
//
// Rather than trust two lists to stay in step, this reads the builder's actual source and
// extracts the tags it declares, then compares. If someone adds a tag to the builder and
// forgets this command, this fails.
func TestAppleTagsMatchTheBuilder(t *testing.T) {
	builderSource, err := os.ReadFile(filepath.Join("..", "build_libbox", "tags.go"))
	if err != nil {
		t.Fatalf("cannot read the builder's tag definition: %v", err)
	}
	source := string(builderSource)

	shared := extractStringSlice(t, source, "appleSharedTags = []string{")
	darwin := extractStringSlice(t, source, "appleDarwinTags = []string{")
	lowMemoryTag := extractStringConst(t, source, "appleLowMemoryTag")

	if len(shared) == 0 {
		t.Fatal("extracted no shared tags from the builder; the parser or the source changed")
	}

	compare := func(name string, want []string, got []string) {
		t.Helper()
		sortedWant := append([]string(nil), want...)
		sortedGot := append([]string(nil), got...)
		sort.Strings(sortedWant)
		sort.Strings(sortedGot)
		if strings.Join(sortedWant, ",") != strings.Join(sortedGot, ",") {
			t.Errorf("%s differs from the builder:\n  builder: %v\n  appletags: %v",
				name, sortedWant, sortedGot)
		}
	}

	compare("shared tags", shared, appleSharedTagList)
	compare("darwin tags", darwin, appleDarwinTagList)
	if lowMemoryTag != appleLowMemoryTagName {
		t.Errorf("low-memory tag: builder %q, appletags %q", lowMemoryTag, appleLowMemoryTagName)
	}
}

func TestLowMemoryTagIsOnlyInTheMobileSet(t *testing.T) {
	// iOS and tvOS ship with_low_memory; macOS does not. Adding it to macOS would make
	// macOS tests exercise a buffer geometry macOS does not ship.
	mobile := canonicalAppleTags(true)
	desktop := canonicalAppleTags(false)

	if !contains(mobile, appleLowMemoryTagName) {
		t.Error("the iOS/tvOS set must contain with_low_memory")
	}
	if contains(desktop, appleLowMemoryTagName) {
		t.Error("the macOS set must NOT contain with_low_memory")
	}

	// The mobile set is exactly the desktop set plus the low-memory tag.
	desktopWithTag := append(append([]string(nil), desktop...), appleLowMemoryTagName)
	sort.Strings(desktopWithTag)
	if strings.Join(desktopWithTag, ",") != strings.Join(mobile, ",") {
		t.Errorf("the mobile set must be the desktop set plus with_low_memory\n  desktop+tag: %v\n  mobile: %v",
			desktopWithTag, mobile)
	}
}

func TestCommandOutputMatchesTheCanonicalSet(t *testing.T) {
	// The command is what the CI scripts consume, so its OUTPUT is compared, not just the
	// underlying function. A command that printed something else would leave the gate
	// testing the wrong tags while this test passed.
	output, err := exec.Command("go", "run", ".", "-low-memory=true").Output()
	if err != nil {
		t.Fatalf("running appletags: %v", err)
	}
	printed := strings.Split(strings.TrimSpace(string(output)), ",")
	sort.Strings(printed)

	want := canonicalAppleTags(true)
	if strings.Join(printed, ",") != strings.Join(want, ",") {
		t.Errorf("printed tags differ from the canonical set:\n  printed: %v\n  want:    %v", printed, want)
	}
}

func TestMacOSOutputHasNoLowMemoryTag(t *testing.T) {
	output, err := exec.Command("go", "run", ".", "-low-memory=false").Output()
	if err != nil {
		t.Fatalf("running appletags: %v", err)
	}
	if strings.Contains(string(output), appleLowMemoryTagName) {
		t.Fatalf("the macOS output must not contain %s, got %q", appleLowMemoryTagName, output)
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// extractStringSlice reads a `name = []string{ ... }` literal's contents.
func extractStringSlice(t *testing.T, source string, marker string) []string {
	t.Helper()
	start := strings.Index(source, marker)
	if start < 0 {
		t.Fatalf("marker %q not found in the builder source", marker)
	}
	rest := source[start+len(marker):]
	end := strings.Index(rest, "}")
	if end < 0 {
		t.Fatalf("unterminated literal after %q", marker)
	}
	var values []string
	for _, line := range strings.Split(rest[:end], "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, `"`) {
			continue
		}
		value := strings.TrimSuffix(strings.TrimPrefix(line, `"`), `",`)
		value = strings.TrimSuffix(value, `"`)
		if value != "" {
			values = append(values, value)
		}
	}
	return values
}

// extractStringConst reads a `name = "value"` constant.
func extractStringConst(t *testing.T, source string, marker string) string {
	t.Helper()
	start := strings.Index(source, marker)
	if start < 0 {
		t.Fatalf("constant %q not found in the builder source", marker)
	}
	rest := source[start+len(marker):]
	first := strings.Index(rest, `"`)
	if first < 0 {
		t.Fatalf("no value for constant %q", marker)
	}
	rest = rest[first+1:]
	second := strings.Index(rest, `"`)
	if second < 0 {
		t.Fatalf("unterminated value for constant %q", marker)
	}
	return rest[:second]
}
