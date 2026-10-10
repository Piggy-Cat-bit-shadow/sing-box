package oomprofile

// The OOM-profile capability is a BUILD BOUNDARY, and this file asserts it from inside the package so
// that a change on either side is caught by running the tests rather than by reading the build
// constraints.
//
// The boundary exists because reading the runtime's profile buffers needs //go:linkname pulls of
// runtime/pprof, which pushes no symbols, so the real implementation only links where the builder
// passes -checklinkname=0. The tag tfogo_checklinkname0 records that, and this package compiles
// either the real writer or a stub that reports the missing capability - never both, and never a
// silently degraded profile. See oomprofile_stub.go for the full reasoning.
//
// This file carries NO build constraint on the tag, so it compiles in both configurations: the
// assertions below hold in whichever one is under test.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestProfileSupportMatchesTheBuildConfiguration is the two-direction assertion.
//
// The tag is the only input, so it is read from the build's own constraint list rather than assumed:
// a test that hard-coded one side would pass in the configuration it was written on and prove
// nothing about the other.
func TestProfileSupportMatchesTheBuildConfiguration(t *testing.T) {
	if profileSupport() {
		// The real writer is compiled. It must behave like a real writer: the profile it is asked
		// for has to exist and be non-empty, so "support" is not an empty promise.
		path := filepath.Join(t.TempDir(), "heap.pprof")
		if err := WriteFile(path, "heap"); err != nil {
			t.Fatalf("this build reports profile support but failed to write a heap profile: %v", err)
		}
		assertNonEmptyFile(t, path)
		return
	}
	// The stub is compiled. It must FAIL CLOSED rather than write a partial profile: a caller that
	// ignores the error must not end up with a file that looks like a profile.
	path := filepath.Join(t.TempDir(), "heap.pprof")
	err := WriteFile(path, "heap")
	if err == nil {
		t.Fatal("this build has no OOM profile writer but WriteFile reported success; the stub must " +
			"fail closed, or a caller will treat an absent profile as a written one")
	}
	if _, statErr := osStat(path); statErr == nil {
		t.Fatalf("the stub wrote %s even though it reported the capability missing; it must not leave "+
			"a file behind", path)
	}
	// The error has to name what to do about it, because the configuration that hits it is the one a
	// reader gets by default.
	for _, want := range []string{"tfogo_checklinkname0", "-checklinkname=0"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the stub's error does not mention %q, so a reader cannot act on it: %v", want, err)
		}
	}
}

// assertNonEmptyFile requires a real profile to have been written.
func assertNonEmptyFile(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("the profile was not written: %v", err)
	}
	if info.Size() == 0 {
		t.Fatalf("%s is empty; a supported build must write a real profile", path)
	}
}

// osStat is os.Stat behind a name, so the stub branch reads as the assertion it is.
func osStat(path string) (os.FileInfo, error) { return os.Stat(path) }
