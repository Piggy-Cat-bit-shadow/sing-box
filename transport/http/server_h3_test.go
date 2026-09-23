//go:build with_quic

package http

import (
	"testing"

	"github.com/sagernet/sing-box/option"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
)

// TestParseBBRProfileDefaultIsStandard pins the compatibility rule: an unset
// bbr_profile keeps the previous hardcoded standard profile.
func TestParseBBRProfileDefaultIsStandard(t *testing.T) {
	for _, name := range []string{"", option.BBRProfileStandard} {
		profile, err := parseBBRProfile(name)
		if err != nil {
			t.Fatalf("profile %q must parse: %v", name, err)
		}
		if profile.Name() != congestion_meta2.ProfileStandard.Name() {
			t.Fatalf("profile %q must resolve to standard, got %q", name, profile.Name())
		}
	}
}

// TestParseBBRProfileAcceptsDependencyProfiles verifies every accepted option
// name maps onto a profile the dependency really exports.
func TestParseBBRProfileAcceptsDependencyProfiles(t *testing.T) {
	testCases := []struct {
		name     string
		expected congestion_meta2.Profile
	}{
		{option.BBRProfileStandard, congestion_meta2.ProfileStandard},
		{option.BBRProfileConservative, congestion_meta2.ProfileConservative},
		{option.BBRProfileAggressive, congestion_meta2.ProfileAggressive},
	}
	for _, testCase := range testCases {
		profile, err := parseBBRProfile(testCase.name)
		if err != nil {
			t.Fatalf("profile %q must parse: %v", testCase.name, err)
		}
		if profile.Name() != testCase.expected.Name() {
			t.Fatalf("profile %q: got %q, want %q", testCase.name, profile.Name(), testCase.expected.Name())
		}
	}
}

// TestParseBBRProfileRejectsUnknown guards against inventing profiles.
func TestParseBBRProfileRejectsUnknown(t *testing.T) {
	for _, name := range []string{"turbo", "BBR2", "STANDARD", "fast"} {
		if _, err := parseBBRProfile(name); err == nil {
			t.Fatalf("profile %q must be rejected", name)
		}
	}
}

// TestBBRProfileNamesMatchDependency keeps the option enum in sync with the
// profiles actually available in congestion_meta2.
func TestBBRProfileNamesMatchDependency(t *testing.T) {
	available := map[string]bool{
		congestion_meta2.ProfileStandard.Name():     true,
		congestion_meta2.ProfileConservative.Name(): true,
		congestion_meta2.ProfileAggressive.Name():   true,
	}
	for _, name := range option.BBRProfileNames() {
		if !available[name] {
			t.Fatalf("option exposes profile %q which the dependency does not define", name)
		}
	}
	if len(option.BBRProfileNames()) != len(available) {
		t.Fatalf("option exposes %d profiles but the dependency defines %d",
			len(option.BBRProfileNames()), len(available))
	}
}

func TestValidateBBRProfile(t *testing.T) {
	if err := option.ValidateBBRProfile(""); err != nil {
		t.Fatalf("an unset bbr_profile must be valid: %v", err)
	}
	for _, name := range option.BBRProfileNames() {
		if err := option.ValidateBBRProfile(name); err != nil {
			t.Fatalf("profile %q must be valid: %v", name, err)
		}
	}
	if err := option.ValidateBBRProfile("nope"); err == nil {
		t.Fatal("an unknown bbr_profile must be rejected")
	}
}
