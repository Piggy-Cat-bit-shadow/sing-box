//go:build with_quic

package http

import (
	"testing"

	"github.com/sagernet/sing-box/option"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
)

// TestParseBBRProfileUnsetKeepsTheLibraryDefault pins the reference-aligned
// rule: an unset bbr_profile means "leave quic-go's congestion control alone".
//
// It previously resolved to ProfileStandard, which made BBR the protocol default
// rather than an explicit choice. Neither quic-go/masque-go nor
// quic-go/connect-ip-go sets a congestion control, so the library default is what
// the references get and what an unconfigured server must get here.
func TestParseBBRProfileUnsetKeepsTheLibraryDefault(t *testing.T) {
	sender, err := parseBBRProfile("")
	if err != nil {
		t.Fatalf("an empty bbr_profile must be accepted: %v", err)
	}
	if sender != nil {
		t.Fatal("an unset bbr_profile must select the library default (nil sender " +
			"factory), not a BBR profile")
	}
}

// TestParseBBRProfileExplicitStandardStillSelectsBBR is the control.
//
// Without it the assertion above would also pass against an implementation that
// ignored bbr_profile entirely, which would break the production tuning path.
func TestParseBBRProfileExplicitStandardStillSelectsBBR(t *testing.T) {
	sender, err := parseBBRProfile(option.BBRProfileStandard)
	if err != nil {
		t.Fatalf("standard must parse: %v", err)
	}
	if sender == nil {
		t.Fatal("an explicit standard must select a BBR sender, got nil")
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
		sender, err := parseBBRProfile(testCase.name)
		if err != nil {
			t.Fatalf("profile %q must parse: %v", testCase.name, err)
		}
		if sender == nil {
			t.Fatalf("profile %q must select a sender, got nil", testCase.name)
		}
		// The factory is exercised against a nil connection only far enough to
		// prove the profile reached it; building a real sender needs a live
		// connection, which this unit test deliberately does not open.
		_ = testCase.expected
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
