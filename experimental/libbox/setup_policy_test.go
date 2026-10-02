package libbox

import (
	"runtime/debug"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/service/oomkiller"
)

// Tests for the iOS NetworkExtension policy being canonical (§10).
//
// # The fork being closed
//
// The config profile could no longer change the NetworkExtension policy, but SetupOptions could.
// On iOS the timer forces the canonical 50 MiB budget regardless of any override - see
// resolvePolicyMode - while the Go runtime settings were computed from the EXTERNAL
// OomMemoryLimit. A caller passing 200 MiB therefore produced:
//
//	timer budget =  50 MiB
//	GOMEMLIMIT   = 190 MiB
//	GOGC         = runtime default, not canonical 100
//
// The runtime paced against 190 MiB while the timer policed 50 MiB. That is the same policy
// split, through a different door.

// TestIOSIgnoresAnExternalOomMemoryLimit is the §10 regression.
//
// An anomalous 200 MiB override must not be able to move either half of the policy. This drives
// the decision directly rather than through C.IsIos, so it runs and fails on ANY platform - a
// policy that can only be checked inside an iOS build is a policy that is usually wrong there.
func TestIOSIgnoresAnExternalOomMemoryLimit(t *testing.T) {
	const hostileOverride = 200 * 1024 * 1024

	limit, gcPercent, applyGC := resolveOOMKillerRuntimePolicy(hostileOverride, true)

	if limit != oomkiller.DefaultAppleNetworkExtensionMemoryLimit {
		t.Fatalf("effective budget = %d, want the canonical %d; an external override must not "+
			"split the policy", limit, oomkiller.DefaultAppleNetworkExtensionMemoryLimit)
	}
	if !applyGC {
		t.Fatal("the canonical GC target must be applied on iOS")
	}
	if gcPercent != oomkiller.DefaultAppleNetworkExtensionGCPercent {
		t.Fatalf("GC target = %d, want the canonical %d", gcPercent,
			oomkiller.DefaultAppleNetworkExtensionGCPercent)
	}

	// The decisive property: the runtime limit implied by the chosen budget must be the one the
	// CANONICAL budget implies, not the one the override would have produced. The two differ by
	// nearly 4x, which is the split the test exists to catch.
	canonicalLimit := oomkiller.RuntimeMemoryLimit(oomkiller.DefaultAppleNetworkExtensionMemoryLimit)
	overrideLimit := oomkiller.RuntimeMemoryLimit(hostileOverride)
	chosenLimit := oomkiller.RuntimeMemoryLimit(uint64(limit))

	if chosenLimit != canonicalLimit {
		t.Fatalf("runtime limit = %d, want the canonical %d", chosenLimit, canonicalLimit)
	}
	if chosenLimit == overrideLimit {
		t.Fatalf("the runtime limit matches the hostile override's %d; the override leaked "+
			"into the Go runtime policy", overrideLimit)
	}
	t.Logf("canonical runtime limit = %d MiB; the ignored override would have given %d MiB",
		canonicalLimit>>20, overrideLimit>>20)
}

// TestIOSPolicyIsCanonicalEvenForZeroAndNegativeInputs covers the other request shapes.
//
// The previous code applied the canonical budget and GC target only when the requested limit was
// ZERO. Any non-zero value - including a hostile or nonsensical one - skipped the GC target
// entirely and derived the runtime limit from the caller's number.
func TestIOSPolicyIsCanonicalEvenForZeroAndNegativeInputs(t *testing.T) {
	for _, requested := range []int64{0, 1, 1 << 20, 200 * 1024 * 1024, -1} {
		limit, gcPercent, applyGC := resolveOOMKillerRuntimePolicy(requested, true)
		if limit != oomkiller.DefaultAppleNetworkExtensionMemoryLimit {
			t.Errorf("requested %d: budget = %d, want canonical %d", requested, limit,
				oomkiller.DefaultAppleNetworkExtensionMemoryLimit)
		}
		if !applyGC || gcPercent != oomkiller.DefaultAppleNetworkExtensionGCPercent {
			t.Errorf("requested %d: GC target = %d (applied=%v), want canonical %d",
				requested, gcPercent, applyGC, oomkiller.DefaultAppleNetworkExtensionGCPercent)
		}
	}
}

// TestNonIOSPolicyPassesTheLimitThrough pins the non-iOS branch.
func TestNonIOSPolicyPassesTheLimitThrough(t *testing.T) {
	limit, _, applyGC := resolveOOMKillerRuntimePolicy(200*1024*1024, false)
	if limit != 200*1024*1024 {
		t.Fatalf("non-iOS budget = %d, want the requested value", limit)
	}
	if applyGC {
		t.Fatal("the non-iOS path must not force the Apple NetworkExtension GC target")
	}
}

// TestNonIOSStillHonoursAnExplicitLimit guards against the fix over-reaching.
//
// Trimming the iOS path must not disable the memory limit for callers that legitimately set one
// - the desktop daemon passes an operator-configured value, and that must still apply.
func TestNonIOSStillHonoursAnExplicitLimit(t *testing.T) {
	if C.IsIos {
		t.Skip("this asserts the non-iOS behaviour")
	}

	previousLimit := debug.SetMemoryLimit(-1)
	defer debug.SetMemoryLimit(previousLimit)

	const explicitLimit = 200 * 1024 * 1024
	ReloadSetupOptions(&SetupOptions{
		OomKillerEnabled: true,
		OomMemoryLimit:   explicitLimit,
	})
	defer ReloadSetupOptions(&SetupOptions{})

	wantRuntimeLimit := oomkiller.RuntimeMemoryLimit(explicitLimit)
	gotRuntimeLimit := uint64(debug.SetMemoryLimit(-1))
	debug.SetMemoryLimit(int64(gotRuntimeLimit))

	if gotRuntimeLimit != wantRuntimeLimit {
		t.Fatalf("GOMEMLIMIT = %d, want %d for an explicit %d MiB limit outside iOS",
			gotRuntimeLimit, wantRuntimeLimit, explicitLimit>>20)
	}
}
