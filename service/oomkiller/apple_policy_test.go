package oomkiller

import (
	"testing"
)

// Pins the Apple NetworkExtension memory policy.
//
// # Why this is worth a test
//
// The iOS runtime memory behaviour is not configured in one obvious place. It is the
// product of three separate values that live in two packages and are applied in a
// third:
//
//	DefaultAppleNetworkExtensionMemoryLimit   the NetworkExtension budget
//	defaultSafetyMargin                       how far below the budget to stay
//	RuntimeMemoryLimit                        the derived Go runtime limit
//
// and they only take effect because libbox/setup.go sets GOMEMLIMIT from
// RuntimeMemoryLimit and GOGC from DefaultAppleNetworkExtensionGCPercent when the
// client enables the OOM killer without supplying a limit - which is exactly what the
// iOS client does.
//
// Every one of those values is individually reasonable to change, and doing so
// silently alters how aggressively iOS collects garbage. A lower derived limit means
// more GC cycles and more CPU on a phone; a higher one risks the process being killed.
// So the numbers are pinned here, and a change to any of them fails this test with a
// message naming what moved.
//
// The test asserts against the real functions rather than restating the arithmetic,
// because restating it is how a test stops testing anything.

func TestAppleNetworkExtensionDefaults(t *testing.T) {
	// 50 MiB is the client's documented NetworkExtension budget.
	if DefaultAppleNetworkExtensionMemoryLimit != 50*1024*1024 {
		t.Errorf("Apple NetworkExtension budget: want 50 MiB (%d), got %d",
			50*1024*1024, DefaultAppleNetworkExtensionMemoryLimit)
	}

	// GOGC 50 collects sooner than the Go default of 100. That is deliberate: inside a
	// NetworkExtension a hard limit is what protects the process, and the GC setting is
	// chosen to work with it rather than against it.
	if DefaultAppleNetworkExtensionGCPercent != 50 {
		t.Errorf("Apple NetworkExtension GOGC: want 50, got %d",
			DefaultAppleNetworkExtensionGCPercent)
	}
}

func TestAppleRuntimeMemoryLimit(t *testing.T) {
	// The value libbox actually hands to debug.SetMemoryLimit on iOS.
	const want = 40 * 1024 * 1024
	got := RuntimeMemoryLimit(DefaultAppleNetworkExtensionMemoryLimit)
	if got != want {
		t.Errorf("RuntimeMemoryLimit(50 MiB): want 40 MiB (%d), got %d", want, got)
	}
}

func TestApplePressureThresholds(t *testing.T) {
	// The full ladder, not just the armed value. These three numbers describe how the
	// killer behaves under pressure, so a change to the margin formula shows up here
	// even if the armed value happened to stay the same.
	thresholds := computeLimitThresholds(
		DefaultAppleNetworkExtensionMemoryLimit,
		defaultSafetyMargin,
	)

	cases := []struct {
		name string
		got  uint64
		want uint64
	}{
		{"trigger", thresholds.trigger, 45 * 1024 * 1024},
		{"armed", thresholds.armed, 40 * 1024 * 1024},
		{"resume", thresholds.resume, 30 * 1024 * 1024},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s threshold: want %d MiB (%d), got %d (%d MiB)",
				tc.name, tc.want/1024/1024, tc.want, tc.got, tc.got/1024/1024)
		}
	}

	// The ladder must be ordered, or the pressure state machine cannot work: a resume
	// at or above the trigger would leave the killer permanently armed.
	if !(thresholds.resume < thresholds.armed && thresholds.armed < thresholds.trigger) {
		t.Errorf("thresholds must satisfy resume < armed < trigger, got %d, %d, %d",
			thresholds.resume, thresholds.armed, thresholds.trigger)
	}
	if thresholds.trigger > DefaultAppleNetworkExtensionMemoryLimit {
		t.Error("the trigger must not exceed the NetworkExtension budget")
	}
}

func TestComputeLimitThresholds_MarginIsClampedToTheLimit(t *testing.T) {
	// A margin larger than the limit itself must not produce a negative threshold,
	// which would wrap around as an unsigned value and disable the killer entirely.
	small := uint64(4 * 1024 * 1024)
	thresholds := computeLimitThresholds(small, 64*1024*1024)
	if thresholds.trigger > small || thresholds.armed > small || thresholds.resume > small {
		t.Errorf("thresholds must be clamped to the limit %d, got %+v", small, thresholds)
	}
}

func TestRuntimeMemoryLimit_Scales(t *testing.T) {
	// Guards the formula itself, independently of the Apple constants: whichever budget
	// is configured, the armed limit sits two safety margins below it.
	cases := []struct {
		budget uint64
		want   uint64
	}{
		{50 * 1024 * 1024, 40 * 1024 * 1024},
		{48 * 1024 * 1024, 38 * 1024 * 1024},
		{44 * 1024 * 1024, 34 * 1024 * 1024},
		{37*1024*1024 + 512*1024, 27*1024*1024 + 512*1024},
	}
	for _, tc := range cases {
		if got := RuntimeMemoryLimit(tc.budget); got != tc.want {
			t.Errorf("RuntimeMemoryLimit(%d MiB): want %d MiB, got %d MiB",
				tc.budget/1024/1024, tc.want/1024/1024, got/1024/1024)
		}
	}
}
