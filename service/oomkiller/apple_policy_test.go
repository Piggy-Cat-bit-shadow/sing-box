package oomkiller

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
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

	// GOGC 100 matches the Go default, and is deliberate rather than an omission.
	// GOMEMLIMIT is what bounds this process; a lower GOGC made the collector run
	// before the heap approached that limit. Measured under memory pressure, GOGC 50
	// cost 36% more GC cycles for 1.13% less throughput with no memory benefit.
	if DefaultAppleNetworkExtensionGCPercent != 100 {
		t.Errorf("Apple NetworkExtension GOGC: want 100, got %d",
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

// --- the canonical policy cannot be split by a profile (§1) ----------------------

// buildNetworkExtensionConfig runs the REAL entry point a profile reaches, so these
// tests constrain buildTimerConfig itself rather than a restatement of its arithmetic.
//
// A test that called computeLimitThresholds directly would pass even if buildTimerConfig
// went on honouring a profile-supplied margin, which is precisely the fork that existed.
func buildNetworkExtensionConfig(t *testing.T, profileJSON string) timerConfig {
	t.Helper()
	options := option.OOMKillerServiceOptions{}
	if profileJSON != "" {
		if err := json.Unmarshal([]byte(profileJSON), &options); err != nil {
			t.Fatalf("profile %s: %v", profileJSON, err)
		}
	}
	config, err := buildTimerConfig(
		options,
		canonicalNetworkExtensionPolicy.memoryLimit(),
		policyModeNetworkExtension,
		false,
	)
	if err != nil {
		t.Fatalf("buildTimerConfig: %v", err)
	}
	return config
}

func requireCanonicalPolicy(t *testing.T, config timerConfig, profile string) {
	t.Helper()
	policy := canonicalNetworkExtensionPolicy

	if config.memoryLimit != policy.memoryLimit() {
		t.Errorf("%s: budget %d, want %d", profile, config.memoryLimit, policy.memoryLimit())
	}
	if config.safetyMargin != policy.safetyMargin {
		t.Errorf("%s: safety margin %d, want %d", profile, config.safetyMargin, policy.safetyMargin)
	}
	if !config.hasSafetyMargin {
		t.Errorf("%s: the margin must be set, or the timer cannot derive its thresholds", profile)
	}
	if config.minInterval != policy.minInterval {
		t.Errorf("%s: min interval %v, want %v", profile, config.minInterval, policy.minInterval)
	}
	if config.maxInterval != policy.maxInterval {
		t.Errorf("%s: max interval %v, want %v", profile, config.maxInterval, policy.maxInterval)
	}
	if config.policyMode != policyModeNetworkExtension {
		t.Errorf("%s: policy mode %d, want network extension", profile, config.policyMode)
	}

	// The footprint thresholds the timer enforces and the Go runtime soft limit must come
	// from the SAME margin, or the process is policed against two different notions of
	// safe.
	thresholds := computeLimitThresholds(config.memoryLimit, config.safetyMargin)
	if thresholds.armed != policy.runtimeMemoryLimit() {
		t.Errorf("%s: timer armed threshold %d disagrees with the Go runtime limit %d",
			profile, thresholds.armed, policy.runtimeMemoryLimit())
	}
	if thresholds.armed != RuntimeMemoryLimit(config.memoryLimit) {
		t.Errorf("%s: %d disagrees with RuntimeMemoryLimit(%d)",
			profile, thresholds.armed, config.memoryLimit)
	}
}

func TestNetworkExtensionPolicyIgnoresProfileOverrides(t *testing.T) {
	// Every one of these profiles weakens or stretches a platform safety limit. None may
	// take effect inside a NetworkExtension.
	profiles := []struct {
		name string
		json string
	}{
		{"no profile", ""},
		{"safety margin shrunk to 1 MiB", `{"safety_margin":"1m"}`},
		{"safety margin widened to 10 MiB", `{"safety_margin":"10m"}`},
		{"tiny min interval", `{"min_interval":"1ms"}`},
		{"huge max interval", `{"max_interval":"30m"}`},
		{"both intervals", `{"min_interval":"1ms","max_interval":"30m"}`},
		{"custom memory limit", `{"memory_limit":"200m"}`},
		{"everything at once", `{"memory_limit":"200m","safety_margin":"1m","min_interval":"1ms","max_interval":"30m"}`},
	}
	for _, profile := range profiles {
		t.Run(profile.name, func(t *testing.T) {
			requireCanonicalPolicy(t, buildNetworkExtensionConfig(t, profile.json), profile.name)
		})
	}
}

func TestNetworkExtensionPolicyIgnoresAnExistingServiceBlock(t *testing.T) {
	// A profile that already declares an oomkiller service is the realistic case: the
	// operator has a block, and its values must still not reach the platform policy.
	config := buildNetworkExtensionConfig(t, `{
		"memory_limit": "200m",
		"safety_margin": "1m",
		"min_interval": "2s",
		"max_interval": "5m"
	}`)
	requireCanonicalPolicy(t, config, "existing service block")
}

func TestNetworkExtensionPolicyIsUnchangedByRepeatedBuilds(t *testing.T) {
	// Building twice with different profiles must not accumulate state.
	first := buildNetworkExtensionConfig(t, `{"safety_margin":"1m"}`)
	second := buildNetworkExtensionConfig(t, "")
	if first.safetyMargin != second.safetyMargin ||
		first.minInterval != second.minInterval ||
		first.maxInterval != second.maxInterval {
		t.Fatal("the policy must not depend on what was built before it")
	}
}

func TestProfileStillTunableOutsideNetworkExtension(t *testing.T) {
	// The negative control: this must stay tunable for ordinary processes. If the
	// short-circuit applied everywhere, a legitimate non-iOS deployment would lose the
	// ability to configure its own OOM killer.
	options := option.OOMKillerServiceOptions{}
	if err := json.Unmarshal([]byte(`{"safety_margin":"8m","min_interval":"2s","max_interval":"30s"}`), &options); err != nil {
		t.Fatal(err)
	}
	config, err := buildTimerConfig(options, 100*1024*1024, policyModeMemoryLimit, false)
	if err != nil {
		t.Fatal(err)
	}
	if config.safetyMargin != 8*1024*1024 {
		t.Errorf("outside a NetworkExtension the profile margin must be honoured, got %d", config.safetyMargin)
	}
	if config.minInterval != 2*time.Second || config.maxInterval != 30*time.Second {
		t.Errorf("outside a NetworkExtension the profile intervals must be honoured, got %v/%v",
			config.minInterval, config.maxInterval)
	}
}
