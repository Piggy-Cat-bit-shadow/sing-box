package oomkiller

import (
	"context"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/memory"
	"github.com/sagernet/sing/service"
)

// Canonical NetworkExtension policy.
//
// # What this is, and what it is NOT
//
// The budget below is a FALLBACK / TUNING DEFAULT, not a documented Apple guarantee and
// not a contract. Apple has stated that the NetworkExtension memory limit has changed
// before and may change again, and it differs between devices - so a number observed on
// one phone is an observation, not a specification. Treating it as fixed would make the
// policy wrong the moment Apple changes it, silently.
//
// The real per-process ceiling is enforced by the OS through jetsam, and the only runtime
// signal for it is os_proc_available_memory(), which is reported by the diagnostics and
// deliberately NOT used to drive a live controller yet: doing so from macOS benchmarks
// would be a guess presented as a policy.
//
// # The two layers are complementary, not the same measurement
//
//	Darwin OOM timer    observes the ENTIRE PROCESS footprint (phys_footprint via
//	                    memory.Total()). That includes Go heap, stacks, GC metadata, and
//	                    every C / Swift / system allocation the process makes.
//
//	GOMEMLIMIT          constrains only the GO RUNTIME's managed memory. It is a soft
//	                    limit on one part of the process, and it says nothing about the
//	                    native side.
//
// Neither one bounds the process on its own. A process can sit comfortably under
// GOMEMLIMIT and still be killed by jetsam because of native allocations, and it can be
// well under the footprint target while the Go runtime is thrashing. Both are reported
// separately and must never be conflated into one number.
const (
	// DefaultAppleNetworkExtensionMemoryLimit is the FALLBACK budget used to derive the
	// Go runtime soft limit and the footprint thresholds when the client runs inside an
	// iOS NetworkExtension and supplies no explicit limit of its own.
	//
	// 50 MiB is an observed packet-tunnel budget, not a documented system limit. See the
	// block comment above.
	DefaultAppleNetworkExtensionMemoryLimit = 50 * 1024 * 1024

	// DefaultAppleNetworkExtensionGCPercent is the GC target for the derived runtime
	// limit.
	//
	// 100 matches the Go default and is a deliberate choice rather than an omission.
	// GOMEMLIMIT already paces the heap against the soft limit, so a lower GOGC made the
	// collector run before the heap was anywhere near it. Measured under memory pressure
	// with the corrected runtime-metrics harness: see the commit that changed this value
	// for the before/after, which replaced an earlier measurement taken with a flawed
	// gctrace parser.
	DefaultAppleNetworkExtensionGCPercent = 100
)

// networkExtensionPolicy is the single source of truth for the iOS NetworkExtension
// safety policy.
//
// # Why a struct rather than loose constants
//
// These values are derived from each other and must stay consistent: the runtime limit is
// the budget minus twice the margin, the footprint thresholds are the budget minus one,
// two and four margins. When the runtime limit and the timer thresholds were computed
// from different inputs - the canonical margin for one, a profile-supplied margin for the
// other - the process was policed against two different notions of "safe", and a profile
// could weaken one without the other.
//
// Everything that needs one of these numbers reads it from here, so a change to the
// policy changes every consumer together or fails to compile.
type networkExtensionPolicy struct {
	// budget is the process footprint the policy aims to stay under.
	budget uint64
	// safetyMargin is the step size for the footprint thresholds and the amount held back
	// from the budget when deriving the Go runtime soft limit.
	safetyMargin uint64
	// minInterval and maxInterval bound the adaptive sampling period.
	minInterval time.Duration
	maxInterval time.Duration
}

// canonicalNetworkExtensionPolicy is THE policy for iOS NetworkExtension.
//
// A user profile cannot change it. The values are platform safety limits: an operator
// tuning their own config should not be able to talk the process into a footprint margin
// of 1 MiB, because the consequence of getting that wrong is the process being killed,
// not a slow request.
var canonicalNetworkExtensionPolicy = networkExtensionPolicy{
	budget:       DefaultAppleNetworkExtensionMemoryLimit,
	safetyMargin: defaultSafetyMargin,
	minInterval:  defaultMinInterval,
	maxInterval:  defaultMaxInterval,
}

// memoryLimit is the budget the policy polices against.
func (p networkExtensionPolicy) memoryLimit() uint64 { return p.budget }

// thresholds are the footprint thresholds, derived from the budget and margin.
func (p networkExtensionPolicy) thresholds() pressureThresholds {
	return computeLimitThresholds(p.budget, p.safetyMargin)
}

// runtimeMemoryLimit is the Go runtime soft limit for this policy.
//
// It is the armed threshold - the budget less two margins - which is the same derivation
// RuntimeMemoryLimit performs, so the two cannot drift.
func (p networkExtensionPolicy) runtimeMemoryLimit() uint64 { return p.thresholds().armed }

type policyMode uint8

const (
	policyModeNone policyMode = iota
	policyModeMemoryLimit
	policyModeAvailable
	policyModeNetworkExtension
)

func (m policyMode) hasTimerMode() bool {
	return m != policyModeNone
}

func (m policyMode) String() string {
	switch m {
	case policyModeMemoryLimit:
		return "memory_limit"
	case policyModeAvailable:
		return "available"
	case policyModeNetworkExtension:
		return "network_extension"
	default:
		return "none"
	}
}

func resolvePolicyMode(ctx context.Context, options option.OOMKillerServiceOptions) (uint64, policyMode) {
	platformInterface := service.FromContext[adapter.PlatformInterface](ctx)
	if C.IsIos && platformInterface != nil && platformInterface.UnderNetworkExtension() {
		return DefaultAppleNetworkExtensionMemoryLimit, policyModeNetworkExtension
	}
	if options.MemoryLimitOverride > 0 {
		return options.MemoryLimitOverride, policyModeMemoryLimit
	}
	if options.MemoryLimit != nil {
		memoryLimit := options.MemoryLimit.Value()
		if memoryLimit > 0 {
			return memoryLimit, policyModeMemoryLimit
		}
	}
	if memory.AvailableAvailable() {
		return 0, policyModeAvailable
	}
	return 0, policyModeNone
}
