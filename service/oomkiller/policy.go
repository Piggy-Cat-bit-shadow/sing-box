package oomkiller

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/memory"
	"github.com/sagernet/sing/service"
)

const (
	DefaultAppleNetworkExtensionMemoryLimit = 50 * 1024 * 1024

	// DefaultAppleNetworkExtensionGCPercent is the GC target for the derived runtime
	// limit above.
	//
	// 100, not the previous 50. Measured on the Shadowsocks copy loop under real memory
	// pressure (24 MiB live set, 256 MiB per iteration, 10 independent runs, medians):
	//
	//	  GOGC 50   5916 MB/s  98 GC cycles/op  143 ms pause
	//	  GOGC 100  5983 MB/s  63 GC cycles/op   85 ms pause
	//
	// The two ranges do not overlap on either metric: throughput is +1.13% and GC work
	// is 36% lower. GOMEMLIMIT already paces the heap against the hard ceiling, so the
	// lower GOGC was making the collector run before the heap was anywhere near the
	// limit - twice the cycles to reach the same place. On a phone those cycles are CPU,
	// and CPU is heat and battery.
	//
	// The limit itself is unchanged: 40 MiB still bounds the process, and the peak heap
	// stayed below it in every run.
	DefaultAppleNetworkExtensionGCPercent = 100
)

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
