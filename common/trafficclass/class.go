// Package trafficclass defines the per-flow traffic class policy.
//
// # Why this package exists separately
//
// TrafficClass describes what a flow is FOR, from the operator's point of view: an interactive
// session that a human is waiting on, bulk transfer, realtime media, or unclassified. It is
// deliberately NOT a property of any protocol. VLESS, AnyTLS, Naive, MASQUE and every other
// outbound are unaware of it; the scheduler that consumes it lives in the generic copy layer.
//
// It is a leaf package with no sing-box imports. Configuration, the adapter metadata and the
// router all need this type, and a shared leaf is the only placement that cannot grow an import
// cycle as those layers evolve.
package trafficclass

import (
	"strconv"

	E "github.com/sagernet/sing/common/exceptions"
)

// Class is a per-flow traffic class.
//
// The zero value is ClassDefault, so an InboundContext that never had a class resolved reports
// "unclassified" without any initialisation. Configuration does NOT rely on that: "unset" and
// "explicitly default" are different intents there, and are distinguished in the option layer.
type Class uint8

const (
	// ClassDefault is unclassified traffic. It has no policy of its own and behaves exactly as
	// sing-box did before traffic classes existed.
	ClassDefault Class = iota

	// ClassInteractive is traffic a person is actively waiting on: chat prompts, page loads,
	// API calls. It is the class the AI outbound groups resolve to.
	ClassInteractive

	// ClassBulk is throughput-oriented traffic where latency does not matter: large uploads,
	// backups, sync.
	ClassBulk

	// ClassRealtime is latency-critical and loss-sensitive traffic, such as calls. Like
	// interactive it is high priority, and it exists so a future round can treat the two
	// differently without changing the configuration surface.
	ClassRealtime
)

// String returns the configuration spelling of the class.
func (c Class) String() string {
	switch c {
	case ClassInteractive:
		return "interactive"
	case ClassBulk:
		return "bulk"
	case ClassRealtime:
		return "realtime"
	case ClassDefault:
		return "default"
	default:
		// A value outside the enum can only come from a corrupted value or a future constant
		// read by older code; naming it is better than silently claiming it is default.
		return "unknown(" + strconv.FormatUint(uint64(c), 10) + ")"
	}
}

// Parse converts a configuration string to a Class.
//
// Unknown values are an error rather than a fallback to default: a typo in a traffic_class field
// would otherwise silently disable the policy the operator asked for.
func Parse(value string) (Class, error) {
	switch value {
	case "", "default":
		return ClassDefault, nil
	case "interactive":
		return ClassInteractive, nil
	case "bulk":
		return ClassBulk, nil
	case "realtime":
		return ClassRealtime, nil
	default:
		return ClassDefault, E.New("unknown traffic class: ", value)
	}
}

// IsHighPriority reports whether the class schedules in the high-priority lane.
//
// The lane split is intentionally coarse for the first round: interactive and realtime are both
// "someone is waiting", and the difference between them is not yet acted on.
func (c Class) IsHighPriority() bool {
	return c == ClassInteractive || c == ClassRealtime
}

// IsDefault reports whether the flow is unclassified.
func (c Class) IsDefault() bool {
	return c == ClassDefault
}
