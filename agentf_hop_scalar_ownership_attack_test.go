package box

import (
	"testing"

	"github.com/sagernet/sing-box/common/physicalpath"

	"github.com/stretchr/testify/require"
)

// Agent F, round 4: the nested fields of `PathStatus.Hops`, verified against the RUNNING code.
//
// # Why this exists
//
// `TestStatusFailureIsAValueOwnedByTheCaller` clobbers every field of the one `*HopFailure` the
// answer carries, and that was my round-3 NOT-DONE item - so the pointer case is now closed. What
// remained was the rest of the value-vs-view question, which I had answered only by reading the struct
// definitions: `HopStatus`, `MTUStatus`, `Generation` and `ControlNode` are made of strings, ints and
// bools, and Go copies those by value, so no field of theirs CAN alias.
//
// A claim about aliasing is a claim about memory, and this repository's rule is to measure rather than
// to reason. So every scalar is clobbered here and the answer is read again: if ANY of them were
// reached through a slice the Box still holds, the second read would show the clobber.
//
// # Why a zero is still a usable probe
//
// The fixture leaves MTU and the generations unestablished, which is exactly the state a caller is
// most likely to read before Start. Clobbering an unestablished field to a loud value and finding it
// back at zero is what proves the copy: an aliased field would keep the loud value.
func TestAgentFEveryHopScalarIsCopiedNotShared(t *testing.T) {
	inner := &statusTestLeaf{tag: "inner", leafType: "test", state: physicalpath.LifecycleStateReady}
	middle := &statusTestLeaf{
		tag:            "middle",
		leafType:       "test",
		state:          physicalpath.LifecycleStateReady,
		dependsOn:      []string{"inner"},
		lastError:      errStatusNoDial,
		lastErrorPhase: physicalpath.PhaseConnect,
	}
	outer := &statusTestLeaf{tag: "outer", leafType: "test", state: physicalpath.LifecycleStateReady, dependsOn: []string{"middle"}}
	instance, _ := statusTestBox(inner, middle, outer)

	first := instance.Status("outer", "tcp")
	require.Len(t, first.Hops, 3, "the fixture must produce the three-hop packet order this test needs")

	// Record the undisturbed answer, so the second read is compared against what it really was
	// rather than against what the fixture was assumed to produce.
	type snapshot struct {
		position  int
		tag       string
		leafTag   string
		hopType   string
		endpoint  bool
		readiness physicalpath.StatusReadiness
		claimed   physicalpath.LifecycleState
		mtu       physicalpath.MTUStatus
		gens      physicalpath.Generation
		errGen    physicalpath.Generation
		reason    string
	}
	was := make([]snapshot, len(first.Hops))
	for index, hop := range first.Hops {
		was[index] = snapshot{
			position: hop.Position, tag: hop.Tag, leafTag: hop.LeafTag, hopType: hop.Type,
			endpoint: hop.Endpoint, readiness: hop.Readiness, claimed: hop.ClaimedState,
			mtu: hop.MTU, gens: hop.Generations, errGen: hop.LastErrorGeneration, reason: hop.Reason,
		}
	}

	// CLOBBER every scalar, including the whole nested MTUStatus and both Generations.
	for index := range first.Hops {
		hop := &first.Hops[index]
		hop.Position = 900 + index
		hop.Tag = "clobbered"
		hop.LeafTag = "clobbered"
		hop.Type = "clobbered"
		hop.Endpoint = !hop.Endpoint
		hop.SelectedBy = "clobbered"
		hop.Readiness = physicalpath.ReadinessReady
		hop.ClaimedState = physicalpath.LifecycleStateReady
		hop.LastError = "clobbered"
		hop.LastErrorPhase = physicalpath.PhaseTunnel
		hop.LastErrorRecovered = true
		hop.LastErrorGeneration = physicalpath.Generation{Network: 999, Resource: 999}
		hop.Generations = physicalpath.Generation{Network: 777, Resource: 777}
		hop.MTU = physicalpath.MTUStatus{
			InnerIP: 999, InnerUDPIPv4: 999, InnerUDPIPv6: 999, OuterQUICInitial: 999,
			Encapsulated: 999, Known: true, OuterKnown: true, Reason: "clobbered",
		}
		hop.Reason = "clobbered"
	}

	// The whole slice header is clobbered too: a caller that truncates or reorders its own copy must
	// not be editing the Box's.
	first.Hops = first.Hops[:1]

	second := instance.Status("outer", "tcp")
	require.Len(t, second.Hops, 3,
		"a caller truncating its own Hops reached the Box's answer: the slice is shared, not copied")

	for index, hop := range second.Hops {
		want := was[index]
		require.Equal(t, want.position, hop.Position)
		require.Equal(t, want.tag, hop.Tag)
		require.Equal(t, want.leafTag, hop.LeafTag)
		require.Equal(t, want.hopType, hop.Type)
		require.Equal(t, want.endpoint, hop.Endpoint)
		require.Equal(t, want.readiness, hop.Readiness)
		require.Equal(t, want.claimed, hop.ClaimedState)
		require.Equal(t, want.mtu, hop.MTU,
			"hop %d's nested MTUStatus kept a clobbered value, so the field is reached through shared "+
				"storage rather than copied", index)
		require.Equal(t, want.gens, hop.Generations,
			"hop %d's Generations kept a clobbered value", index)
		require.Equal(t, want.errGen, hop.LastErrorGeneration,
			"hop %d's LastErrorGeneration kept a clobbered value", index)
		require.Equal(t, want.reason, hop.Reason)
	}

	t.Logf("MEASURED: %d hops x every scalar including the whole nested MTUStatus and both "+
		"Generations clobbered; the second read reproduced all of them", len(second.Hops))
}
