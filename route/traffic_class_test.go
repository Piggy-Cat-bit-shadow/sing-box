package route

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/trafficclass"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

// fakeTaggedOutbound satisfies adapter.Outbound by embedding the interface: every method other than
// Tag panics, which is exactly the contract resolveTrafficClass must honour. If the resolver ever
// starts reading more of the outbound, these tests fail loudly instead of silently changing
// meaning.
type fakeTaggedOutbound struct {
	adapter.Outbound
	tag string
}

func (f fakeTaggedOutbound) Tag() string { return f.tag }

func chain(tags ...string) []adapter.Outbound {
	result := make([]adapter.Outbound, len(tags))
	for i, tag := range tags {
		result[i] = fakeTaggedOutbound{tag: tag}
	}
	return result
}

func policy(class trafficclass.Class) option.TrafficClassPolicy {
	return option.TrafficClassPolicy{Class: class}
}

// TestResolveTrafficClassAutoDetection covers the automatic path, which is how this fork's
// production configuration works: nothing states a class, and the AI group is recognised by tag.
func TestResolveTrafficClassAutoDetection(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		tags  []string
		class trafficclass.Class
	}{
		{"outermost group is AI", []string{"?? AI", "Residential", "VLESS-US"}, trafficclass.ClassInteractive},
		{"middle group is AI", []string{"Proxy", "?? AI", "VLESS-US"}, trafficclass.ClassInteractive},
		{"leaf tag is AI", []string{"Proxy", "OpenAI"}, trafficclass.ClassInteractive},
		{"no AI anywhere", []string{"Proxy", "VLESS-US"}, trafficclass.ClassDefault},
		{"near miss is not AI", []string{"Proxy", "NaiveProxy"}, trafficclass.ClassDefault},
		{"single AI leaf", []string{"ai"}, trafficclass.ClassInteractive},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.class, resolveTrafficClass(chain(testCase.tags...), nil),
				"tags %v", testCase.tags)
		})
	}
}

// TestResolveTrafficClassExplicitBeatsAuto pins the first precedence rule.
func TestResolveTrafficClassExplicitBeatsAuto(t *testing.T) {
	policies := TrafficClassPolicies{"Proxy": policy(trafficclass.ClassBulk)}

	require.Equal(t, trafficclass.ClassBulk,
		resolveTrafficClass(chain("Proxy", "?? AI", "VLESS-US"), policies),
		"an explicit class must win over an inner AI tag")

	// And the automatic rule still applies where no explicit policy exists.
	require.Equal(t, trafficclass.ClassInteractive,
		resolveTrafficClass(chain("Other", "?? AI"), policies))
}

// TestResolveTrafficClassExplicitDefaultBlocksAuto is the reason the configuration type can
// distinguish unset from default: without it there is no way to exclude an outbound from automatic
// classification.
func TestResolveTrafficClassExplicitDefaultBlocksAuto(t *testing.T) {
	policies := TrafficClassPolicies{"Proxy": policy(trafficclass.ClassDefault)}

	require.Equal(t, trafficclass.ClassDefault,
		resolveTrafficClass(chain("Proxy", "?? AI", "OpenAI"), policies),
		"an explicit default must stop automatic detection for the whole chain")
}

// TestResolveTrafficClassOutermostExplicitWins: the first explicit value scanning outward-in is
// authoritative, so an inner level cannot override the entry group's decision.
func TestResolveTrafficClassOutermostExplicitWins(t *testing.T) {
	policies := TrafficClassPolicies{
		"Outer": policy(trafficclass.ClassInteractive),
		"Inner": policy(trafficclass.ClassBulk),
	}
	require.Equal(t, trafficclass.ClassInteractive,
		resolveTrafficClass(chain("Outer", "Middle", "Inner"), policies))
}

// TestResolveTrafficClassExplicitSuppressesAutoForWholeChain: automatic detection is a property of
// the chain, not of each level. Once any level states a policy, no level is auto-classified.
func TestResolveTrafficClassExplicitSuppressesAutoForWholeChain(t *testing.T) {
	// The leaf is an AI-looking tag but the chain carries an explicit policy at the top.
	policies := TrafficClassPolicies{"Outer": policy(trafficclass.ClassBulk)}
	require.Equal(t, trafficclass.ClassBulk,
		resolveTrafficClass(chain("Outer", "?? AI", "ChatGPT"), policies))
}

// TestResolveTrafficClassInnerExplicitAppliesWhenOuterIsUnset covers the third row of the
// precedence table.
func TestResolveTrafficClassInnerExplicitAppliesWhenOuterIsUnset(t *testing.T) {
	policies := TrafficClassPolicies{"Leaf": policy(trafficclass.ClassBulk)}
	require.Equal(t, trafficclass.ClassBulk,
		resolveTrafficClass(chain("Outer", "Middle", "Leaf"), policies))
}

// TestResolveTrafficClassNoLeafContamination is the property that motivates resolving from the
// chain rather than storing a class on the outbound.
//
// The SAME leaf outbound is reached through two different logical groups. Each flow must get its
// own answer, and the leaf must not acquire a class that outlives the flow.
func TestResolveTrafficClassNoLeafContamination(t *testing.T) {
	// One shared leaf object, used by both flows.
	sharedLeaf := fakeTaggedOutbound{tag: "???? ??? VLESS"}
	aiChain := []adapter.Outbound{fakeTaggedOutbound{tag: "?? AI"}, sharedLeaf}
	normalChain := []adapter.Outbound{fakeTaggedOutbound{tag: "?? ??????"}, sharedLeaf}

	// Interleaved on purpose: a memoised or object-stored class would leak from one to the other.
	require.Equal(t, trafficclass.ClassInteractive, resolveTrafficClass(aiChain, nil))
	require.Equal(t, trafficclass.ClassDefault, resolveTrafficClass(normalChain, nil))
	require.Equal(t, trafficclass.ClassInteractive, resolveTrafficClass(aiChain, nil),
		"the second pass must not have been influenced by the normal flow")
}

// TestResolveTrafficClassEmptyChainIsDefault pins the zero-cost fallback.
func TestResolveTrafficClassEmptyChainIsDefault(t *testing.T) {
	require.Equal(t, trafficclass.ClassDefault, resolveTrafficClass(nil, nil))
	require.Equal(t, trafficclass.ClassDefault, resolveTrafficClass(nil, TrafficClassPolicies{"x": policy(trafficclass.ClassBulk)}))
}
