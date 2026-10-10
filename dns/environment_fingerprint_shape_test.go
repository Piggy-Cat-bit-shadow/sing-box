package dns

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"

	"github.com/stretchr/testify/require"
)

// Tests for the order-invariance and change-sensitivity of the aggregate DNS-environment fingerprint.
//
// # Why these exist
//
// The fingerprint used to be an FNV-1a stream over a list SORTED BY TAG. It is now an XOR of one
// running FNV per transport, which is what removed the sort, the slice and the description join from
// the connection path (measured: 32 transports went from 8290 ns / 73 allocs to 1261 ns / 0 allocs per
// lookup). The rewrite changed the ARITHMETIC, so the two properties that make the value usable as an
// epoch have to be re-established rather than assumed:
//
//  1. INVARIANT across transports: `Transports()` is backed by a map, so the iteration order is not a
//     property of the environment. A fingerprint that moved when the map did would advance the epoch
//     on its own and retire every cached answer for no reason. This is the failure the old sort
//     existed to prevent, and XOR is what prevents it now.
//  2. SENSITIVE to a change: a different resolver list, a different tag, or the same entries in a
//     different order within ONE transport must all produce a different value. The within-transport
//     order is significant on purpose - it is resolution semantics, and Client.environmentHash hashes
//     that list in order, so a fingerprint blind to it would sit on an older epoch than the namespace
//     the caches had already moved to.

// fingerprintRouter builds a Router over the given transports, in the given order.
func fingerprintRouter(transports ...adapter.DNSTransport) *Router {
	return &Router{
		logger:    log.NewNOPFactory().Logger(),
		transport: &benchmarkTransportManager{transports: transports},
	}
}

func fingerprintTransport(tag string, environment ...string) *benchmarkTransport {
	return &benchmarkTransport{tag: tag, environment: environment}
}

// TestFingerprintIsInvariantAcrossTransportOrder is property 1.
func TestFingerprintIsInvariantAcrossTransportOrder(t *testing.T) {
	first := fingerprintTransport("a", "resolver-a.example")
	second := fingerprintTransport("b", "resolver-b.example")
	third := fingerprintTransport("c", "resolver-c.example")

	forward, forwardPublished := fingerprintRouter(first, second, third).dnsEnvironmentFingerprintOnly()
	reverse, reversePublished := fingerprintRouter(third, second, first).dnsEnvironmentFingerprintOnly()
	shuffled, shuffledPublished := fingerprintRouter(second, third, first).dnsEnvironmentFingerprintOnly()

	require.True(t, forwardPublished)
	require.True(t, reversePublished)
	require.True(t, shuffledPublished)
	require.Equal(t, forward, reverse,
		"the aggregate must not depend on the order Transports() happened to return, or the epoch "+
			"would advance on map iteration alone")
	require.Equal(t, forward, shuffled)
}

// TestFingerprintChangesWithTheEnvironment is property 2, across the three shapes of change.
func TestFingerprintChangesWithTheEnvironment(t *testing.T) {
	base, _ := fingerprintRouter(
		fingerprintTransport("a", "resolver-a.example"),
		fingerprintTransport("b", "resolver-b.example"),
	).dnsEnvironmentFingerprintOnly()

	changedEntry, _ := fingerprintRouter(
		fingerprintTransport("a", "resolver-a.example"),
		fingerprintTransport("b", "resolver-DIFFERENT.example"),
	).dnsEnvironmentFingerprintOnly()
	require.NotEqual(t, base, changedEntry, "a changed resolver list must move the fingerprint")

	changedTag, _ := fingerprintRouter(
		fingerprintTransport("a", "resolver-a.example"),
		fingerprintTransport("RENAMED", "resolver-b.example"),
	).dnsEnvironmentFingerprintOnly()
	require.NotEqual(t, base, changedTag,
		"the tag is part of the value, so renaming the transport that publishes it is a change")

	addedTransport, _ := fingerprintRouter(
		fingerprintTransport("a", "resolver-a.example"),
		fingerprintTransport("b", "resolver-b.example"),
		fingerprintTransport("c", "resolver-c.example"),
	).dnsEnvironmentFingerprintOnly()
	require.NotEqual(t, base, addedTransport, "a third resolver must move the fingerprint")
}

// TestFingerprintIsSensitiveToOrderWithinOneTransport is the deliberate asymmetry: order-INSENSITIVE
// across transports, order-SENSITIVE within one transport's list.
func TestFingerprintIsSensitiveToOrderWithinOneTransport(t *testing.T) {
	inOrder, _ := fingerprintRouter(
		fingerprintTransport("a", "first.example", "second.example"),
	).dnsEnvironmentFingerprintOnly()
	reordered, _ := fingerprintRouter(
		fingerprintTransport("a", "second.example", "first.example"),
	).dnsEnvironmentFingerprintOnly()
	require.NotEqual(t, inOrder, reordered,
		"the published order is resolution semantics and Client.environmentHash hashes it in order, "+
			"so a fingerprint blind to it would lag the namespace the caches had already moved to")
}

// TestFingerprintIgnoresTransportsThatPublishNothing keeps the existing rule: a transport with no
// environment of its own contributes nothing, which is the same rule Client.environmentHash applies.
func TestFingerprintIgnoresTransportsThatPublishNothing(t *testing.T) {
	withSilent, published := fingerprintRouter(
		fingerprintTransport("a", "resolver-a.example"),
		fingerprintTransport("silent"),
	).dnsEnvironmentFingerprintOnly()
	withoutSilent, _ := fingerprintRouter(
		fingerprintTransport("a", "resolver-a.example"),
	).dnsEnvironmentFingerprintOnly()

	require.True(t, published)
	require.Equal(t, withoutSilent, withSilent,
		"a transport that publishes an empty list must not perturb the value")

	// And a Router where NOTHING publishes an environment reports that, rather than inventing a value.
	_, anyPublished := fingerprintRouter(fingerprintTransport("silent")).dnsEnvironmentFingerprintOnly()
	require.False(t, anyPublished)

	_, nilPublished := (&Router{logger: log.NewNOPFactory().Logger()}).dnsEnvironmentFingerprintOnly()
	require.False(t, nilPublished, "a Router with no transport manager must degrade, not panic")
}

// TestFingerprintDoesNotShiftAcrossRepeatedReads is the de-bounce property the epoch depends on: a
// stably re-read environment must produce the SAME value every time, or every lookup would advance the
// generation and purge the reverse mapping.
func TestFingerprintDoesNotShiftAcrossRepeatedReads(t *testing.T) {
	router := fingerprintRouter(
		fingerprintTransport("a", "resolver-a.example", "resolver-b.example"),
		fingerprintTransport("b", "resolver-c.example"),
	)
	first, published := router.dnsEnvironmentFingerprintOnly()
	require.True(t, published)
	for range 64 {
		again, _ := router.dnsEnvironmentFingerprintOnly()
		require.Equal(t, first, again,
			"an unchanged environment must fingerprint identically on every read")
	}
}

// TestFingerprintStillMatchesTheDescriptionForm proves the two halves describe the same environment:
// the value used for comparison and the string used for logging must not disagree about what is
// published, or a change could be logged as "changed" with an identical description.
func TestFingerprintStillMatchesTheDescriptionForm(t *testing.T) {
	router := fingerprintRouter(
		fingerprintTransport("b", "resolver-b.example"),
		fingerprintTransport("a", "resolver-a.example"),
	)
	fingerprint, description, published := router.dnsEnvironmentFingerprintNow()
	require.True(t, published)
	require.Equal(t, "a=resolver-a.example, b=resolver-b.example", description,
		"the description is sorted by tag, which is what makes a log line stable")

	only, onlyPublished := router.dnsEnvironmentFingerprintOnly()
	require.True(t, onlyPublished)
	require.Equal(t, fingerprint, only,
		"the description form and the fingerprint-only form must agree on the value")
}
