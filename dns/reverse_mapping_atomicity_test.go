package dns

import (
	"net/netip"
	"testing"
	"time"

	mDNS "github.com/miekg/dns"

	"github.com/stretchr/testify/require"
)

// Tests for the atomicity of the reverse-mapping invalidation protocol.
//
// # The window these pin
//
// recordReverseMappingFrom asked the generation whether the captured epoch was still current and
// THEN wrote the answers, in two separate steps with no shared boundary:
//
//	if !r.reverseMappingGenerationCurrent(generation) { return }
//	for _, answer := range response.Answer {
//	    r.dnsReverseMapping.AddWithLifetime(...)      // <- after the check, unguarded
//	}
//
// Everything that invalidates this cache - observeDNSEnvironment for a resolver/search-domain change,
// ResetNetwork for a network transition - advances an epoch and purges the cache. A purge that lands
// in the gap between the check and the write therefore removes nothing that the write is about to
// add: the answer describes the resolver set the device was on when the QUESTION was asked, and it is
// recorded as if it belonged to the one it is on now.
//
// # How the gap is held open
//
// The router exposes one seam at exactly that boundary - testReverseMappingRecordHook, evaluated
// after the epoch comparison and before the writes. A test holds the recording side there and
// completes a real invalidation from the other side, through the router's own entry points, with a
// real environment change behind it. Nothing here is a reimplementation of the cache or of the
// invalidation; the seam decides only WHEN the two sides meet.
//
// The wait for the seam is bounded. A build in which the seam is never reached fails with that as the
// reason instead of hanging: a check that has already returned cannot be held apart from the write
// that follows it, which is the defect itself.

// recordBoundaryTimeout bounds the wait for the recording seam.
const recordBoundaryTimeout = 10 * time.Second

// awaitRecordBoundary waits for the recording side to reach the boundary between its ownership check
// and its publication.
func awaitRecordBoundary(t *testing.T, recordReady <-chan struct{}) {
	t.Helper()
	select {
	case <-recordReady:
	case <-time.After(recordBoundaryTimeout):
		t.Fatal("the recording never reached the boundary between the ownership check and the " +
			"publication of the answers: this build has no decision to hold open, which is itself " +
			"the defect - the check and the write are not one step")
	}
}

// awaitRecordDone waits for the recording goroutine to finish.
func awaitRecordDone(t *testing.T, recordDone <-chan struct{}) {
	t.Helper()
	select {
	case <-recordDone:
	case <-time.After(recordBoundaryTimeout):
		t.Fatal("the recording never finished")
	}
}

// beginRecordingAtTheBoundary starts a recording of one response and returns the channels a test
// needs: `reached` closes when the recording is stopped at the boundary, `release` lets it continue,
// `done` closes when it has finished.
//
// While the recording is stopped at the boundary the caller holds it there and runs whatever
// invalidation it wants to prove the boundary is atomic against.
func beginRecordingAtTheBoundary(t *testing.T, router *Router, message *mDNS.Msg, response *mDNS.Msg, transport *mutableEnvironmentTransport, generation uint64) (reached chan struct{}, release chan struct{}, done chan struct{}) {
	t.Helper()
	reached = make(chan struct{})
	release = make(chan struct{})
	done = make(chan struct{})
	var reachedOnce bool
	router.testReverseMappingRecordHook = func([]reverseMappingAnswer, uint64) {
		if reachedOnce {
			return
		}
		reachedOnce = true
		close(reached)
		<-release
	}
	go func() {
		defer close(done)
		router.recordReverseMappingFrom(message, response, transport, generation)
	}()
	return reached, release, done
}

// answerWithAddresses builds the message/response pair the recording path consumes, from
// name/address pairs.
func answerWithAddresses(pairs ...any) (*mDNS.Msg, *mDNS.Msg) {
	response := new(mDNS.Msg)
	for index := 0; index+1 < len(pairs); index += 2 {
		name := pairs[index].(string)
		address := pairs[index+1].(netip.Addr)
		response.Answer = append(response.Answer, &mDNS.A{
			Hdr: mDNS.RR_Header{Name: mDNS.Fqdn(name), Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: 300},
			A:   address.AsSlice(),
		})
	}
	message := new(mDNS.Msg)
	message.Question = []mDNS.Question{{Name: mDNS.Fqdn("recorded.example"), Qtype: mDNS.TypeA, Qclass: mDNS.ClassINET}}
	return message, response
}

// TestReverseMappingAnswerIsNotRecordedAcrossAnEnvironmentChange is the window, forced
// deterministically, for the DNS-only invalidation source.
//
// Establish the environment, capture a generation, hold the recording at the boundary, let the
// resolver set change so the invalidation completes for real, and only then let the recording
// continue. The answer was asked for under the OLD resolver set, and the invalidation has already
// finished by the time a write would happen.
func TestReverseMappingAnswerIsNotRecordedAcrossAnEnvironmentChange(t *testing.T) {
	address := netip.MustParseAddr("203.0.113.11")
	establishing := newMutableEnvironmentTransport("atomic-establish", "1.1.1.1:53")
	transport := newMutableEnvironmentTransport("atomic-invalidation", "1.1.1.1:53")
	transport.address = address
	router := newRouterForEnvironmentTest(t, establishing, transport)

	// Pin the environment: the change below is then a genuine change rather than the first
	// observation.
	exchangeForEnvironmentTest(t, router, establishing, "pin.example")
	require.EqualValues(t, 0, router.dnsGeneration())

	// The generation is captured as prepareExchange captures it: when the question is issued.
	capturedGeneration := router.dnsGeneration()
	message, response := answerWithAddresses("split-horizon.example", address)

	reached, release, done := beginRecordingAtTheBoundary(t, router, message, response, transport, capturedGeneration)
	awaitRecordBoundary(t, reached)

	// The resolvers change on the SAME interface while the recording is stopped at the boundary. This
	// is the router's own invalidation entry point, so the epoch advance and the purge are exactly the
	// ones production performs.
	transport.setEnvironment("9.9.9.9:53")
	advanced := router.observeDNSEnvironment()
	require.Greater(t, advanced, uint64(0),
		"the premise of this test: the environment change must advance the DNS generation")
	require.NotEqual(t, capturedGeneration, router.dnsGeneration(),
		"the premise of this test: the captured generation must be stale by now")

	close(release)
	awaitRecordDone(t, done)

	_, loaded := router.LookupReverseMapping(address)
	require.False(t, loaded,
		"an answer to a question asked under the previous resolver set was recorded AFTER the change "+
			"had advanced the generation and completed its purge. The check and the write are two "+
			"separate steps, so the purge completes in the gap between them and the mapping it was "+
			"supposed to retire is added immediately afterwards - describing a name learned from "+
			"resolvers the device is no longer using")
}

// TestReverseMappingAnswerIsNotRecordedAcrossANetworkTransition is the same window for the other
// invalidation source, ResetNetwork.
func TestReverseMappingAnswerIsNotRecordedAcrossANetworkTransition(t *testing.T) {
	address := netip.MustParseAddr("203.0.113.12")
	establishing := newMutableEnvironmentTransport("atomic-reset-establish", "1.1.1.1:53")
	transport := newMutableEnvironmentTransport("atomic-reset", "1.1.1.1:53")
	transport.address = address
	router := newRouterForEnvironmentTest(t, establishing, transport)

	exchangeForEnvironmentTest(t, router, establishing, "pin.example")
	capturedGeneration := router.dnsGeneration()
	message, response := answerWithAddresses("transition.example", address)

	reached, release, done := beginRecordingAtTheBoundary(t, router, message, response, transport, capturedGeneration)
	awaitRecordBoundary(t, reached)

	router.ResetNetwork()
	close(release)
	awaitRecordDone(t, done)

	_, loaded := router.LookupReverseMapping(address)
	require.False(t, loaded,
		"a network transition purged the reverse mapping and the in-flight response refilled it: the "+
			"generation check and the write are not one decision, so the purge and the write interleave")
}

// TestReverseMappingLookupObservesTheEnvironmentWithoutANewQuery pins the second reachability
// question: LookupReverseMapping was a bare cache Get, so between the resolver change and the first
// new DNS request the route policy could still read a name learned from the previous resolver set.
//
// Nothing in this test issues a DNS query after the change. If the lookup does not observe the
// environment itself, the old name is still there.
func TestReverseMappingLookupObservesTheEnvironmentWithoutANewQuery(t *testing.T) {
	address := netip.MustParseAddr("203.0.113.13")
	transport := newMutableEnvironmentTransport("lazy-observation", "1.1.1.1:53")
	transport.address = address
	router := newRouterForEnvironmentTest(t, transport)

	exchangeForEnvironmentTest(t, router, transport, "before-change.example")
	domain, loaded := router.LookupReverseMapping(address)
	require.True(t, loaded, "the premise: the answer was recorded")
	require.Equal(t, "before-change.example", domain)

	// The resolver set changes. No query follows it - this is the window between the change and the
	// first new DNS request.
	transport.setEnvironment("9.9.9.9:53")

	domain, loaded = router.LookupReverseMapping(address)
	require.False(t, loaded,
		"route policy read %q from the reverse mapping after the resolver set changed and before any "+
			"new DNS request was issued. Every other DNS cache is namespaced by the live environment "+
			"hash, so only this one can be read this way, and with split-horizon or captive-portal DNS "+
			"the same address means a different name on the new resolvers", domain)
}

// TestReverseMappingBatchIsAllOrNothing pins that the invalidation is a decision about the WHOLE
// response, not about each answer in turn: a response carrying several addresses must not land part
// of its names in the retired epoch.
func TestReverseMappingBatchIsAllOrNothing(t *testing.T) {
	first := netip.MustParseAddr("203.0.113.21")
	second := netip.MustParseAddr("203.0.113.22")
	establishing := newMutableEnvironmentTransport("atomic-batch-establish", "1.1.1.1:53")
	transport := newMutableEnvironmentTransport("atomic-batch", "1.1.1.1:53")
	router := newRouterForEnvironmentTest(t, establishing, transport)

	exchangeForEnvironmentTest(t, router, establishing, "pin.example")
	capturedGeneration := router.dnsGeneration()
	message, response := answerWithAddresses("first.example", first, "second.example", second)

	reached, release, done := beginRecordingAtTheBoundary(t, router, message, response, transport, capturedGeneration)
	awaitRecordBoundary(t, reached)

	transport.setEnvironment("9.9.9.9:53")
	router.observeDNSEnvironment()
	close(release)
	awaitRecordDone(t, done)

	for _, probe := range []struct {
		address netip.Addr
		name    string
	}{{first, "first.example"}, {second, "second.example"}} {
		domain, loaded := router.LookupReverseMapping(probe.address)
		require.False(t, loaded,
			"%s was recorded from a response that belongs to the retired epoch (as %q): a response "+
				"carrying several addresses must be accepted or refused as one decision, or a single "+
				"answer lands half in the old epoch and half in the new one", probe.address, domain)
	}
}

// TestDNSOnlyChangeLeavesTheNetworkEpochAndTransportsAlone is the containment rule: the DNS
// environment invalidation must not become a network transition.
func TestDNSOnlyChangeLeavesTheNetworkEpochAndTransportsAlone(t *testing.T) {
	transport := newMutableEnvironmentTransport("containment", "1.1.1.1:53")
	router := newRouterForEnvironmentTest(t, transport)

	exchangeForEnvironmentTest(t, router, transport, "pin.example")
	networkEpochBefore := router.networkGeneration.Load()
	generationBefore := router.dnsGeneration()

	transport.setEnvironment("9.9.9.9:53")
	generationAfter := router.dnsGeneration()

	require.Greater(t, generationAfter, generationBefore,
		"the resolver change must advance the DNS environment generation")
	require.Equal(t, networkEpochBefore, router.networkGeneration.Load(),
		"a DNS-only change advanced the NETWORK epoch: that epoch tears connections down, and the "+
			"interface never changed, so every active QUIC, H2, MASQUE and voice session on this "+
			"device would be killed for a resolver change")
	require.EqualValues(t, 0, transport.resetCount.Load(),
		"a DNS-only change reset the transport, which would drop the connections the resolver set "+
			"has nothing to do with")
}

// TestReverseMappingRecordingIsRefusedOnceTheInvalidationHasCompleted is the same window with the
// ordering made explicit, so the assertion cannot be satisfied by a check that merely happens to run
// late.
//
// The hook completes the invalidation itself and records that it has done so. By the time the
// recording side continues, the epoch has advanced AND the purge has run against a cache this
// response had already put a mapping into, so the only thing that can still refuse the answer is the
// comparison the protocol makes after the invalidation. The cache is checked directly as well as
// through the lookup, so "nothing was written" is asserted even if the lookup had observed the
// environment itself.
func TestReverseMappingRecordingIsRefusedOnceTheInvalidationHasCompleted(t *testing.T) {
	address := netip.MustParseAddr("203.0.113.31")
	control := netip.MustParseAddr("203.0.113.32")
	establishing := newMutableEnvironmentTransport("explicit-order-establish", "1.1.1.1:53")
	transport := newMutableEnvironmentTransport("explicit-order", "1.1.1.1:53")
	transport.address = address
	router := newRouterForEnvironmentTest(t, establishing, transport)

	exchangeForEnvironmentTest(t, router, establishing, "pin.example")
	capturedGeneration := router.dnsGeneration()
	message, response := answerWithAddresses("explicit.example", address)

	var invalidationCompleted bool
	router.testReverseMappingRecordHook = func(_ []reverseMappingAnswer, _ uint64) {
		// A mapping that must not survive the invalidation, written before it runs, so "the purge
		// really ran" is observable rather than assumed.
		router.dnsReverseMapping.AddWithLifetime(control, "control.example", time.Hour)
		transport.setEnvironment("9.9.9.9:53")
		router.observeDNSEnvironment()
		invalidationCompleted = true
	}

	router.recordReverseMappingFrom(message, response, transport, capturedGeneration)

	require.True(t, invalidationCompleted, "the premise: the invalidation ran inside the boundary")
	if _, loaded := router.dnsReverseMapping.Get(control); loaded {
		t.Fatal("the premise: the invalidation's purge must have removed the control mapping")
	}
	require.Equal(t, 0, router.dnsReverseMapping.Len(),
		"the answer was published into the reverse mapping after the invalidation had already "+
			"completed: the ownership check and the write are not one decision, so an answer asked "+
			"for under the retired resolver set survives the purge that was supposed to retire it")
}
