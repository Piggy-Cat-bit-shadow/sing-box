package bridge

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

// Tests for the ownership of a bridge instance index.
//
// # The resource
//
// A bridge claims one of bridgeMaxInstances PROCESS-GLOBAL slots, which selects the addresses and
// ports it uses. Global state outlives any object that fails to be constructed, so who owns a slot
// and when it is returned is a correctness question rather than bookkeeping.
//
// # The defect these pin
//
// The index was allocated in the CONSTRUCTOR and released only in Close. A constructor does not own
// a running resource, and nothing closes an object that was never successfully built: when a later
// part of startup fails, the object is discarded and Close is never called. Each failure therefore
// burned a slot permanently, and enough failures would make bridge creation fail with a limit error
// the configuration had not actually reached.

// usedIndexCount reports how many global slots are claimed.
func usedIndexCount() int {
	bridgeIndexAccess.Lock()
	defer bridgeIndexAccess.Unlock()
	count := 0
	for _, inUse := range bridgeIndexInUse {
		if inUse {
			count++
		}
	}
	return count
}

// constructBackend builds a backend exactly as the outbound constructor does.
func constructBackend(t *testing.T, tag string) (Backend, error) {
	t.Helper()
	return newBackend(
		context.Background(),
		log.NewNOPFactory().NewLogger("bridge"),
		nil,
		tag,
		option.BridgeOutboundOptions{},
	)
}

// TestAbandonedConstructorDoesNotLeakIndex is the release blocker.
//
// A bridge constructed and then ABANDONED - which is exactly what happens when a later part of
// startup fails - must not hold its slot forever.
func TestAbandonedConstructorDoesNotLeakIndex(t *testing.T) {
	before := usedIndexCount()

	backend, err := constructBackend(t, "abandoned")
	if err != nil {
		require.Equal(t, before, usedIndexCount(),
			"a failed construction must not leave a slot claimed")
		t.Skipf("backend construction unavailable on this platform: %v", err)
	}

	// Construction must claim NOTHING.
	//
	// A constructor has no failure path and nothing closes an object that was never built, so a
	// slot claimed here is lost whenever startup fails afterwards.
	require.Equal(t, before, usedIndexCount(),
		"the constructor claimed a global bridge slot. A startup failure after bridge "+
			"construction discards the object without calling Close, so the slot is burned "+
			"permanently - and %d such failures make a LATER VALID configuration fail with a limit "+
			"error it never reached. The slot must be acquired by the owned lifecycle",
		bridgeMaxInstances)

	// Abandon it: no Close, which is precisely what a failed startup does. Nothing to leak.
	_ = backend
	require.Equal(t, before, usedIndexCount(), "an abandoned object holds nothing")
}

// TestManyAbandonedConstructorsDoNotExhaustThePool is the same defect at scale.
//
// This is the shape a user actually hits: a configuration that fails to start repeatedly.
func TestManyAbandonedConstructorsDoNotExhaustThePool(t *testing.T) {
	before := usedIndexCount()

	constructed := 0
	for attempt := 0; attempt < bridgeMaxInstances+10; attempt++ {
		backend, err := constructBackend(t, "repeated")
		if err != nil {
			break
		}
		constructed++
		_ = backend
	}

	if constructed == 0 {
		t.Skip("backend construction unavailable on this platform")
	}

	require.Equal(t, before, usedIndexCount(),
		"after %d abandoned constructions the pool must be back where it started. Leaking here "+
			"means a configuration that fails to start a few times permanently exhausts the bridge "+
			"index pool, and a later valid configuration is refused for a limit it never reached",
		constructed)
}

// TestExhaustedPoolBlocksALaterValidConfiguration is the user-visible consequence.
//
// Repeated startup failures must not make a subsequent valid configuration fail.
func TestExhaustedPoolBlocksALaterValidConfiguration(t *testing.T) {
	// Drain the pool the way repeated failed startups do.
	drained := 0
	for attempt := 0; attempt < bridgeMaxInstances+5; attempt++ {
		backend, err := constructBackend(t, "drain")
		if err != nil {
			break
		}
		drained++
		_ = backend
	}
	if drained == 0 {
		t.Skip("backend construction unavailable on this platform")
	}

	// A valid configuration now asks for a bridge.
	_, err := constructBackend(t, "valid")

	require.NoError(t, err,
		"after %d abandoned constructions a VALID bridge could not be created: %v. The user's "+
			"configuration is refused for a global limit it never reached, because slots leaked "+
			"from objects that were never closed", drained, err)
}

// TestAcquireReleaseCycleIsBalanced is the positive control.
//
// The slot must be claimed while held and returned afterwards, or the fix would have replaced a
// leak with a different bug. The full network start needs a real TUN device that a unit test
// cannot create, so this drives the ownership contract directly - which is the part that was
// broken and the part Start and Close delegate to.
func TestAcquireReleaseCycleIsBalanced(t *testing.T) {
	before := usedIndexCount()

	base := &backendBase{}
	_, err := base.acquireIndex()
	require.NoError(t, err, "acquiring an index succeeds")
	require.Equal(t, before+1, usedIndexCount(), "an acquired slot is held")

	base.releaseIndex()
	require.Equal(t, before, usedIndexCount(), "releasing returns it")
}

// TestAcquireIndexIsIdempotent guards against a repeated Start consuming a second slot.
func TestAcquireIndexIsIdempotent(t *testing.T) {
	before := usedIndexCount()

	base := &backendBase{}
	_, err := base.acquireIndex()
	require.NoError(t, err)
	_, err = base.acquireIndex()
	require.NoError(t, err, "a second Start must not allocate again")
	_, err = base.acquireIndex()
	require.NoError(t, err)
	require.Equal(t, before+1, usedIndexCount(),
		"repeated acquisition must hold exactly one slot, not one per call")

	base.releaseIndex()
	require.Equal(t, before, usedIndexCount())
}

// TestReleaseIndexIsIdempotent guards against a double release.
//
// A failed Start calls Close, and a later Close may follow. Freeing a slot twice hands it to a
// second bridge while the first still believes it owns it, which corrupts the pool rather than
// merely leaking from it.
func TestReleaseIndexIsIdempotent(t *testing.T) {
	before := usedIndexCount()

	base := &backendBase{}
	_, err := base.acquireIndex()
	require.NoError(t, err)

	base.releaseIndex()
	base.releaseIndex()
	base.releaseIndex()

	require.Equal(t, before, usedIndexCount(),
		"repeated release must return the slot once; the helper is what Start's failure path and "+
			"Close both call, so idempotence is what makes their combination safe")
}

// TestReleaseWithoutAcquireIsSafe covers Close on a bridge that never started.
func TestReleaseWithoutAcquireIsSafe(t *testing.T) {
	before := usedIndexCount()

	base := &backendBase{}
	base.releaseIndex()

	require.Equal(t, before, usedIndexCount(),
		"closing a bridge that never started must not free a slot it never held")
}
