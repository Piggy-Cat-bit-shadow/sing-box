package http

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// These tests pin the fairness of slot selection.
//
// The strategy is "healthy least-active": the slot with the fewest live tunnels
// must win, because that is the connection whose congestion controller has the
// least queued work. Among slots tied on that minimum, the choice must rotate
// evenly. A tie-break that always lands on the lowest index quietly turns the
// pool back into "slot 0 gets everything", which defeats the point of having a
// pool at all.

// newSelectionTestClient builds a client whose slots are synthetic, so selection
// can be measured without any network.
func newSelectionTestClient(t *testing.T, active []int) *http3ClientImpl {
	t.Helper()
	client := &http3ClientImpl{}
	now := time.Now()
	for _, count := range active {
		slot := &http3PoolSlot{
			state:    http3SlotHealthy,
			active:   count,
			created:  now,
			lastUsed: now,
		}
		client.slots = append(client.slots, slot)
	}
	return client
}

// slotIndex reports the position of a slot in the pool, so tests can assert
// which slot was chosen.
func (c *http3ClientImpl) slotIndex(slot *http3PoolSlot) int {
	for index, candidate := range c.slots {
		if candidate == slot {
			return index
		}
	}
	return -1
}

// TestPickSlotPrefersLeastActive is the primary rule: the minimum active count
// always wins, regardless of index.
func TestPickSlotPrefersLeastActive(t *testing.T) {
	cases := []struct {
		name   string
		active []int
		want   int
	}{
		{"first slot least active", []int{0, 3, 3, 3}, 0},
		{"middle slot least active", []int{4, 1, 4, 4}, 1},
		{"last slot least active", []int{5, 5, 5, 2}, 3},
		{"single slot", []int{0}, 0},
		{"strict minimum only", []int{9, 8, 7, 6}, 3},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			client := newSelectionTestClient(t, testCase.active)
			for range 20 {
				slot := client.pickSlot()
				require.NotNil(t, slot)
				require.Equal(t, testCase.want, client.slotIndex(slot),
					"the least-active slot must always win when it is unique")
			}
		})
	}
}

// TestPickSlotRotatesAmongTiedSlots is the tie-break rule. When every eligible
// slot has the same active count, selection must spread evenly across them
// rather than consistently choosing the first.
func TestPickSlotRotatesAmongTiedSlots(t *testing.T) {
	const slots = 4
	const draws = 400
	client := newSelectionTestClient(t, []int{2, 2, 2, 2})

	counts := make([]int, slots)
	for range draws {
		slot := client.pickSlot()
		require.NotNil(t, slot)
		counts[client.slotIndex(slot)]++
	}

	// Every tied slot must be chosen. A first-index-only tie-break would leave
	// slots 1..3 at zero, which is precisely the bias this asserts against.
	for index, count := range counts {
		require.NotZero(t, count,
			"slot %d was never selected although all slots were tied; counts=%v",
			index, counts)
	}

	// And the spread must be reasonably even. A loose bound keeps this from
	// becoming flaky while still catching a heavy skew.
	expected := draws / slots
	for index, count := range counts {
		require.Greater(t, count, expected/2,
			"slot %d is under-used: counts=%v", index, counts)
		require.Less(t, count, expected*2,
			"slot %d is over-used: counts=%v", index, counts)
	}
}

// TestPickSlotRotatesAmongTiedMinimumSubset covers the partial-tie case: some
// slots share the minimum and others do not. Only the minimum subset may be
// chosen, and it must still rotate.
func TestPickSlotRotatesAmongTiedMinimumSubset(t *testing.T) {
	// Slots 1 and 3 share the minimum of 1; slots 0 and 2 are busier.
	client := newSelectionTestClient(t, []int{7, 1, 7, 1})

	counts := make([]int, 4)
	for range 400 {
		slot := client.pickSlot()
		require.NotNil(t, slot)
		counts[client.slotIndex(slot)]++
	}

	require.Zero(t, counts[0], "a busier slot must never be chosen: counts=%v", counts)
	require.Zero(t, counts[2], "a busier slot must never be chosen: counts=%v", counts)
	require.NotZero(t, counts[1], "the tied minimum must be reachable: counts=%v", counts)
	require.NotZero(t, counts[3], "the tied minimum must be reachable: counts=%v", counts)
}

// TestPickSlotSkipsIneligibleSlots proves unhealthy slots are never selected,
// whatever their active count would otherwise suggest.
func TestPickSlotSkipsIneligibleSlots(t *testing.T) {
	client := newSelectionTestClient(t, []int{0, 0, 0, 0})
	// Slot 0 looks most attractive by active count but is draining; slot 2 is
	// dead. Neither may ever be chosen.
	client.slots[0].state = http3SlotDraining
	client.slots[0].drainingSince = time.Now()
	client.slots[2].state = http3SlotDead

	for range 200 {
		slot := client.pickSlot()
		require.NotNil(t, slot)
		index := client.slotIndex(slot)
		require.NotEqual(t, 0, index, "a draining slot must never receive a new tunnel")
		require.NotEqual(t, 2, index, "a dead slot must never receive a new tunnel")
	}
}

// TestPickSlotSkipsCooldownSlots proves a slot in cooldown is not selected until
// its cooldown expires.
func TestPickSlotSkipsCooldownSlots(t *testing.T) {
	client := newSelectionTestClient(t, []int{0, 0})
	client.slots[0].state = http3SlotCooldown
	client.slots[0].cooldownUntil = time.Now().Add(time.Hour)

	for range 100 {
		slot := client.pickSlot()
		require.NotNil(t, slot)
		require.Equal(t, 1, client.slotIndex(slot),
			"a slot in cooldown must not be selected")
	}

	// Once the cooldown expires the slot becomes eligible again, so the pool can
	// recover rather than permanently losing capacity.
	client.slots[0].cooldownUntil = time.Now().Add(-time.Millisecond)
	client.slots[0].state = http3SlotHealthy
	seen := map[int]bool{}
	for range 200 {
		slot := client.pickSlot()
		require.NotNil(t, slot)
		seen[client.slotIndex(slot)] = true
	}
	require.True(t, seen[0], "a recovered slot must be selectable again")
	require.True(t, seen[1], "the recovered slot must not starve the other")
}

// TestPickSlotReturnsNilWhenAllIneligible covers the exhausted case: the caller
// must be told "no slot", so it can consult authority-level state rather than
// assuming H3 is unusable.
func TestPickSlotReturnsNilWhenAllIneligible(t *testing.T) {
	client := newSelectionTestClient(t, []int{0, 0})
	for _, slot := range client.slots {
		slot.state = http3SlotDead
	}
	require.Nil(t, client.pickSlot(),
		"an exhausted pool must report no slot rather than an ineligible one")
}

// TestPickSlotLeastActiveThenRotateUsesRealisticCounts runs the combined rule
// with a realistic mix, asserting the two properties together: never pick a
// busier slot, and do rotate within the minimum.
func TestPickSlotLeastActiveThenRotateUsesRealisticCounts(t *testing.T) {
	// Slots 0 and 2 tie at the minimum 3.
	client := newSelectionTestClient(t, []int{3, 8, 3, 8})

	counts := make([]int, 4)
	for range 300 {
		slot := client.pickSlot()
		require.NotNil(t, slot)
		counts[client.slotIndex(slot)]++
	}
	require.Zero(t, counts[1])
	require.Zero(t, counts[3])
	require.NotZero(t, counts[0])
	require.NotZero(t, counts[2],
		"the second tied slot must be used too; counts=%v", counts)
}
