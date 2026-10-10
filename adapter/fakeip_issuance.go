package adapter

import (
	"cmp"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
)

// maxIssuanceGenerations bounds how many FakeIP generations the ledger remembers.
//
// # Why a bound is not a compromise
//
// An address is refused because the Box can PROVE it issued it. Past the bound the proof is gone, and
// the honest answer is the same one the ledger gives when it is absent: "not attributable to this
// instance". Keeping every generation forever would be a growth path with no owner - a daemon that
// reloads on a schedule would accumulate one entry per reload, forever - and a thousand generations
// of configuration churn in one process is far past the point where an address from the first of them
// is still in anybody's DNS cache. The bound is stated here rather than hidden inside an eviction
// policy, and `FakeIPIssuanceLedger.Generations` reports the live count so a measurement can read it.
const maxIssuanceGenerations = 1024

// FakeIPIssuanceInterval is a closed range of addresses of ONE family that a FakeIP generation has
// handed out. It is reported in the normalised four-byte form for an IPv4 address.
type FakeIPIssuanceInterval struct {
	From netip.Addr
	To   netip.Addr
}

func (i FakeIPIssuanceInterval) String() string {
	if i.From == i.To {
		return i.From.String()
	}
	return i.From.String() + ".." + i.To.String()
}

// contains reports whether the interval covers `address`. The bit lengths must match: a 4-in-6
// address is a different value from the IPv4 address it denotes, and comparing across the two is how
// a mapped destination silently escapes a check written for four-byte addresses.
func (i FakeIPIssuanceInterval) contains(address netip.Addr) bool {
	return i.From.IsValid() && i.From.BitLen() == address.BitLen() &&
		i.From.Compare(address) <= 0 && address.Compare(i.To) <= 0
}

// issuanceSnapshot is the immutable set of intervals the ledger has recorded, published as one value
// so readers take no lock.
//
// The router asks this question on every connection it matches, and the answer must not become a
// point of contention between Boxes or between connections. One atomic load of a pointer is the whole
// read path; a writer copies the merged slice, which is bounded by maxIssuanceGenerations.
type issuanceSnapshot struct {
	intervals []FakeIPIssuanceInterval
}

// FakeIPIssuanceLedger records the address intervals a FakeIP store has handed out, across the Boxes
// that share it.
//
// # Why this object exists, and why it is reached through a context
//
// `route/route.go` must refuse a destination that this Box can prove it once issued but can no longer
// map - after the range moved, or after the fakeip server was removed from the configuration. Both of
// those are statements about a PREVIOUS Box, and the object that could answer them is closed.
//
// So the ledger is registered once in the context that owns the SEQUENCE of Boxes.
// `sing/service.ExtendContext` is `registry.Clone()`, and `Clone` is a shallow `maps.Copy`, so service
// pointers inherit across a Box boundary: every Box built for that owner receives the SAME ledger, and
// it dies with the owner. That is not a package-level global, and a Box built from a context without
// one simply has no cross-Box memory - which is the COMMON path, not an exotic one: the CLI,
// `cmd_check`, libbox configuration validation and every test harness build one Box and register
// nothing.
//
// # The key derivation, stated because a mismatch here fails silently
//
// The registered value is `*FakeIPIssuanceLedger` and the reader calls
// `service.PtrFromContext[FakeIPIssuanceLedger]`. `service.MustRegisterPtr[T]` and
// `service.PtrFromContext[T]` both key on `common.DefaultValue[*T]()`, so the two agree. Using
// `service.ContextWith` or `service.FromContext[*T]` instead would key on `DefaultValue[**T]()` and
// find nothing - the wrong pair returns nil rather than failing to compile, which is why the pair is
// pinned by a test rather than left to a comment.
//
// # What it does not do
//
// It does not store names, it does not survive a process, and it does not claim interception it cannot
// prove. Those are deliberate: an address this process cannot attribute is left as an ordinary
// literal, because guessing from the address alone is a blanket guard that would break real traffic
// (on the machine this was measured on, `198.18.0.0/15` is live routed space whose resolver answers
// real queries).
type FakeIPIssuanceLedger struct {
	access   sync.Mutex
	sequence uint64
	records  []issuanceRecord
	current  atomic.Pointer[issuanceSnapshot]
}

type issuanceRecord struct {
	// sequence disambiguates two generations that carry the same generation index, which happens after
	// a restart: the counter starts at zero again while the store finds the same index on disk.
	sequence   uint64
	generation int
	inet4      familyIssuance
	inet6      familyIssuance
}

// familyIssuance is one family's record for one generation. `addressRange` is kept so the walk can be
// continued without the caller re-supplying it.
type familyIssuance struct {
	addressRange netip.Prefix
	intervals    []FakeIPIssuanceInterval
}

// NewFakeIPIssuanceLedger returns an empty ledger. Register it in the context that owns the sequence
// of Boxes; a Box built from a context without one records nothing and refuses nothing on this basis.
func NewFakeIPIssuanceLedger() *FakeIPIssuanceLedger {
	ledger := &FakeIPIssuanceLedger{}
	ledger.current.Store(&issuanceSnapshot{})
	return ledger
}

// Sequence reports the current logical tick.
//
// A generation RETIRED by the one replacing it belongs to the tick before: `Store.Start` advances the
// tick for the generation it is starting and records the retired one at `Sequence()-1`. That is the
// whole disambiguation, because a generation index alone is ambiguous - `FakeIPMetadata` carries no
// index at all, so a restart finds index zero again.
func (l *FakeIPIssuanceLedger) Sequence() uint64 {
	if l == nil {
		return 0
	}
	l.access.Lock()
	defer l.access.Unlock()
	return l.sequence
}

// Advance starts a new tick and returns it, for an owner about to begin a generation.
func (l *FakeIPIssuanceLedger) Advance() uint64 {
	if l == nil {
		return 0
	}
	l.access.Lock()
	defer l.access.Unlock()
	l.sequence++
	return l.sequence
}

// RecordSeed notes the state a generation STARTS from: the ranges it is configured with, and the
// cursors it has already reached - either by issuing in this process or by loading them from disk.
//
// The cursor may be ahead of anything this process handed out: the store persists its cursor a whole
// reservation window ahead of the addresses it has really issued, so that a process death cannot make
// a restart re-issue a live address. The interval recorded here is therefore an over-approximation of
// at most that window. It is bounded, it is in the safe direction for the refusal, every later
// `RecordIssued` narrows it, and it is stated rather than hidden.
//
// A seed REPLACES the generation's record, because it is a statement about where that generation
// begins rather than about one more address it handed out.
func (l *FakeIPIssuanceLedger) RecordSeed(sequence uint64, generation int, inet4Range netip.Prefix, inet4Cursor netip.Addr, inet6Range netip.Prefix, inet6Cursor netip.Addr) {
	if l == nil {
		return
	}
	l.access.Lock()
	defer l.access.Unlock()
	record := l.recordLocked(sequence, generation)
	record.inet4 = seedFamily(inet4Range, inet4Cursor)
	record.inet6 = seedFamily(inet6Range, inet6Cursor)
	l.publishLocked()
}

// RecordIssued notes one address a generation really handed out. It is the exact record: the walk only
// ever moves forward, so consecutive calls extend one interval and a wrap starts a second.
func (l *FakeIPIssuanceLedger) RecordIssued(sequence uint64, generation int, address netip.Addr) {
	if l == nil || !address.IsValid() {
		return
	}
	l.access.Lock()
	defer l.access.Unlock()
	record := l.recordLocked(sequence, generation)
	if address.Is4() {
		record.inet4 = extendFamily(record.inet4, address)
	} else {
		record.inet6 = extendFamily(record.inet6, address)
	}
	l.publishLocked()
}

// Issued reports whether the ledger can prove it recorded an issuance covering `address`.
//
// The caller must pass a NORMALISED address: a 4-in-6 spelling is a different `netip.Addr` value, and
// `netip.Prefix.Contains` compares bit lengths, so `::ffff:198.18.0.2` would miss an IPv4 interval.
func (l *FakeIPIssuanceLedger) Issued(address netip.Addr) bool {
	_, loaded := l.IssuedInterval(address)
	return loaded
}

// IssuedInterval returns the interval covering `address`, so a refusal can TELL the operator which
// recorded issuance it came from instead of only that it was refused.
func (l *FakeIPIssuanceLedger) IssuedInterval(address netip.Addr) (FakeIPIssuanceInterval, bool) {
	if l == nil || !address.IsValid() {
		return FakeIPIssuanceInterval{}, false
	}
	snapshot := l.current.Load()
	if snapshot == nil {
		return FakeIPIssuanceInterval{}, false
	}
	for _, interval := range snapshot.intervals {
		if interval.contains(address) {
			return interval, true
		}
	}
	return FakeIPIssuanceInterval{}, false
}

// Clear drops every recorded generation and starts a new tick.
//
// It exists for the owner of the ledger - a service stop that is not a reload, a diagnostic reset - so
// that "this process has no issuance memory" is expressible without discarding the object other
// components already hold.
func (l *FakeIPIssuanceLedger) Clear() {
	if l == nil {
		return
	}
	l.access.Lock()
	defer l.access.Unlock()
	l.sequence++
	l.records = nil
	l.publishLocked()
}

// Intervals reports how many intervals are currently recorded, which is what a boundedness
// measurement reads.
func (l *FakeIPIssuanceLedger) Intervals() int {
	if l == nil {
		return 0
	}
	snapshot := l.current.Load()
	if snapshot == nil {
		return 0
	}
	return len(snapshot.intervals)
}

// Generations reports how many generation records the ledger holds.
func (l *FakeIPIssuanceLedger) Generations() int {
	if l == nil {
		return 0
	}
	l.access.Lock()
	defer l.access.Unlock()
	return len(l.records)
}

func (l *FakeIPIssuanceLedger) recordLocked(sequence uint64, generation int) *issuanceRecord {
	for index := range l.records {
		if l.records[index].sequence == sequence && l.records[index].generation == generation {
			return &l.records[index]
		}
	}
	if len(l.records) >= maxIssuanceGenerations {
		copy(l.records, l.records[1:])
		l.records = l.records[:len(l.records)-1]
	}
	l.records = append(l.records, issuanceRecord{sequence: sequence, generation: generation})
	return &l.records[len(l.records)-1]
}

func (l *FakeIPIssuanceLedger) publishLocked() {
	merged := make([]FakeIPIssuanceInterval, 0, len(l.records)*2)
	for _, record := range l.records {
		merged = append(merged, record.inet4.intervals...)
		merged = append(merged, record.inet6.intervals...)
	}
	l.current.Store(&issuanceSnapshot{intervals: mergeIssuanceIntervals(merged)})
}

// seedFamily builds a family's record from a range and a cursor, or nothing when the family is not
// configured.
func seedFamily(addressRange netip.Prefix, cursor netip.Addr) familyIssuance {
	if !addressRange.IsValid() {
		return familyIssuance{}
	}
	family := familyIssuance{addressRange: addressRange}
	if cursor.IsValid() && cursor.BitLen() == addressRange.Addr().BitLen() && addressRange.Contains(cursor) {
		first := addressRange.Addr().Next()
		if first.IsValid() && cursor.Compare(first) >= 0 {
			family.intervals = []FakeIPIssuanceInterval{{From: first, To: cursor}}
		}
	}
	return family
}

// extendFamily adds one issued address to a family's record.
//
// # Why the wrap is handled by comparison rather than by a heuristic
//
// `nextAddress` walks the range in order and wraps at the end, so an address at or before where this
// generation's first interval began is the start of a SECOND interval, not a jump forward. Anything
// else that is ahead of the current end is a jump, which happens only once per reservation window on
// the durable path and is bounded by that window.
func extendFamily(family familyIssuance, address netip.Addr) familyIssuance {
	if len(family.intervals) == 0 {
		return familyIssuance{
			addressRange: family.addressRange,
			intervals:    []FakeIPIssuanceInterval{{From: address, To: address}},
		}
	}
	last := &family.intervals[len(family.intervals)-1]
	if last.From.BitLen() != address.BitLen() {
		return familyIssuance{
			addressRange: family.addressRange,
			intervals:    append(family.intervals, FakeIPIssuanceInterval{From: address, To: address}),
		}
	}
	switch {
	case last.contains(address):
		return family
	case address.Compare(last.To.Next()) == 0:
		// The walk continued: the very next address in the range.
		last.To = address
	case address.Compare(family.intervals[0].From) <= 0:
		// The walk wrapped: a second interval begins at the head of the range.
		family.intervals = append(family.intervals, FakeIPIssuanceInterval{From: address, To: address})
	default:
		// A jump forward, which the durable path produces when the persisted cursor leads the true
		// high-water mark. Extending keeps the record in the safe direction for the refusal, and the
		// jump is bounded by the reservation window the store writes.
		last.To = address
	}
	return family
}

// mergeIssuanceIntervals returns the union of the intervals as an ordered, disjoint set, merging only
// across the same address family.
func mergeIssuanceIntervals(intervals []FakeIPIssuanceInterval) []FakeIPIssuanceInterval {
	if len(intervals) == 0 {
		return nil
	}
	slices.SortFunc(intervals, func(left, right FakeIPIssuanceInterval) int {
		if order := cmp.Compare(left.From.BitLen(), right.From.BitLen()); order != 0 {
			return order
		}
		return left.From.Compare(right.From)
	})
	merged := make([]FakeIPIssuanceInterval, 0, len(intervals))
	for _, interval := range intervals {
		if len(merged) == 0 {
			merged = append(merged, interval)
			continue
		}
		previous := &merged[len(merged)-1]
		if previous.From.BitLen() != interval.From.BitLen() {
			merged = append(merged, interval)
			continue
		}
		// Overlapping or adjacent: extend the previous interval to whichever end is further.
		if interval.From.Compare(previous.To.Next()) <= 0 {
			if interval.To.Compare(previous.To) > 0 {
				previous.To = interval.To
			}
			continue
		}
		merged = append(merged, interval)
	}
	return merged
}
