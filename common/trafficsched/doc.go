// Package trafficsched implements the cross-flow upload scheduler and the write-side gate that
// puts it in the data path.
//
// # Managed domain
//
// Userspace-proxied upload flows. A flow reaches this package only when the kernel-splice copy path
// is not available to it (see route.ConnectionManager.uploadStreamGate), so nothing here competes
// with splice or with the native direct bypass. It is not machine-wide QoS: it can arbitrate only
// the flows that share this scheduler, and it says nothing about traffic that never enters sing-box.
//
// # What was measured, and what it settles
//
// The experiments are in contention_test.go and rig_test.go. Each one reports the receiver-visible
// delivery latency of a small high-priority message under contention, because that is the product
// goal; grant latency, queue depth and write completion are recorded only as explanations.
//
// ## 1. Reordering does not work. Shaping does.
//
// (4 NORMAL flows flooding a 2 MB/s shared FIFO wire through a 64 KiB per-flow acceptance window)
//
//	no gate (baseline)               p99 146 ms    queue mean 257 KiB
//	gate installed, no rate          p99 150 ms    queue mean 257 KiB
//	ModeAdmission                    p99 145 ms    queue mean 257 KiB
//	ModeService                      p99 155 ms    queue mean 257 KiB
//	ModePacedNormalOnly @ 85%        p99  14 ms    queue mean  17 KiB   bulk 1.74 MB/s
//	ModePaced (aggregate) @ 85%      p99   9 ms    queue mean  15 KiB   bulk 1.72 MB/s
//	ModePaced (aggregate) @ 70%      p99   8 ms    queue mean  14 KiB   bulk 1.42 MB/s
//
// The first four rows are the design that was proposed, and they are indistinguishable from doing
// nothing. They cannot do better: the bytes delaying the high-priority message are already inside
// the sender's acceptance window, which userspace cannot reach, and neither model leaves that
// window any emptier than the other. Only admitting data at no more than the rate the path actually
// sustains changes the queue itself.
//
// ## 2. A pacer that starts when interactive traffic arrives protects the SECOND request.
//
// The ordering modes arm on high-priority activity. For the case that matters to a person - minutes
// of backup, then one prompt - that means the pacer is disarmed for the entire time the queue is
// filling, and it arrives to find the damage done. Measured as the FIRST 256-byte high-priority
// write after a second of uninterrupted bulk upload:
//
//	no gate (baseline)               p50 127 ms
//	ModeAdmission (armed)            p50 128 ms
//	ModePacedNormalOnly (continuous) p50   2 ms
//	ModePaced (aggregate, continuous) p50  2 ms
//
// So the paced modes do not arm at all: when a rate is configured, shaping runs for as long as the
// scheduler exists. This is also why the configured number has to be a rate the path actually
// sustains rather than a ceiling that only applies under contention.
//
// ## 3. Shaping must cover the high-priority lane too.
//
// A high-priority flow doing bulk work - which is normal, because a class says what traffic is FOR
// and not how large it is - can fill the same acceptance windows the NORMAL lane was just prevented
// from filling. Two HIGH bulk flows and one small HIGH probe:
//
//	no gate (baseline)               p99 114 ms    queue mean 128 KiB
//	ModePacedNormalOnly @ 85%        p99  73 ms    queue mean 128 KiB
//	ModePaced (aggregate) @ 85%      p99   8 ms    queue mean  15 KiB
//
// Shaping only the NORMAL lane barely helps and leaves the queue exactly as deep as it was. The
// aggregate mode is therefore the mode that ships.
//
// ## 4. A write larger than the bucket is charged, not exempted.
//
// A write larger than the bucket can never be covered by it, so the previous rule admitted such a
// write and charged nothing - which made the largest writes the only ones exempt from shaping. The
// charge is now split: the shared bucket pays what the write had to see (at most one burst, so no
// flow can hold another hostage) and the flow that sent it pays the rest in its own future. A flow
// writing 256 KiB at a time into a 64 KiB bucket is admitted at 1.84 MB/s against a configured
// 1.70, where an unshaped control reaches 2.10.
//
// ## 5. A learned rate is not ready, and the reason is worth recording.
//
// The obvious observable for a controller is "how long the write blocked". Measured against a link
// whose capacity is 2.00 MB/s, it reports 1.29 MB/s with one flow and 0.35 MB/s with four, with a
// p90/p10 spread of 1.03 in both cases. It is a stable, precise, WRONG number: it measures the wait
// produced by contention with the other flows, not the rate of the path.
//
// A prototype AIMD controller built on the direction of that signal does follow a moving capacity -
// it comes down when the capacity drops and climbs back when it returns - but it settles AT the
// capacity, and at the capacity the queue is built. Against an oracle that knows the capacity:
//
//	fixed rate at  85% of capacity   HIGH p95   8 ms   bulk 1.69 MB/s
//	fixed rate at 100% of capacity   HIGH p95  42 ms   bulk 1.99 MB/s
//	learned rate (AIMD prototype)    HIGH p95  62 ms   settles at 100%
//
// AIMD needs a queue to exist in order to detect that it is too fast, and this feature exists to
// remove the queue. A learned rate would need a controller that targets a queue-delay signal the
// gate does not currently have; until then, a configured rate below the sustained rate is the only
// configuration that delivers, and the seam for a controller is in place for whoever builds one.
//
// # The production default
//
// ModePaced with no rate source: the gate observes every byte and admits all of them, and no queue,
// lock or timer is ever started. Shaping is switched on by installing a rate, not by changing the
// shape of the data path. See Options.RateSource and Scheduler.SetRateSource.
//
// # Cost when nothing contends
//
// A write costs about 9 ns more than writing to the bare writer, with no allocation on the
// uncontended path. About 2.5 ns of that is the wrapper itself and the rest is the two atomic loads
// that let a rate be installed, replaced or absent without the gate, the lane policy or the flow
// holding a copy of it. A real write is measured in microseconds, so this is a fraction of a
// percent; it is recorded because "the fast path is cheap" should be a number and not a claim. See
// bench_test.go.
package trafficsched
