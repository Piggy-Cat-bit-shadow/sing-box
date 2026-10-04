// Package trafficsched implements the cross-flow upload scheduler and the write-side gate that
// puts it in the data path.
//
// # Managed domain
//
// Userspace-proxied upload flows. A flow reaches this package only when the kernel-splice copy
// path is not available to it (see route.ConnectionManager.uploadStreamGate), so nothing here
// competes with splice or with the native direct bypass. It is not a machine-wide QoS: it can
// arbitrate only the flows that share this scheduler, and it says nothing about traffic that never
// enters sing-box.
//
// # What was measured, and what it settles
//
// The experiment in contention_test.go runs the four candidate policies against the same rig: a
// shared FIFO uplink at a fixed byte rate, several flows flooding it, and a per-flow acceptance
// window standing in for the kernel send buffer, which is the part a userspace process cannot
// reach. The measured quantity is the receiver-visible delivery latency of a small high-priority
// message, because that is the product goal and every other number is intermediate.
//
// Results at 2 MB/s nominal (about 1.75 MB/s effective), 4 bulk flows, 64 KiB windows, p99:
//
//	no gate (baseline)          162 ms    queue mean 257 KiB
//	gate, nothing armed         162 ms    queue mean 257 KiB
//	ModeAdmission               162 ms    queue mean 257 KiB
//	ModeService                 162 ms    queue mean 258 KiB
//	ModePaced at 95% of nominal 133 ms    queue mean 244 KiB   wire 1.99 MB/s
//	ModePaced at 85% of nominal   8 ms    queue mean  15 KiB   wire 1.74 MB/s
//	ModePaced at 70% of nominal   9 ms    queue mean  14 KiB   wire 1.44 MB/s
//
// Two conclusions follow, and both are load-bearing:
//
//  1. Scheduling models that only change WHEN a write starts - admission ordering and service
//     slots - do not move the receiver-visible latency at all, to within noise. They cannot: the
//     bytes that delay the high-priority message are already inside the sender's acceptance
//     window, out of userspace's reach, and both models leave that window just as full.
//
//  2. The only mechanism with a physical basis is to admit NORMAL data at no more than the rate
//     the path actually sustains. At or just below that rate the queue never builds, latency
//     collapses by an order of magnitude, and bulk throughput is unchanged; above it the queue
//     stays full and nothing improves. Note the 95% row: a rate that is 95% of the NOMINAL link
//     rate was still above the rate the path could actually sustain, and it bought almost nothing.
//
// # Consequence for the default
//
// The default configuration therefore does not pace: ModePaced with a zero rate admits
// immediately, which is what admission mode does, and ModeAdmission is what the connection
// manager installs. That is deliberately a no-op at the traffic level rather than a scheduling
// policy that pretends to work. Making the feature effective requires a rate the path actually
// sustains, which is either configured or learned; until one of those exists, the honest
// behaviour is to stay out of the way.
//
// # Cost when nothing contends
//
// A NORMAL flow with no recent high-priority activity takes one atomic load and returns: nothing
// is enqueued, nothing is locked, nothing is allocated. One write costs about 4.5 ns more than
// writing to the bare writer, which is under 0.5% of a 4 KiB write's own cost. See bench_test.go.
package trafficsched
