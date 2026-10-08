package trafficsched

import (
	"fmt"
	"io"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/trafficclass"
	"github.com/sagernet/sing/common/buf"
)

// The contention rig and the experiments that decide the design.
//
// # What is being modelled
//
// A shared uplink with a fixed byte rate, fed by several independent flows whose bytes are
// delivered in the order they were accepted. In front of the wire, each flow has an acceptance
// window: a writer may deposit at most `window` bytes that have not been delivered yet, which is
// what a kernel send buffer does, and is the reason a userspace scheduler cannot fix latency by
// reordering alone.
//
//	flow -> [gate] -> wireConn(window) -> FIFO wire(rate) -> delivery timestamp
//
// The measured quantity is what the product cares about and nothing else: the delivery time of a
// small high-priority message MINUS the time its write returned. Grant latency, queue depth and
// write completion are intermediate and are deliberately not the headline, because a scheduler
// with beautiful grant latency and unchanged delivery time has achieved nothing.

// wireChunk is one accepted write on the shared wire.
type wireChunk struct {
	conn   *wireConn
	size   int
	at     time.Time
	marker bool
}

// wire is a single FIFO link with a fixed byte rate.
type wire struct {
	rate   float64
	window int

	mu      sync.Mutex
	cond    *sync.Cond
	queue   []wireChunk
	pending map[*wireConn]int
	closed  bool

	// diagnostics, reset by the runner before the measurement window
	delivered  int64
	queued     int
	queueHigh  int
	queueSum   int64
	queueTicks int64
}

func newWire(rate float64, window int) *wire {
	w := &wire{
		rate:    rate,
		window:  window,
		pending: make(map[*wireConn]int),
	}
	w.cond = sync.NewCond(&w.mu)
	go w.run()
	return w
}

// setRate changes the wire's capacity while it is running, so a controller can be evaluated against
// a link that moves rather than only against one that does not.
func (w *wire) setRate(rate float64) {
	w.mu.Lock()
	w.rate = rate
	w.mu.Unlock()
}

func (w *wire) currentRate() float64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.rate
}

func (w *wire) run() {
	// due is when the chunk currently being served must have finished. The wire models a FIXED-RATE
	// link, so its schedule is absolute rather than relative: a host hiccup that delays the drain
	// makes the next sleep shorter, never the link slower.
	//
	// Sleeping for chunk.size/rate after each chunk instead lets every scheduling delay accumulate as
	// drift, which silently turns the modelled link into a measurement of the runner. That is not a
	// theoretical concern: it is what let a loaded host fill the acceptance windows of a SHAPED run -
	// measured at 52 KiB of queue mean where an idle host read 20 KiB - so that the shaper appeared
	// not to be shaping, and the HIGH-versus-HIGH experiment failed on a property the shaper does not
	// control. A fixed-rate link whose rate is a function of the CPU is not the link the experiment
	// means to model.
	var due time.Time
	for {
		w.mu.Lock()
		for len(w.queue) == 0 && !w.closed {
			w.cond.Wait()
		}
		if w.closed {
			w.mu.Unlock()
			return
		}
		chunk := w.queue[0]
		// The rate is read under the lock: the adaptive experiment changes it while the drain is
		// running, which is the whole point of that experiment.
		rate := w.rate
		w.mu.Unlock()

		service := time.Duration(float64(time.Second) * float64(chunk.size) / rate)
		if due.IsZero() || time.Since(due) > time.Second {
			// The link was idle (or so far behind that catching up would mean delivering a backlog
			// instantly). Restart the schedule from now, exactly as a real idle link would.
			due = time.Now()
		}
		due = due.Add(service)
		if sleep := time.Until(due); sleep > 0 {
			time.Sleep(sleep)
		}

		w.mu.Lock()
		// Only this goroutine pops, so the head is still the chunk that was slept on.
		w.queue = w.queue[1:]
		chunk.conn.pending -= chunk.size
		w.pending[chunk.conn] -= chunk.size
		w.queued -= chunk.size
		w.delivered += int64(chunk.size)
		delivered := time.Now()
		w.cond.Broadcast()
		w.mu.Unlock()

		chunk.conn.deliver(chunk.at, delivered, chunk.marker)
	}
}

// drain waits until every accepted byte has been delivered, so that the conservation check that
// follows is about the scheduler and not about how long the caller happened to wait.
//
// It is bounded rather than unbounded on purpose: a wire that never empties is a scheduler that lost
// a grant, and reporting that as a failure is more useful than hanging the package.
func (w *wire) drain(t *testing.T, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		w.mu.Lock()
		queued := w.queued
		w.mu.Unlock()
		if queued == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the wire did not drain %d accepted bytes within %s: a grant was lost", queued, timeout)
		}
		time.Sleep(time.Millisecond)
	}
}

func (w *wire) close() {
	w.mu.Lock()
	w.closed = true
	w.cond.Broadcast()
	w.mu.Unlock()
}

func (w *wire) snapshot() (delivered int64, queueHigh, queueMean int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.queueTicks > 0 {
		queueMean = int(w.queueSum / w.queueTicks)
	}
	return w.delivered, w.queueHigh, queueMean
}

func (w *wire) resetStats() {
	w.mu.Lock()
	w.queueHigh = 0
	w.queueSum = 0
	w.queueTicks = 0
	w.mu.Unlock()
}

// wireConn is one flow's endpoint on the wire. Its Write blocks exactly like a socket write: it
// returns as soon as the bytes are accepted into the flow's window, and not before.
type wireConn struct {
	wire *wire
	name string
	kind string

	// guarded by wire.mu
	pending int

	// latency bookkeeping, guarded by mu
	mu        sync.Mutex
	accepted  int64
	latencies []time.Duration
	// ahead is how many bytes were already accepted and not yet delivered at the moment each
	// high-priority write was accepted.
	//
	// It is the ACCOUNTING driver of the delivery latency and the reason this rig can be asserted on
	// at all. The wire is a strict FIFO that spends chunk.size/rate seconds on every chunk it pops, so
	// a write's delivery time is (the bytes in front of it)/rate plus its own service time. Measuring
	// those bytes rather than the elapsed time is the difference between a quantity the mechanism
	// controls and a quantity the host's scheduler perturbs: a loaded run in this tree showed a probe
	// p95 of 339 ms against a 176 ms typical while the byte count in front of the probe did not move.
	ahead []int
}

func (w *wire) newConn(name, kind string) *wireConn {
	return &wireConn{wire: w, name: name, kind: kind}
}

func (c *wireConn) Write(p []byte) (int, error) { return c.accept(len(p)) }

func (c *wireConn) WriteBuffer(buffer *buf.Buffer) error {
	defer buffer.Release()
	_, err := c.accept(buffer.Len())
	return err
}

func (c *wireConn) accept(size int) (int, error) {
	w := c.wire
	w.mu.Lock()
	for !w.closed && c.pending+size > w.window {
		w.cond.Wait()
	}
	if w.closed {
		w.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	now := time.Now()
	// queuedAhead is read BEFORE this write's own bytes are added, so it is exactly what stands in
	// front of it in the FIFO.
	queuedAhead := w.queued
	c.pending += size
	w.pending[c] += size
	w.queued += size
	w.queueSum += int64(w.queued)
	w.queueTicks++
	if w.queued > w.queueHigh {
		w.queueHigh = w.queued
	}
	w.queue = append(w.queue, wireChunk{conn: c, size: size, at: now, marker: c.kind == "high"})
	w.cond.Broadcast()
	w.mu.Unlock()

	c.mu.Lock()
	c.accepted += int64(size)
	if c.kind == "high" {
		c.ahead = append(c.ahead, queuedAhead)
	}
	c.mu.Unlock()
	return size, nil
}

func (c *wireConn) deliver(arrived, delivered time.Time, marker bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if marker {
		c.latencies = append(c.latencies, delivered.Sub(arrived))
	}
}

func (c *wireConn) acceptedBytes() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.accepted
}

// resetLatencies discards the warm-up samples of BOTH the measured delivery times and the byte
// counts behind them. The two are the same observation in different units, so a caller that means
// "throw away the transient" must not keep one and drop the other: a queue-ahead percentile taken
// over a warm-up that included an unpaced phase would describe a scheduler that no longer exists.
func (c *wireConn) resetLatencies() {
	c.mu.Lock()
	c.latencies = c.latencies[:0]
	c.ahead = c.ahead[:0]
	c.mu.Unlock()
}

func (c *wireConn) latencyCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.latencies)
}

func (c *wireConn) snapshot() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]time.Duration, len(c.latencies))
	copy(out, c.latencies)
	return out
}

// aheadSnapshot returns the bytes queued ahead of each high-priority write, in accept order.
func (c *wireConn) aheadSnapshot() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]int, len(c.ahead))
	copy(out, c.ahead)
	return out
}

type contentionResult struct {
	label string
	// highLatencies are the receiver-visible delivery times of the small high-priority messages,
	// measured from the moment each write returned. This is the product number, and it is LOGGED
	// rather than gated on, because a busy host moves it.
	highLatencies []time.Duration
	// highQueueAhead is, for each small high-priority message, how many bytes were queued ahead of it
	// when it was accepted. It is the same observation as highLatencies in the units the wire actually
	// conserves - see wireConn.ahead - and it is what the assertions are allowed to fail on.
	highQueueAhead []int
	// bulkThroughput is what the bulk flows managed to hand to the wire during the measurement
	// window. It is the price of the latency above, and it is logged for the same reason.
	bulkThroughput float64
	// bulkAccepted is the same work as bulkThroughput without the division: the bytes the bulk flows
	// handed to the wire during the window. Comparisons between two configurations are made on this
	// count, so that two independently measured window lengths cannot turn a real difference in
	// admitted work into a difference in the denominator.
	bulkAccepted   int64
	wireThroughput float64
	// window is how long the measured interval actually lasted, as opposed to the duration that was
	// slept for. It is the interval the shaping budget is asserted over.
	window    time.Duration
	queueHigh int
	queueMean int
}

type contentionConfig struct {
	label string
	mode  Mode
	// rate is the configured shaping rate in bytes per second; zero installs no rate source at all,
	// which is the production default.
	rate  float64
	burst int

	wireRate float64
	window   int

	bulkFlows     int
	highBulkFlows int
	bulkChunk     int
	highBulkChunk int

	pingSize  int
	pingEvery time.Duration
	settle    time.Duration
	duration  time.Duration

	// gateBulk and gateHigh install the production gate in front of the two kinds of upload.
	gateBulk bool
	gateHigh bool
}

func defaultContentionConfig(label string) contentionConfig {
	return contentionConfig{
		label:         label,
		mode:          ModePaced,
		wireRate:      2_000_000,
		window:        64 * 1024,
		bulkFlows:     4,
		bulkChunk:     16 * 1024,
		highBulkChunk: 16 * 1024,
		pingSize:      256,
		pingEvery:     20 * time.Millisecond,
		settle:        1500 * time.Millisecond,
		duration:      2 * time.Second,
		gateBulk:      true,
		gateHigh:      true,
	}
}

func (c contentionConfig) option() Options {
	options := Options{Mode: c.mode}
	if c.burst > 0 {
		options.Burst = c.burst
	}
	if c.rate > 0 {
		options.RateSource = NewFixedRate(int64(c.rate))
	}
	return options
}

// runContention executes one configuration and returns the receiver-visible picture.
func runContention(t *testing.T, config contentionConfig) contentionResult {
	t.Helper()

	shared := newWire(config.wireRate, config.window)
	defer shared.close()

	highConn := shared.newConn("high", "high")
	bulkConns := make([]*wireConn, config.bulkFlows)
	for index := range bulkConns {
		bulkConns[index] = shared.newConn(fmt.Sprintf("bulk-%d", index), "bulk")
	}
	highBulkConns := make([]*wireConn, config.highBulkFlows)
	for index := range highBulkConns {
		highBulkConns[index] = shared.newConn(fmt.Sprintf("highbulk-%d", index), "bulk")
	}

	var scheduler *Scheduler
	if config.gateBulk || config.gateHigh {
		scheduler = NewScheduler(config.option())
		defer scheduler.Close()
	}

	highWriter := io.Writer(highConn)
	if config.gateHigh {
		highWriter = NewGate(highConn, scheduler.NewFlow(trafficclass.ClassInteractive))
	}
	bulkWriters := make([]io.Writer, len(bulkConns))
	for index, conn := range bulkConns {
		if config.gateBulk {
			bulkWriters[index] = NewGate(conn, scheduler.NewFlow(trafficclass.ClassDefault))
		} else {
			bulkWriters[index] = conn
		}
	}
	highBulkWriters := make([]io.Writer, len(highBulkConns))
	for index, conn := range highBulkConns {
		if config.gateHigh {
			highBulkWriters[index] = NewGate(conn, scheduler.NewFlow(trafficclass.ClassInteractive))
		} else {
			highBulkWriters[index] = conn
		}
	}

	stop := make(chan struct{})
	// flooders is the number of bulk worker goroutines, tracked so the run can wait for all of
	// them before it reads its counters.
	var workers sync.WaitGroup

	startFlood := func(writer io.Writer, chunk int) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			payload := make([]byte, chunk)
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := writer.Write(payload); err != nil {
					return
				}
			}
		}()
	}
	for index := range bulkWriters {
		startFlood(bulkWriters[index], config.bulkChunk)
	}
	for index := range highBulkWriters {
		startFlood(highBulkWriters[index], config.highBulkChunk)
	}

	pingDone := make(chan struct{})
	workers.Add(1)
	go func() {
		defer workers.Done()
		defer close(pingDone)
		payload := make([]byte, config.pingSize)
		ticker := time.NewTicker(config.pingEvery)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if _, err := highWriter.Write(payload); err != nil {
					return
				}
			}
		}
	}()

	// Let each mode reach its steady state, then throw away the warm-up samples and the warm-up
	// queue statistics. A pacer at just under the link rate needs time to drain the queue an
	// unpaced phase built, and charging that transient to it would understate what it can hold in
	// equilibrium - which is the property that matters for a long transfer.
	time.Sleep(config.settle)
	highConn.resetLatencies()
	shared.resetStats()
	deliveredStart, _, _ := shared.snapshot()
	acceptedAtStart := acceptedTotal(bulkConns, highBulkConns)

	measureStart := time.Now()
	time.Sleep(config.duration)
	close(stop)
	workers.Wait()
	<-pingDone
	// The window is measured rather than assumed, and it is sampled only AFTER the senders have
	// stopped: a sleep is not exact, and a worker that was already inside a write when the stop
	// signal arrived still lands its bytes in the count below. Measuring to the stop signal instead
	// would exclude those bytes from the interval the shaping budget is asserted over, which is how a
	// correct shaper reads as over-admitting by less than one write.
	window := time.Since(measureStart)

	deliveredEnd, queueHigh, queueMean := shared.snapshot()

	bulkBytes := acceptedTotal(bulkConns, highBulkConns) - acceptedAtStart

	// Conservation, the invariant that says the gate is a scheduler and not a lossy filter: once the
	// senders have stopped and the wire has drained, every byte that was accepted must have been
	// delivered, exactly once. It is checked after the measurement so that it cannot perturb it, and
	// it is independent of the host because it counts bytes rather than time.
	shared.drain(t, 30*time.Second)
	deliveredFinal, _, _ := shared.snapshot()
	acceptedFinal := acceptedTotal(bulkConns, highBulkConns, []*wireConn{highConn})
	if deliveredFinal != acceptedFinal {
		t.Errorf("%s: %d bytes were accepted through the gate but %d were delivered: a grant was "+
			"lost, or bytes were delivered that were never admitted",
			config.label, acceptedFinal, deliveredFinal)
	}

	return contentionResult{
		label:          config.label,
		highLatencies:  highConn.snapshot(),
		highQueueAhead: highConn.aheadSnapshot(),
		bulkThroughput: float64(bulkBytes) / config.duration.Seconds(),
		bulkAccepted:   bulkBytes,
		wireThroughput: float64(deliveredEnd-deliveredStart) / config.duration.Seconds(),
		window:         window,
		queueHigh:      queueHigh,
		queueMean:      queueMean,
	}
}

func acceptedTotal(groups ...[]*wireConn) int64 {
	var total int64
	for _, group := range groups {
		for _, conn := range group {
			total += conn.acceptedBytes()
		}
	}
	return total
}

func sortedCopy(latencies []time.Duration) []time.Duration {
	out := append([]time.Duration(nil), latencies...)
	sort.Slice(out, func(a, b int) bool { return out[a] < out[b] })
	return out
}

func percentile(sorted []time.Duration, fraction float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	index := int(float64(len(sorted)-1) * fraction)
	return sorted[index]
}

func p50(latencies []time.Duration) time.Duration {
	return percentile(sortedCopy(latencies), 0.50)
}

func p95(latencies []time.Duration) time.Duration {
	return percentile(sortedCopy(latencies), 0.95)
}

func p99(latencies []time.Duration) time.Duration {
	return percentile(sortedCopy(latencies), 0.99)
}

func maxOf(latencies []time.Duration) time.Duration {
	if len(latencies) == 0 {
		return 0
	}
	return sortedCopy(latencies)[len(latencies)-1]
}

func summariseLatencies(latencies []time.Duration) string {
	if len(latencies) == 0 {
		return "no samples"
	}
	sorted := sortedCopy(latencies)
	return fmt.Sprintf("n=%3d p50=%8s p95=%8s p99=%8s max=%8s",
		len(sorted),
		percentile(sorted, 0.50).Round(100*time.Microsecond),
		percentile(sorted, 0.95).Round(100*time.Microsecond),
		percentile(sorted, 0.99).Round(100*time.Microsecond),
		sorted[len(sorted)-1].Round(100*time.Microsecond),
	)
}

// The integer-percentile helpers are the accounting counterparts of the duration ones above. They
// rank the same samples - the bytes queued ahead of each probe - and the order statistics are the
// same, because delivery time is that byte count divided by the wire rate. What changes is that the
// quantity being ranked is one the wire conserves rather than one the host's scheduler can move.

func sortedIntsCopy(values []int) []int {
	out := append([]int(nil), values...)
	sort.Ints(out)
	return out
}

func percentileInt(sorted []int, fraction float64) int {
	if len(sorted) == 0 {
		return 0
	}
	return sorted[int(float64(len(sorted)-1)*fraction)]
}

func p50Int(values []int) int { return percentileInt(sortedIntsCopy(values), 0.50) }
func p99Int(values []int) int { return percentileInt(sortedIntsCopy(values), 0.99) }

// queuedBytesAsWireTime renders a byte count as the wire time it represents, so a failure message
// can state the accounting quantity and the product quantity together. It is presentation only and
// is never asserted on.
func queuedBytesAsWireTime(queued int, rate float64) time.Duration {
	if rate <= 0 {
		return 0
	}
	return time.Duration(float64(queued) / rate * float64(time.Second))
}

func summariseQueueAhead(values []int) string {
	if len(values) == 0 {
		return "no samples"
	}
	sorted := sortedIntsCopy(values)
	return fmt.Sprintf("n=%3d p50=%7dB p95=%7dB p99=%7dB max=%7dB",
		len(sorted),
		percentileInt(sorted, 0.50),
		percentileInt(sorted, 0.95),
		percentileInt(sorted, 0.99),
		sorted[len(sorted)-1],
	)
}

// coldStartSample is one repetition's two views of the same first request: the delivery time the
// product cares about, and the bytes that stood in front of it in the FIFO when it was accepted.
type coldStartSample struct {
	latency    time.Duration
	queueAhead int
}

func runColdStart(t *testing.T, config contentionConfig, gap time.Duration, repeats int) []coldStartSample {
	t.Helper()
	samples := make([]coldStartSample, 0, repeats)
	for repeat := 0; repeat < repeats; repeat++ {
		shared := newWire(config.wireRate, config.window)
		scheduler := NewScheduler(config.option())
		defer scheduler.Close()

		pingConn := shared.newConn("ping", "high")

		var pingWriter io.Writer = pingConn
		if config.gateHigh {
			pingWriter = NewGate(pingConn, scheduler.NewFlow(trafficclass.ClassInteractive))
		}

		stop := make(chan struct{})
		var workers sync.WaitGroup
		for index := 0; index < config.bulkFlows; index++ {
			bulkConn := shared.newConn(fmt.Sprintf("bulk-%d", index), "bulk")
			var bulkWriter io.Writer = bulkConn
			if config.gateBulk {
				bulkWriter = NewGate(bulkConn, scheduler.NewFlow(trafficclass.ClassDefault))
			}
			workers.Add(1)
			go func(writer io.Writer) {
				defer workers.Done()
				payload := make([]byte, config.bulkChunk)
				for {
					select {
					case <-stop:
						return
					default:
					}
					if _, err := writer.Write(payload); err != nil {
						return
					}
				}
			}(bulkWriter)
		}

		time.Sleep(gap)
		if _, err := pingWriter.Write(make([]byte, config.pingSize)); err != nil {
			close(stop)
			workers.Wait()
			shared.close()
			continue
		}

		deadline := time.Now().Add(30 * time.Second)
		for pingConn.latencyCount() == 0 && time.Now().Before(deadline) {
			time.Sleep(200 * time.Microsecond)
		}
		latencies := pingConn.snapshot()
		queueAhead := pingConn.aheadSnapshot()
		if len(latencies) > 0 && len(queueAhead) > 0 {
			samples = append(samples, coldStartSample{latency: latencies[0], queueAhead: queueAhead[0]})
		}

		close(stop)
		workers.Wait()
		shared.close()
	}
	return samples
}

func coldStartLatencies(samples []coldStartSample) []time.Duration {
	out := make([]time.Duration, len(samples))
	for index, sample := range samples {
		out[index] = sample.latency
	}
	return out
}

func coldStartAhead(samples []coldStartSample) []int {
	out := make([]int, len(samples))
	for index, sample := range samples {
		out[index] = sample.queueAhead
	}
	return out
}
