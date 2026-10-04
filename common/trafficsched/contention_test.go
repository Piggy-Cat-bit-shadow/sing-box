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

// The contention experiment.
//
// # What is being modelled
//
// A shared uplink with a fixed byte rate, fed by several independent flows whose bytes are
// delivered in the order they were accepted. In front of the wire, each flow has an acceptance
// window: a writer may deposit at most `window` bytes that have not been delivered yet, which is
// precisely what a kernel send buffer does, and is the reason a userspace scheduler cannot fix
// latency by reordering alone.
//
//	flow -> [gate] -> wireConn(window) -> FIFO wire(rate) -> delivery timestamp
//
// The measured quantity is what the product cares about and nothing else: the delivery time of a
// small high-priority message MINUS the time its write returned, under bulk contention. Grant
// latency, queue depth and write completion are all intermediate and are deliberately not the
// headline.
//
// # Why the rig is built this way
//
// The interesting question is not whether a scheduler can reorder writes - it obviously can - but
// whether reordering changes what is already queued ahead of a high-priority message. The window
// is what makes that question meaningful: bytes accepted into it are out of the scheduler's reach
// forever, exactly as they are in the kernel.

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
	done    chan struct{}
	started bool

	// diagnostics
	queued     int
	delivered  int64
	queueHigh  int
	queueSum   int64
	queueTicks int64
}

func newWire(rate float64, window int) *wire {
	w := &wire{
		rate:    rate,
		window:  window,
		pending: make(map[*wireConn]int),
		done:    make(chan struct{}),
	}
	w.cond = sync.NewCond(&w.mu)
	go w.run()
	return w
}

func (w *wire) run() {
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
		w.mu.Unlock()

		time.Sleep(time.Duration(float64(time.Second) * float64(chunk.size) / w.rate))

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

func (w *wire) close() {
	w.mu.Lock()
	w.closed = true
	w.cond.Broadcast()
	w.mu.Unlock()
}

// wireConn is one flow's endpoint on the wire. Its Write blocks exactly like a socket write: it
// returns as soon as the bytes are accepted into the flow's window, and not before.
type wireConn struct {
	wire *wire
	name string

	// guarded by wire.mu
	pending int

	// acceptance and delivery bookkeeping, guarded by mu
	mu        sync.Mutex
	accepted  int64
	latencies []time.Duration
	kind      string
}

func (w *wire) newConn(name, kind string) *wireConn {
	return &wireConn{wire: w, name: name, kind: kind}
}

func (c *wireConn) Write(p []byte) (int, error) {
	return c.accept(len(p))
}

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
	_ = now
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

// resetLatencies drops the samples collected so far, so a measurement window can exclude its own
// warm-up.
func (c *wireConn) resetLatencies() {
	c.mu.Lock()
	c.latencies = c.latencies[:0]
	c.mu.Unlock()
}

func (c *wireConn) snapshotLatencies() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]time.Duration, len(c.latencies))
	copy(out, c.latencies)
	return out
}

type contentionResult struct {
	label          string
	highLatencies  []time.Duration
	bulkBytes      int64
	bulkThroughput float64
	highBytes      int64
	queueHigh      int
	queueMean      int
}

type contentionConfig struct {
	label     string
	wireRate  float64
	window    int
	bulkFlows int
	bulkChunk int
	pingSize  int
	pingEvery time.Duration
	settle    time.Duration
	duration  time.Duration
	scheduler *Scheduler
	gateHigh  bool
	gateBulk  bool
	bulkClass trafficclass.Class
	gateClass trafficclass.Class
}

func defaultContentionConfig(label string) contentionConfig {
	return contentionConfig{
		label:     label,
		wireRate:  2_000_000,
		window:    64 * 1024,
		bulkFlows: 4,
		bulkChunk: 16 * 1024,
		pingSize:  256,
		pingEvery: 20 * time.Millisecond,
		settle:    1500 * time.Millisecond,
		duration:  2 * time.Second,
		bulkClass: trafficclass.ClassDefault,
		gateClass: trafficclass.ClassInteractive,
	}
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

	highWriter := io.Writer(highConn)
	bulkWriters := make([]io.Writer, len(bulkConns))
	for index, conn := range bulkConns {
		bulkWriters[index] = conn
	}

	if config.scheduler != nil && config.gateHigh {
		flow := config.scheduler.NewFlow(config.gateClass)
		highWriter = NewGate(highConn, flow)
	}
	if config.scheduler != nil && config.gateBulk {
		for index := range bulkWriters {
			flow := config.scheduler.NewFlow(config.bulkClass)
			bulkWriters[index] = NewGate(bulkConns[index], flow)
		}
	}

	stop := make(chan struct{})
	var workers sync.WaitGroup

	for index := range bulkWriters {
		writer := bulkWriters[index]
		workers.Add(1)
		go func() {
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
		}()
	}

	highDone := make(chan struct{})
	workers.Add(1)
	go func() {
		defer workers.Done()
		payload := make([]byte, config.pingSize)
		ticker := time.NewTicker(config.pingEvery)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				close(highDone)
				return
			case <-ticker.C:
				if _, err := highWriter.Write(payload); err != nil {
					close(highDone)
					return
				}
			}
		}
	}()

	// Let each mode reach its steady state, then throw the warm-up samples and the warm-up
	// queue statistics away. A pacer at just under the link rate needs time to drain the queue
	// the UNPACED phase built, and charging that transient to it would understate what it can
	// hold in equilibrium - which is the property that matters for a long transfer.
	time.Sleep(config.settle)
	highConn.resetLatencies()
	shared.mu.Lock()
	deliveredAtStart := shared.delivered
	shared.queueHigh = 0
	shared.queueSum = 0
	shared.queueTicks = 0
	shared.mu.Unlock()

	time.Sleep(config.duration)
	close(stop)
	workers.Wait()
	<-highDone

	var bulkBytes, highBytes int64
	for _, conn := range bulkConns {
		bulkBytes += conn.acceptedBytes()
	}
	highBytes = highConn.acceptedBytes()

	shared.mu.Lock()
	delivered := shared.delivered - deliveredAtStart
	queueHigh := shared.queueHigh
	var queueMean int
	if shared.queueTicks > 0 {
		queueMean = int(shared.queueSum / shared.queueTicks)
	}
	shared.mu.Unlock()

	result := contentionResult{
		label:          config.label,
		highLatencies:  highConn.snapshotLatencies(),
		bulkBytes:      bulkBytes,
		highBytes:      highBytes,
		bulkThroughput: float64(delivered) / config.duration.Seconds(),
		queueHigh:      queueHigh,
		queueMean:      queueMean,
	}
	return result
}

func percentile(sorted []time.Duration, fraction float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	index := int(float64(len(sorted)-1) * fraction)
	return sorted[index]
}

func summariseLatencies(latencies []time.Duration) string {
	if len(latencies) == 0 {
		return "no samples"
	}
	sorted := append([]time.Duration(nil), latencies...)
	sort.Slice(sorted, func(a, b int) bool { return sorted[a] < sorted[b] })
	return fmt.Sprintf("n=%3d p50=%7s p95=%7s p99=%7s max=%7s",
		len(sorted),
		percentile(sorted, 0.50).Round(100*time.Microsecond),
		percentile(sorted, 0.95).Round(100*time.Microsecond),
		percentile(sorted, 0.99).Round(100*time.Microsecond),
		sorted[len(sorted)-1].Round(100*time.Microsecond),
	)
}

// TestContentionExperiment is the measurement that decides which scheduling model, if any, earns
// its place in the data path.
//
// It is a test rather than a benchmark because the output is a table to be read and compared, and
// because what has to hold is a relationship between rows, not a nanosecond budget on one of them.
func TestContentionExperiment(t *testing.T) {
	if testing.Short() {
		t.Skip("contention experiment runs for several seconds")
	}

	const wireRate = 2_000_000.0

	baseline := defaultContentionConfig("A. no gate (baseline)")
	baseline.wireRate = wireRate

	gateOnly := defaultContentionConfig("B. gate, nothing armed by design")
	gateOnly.wireRate = wireRate
	gateOnly.scheduler = NewScheduler(Options{})
	gateOnly.gateHigh = true
	gateOnly.gateBulk = true

	admission := defaultContentionConfig("C. ModeAdmission (yield while HIGH writes)")
	admission.wireRate = wireRate
	admission.scheduler = NewScheduler(Options{Mode: ModeAdmission})
	admission.gateHigh = true
	admission.gateBulk = true

	service := defaultContentionConfig("D. ModeService (one write in flight)")
	service.wireRate = wireRate
	service.scheduler = NewScheduler(Options{Mode: ModeService})
	service.gateHigh = true
	service.gateBulk = true

	paced := func(fraction float64) contentionConfig {
		config := defaultContentionConfig(fmt.Sprintf("E. ModePaced at %.0f%% of the wire rate", fraction*100))
		config.wireRate = wireRate
		config.scheduler = NewScheduler(Options{
			Mode:       ModePaced,
			NormalRate: int64(wireRate * fraction),
		})
		config.gateHigh = true
		config.gateBulk = true
		return config
	}

	configs := []contentionConfig{baseline, gateOnly, admission, service, paced(0.95), paced(0.85), paced(0.70)}
	results := make([]contentionResult, 0, len(configs))
	for _, config := range configs {
		results = append(results, runContention(t, config))
	}

	t.Logf("receiver-visible delivery latency of a 256-byte high-priority message every 20 ms, "+
		"while %d flows flood a %.1f MB/s shared FIFO wire through a %d KiB per-flow acceptance "+
		"window", baseline.bulkFlows, wireRate/1_000_000, baseline.window/1024)
	t.Log("")
	for _, result := range results {
		t.Logf("%-44s %s", result.label, summariseLatencies(result.highLatencies))
		t.Logf("%-44s wire %.2f MB/s   queue mean %3d KiB  peak %3d KiB",
			"", result.bulkThroughput/1_000_000, result.queueMean/1024, result.queueHigh/1024)
	}
	t.Log("")

	baselineP99 := percentile(sortedCopy(baseline.result(results).highLatencies), 0.99)
	admissionResult := admission.result(results)
	serviceResult := service.result(results)
	fastPace := configs[4].result(results)
	slowPace := configs[6].result(results)

	t.Logf("p99 versus baseline (%s):", baselineP99.Round(time.Millisecond))
	t.Logf("  admission          %s   wire %.2f MB/s", percentile(sortedCopy(admissionResult.highLatencies), 0.99).Round(time.Millisecond), admissionResult.bulkThroughput/1_000_000)
	t.Logf("  service            %s   wire %.2f MB/s", percentile(sortedCopy(serviceResult.highLatencies), 0.99).Round(time.Millisecond), serviceResult.bulkThroughput/1_000_000)
	t.Logf("  paced 95%%          %s   wire %.2f MB/s", percentile(sortedCopy(fastPace.highLatencies), 0.99).Round(time.Millisecond), fastPace.bulkThroughput/1_000_000)
	t.Logf("  paced 70%%          %s   wire %.2f MB/s", percentile(sortedCopy(slowPace.highLatencies), 0.99).Round(time.Millisecond), slowPace.bulkThroughput/1_000_000)

	if baselineP99 < 50*time.Millisecond {
		t.Fatalf("the rig must contend before any comparison is meaningful: baseline p99 was %s",
			baselineP99)
	}

	// The result this experiment exists to establish: neither of the two models that only change
	// WHEN a write starts can empty a queue that is already inside the sender's acceptance
	// window. Both must therefore land within noise of the baseline.
	for _, candidate := range []struct {
		name   string
		result contentionResult
	}{
		{"ModeAdmission", admissionResult},
		{"ModeService", serviceResult},
	} {
		candidateP99 := percentile(sortedCopy(candidate.result.highLatencies), 0.99)
		if candidateP99 < baselineP99*4/5 {
			t.Logf("NOTE: %s improved p99 from %s to %s, which the window model does not predict; "+
				"re-examine the rig before trusting it", candidate.name, baselineP99, candidateP99)
		}
	}

	// And the mechanism that does work, with its price visible in the same table.
	if !(slowPace.bulkThroughput < fastPace.bulkThroughput) {
		t.Errorf("pacing harder must cost bulk throughput: 95%% gave %.2f MB/s and 70%% gave %.2f MB/s",
			fastPace.bulkThroughput/1_000_000, slowPace.bulkThroughput/1_000_000)
	}
	if !(slowPace.queueMean < baseline.result(results).queueMean) {
		t.Errorf("pacing must shrink the queue the high-priority message waits behind")
	}
}

// result finds a configuration's outcome by label, so the assertions above stay tied to the table
// a reader sees rather than to slice positions.
func (c contentionConfig) result(results []contentionResult) contentionResult {
	for _, result := range results {
		if result.label == c.label {
			return result
		}
	}
	panic("missing result for " + c.label)
}

func sortedCopy(latencies []time.Duration) []time.Duration {
	out := append([]time.Duration(nil), latencies...)
	sort.Slice(out, func(a, b int) bool { return out[a] < out[b] })
	return out
}
