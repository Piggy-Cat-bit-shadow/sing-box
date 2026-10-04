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

		time.Sleep(time.Duration(float64(time.Second) * float64(chunk.size) / rate))

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

func (c *wireConn) resetLatencies() {
	c.mu.Lock()
	c.latencies = c.latencies[:0]
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

type contentionResult struct {
	label string
	// highLatencies are the receiver-visible delivery times of the small high-priority messages,
	// measured from the moment each write returned. This is the product number.
	highLatencies []time.Duration
	// bulkThroughput is what the bulk flows managed to hand to the wire during the measurement
	// window. It is the price of the latency above.
	bulkThroughput float64
	wireThroughput float64
	queueHigh      int
	queueMean      int
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

	time.Sleep(config.duration)
	close(stop)
	workers.Wait()
	<-pingDone

	deliveredEnd, queueHigh, queueMean := shared.snapshot()

	bulkBytes := acceptedTotal(bulkConns, highBulkConns) - acceptedAtStart

	return contentionResult{
		label:          config.label,
		highLatencies:  highConn.snapshot(),
		bulkThroughput: float64(bulkBytes) / config.duration.Seconds(),
		wireThroughput: float64(deliveredEnd-deliveredStart) / config.duration.Seconds(),
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

func runColdStart(t *testing.T, config contentionConfig, gap time.Duration, repeats int) []time.Duration {
	t.Helper()
	latencies := make([]time.Duration, 0, repeats)
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
		if samples := pingConn.snapshot(); len(samples) > 0 {
			latencies = append(latencies, samples[0])
		}

		close(stop)
		workers.Wait()
		shared.close()
	}
	return latencies
}
