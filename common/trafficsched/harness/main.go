// Command traffic-scheduler-harness measures the upload scheduler on a real link.
//
// It is a manual engineering tool, not a test. The automated experiments in the parent package use
// a synthetic link so that they are reproducible and bounded in time; this one uses the network, so
// its numbers are the ones that describe a real deployment and its numbers are also the ones that
// move when the coffee shop's uplink does.
//
// # Running it
//
// On a host with capacity - a VPS, a second machine, anything reachable:
//
//	go run ./common/trafficsched/harness -listen :9000
//
// On the machine under test, with the rate the path is expected to sustain for uploads:
//
//	go run ./common/trafficsched/harness \
//	    -server HOST:9000 \
//	    -rate 8MiB/s \
//	    -bulk 4 \
//	    -bulk-class normal \
//	    -idle-gap 5s \
//	    -duration 20s
//
// # What it reports
//
//	first ping RTT   the round trip of the FIRST probe after -idle-gap of uninterrupted bulk
//	                 upload. This is the number the arming design failed to protect: a pacer that
//	                 starts when interactive traffic arrives protects the second request.
//	ping p50/p95/p99 round trips of a probe every -ping-interval for the rest of the run
//	bulk             the aggregate upload throughput the bulk flows achieved
//
// # What to run
//
//	-rate below what the path sustains   the intended configuration, and the only one that helps
//	-rate above what the path sustains    shows the failure mode: throughput is unchanged and the
//	                                     probe latency is back to unscheduled
//	-bulk-class high                     two classes of interactive traffic competing, which is the
//	                                     case aggregate shaping exists for and NORMAL-only shaping
//	                                     does not cover
//
// # Protocol
//
// Deliberately trivial, because the measurement is the point: a one-byte tag, a four-byte
// big-endian length, and the payload. Tag 'B' is bulk and is read and discarded. Tag 'P' is a probe
// and is echoed back verbatim, so the client measures a round trip through the same path the bulk
// data takes.
package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/trafficclass"
	"github.com/sagernet/sing-box/common/trafficsched"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	tagBulk  = 'B'
	tagProbe = 'P'
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		listen        = flag.String("listen", "", "run as the receiver on this address instead of measuring")
		server        = flag.String("server", "", "receiver address to measure against")
		rate          = flag.String("rate", "", "managed upload shaping rate, e.g. 8MiB/s or 2000000; empty or 0 leaves the scheduler inert")
		burst         = flag.Int("burst", 0, "shaping bucket size in bytes; 0 uses the package default")
		bulkCount     = flag.Int("bulk", 4, "number of concurrent bulk upload connections")
		bulkClass     = flag.String("bulk-class", "normal", "traffic class of the bulk flows: normal or high")
		bulkChunk     = flag.Int("bulk-chunk", 64*1024, "bytes per bulk write")
		probeSize     = flag.Int("probe-size", 256, "bytes per probe")
		probeEvery    = flag.Duration("ping-interval", 20*time.Millisecond, "interval between probes")
		idleGap       = flag.Duration("idle-gap", 5*time.Second, "bulk-only stretch before the first probe")
		duration      = flag.Duration("duration", 20*time.Second, "measurement length after the gap")
		warmup        = flag.Duration("warmup", 3*time.Second, "discarded samples before the measurement")
		mode          = flag.String("mode", "paced", "scheduler mode: paced (aggregate), normal-only, admission, service, off")
		highPerNormal = flag.Int("high-per-normal", 0, "NORMAL grants per high-priority grant; 0 uses the default")
	)
	flag.Parse()

	if *listen != "" {
		return runReceiver(*listen)
	}
	if *server == "" {
		return fmt.Errorf("-server is required (or -listen to run the receiver)")
	}
	if *duration <= 0 {
		return fmt.Errorf("-duration must be positive")
	}
	return runClient(clientConfig{
		server:        *server,
		rate:          *rate,
		burst:         *burst,
		bulkCount:     *bulkCount,
		bulkClass:     *bulkClass,
		bulkChunk:     *bulkChunk,
		probeSize:     *probeSize,
		probeEvery:    *probeEvery,
		idleGap:       *idleGap,
		duration:      *duration,
		warmup:        *warmup,
		mode:          *mode,
		highPerNormal: *highPerNormal,
	})
}

// --- receiver ---------------------------------------------------------------------------------

func runReceiver(address string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	fmt.Printf("receiver listening on %s\n", listener.Addr())
	for {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return acceptErr
		}
		go func() {
			defer conn.Close()
			if serveErr := serveReceiver(conn); serveErr != nil && serveErr != io.EOF {
				fmt.Fprintln(os.Stderr, "receiver connection:", serveErr)
			}
		}()
	}
}

// serveReceiver reads framed messages and echoes probes. Bulk payloads are read and dropped, which
// is what lets the path fill: a receiver that stopped reading would measure its own window instead
// of the link.
func serveReceiver(conn net.Conn) error {
	header := make([]byte, 5)
	for {
		if _, err := io.ReadFull(conn, header); err != nil {
			return err
		}
		tag := header[0]
		length := int(binary.BigEndian.Uint32(header[1:5]))
		if length < 0 || length > 1<<24 {
			return fmt.Errorf("implausible frame length: %d", length)
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return err
		}
		if tag != tagProbe {
			continue
		}
		if _, err := conn.Write(header[:5]); err != nil {
			return err
		}
		if _, err := conn.Write(payload); err != nil {
			return err
		}
	}
}

// --- client -----------------------------------------------------------------------------------

type clientConfig struct {
	server        string
	rate          string
	burst         int
	bulkCount     int
	bulkClass     string
	bulkChunk     int
	probeSize     int
	probeEvery    time.Duration
	idleGap       time.Duration
	duration      time.Duration
	warmup        time.Duration
	mode          string
	highPerNormal int
}

// directDialer hands every destination to the configured receiver, so the harness needs no
// configuration beyond the address it is measuring against.
type directDialer struct {
	address string
}

func (d directDialer) DialContext(ctx context.Context, network string, _ M.Socksaddr) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, d.address)
}

func (d directDialer) ListenPacket(ctx context.Context, _ M.Socksaddr) (net.PacketConn, error) {
	var listener net.ListenConfig
	return listener.ListenPacket(ctx, "udp", "")
}

func runClient(config clientConfig) error {
	mode, err := parseMode(config.mode)
	if err != nil {
		return err
	}
	options := trafficsched.Options{Mode: mode}
	if config.burst > 0 {
		options.Burst = config.burst
	}
	if config.highPerNormal > 0 {
		options.HighPerNormal = config.highPerNormal
	}

	// The production path: the connection manager owns the scheduler, installs the gate on flows
	// that would not have been spliced, and copies through it.
	manager := route.NewConnectionManager(log.NewNOPFactory().Logger())
	defer manager.Close()

	burst := options.Burst
	if burst == 0 {
		burst = trafficsched.DefaultBurst
	}

	if config.rate != "" && config.rate != "0" {
		parsed, parseErr := option.ParseByteRate(config.rate)
		if parseErr != nil {
			return parseErr
		}
		manager.SetUploadRate(parsed.Build())
	}

	fmt.Printf("receiver        %s\n", config.server)
	fmt.Printf("mode            %s\n", config.mode)
	fmt.Printf("configured rate %s\n", describeRate(manager.UploadRate()))
	fmt.Printf("bucket          %s\n", describeBytes(burst))
	fmt.Printf("bulk            %d flows, class %s, %s per write\n",
		config.bulkCount, config.bulkClass, describeBytes(config.bulkChunk))
	fmt.Printf("probe           %s every %s, first one after %s of bulk-only traffic\n",
		describeBytes(config.probeSize), config.probeEvery, config.idleGap)
	fmt.Println()

	bulkClass, err := parseClass(config.bulkClass)
	if err != nil {
		return err
	}

	dialer := directDialer{address: config.server}
	destination := M.ParseSocksaddrHostPort(strings.Split(config.server, ":")[0], portOf(config.server))

	stop := make(chan struct{})
	var bulkWorkers sync.WaitGroup
	var bulkBytes atomic.Int64

	startBulk := func() {
		for index := 0; index < config.bulkCount; index++ {
			bulkWorkers.Add(1)
			go func(index int) {
				defer bulkWorkers.Done()
				if runErr := runBulkFlow(manager, dialer, destination, bulkClass, config.bulkChunk, stop, &bulkBytes); runErr != nil && runErr != io.EOF {
					fmt.Fprintf(os.Stderr, "bulk %d: %v\n", index, runErr)
				}
			}(index)
		}
	}

	startBulk()

	// The gap. Everything the design is judged on happens here: with no interactive traffic at all,
	// the ordered modes are disarmed and the acceptance window fills, and the paced modes are still
	// shaping.
	fmt.Printf("filling for %s with no interactive traffic...\n", config.idleGap)
	time.Sleep(config.idleGap)

	probeConn, err := dialScheduled(manager, dialer, destination, trafficclass.ClassInteractive)
	if err != nil {
		close(stop)
		bulkWorkers.Wait()
		return fmt.Errorf("dial probe: %w", err)
	}
	defer probeConn.Close()

	firstProbe, err := probeOnce(probeConn, config.probeSize)
	if err != nil {
		close(stop)
		bulkWorkers.Wait()
		return fmt.Errorf("first probe: %w", err)
	}

	// Discard the warm-up, then measure.
	time.Sleep(config.warmup)
	bulkAtStart := bulkBytes.Load()
	if os.Getenv("HARNESS_DEBUG") != "" {
		// A per-second rate trace, because the number that matters here is a rate and a single
		// total cannot distinguish a steady one from a bursty one.
		go func() {
			previous := bulkAtStart
			last := time.Now()
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-stop:
					return
				case <-ticker.C:
				}
				now := bulkBytes.Load()
				fmt.Printf("  [debug] accepted %s/s\n",
					describeBytes(int(float64(now-previous)/time.Since(last).Seconds())))
				previous, last = now, time.Now()
			}
		}()
	}
	samples, err := probeLoop(probeConn, config.probeSize, config.probeEvery, config.duration, stop)
	bulkElapsed := config.duration
	close(stop)
	bulkWorkers.Wait()
	bulkUploaded := bulkBytes.Load() - bulkAtStart
	if err != nil {
		return err
	}

	fmt.Println()
	fmt.Printf("first probe after the gap   %s\n", firstProbe.Round(100*time.Microsecond))
	if len(samples) > 0 {
		fmt.Printf("probe round trip            %s\n", describeLatencies(samples))
	} else {
		fmt.Printf("probe round trip            no samples\n")
	}
	fmt.Printf("bulk throughput             %s/s over %s\n",
		describeBytes(int(float64(bulkUploaded)/bulkElapsed.Seconds())), bulkElapsed.Round(time.Second))
	fmt.Println()
	fmt.Println("A rate the path sustains shows a large gap between the configured rate and the bulk")
	fmt.Println("throughput only when the rate is set BELOW it; a rate above what the path carries")
	fmt.Println("shows bulk throughput equal to the path and a probe latency equal to unscheduled.")
	return nil
}

func portOf(address string) uint16 {
	_, portString, err := net.SplitHostPort(address)
	if err != nil {
		return 0
	}
	var port int
	_, _ = fmt.Sscanf(portString, "%d", &port)
	return uint16(port)
}

// dialScheduled opens one connection through the production path. The inbound side is a real socket
// pair, because the whole point is to measure the gate inside the copy loop the connection manager
// starts, not a writer the harness wrapped for itself.
func dialScheduled(manager *route.ConnectionManager, dialer N.Dialer, destination M.Socksaddr, class trafficclass.Class) (net.Conn, error) {
	client, server := net.Pipe()
	metadata := adapter.InboundContext{
		Destination:  destination,
		TrafficClass: class,
	}
	closed := make(chan struct{})
	var closeOnce sync.Once
	go manager.NewConnection(context.Background(), dialer, server, metadata, func(error) {
		closeOnce.Do(func() { close(closed) })
	})
	return client, nil
}

// runBulkFlow writes framed bulk data through one scheduled upload until the run stops.
//
// The counter is shared and updated per write rather than returned at the end: a total that only
// appears when the goroutine finishes cannot be sampled, so a measurement window would silently
// include the fill and warm-up phases that preceded it.
func runBulkFlow(manager *route.ConnectionManager, dialer N.Dialer, destination M.Socksaddr, class trafficclass.Class, chunk int, stop <-chan struct{}, uploaded *atomic.Int64) error {
	conn, err := dialScheduled(manager, dialer, destination, class)
	if err != nil {
		return err
	}
	defer conn.Close()

	frame := make([]byte, 5+chunk)
	frame[0] = tagBulk
	binary.BigEndian.PutUint32(frame[1:5], uint32(chunk))

	for {
		select {
		case <-stop:
			return nil
		default:
		}
		written, writeErr := conn.Write(frame)
		uploaded.Add(int64(written))
		if writeErr != nil {
			return writeErr
		}
	}
}

func probeOnce(conn net.Conn, size int) (time.Duration, error) {
	frame := make([]byte, 5+size)
	frame[0] = tagProbe
	binary.BigEndian.PutUint32(frame[1:5], uint32(size))

	start := time.Now()
	if _, err := conn.Write(frame); err != nil {
		return 0, err
	}
	if _, err := io.ReadFull(conn, frame); err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

func probeLoop(conn net.Conn, size int, every, duration time.Duration, stop <-chan struct{}) ([]time.Duration, error) {
	deadline := time.Now().Add(duration)
	ticker := time.NewTicker(every)
	defer ticker.Stop()

	var samples []time.Duration
	for time.Now().Before(deadline) {
		select {
		case <-stop:
			return samples, nil
		case <-ticker.C:
		}
		sample, err := probeOnce(conn, size)
		if err != nil {
			return samples, err
		}
		samples = append(samples, sample)
	}
	return samples, nil
}

func parseMode(value string) (trafficsched.Mode, error) {
	switch value {
	case "paced", "aggregate", "":
		return trafficsched.ModePaced, nil
	case "normal-only":
		return trafficsched.ModePacedNormalOnly, nil
	case "admission":
		return trafficsched.ModeAdmission, nil
	case "service":
		return trafficsched.ModeService, nil
	case "off", "inert":
		// The production default: the gate is installed and shapes nothing, because no rate source
		// is installed either.
		return trafficsched.ModePaced, nil
	default:
		return 0, fmt.Errorf("unknown -mode %q", value)
	}
}

func parseClass(value string) (trafficclass.Class, error) {
	switch value {
	case "normal", "default", "":
		return trafficclass.ClassDefault, nil
	case "high", "interactive":
		return trafficclass.ClassInteractive, nil
	case "bulk":
		return trafficclass.ClassBulk, nil
	case "realtime":
		return trafficclass.ClassRealtime, nil
	default:
		return 0, fmt.Errorf("unknown -bulk-class %q", value)
	}
}

func describeLatencies(samples []time.Duration) string {
	sorted := append([]time.Duration(nil), samples...)
	sort.Slice(sorted, func(a, b int) bool { return sorted[a] < sorted[b] })
	return fmt.Sprintf("n=%3d p50=%8s p95=%8s p99=%8s max=%8s",
		len(sorted), percentile(sorted, 0.50), percentile(sorted, 0.95),
		percentile(sorted, 0.99), sorted[len(sorted)-1])
}

func percentile(sorted []time.Duration, fraction float64) time.Duration {
	return sorted[int(float64(len(sorted)-1)*fraction)].Round(100 * time.Microsecond)
}

func describeBytes(bytes int) string {
	switch {
	case bytes >= 1<<30:
		return fmt.Sprintf("%.2f GiB", float64(bytes)/(1<<30))
	case bytes >= 1<<20:
		return fmt.Sprintf("%.2f MiB", float64(bytes)/(1<<20))
	case bytes >= 1<<10:
		return fmt.Sprintf("%.2f KiB", float64(bytes)/(1<<10))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

func describeRate(bytesPerSecond int64) string {
	if bytesPerSecond <= 0 {
		return "none (scheduler inert: every managed byte is admitted immediately)"
	}
	return describeBytes(int(bytesPerSecond)) + "/s"
}
