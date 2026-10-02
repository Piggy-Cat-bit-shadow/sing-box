package oomkiller

import (
	"context"
	"runtime"
	runtimeDebug "runtime/debug"
	"runtime/metrics"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/byteformats"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/memory"
)

const (
	defaultMinInterval               = 100 * time.Millisecond
	defaultMaxInterval               = 10 * time.Second
	defaultReleaseInterval           = time.Second
	defaultReleaseShrinkFloor        = 16
	defaultReleaseShrinkDivisor      = 10
	defaultMaxRateLookahead          = time.Second
	defaultSafetyMargin              = 5 * 1024 * 1024
	defaultAvailableTriggerMarginMin = 32 * 1024 * 1024
	defaultAvailableTriggerMarginMax = 128 * 1024 * 1024
)

type pressureState uint8

const (
	pressureStateNormal pressureState = iota
	pressureStateArmed
	pressureStateTriggered
)

type memorySample struct {
	usage          uint64
	available      uint64
	availableKnown bool
}

type pressureThresholds struct {
	trigger uint64
	armed   uint64
	resume  uint64
}

type timerConfig struct {
	memoryLimit     uint64
	safetyMargin    uint64
	hasSafetyMargin bool
	minInterval     time.Duration
	maxInterval     time.Duration
	policyMode      policyMode
	killerDisabled  bool
}

func buildTimerConfig(options option.OOMKillerServiceOptions, memoryLimit uint64, policyMode policyMode, killerDisabled bool) (timerConfig, error) {
	// Inside an iOS NetworkExtension the policy is a PLATFORM safety contract, not a
	// tunable. A profile may not widen the sampling gap or shrink the footprint margin,
	// because the Go runtime soft limit is derived from the same margin: letting a profile
	// set one and not the other policed the process against two different notions of
	// "safe", and the failure mode is the process being killed rather than a slow request.
	//
	// Returning the canonical config here, before any option is read, is what makes the
	// two layers consistent by construction instead of by convention.
	if policyMode == policyModeNetworkExtension {
		policy := canonicalNetworkExtensionPolicy
		return timerConfig{
			memoryLimit:     policy.memoryLimit(),
			safetyMargin:    policy.safetyMargin,
			hasSafetyMargin: true,
			minInterval:     policy.minInterval,
			maxInterval:     policy.maxInterval,
			policyMode:      policyMode,
			killerDisabled:  killerDisabled,
		}, nil
	}

	minInterval := defaultMinInterval
	if options.MinInterval != 0 {
		minInterval = time.Duration(options.MinInterval.Build())
		if minInterval <= 0 {
			return timerConfig{}, E.New("min_interval must be greater than 0")
		}
	}

	maxInterval := defaultMaxInterval
	if options.MaxInterval != 0 {
		maxInterval = time.Duration(options.MaxInterval.Build())
		if maxInterval <= 0 {
			return timerConfig{}, E.New("max_interval must be greater than 0")
		}
	}
	if maxInterval < minInterval {
		return timerConfig{}, E.New("max_interval must be greater than or equal to min_interval")
	}

	var (
		safetyMargin    uint64
		hasSafetyMargin bool
	)
	if options.SafetyMargin != nil && options.SafetyMargin.Value() > 0 {
		safetyMargin = options.SafetyMargin.Value()
		hasSafetyMargin = true
	} else if memoryLimit > 0 {
		safetyMargin = defaultSafetyMargin
		hasSafetyMargin = true
	}

	return timerConfig{
		memoryLimit:     memoryLimit,
		safetyMargin:    safetyMargin,
		hasSafetyMargin: hasSafetyMargin,
		minInterval:     minInterval,
		maxInterval:     maxInterval,
		policyMode:      policyMode,
		killerDisabled:  killerDisabled,
	}, nil
}

type timerState struct {
	state                   pressureState
	currentInterval         time.Duration
	forceMinInterval        bool
	pendingPressureBaseline bool
	pressureBaseline        memorySample
	pressureBaselineTime    time.Time
}

type adaptiveTimer struct {
	timerConfig
	logger          log.ContextLogger
	network         adapter.NetworkManager
	connections     adapter.ConnectionManager
	cacheFile       adapter.CacheFile
	recorder        *Recorder
	pressure        *atomic.Uint32
	limitThresholds pressureThresholds

	access          sync.Mutex
	timer           *time.Timer
	lastGoroutines  int
	lastConnections int
	lastGCCycles    uint64
	lastRelease     time.Time
	timerState
}

func newAdaptiveTimer(logger log.ContextLogger, network adapter.NetworkManager, connections adapter.ConnectionManager, cacheFile adapter.CacheFile, recorder *Recorder, pressure *atomic.Uint32, config timerConfig) *adaptiveTimer {
	t := &adaptiveTimer{
		timerConfig: config,
		logger:      logger,
		network:     network,
		connections: connections,
		cacheFile:   cacheFile,
		recorder:    recorder,
		pressure:    pressure,
	}
	if config.policyMode == policyModeMemoryLimit || config.policyMode == policyModeNetworkExtension {
		t.limitThresholds = computeLimitThresholds(config.memoryLimit, config.safetyMargin)
	}
	return t
}

func (t *adaptiveTimer) start(carriedState *timerState) {
	t.access.Lock()
	defer t.access.Unlock()
	if t.timer != nil {
		return
	}
	if carriedState != nil {
		t.timerState = *carriedState
		t.timer = time.AfterFunc(t.minInterval, t.poll)
		return
	}
	t.startLocked()
}

func (t *adaptiveTimer) startLocked() {
	if t.timer != nil {
		return
	}
	t.state = pressureStateNormal
	t.forceMinInterval = false
	t.timer = time.AfterFunc(t.minInterval, t.poll)
}

func (t *adaptiveTimer) stop() timerState {
	t.access.Lock()
	defer t.access.Unlock()
	if t.timer != nil {
		t.timer.Stop()
		t.timer = nil
	}
	return t.timerState
}

func (t *adaptiveTimer) poll() {
	var triggered bool
	var rateTriggered bool
	sample := readMemorySample(t.policyMode)

	t.access.Lock()
	if t.timer == nil {
		t.access.Unlock()
		return
	}
	if t.pendingPressureBaseline {
		t.pressureBaseline = sample
		t.pressureBaselineTime = time.Now()
		t.pendingPressureBaseline = false
	}
	previousState := t.state
	t.state = t.nextState(sample)
	if t.state == pressureStateNormal {
		t.forceMinInterval = false
		if !t.pressureBaselineTime.IsZero() && time.Since(t.pressureBaselineTime) > t.maxInterval {
			t.pressureBaselineTime = time.Time{}
		}
	}
	interval := t.intervalForState()
	t.timer.Reset(interval)
	triggered = previousState != pressureStateTriggered && t.state == pressureStateTriggered
	if !triggered && !t.pressureBaselineTime.IsZero() && t.memoryLimit > 0 &&
		sample.usage > t.pressureBaseline.usage && sample.usage < t.memoryLimit {
		elapsed := time.Since(t.pressureBaselineTime)
		if elapsed >= t.minInterval/2 {
			growth := sample.usage - t.pressureBaseline.usage
			ratePerSecond := float64(growth) / elapsed.Seconds()
			headroom := t.memoryLimit - sample.usage
			secondsUntilLimit := float64(headroom) / ratePerSecond
			lookahead := min(2*interval, defaultMaxRateLookahead)
			if secondsUntilLimit < lookahead.Seconds() {
				triggered = true
				rateTriggered = true
				t.state = pressureStateTriggered
			}
		}
	}
	state := t.state
	t.access.Unlock()
	t.pressure.Store(uint32(state.memoryPressure()))
	var connections int
	if t.connections != nil {
		connections = t.connections.Count()
	}
	if t.recorder != nil {
		t.recorder.sample(sample, state, connections)
		if state != previousState {
			t.recorder.recordStateChange(state, sample)
		}
	}
	if !triggered {
		t.releaseIdleMemory(sample, connections)
		return
	}
	var reason string
	if rateTriggered {
		reason = resetReasonRate
		if t.killerDisabled {
			t.logger.Warn("memory growth rate critical (report only), usage: ", byteformats.FormatMemoryBytes(sample.usage), t.logDetails(sample))
		} else {
			t.logger.Error("memory growth rate critical, usage: ", byteformats.FormatMemoryBytes(sample.usage), t.logDetails(sample), ", resetting network")
			t.network.ReleaseMemory(context.Background())
		}
	} else {
		reason = resetReasonThreshold
		if t.killerDisabled {
			t.logger.Warn("memory threshold reached (report only), usage: ", byteformats.FormatMemoryBytes(sample.usage), t.logDetails(sample))
		} else {
			t.logger.Error("memory threshold reached, usage: ", byteformats.FormatMemoryBytes(sample.usage), t.logDetails(sample), ", resetting network")
			t.network.ReleaseMemory(context.Background())
		}
	}
	t.releaseMemory()
	if t.recorder != nil {
		after := readMemorySample(t.policyMode)
		t.recorder.recordReset(reason, sample, after, connections, t.killerDisabled)
		t.recorder.snapshot(SnapshotReasonReset, sample, t.belowTrigger(after), false)
	}
}

func (t *adaptiveTimer) releaseIdleMemory(sample memorySample, connections int) {
	goroutines := runtime.NumGoroutine()
	gcCycles := readGCCycles()
	now := time.Now()
	t.access.Lock()
	shrank := hasMeaningfulDrop(t.lastGoroutines, goroutines) || hasMeaningfulDrop(t.lastConnections, connections)
	idleGC := gcCycles == t.lastGCCycles
	t.lastGoroutines = goroutines
	t.lastConnections = connections
	t.lastGCCycles = gcCycles
	if t.belowResume(sample) || now.Sub(t.lastRelease) < defaultReleaseInterval || (!shrank && !idleGC) {
		t.access.Unlock()
		return
	}
	t.lastRelease = now
	t.access.Unlock()
	runtimeDebug.FreeOSMemory()
	t.access.Lock()
	t.lastGCCycles = readGCCycles()
	t.access.Unlock()
	t.logger.Trace("released idle memory, usage: ", byteformats.FormatMemoryBytes(sample.usage), " -> ", byteformats.FormatMemoryBytes(memory.Total()))
}

func hasMeaningfulDrop(previous int, current int) bool {
	if current >= previous {
		return false
	}
	return previous-current >= max(defaultReleaseShrinkFloor, previous/defaultReleaseShrinkDivisor)
}

func readGCCycles() uint64 {
	samples := []metrics.Sample{{Name: "/gc/cycles/total:gc-cycles"}}
	metrics.Read(samples)
	if samples[0].Value.Kind() != metrics.KindUint64 {
		return 0
	}
	return samples[0].Value.Uint64()
}

func (t *adaptiveTimer) belowResume(sample memorySample) bool {
	switch t.policyMode {
	case policyModeMemoryLimit, policyModeNetworkExtension:
		return sample.usage < t.limitThresholds.resume
	case policyModeAvailable:
		return !sample.availableKnown || sample.available > t.availableThresholds(sample).resume
	default:
		return true
	}
}

func (t *adaptiveTimer) belowTrigger(sample memorySample) bool {
	switch t.policyMode {
	case policyModeMemoryLimit, policyModeNetworkExtension:
		return sample.usage < t.limitThresholds.trigger
	case policyModeAvailable:
		return !sample.availableKnown || sample.available > t.availableThresholds(sample).trigger
	default:
		return true
	}
}

func (t *adaptiveTimer) releaseMemory() {
	if t.cacheFile != nil {
		t.cacheFile.Flush()
	}
	t.pressure.Store(uint32(tun.MemoryPressureCritical))
	badCleanup()
	runtimeDebug.FreeOSMemory()
}

func (s pressureState) memoryPressure() tun.MemoryPressure {
	switch s {
	case pressureStateArmed:
		return tun.MemoryPressureWarning
	case pressureStateTriggered:
		return tun.MemoryPressureCritical
	default:
		return tun.MemoryPressureNone
	}
}

func (t *adaptiveTimer) nextState(sample memorySample) pressureState {
	switch t.policyMode {
	case policyModeMemoryLimit, policyModeNetworkExtension:
		return nextPressureState(t.state,
			sample.usage >= t.limitThresholds.trigger,
			sample.usage >= t.limitThresholds.armed,
			sample.usage >= t.limitThresholds.resume,
		)
	case policyModeAvailable:
		if !sample.availableKnown {
			return pressureStateNormal
		}
		thresholds := t.availableThresholds(sample)
		return nextPressureState(t.state,
			sample.available <= thresholds.trigger,
			sample.available <= thresholds.armed,
			sample.available <= thresholds.resume,
		)
	default:
		return pressureStateNormal
	}
}

func computeLimitThresholds(memoryLimit uint64, safetyMargin uint64) pressureThresholds {
	triggerMargin := min(safetyMargin, memoryLimit)
	armedMargin := min(triggerMargin*2, memoryLimit)
	resumeMargin := min(triggerMargin*4, memoryLimit)
	return pressureThresholds{
		trigger: memoryLimit - triggerMargin,
		armed:   memoryLimit - armedMargin,
		resume:  memoryLimit - resumeMargin,
	}
}

// RuntimeMemoryLimit returns the Go runtime soft limit for a given process budget.
//
// It is the "armed" threshold - the budget less two safety margins - and it shares the
// derivation with the canonical NetworkExtension policy rather than repeating the
// arithmetic. When this and the timer thresholds were computed independently they could
// disagree about the same budget, which is exactly the fork this helper removes.
func RuntimeMemoryLimit(memoryLimit uint64) uint64 {
	return computeLimitThresholds(memoryLimit, defaultSafetyMargin).armed
}

// runtimeMemoryLimitForPolicy is the runtime soft limit the canonical policy implies.
//
// Callers inside a NetworkExtension use this rather than recomputing from the budget, so
// the value cannot diverge from the thresholds the timer enforces.
func runtimeMemoryLimitForPolicy() uint64 {
	return canonicalNetworkExtensionPolicy.runtimeMemoryLimit()
}

func (t *adaptiveTimer) availableThresholds(sample memorySample) pressureThresholds {
	var triggerMargin uint64
	if t.hasSafetyMargin {
		triggerMargin = t.safetyMargin
	} else if sample.usage == 0 {
		triggerMargin = defaultAvailableTriggerMarginMin
	} else {
		triggerMargin = max(defaultAvailableTriggerMarginMin, min(sample.usage/4, defaultAvailableTriggerMarginMax))
	}
	return pressureThresholds{
		trigger: triggerMargin,
		armed:   triggerMargin * 2,
		resume:  triggerMargin * 4,
	}
}

// intervalForState returns how long to wait before the next observation.
//
// # The fresh-start ramp
//
// A fresh timer polls at minInterval, then DOUBLES on each normal sample until it reaches
// maxInterval. The previous code special-cased the first normal poll as
//
//	if t.currentInterval == 0 { t.currentInterval = t.maxInterval }
//
// which skipped the entire ladder: the only guaranteed observations were at 100ms and then
// 10s later. With the canonical policy - a 50 MiB budget, a 5 MiB margin and a 45 MiB trigger -
// a native or Swift allocation burst of more than 5 MiB during that ten-second gap would never
// be seen by the timer.
//
// # Why the gap was not covered elsewhere
//
// The dispatch memory-pressure source is NOT a substitute. DISPATCH_MEMORYPRESSURE_CRITICAL is
// a SYSTEM-WIDE signal: it reports that the kernel is under pressure generally, not that this
// process is approaching its own limit. It can fire for another app's allocations, and there is
// no guarantee it fires before a per-process jetsam high-water mark is reached. The timer is the
// only component that observes THIS process's phys_footprint on a schedule, so the schedule has
// to be dense enough to be useful.
//
// # Why a ramp rather than a permanent fast poll
//
// Polling at 100ms forever would close the gap completely and cost a wakeup every 100ms for the
// entire life of a tunnel that is usually idle - battery spent observing a process that is not
// changing. The ramp concentrates the observations where the risk is: shortly after start, and
// whenever memory is actually moving. The cost is a bounded number of extra wakeups - 100ms,
// 200ms, 400ms, ... up to 10s, so about seven extra polls - and it is measured rather than
// assumed; see the cadence benchmark.
//
// # Where the risk actually is
//
// A process that is genuinely growing rarely stays in the normal state: it crosses the armed
// threshold and returns to minInterval on its own. The ramp's job is to make sure it is SEEN
// crossing.
func (t *adaptiveTimer) intervalForState() time.Duration {
	switch {
	case t.forceMinInterval || t.state != pressureStateNormal || !t.pressureBaselineTime.IsZero():
		// Pressure, or a recent pressure event: observe closely.
		t.currentInterval = t.minInterval
	default:
		if t.currentInterval == 0 {
			// The first normal sample after start (or after a reset). Begin the ramp from the
			// bottom rather than jumping to the ceiling.
			t.currentInterval = t.minInterval
		} else {
			t.currentInterval = min(t.currentInterval*2, t.maxInterval)
		}
	}
	return t.currentInterval
}

// intervalScheduleForDiagnostics returns the observation schedule a fresh timer follows while
// everything stays normal, for reporting and for tests.
//
// It exists so the ramp's shape is a stated property rather than something a reader has to
// derive by simulating the timer.
func intervalScheduleForDiagnostics(minInterval time.Duration, maxInterval time.Duration, steps int) []time.Duration {
	if steps <= 0 {
		return nil
	}
	schedule := make([]time.Duration, 0, steps)
	current := time.Duration(0)
	for i := 0; i < steps; i++ {
		if current == 0 {
			current = minInterval
		} else {
			current = min(current*2, maxInterval)
		}
		schedule = append(schedule, current)
	}
	return schedule
}

func (t *adaptiveTimer) logDetails(sample memorySample) string {
	switch t.policyMode {
	case policyModeMemoryLimit, policyModeNetworkExtension:
		headroom := uint64(0)
		if sample.usage < t.memoryLimit {
			headroom = t.memoryLimit - sample.usage
		}
		return ", limit: " + byteformats.FormatMemoryBytes(t.memoryLimit) + ", headroom: " + byteformats.FormatMemoryBytes(headroom)
	case policyModeAvailable:
		if sample.availableKnown {
			return ", available: " + byteformats.FormatMemoryBytes(sample.available)
		}
	}
	return ""
}

func nextPressureState(current pressureState, shouldTrigger, shouldArm, shouldStayTriggered bool) pressureState {
	if current == pressureStateTriggered {
		if shouldStayTriggered {
			return pressureStateTriggered
		}
		return pressureStateNormal
	}
	if shouldTrigger {
		return pressureStateTriggered
	}
	if shouldArm {
		return pressureStateArmed
	}
	return pressureStateNormal
}

// readMemorySample reads the process footprint, and the available-memory figure when the
// platform actually provides one.
//
// # Why availableKnown is not simply set by mode
//
// The previous version marked the sample "known" whenever the mode was one that could use
// it. That conflates two different states: "the platform says there are N bytes free" and
// "this platform has no such API". On the second, memory.Available() returns 0, and a
// zero read as a real measurement means "no memory available" - the timer would treat a
// healthy process on an unsupported platform as being in permanent critical pressure.
//
// memory.AvailableAvailable() is the platform's own answer to whether the figure is
// meaningful, so it decides. phys_footprint (memory.Total()) remains the primary signal
// and is always available.
func readMemorySample(mode policyMode) memorySample {
	sample := memorySample{
		usage: memory.Total(),
	}
	if mode == policyModeAvailable || mode == policyModeNetworkExtension {
		if memory.AvailableAvailable() {
			sample.available = memory.Available()
			sample.availableKnown = true
		}
	}
	return sample
}

func (s pressureState) String() string {
	switch s {
	case pressureStateArmed:
		return "armed"
	case pressureStateTriggered:
		return "triggered"
	default:
		return "normal"
	}
}
