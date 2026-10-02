package libbox

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/sagernet/sing-box/common/networkquality"
	"github.com/sagernet/sing-box/common/stun"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/experimental/locale"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/service/oomkiller"
	"github.com/sagernet/sing/common/byteformats"
	E "github.com/sagernet/sing/common/exceptions"
)

var (
	sBasePath                string
	sWorkingPath             string
	sTempPath                string
	sUserID                  int
	sGroupID                 int
	sFixAndroidStack         bool
	sCommandServerListenPort uint16
	sCommandServerSecret     string
	sLogMaxLines             int
	sDebug                   bool
	sCrashReportSource       string
	sAppVersion              string
	sAppMarketingVersion     string
	sOOMKillerEnabled        bool
	sOOMKillerDisabled       bool
	sOOMMemoryLimit          int64
	sPowerReportEnabled      bool
	sPlatformMetadata        []byte
)

func init() {
	debug.SetPanicOnFault(true)
	debug.SetTraceback("all")
}

type SetupOptions struct {
	BasePath                string
	WorkingPath             string
	TempPath                string
	FixAndroidStack         bool
	CommandServerListenPort int32
	CommandServerSecret     string
	LogMaxLines             int
	Debug                   bool
	CrashReportSource       string
	AppVersion              string
	AppMarketingVersion     string
	OomKillerEnabled        bool
	OomKillerDisabled       bool
	OomMemoryLimit          int64
	PowerReportEnabled      bool
	PlatformMetadata        string
}

func applySetupOptions(options *SetupOptions) {
	sBasePath = options.BasePath
	sWorkingPath = options.WorkingPath
	sTempPath = options.TempPath

	sUserID = os.Getuid()
	sGroupID = os.Getgid()

	// TODO: remove after fixed
	// https://github.com/golang/go/issues/68760
	sFixAndroidStack = options.FixAndroidStack

	sCommandServerListenPort = uint16(options.CommandServerListenPort)
	sCommandServerSecret = options.CommandServerSecret
	sLogMaxLines = options.LogMaxLines
	sDebug = options.Debug
	sCrashReportSource = options.CrashReportSource
	sAppVersion = options.AppVersion
	sAppMarketingVersion = options.AppMarketingVersion
	ReloadSetupOptions(options)
}

func ReloadSetupOptions(options *SetupOptions) {
	sOOMKillerEnabled = options.OomKillerEnabled
	sOOMKillerDisabled = options.OomKillerDisabled
	sOOMMemoryLimit = options.OomMemoryLimit
	sPowerReportEnabled = options.PowerReportEnabled
	if json.Valid([]byte(options.PlatformMetadata)) {
		sPlatformMetadata = []byte(options.PlatformMetadata)
	} else {
		sPlatformMetadata = nil
	}
	if sOOMKillerEnabled {
		// On iOS the OOM killer only ever means the PacketTunnel NetworkExtension, and that
		// deployment has a CANONICAL policy: a 50 MiB fallback budget with a 100 GC target.
		//
		// The timer already forces that canonical policy on iOS under a NetworkExtension -
		// see resolvePolicyMode, which ignores every override and returns the canonical budget.
		// The Go runtime settings here were computed from the EXTERNAL OomMemoryLimit instead,
		// which let the two halves disagree:
		//
		//	OomMemoryLimit = 200 MiB on iOS
		//	  timer budget   =  50 MiB   (canonical, from the policy)
		//	  GOMEMLIMIT     = 190 MiB   (RuntimeMemoryLimit(200 MiB))
		//	  GOGC           = runtime default, NOT the canonical 100
		//
		// That is the same policy split the config profile used to allow, through a different
		// door: the runtime paced against 190 MiB while the timer policed 50 MiB, and the
		// collector target was whatever the runtime default happened to be.
		//
		// The external value is therefore ignored on iOS, and the canonical budget and GC
		// target are applied unconditionally. Ignoring it is the correct behaviour rather
		// than a workaround: an iOS NetworkExtension's memory limit is imposed by the system,
		// not chosen by the caller, so a caller-supplied number is not a setting - it is a
		// disagreement with the system.
		// The decision is a pure function so it can be tested on any platform. An earlier
		// version was inline behind C.IsIos, which meant the only place it could be exercised
		// was an iOS build - and a policy that can only be checked on one platform is a policy
		// that is usually wrong on that platform.
		effectiveLimit, gcPercent, applyGCPercent := resolveOOMKillerRuntimePolicy(
			sOOMMemoryLimit,
			C.IsIos,
		)
		sOOMMemoryLimit = effectiveLimit
		if applyGCPercent {
			debug.SetGCPercent(gcPercent)
		}
		if sOOMMemoryLimit > 0 {
			runtimeMemoryLimit := oomkiller.RuntimeMemoryLimit(uint64(sOOMMemoryLimit))
			debug.SetMemoryLimit(int64(runtimeMemoryLimit))
			// One startup line, reporting what the runtime actually has in force.
			//
			// The effective iOS memory policy is the product of a budget, a safety margin
			// and a GC percentage that live across three files, so a device log otherwise
			// gives no way to confirm what is really set. On a phone this is the
			// difference between "the client is collecting too aggressively" and guessing.
			//
			// The values are read from runtime/metrics, which has no side effects. The
			// previous version called debug.SetGCPercent(-1) to make it return the current
			// value, and -1 does not mean "read" - it means "disable garbage collection".
			// A memory diagnostic was briefly turning the collector off.
			//
			// Nothing here is hot-path: it runs once per process start.
			if C.IsIos {
				log.Info(runtimeMemoryDiagnostic(uint64(sOOMMemoryLimit), readRuntimeMemoryState()))
			}
		} else {
			debug.SetMemoryLimit(math.MaxInt64)
		}
	} else {
		debug.SetMemoryLimit(math.MaxInt64)
	}
}

func Setup(options *SetupOptions) error {
	applySetupOptions(options)
	os.MkdirAll(sWorkingPath, 0o777)
	os.MkdirAll(sTempPath, 0o777)
	err := redirectStderr(filepath.Join(sWorkingPath, "CrashReport-"+sCrashReportSource+".log"))
	savePlatformSnapshot()
	return err
}

func SetLocale(localeID string) error {
	if !locale.Set(localeID) {
		return E.New("unsupported locale: ", localeID)
	}
	return nil
}

func Version() string {
	return C.Version
}

func GoVersion() string {
	return runtime.Version() + ", " + runtime.GOOS + "/" + runtime.GOARCH
}

func FormatBytes(length int64) string {
	return byteformats.FormatKBytes(uint64(length))
}

func FormatMemoryBytes(length int64) string {
	return byteformats.FormatMemoryKBytes(uint64(length))
}

func FormatDuration(duration int64) string {
	return log.FormatDuration(time.Duration(duration) * time.Millisecond)
}

func FormatBitrate(bps int64) string {
	return networkquality.FormatBitrate(bps)
}

const NetworkQualityDefaultConfigURL = networkquality.DefaultConfigURL

const NetworkQualityDefaultMaxRuntimeSeconds = int32(networkquality.DefaultMaxRuntime / time.Second)

const (
	NetworkQualityAccuracyLow    = int32(networkquality.AccuracyLow)
	NetworkQualityAccuracyMedium = int32(networkquality.AccuracyMedium)
	NetworkQualityAccuracyHigh   = int32(networkquality.AccuracyHigh)
)

const (
	NetworkQualityPhaseIdle     = int32(networkquality.PhaseIdle)
	NetworkQualityPhaseDownload = int32(networkquality.PhaseDownload)
	NetworkQualityPhaseUpload   = int32(networkquality.PhaseUpload)
	NetworkQualityPhaseDone     = int32(networkquality.PhaseDone)
)

const STUNDefaultServer = stun.DefaultServer

const (
	STUNPhaseBinding      = int32(stun.PhaseBinding)
	STUNPhaseNATMapping   = int32(stun.PhaseNATMapping)
	STUNPhaseNATFiltering = int32(stun.PhaseNATFiltering)
	STUNPhaseDone         = int32(stun.PhaseDone)
)

const (
	NATMappingEndpointIndependent     = int32(stun.NATMappingEndpointIndependent)
	NATMappingAddressDependent        = int32(stun.NATMappingAddressDependent)
	NATMappingAddressAndPortDependent = int32(stun.NATMappingAddressAndPortDependent)
)

const (
	NATFilteringEndpointIndependent     = int32(stun.NATFilteringEndpointIndependent)
	NATFilteringAddressDependent        = int32(stun.NATFilteringAddressDependent)
	NATFilteringAddressAndPortDependent = int32(stun.NATFilteringAddressAndPortDependent)
)

func FormatNATMapping(value int32) string {
	return stun.NATMapping(value).String()
}

func FormatNATFiltering(value int32) string {
	return stun.NATFiltering(value).String()
}

func FormatFQDN(fqdn string) string {
	return dns.FqdnToDomain(fqdn)
}

func ProxyDisplayType(proxyType string) string {
	return C.ProxyDisplayName(proxyType)
}

// resolveOOMKillerRuntimePolicy maps a requested memory limit to the limit and GC target the Go
// runtime should actually use.
//
// # Why the iOS branch ignores its input
//
// On iOS the OOM killer only ever means the PacketTunnel NetworkExtension, whose memory limit is
// imposed by the SYSTEM rather than chosen by the caller. The timer already forces the canonical
// budget there (see resolvePolicyMode, which ignores every override), so honouring an external
// number in the runtime settings would pace the Go runtime against one budget while the timer
// policed another.
//
// Concretely, an override of 200 MiB used to produce a 50 MiB timer budget, a 190 MiB
// GOMEMLIMIT and a non-canonical GOGC - the same policy split the config profile used to allow.
//
// Ignoring the input is therefore the correct behaviour, not a workaround: a caller-supplied
// number is not a setting here, it is a disagreement with the system.
func resolveOOMKillerRuntimePolicy(requestedLimit int64, isIOS bool) (effectiveLimit int64, gcPercent int, applyGCPercent bool) {
	if isIOS {
		return oomkiller.DefaultAppleNetworkExtensionMemoryLimit,
			oomkiller.DefaultAppleNetworkExtensionGCPercent,
			true
	}
	return requestedLimit, 0, false
}
