package option

import (
	"math"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/schema"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
)

// TrafficSchedulerOptions configures the managed upload traffic scheduler.
//
// # This is a fork extension
//
// The key does not exist in official sing-box, and a configuration that uses it is not loadable by
// the official client. It is omitted when unset, so a configuration that does not use it stays
// exactly as it was and remains interchangeable in both directions.
//
// # What it shapes
//
// Only flows this fork manages: userspace-proxied uploads whose copy loop is in sing-box. Traffic
// that never enters sing-box, flows served by the kernel splice path, and downloads are not
// affected. It is not machine-wide QoS and it is not a download limit.
type TrafficSchedulerOptions struct {
	// UploadRate is the rate the managed upload path is shaped to.
	//
	// # What the number means
	//
	// It is the actual shaping rate, applied exactly as written. There is no hidden safety factor
	// and no fraction is reserved: a configured 8 MiB/s admits 8 MiB/s of managed upload.
	//
	// It is NOT the ISP's nominal bandwidth, and it is not a ceiling that only applies while
	// interactive traffic is present. When a rate is configured the shaper runs continuously, for
	// as long as the process does, because the queue it exists to prevent fills up during the idle
	// periods too.
	//
	// # What to configure
	//
	// The rate the path actually sustains for uploads, measured rather than quoted: a connection
	// advertised at 200 Mbit/s uploads considerably less, and a rate above what the path carries
	// keeps the queue built and buys nothing at all. Configuring slightly below the measured rate
	// is the intended use; the package documentation in common/trafficsched carries the
	// measurements behind that, including a rate at the sustained rate delivering 42 ms p95 where
	// the same rate a notch below delivers 8 ms.
	//
	// Zero or absent leaves the scheduler inert: it observes every managed byte and admits all of
	// them immediately, with no queue, no lock and no timer.
	UploadRate ByteRate `json:"upload_rate,omitempty"`
}

// ByteRate is a byte-per-second rate in configuration.
//
// It accepts a JSON number, which is bytes per second, or a string with a unit:
//
//	8388608            bytes per second
//	"8388608"          bytes per second
//	"8 MiB/s"          binary size unit, the overwhelmingly likely spelling
//	"8MiB"             the /s is decorative: the field is a rate whatever it says
//	"20 MB/s"          decimal size unit
//	"20 Mbps"          bit unit, converted at 8 bits to the byte
//
// A negative value is rejected rather than wrapped, and a value whose unit conversion would
// overflow int64 is rejected rather than silently truncated. Both cases would otherwise be accepted
// and then ignored, which for a rate limit means the configuration says one thing and the process
// does another.
//
// Marshalling emits the exact integer with a B/s unit, so the value round-trips without loss: a
// rate the user wrote as "1.5 MB/s" is emitted as "1500000B/s" rather than being re-rounded to a
// prettier unit and changed.
type ByteRate int64

// Build returns the rate in bytes per second.
func (r ByteRate) Build() int64 { return int64(r) }

var (
	// byteRateUnits map a unit suffix to how many bytes per second one unit is.
	byteRateUnits = map[string]int64{
		"":    1,
		"b":   1,
		"kb":  1000,
		"mb":  1000 * 1000,
		"gb":  1000 * 1000 * 1000,
		"tb":  1000 * 1000 * 1000 * 1000,
		"kib": 1 << 10,
		"mib": 1 << 20,
		"gib": 1 << 30,
		"tib": 1 << 40,
	}
	// bitRateUnits map a unit suffix to how many BITS per second one unit is. They are divided by
	// eight after scaling, which is why a "20 Mbps" line is not the same number as "20 MB/s".
	bitRateUnits = map[string]int64{
		"bps":  1,
		"kbps": 1000,
		"mbps": 1000 * 1000,
		"gbps": 1000 * 1000 * 1000,
	}
)

func (r ByteRate) MarshalJSON() ([]byte, error) {
	return json.Marshal(strconv.FormatInt(int64(r), 10) + "B/s")
}

func (r *ByteRate) UnmarshalJSON(content []byte) error {
	var intValue int64
	if err := json.Unmarshal(content, &intValue); err == nil {
		if intValue < 0 {
			return E.New("rate must not be negative: ", intValue)
		}
		*r = ByteRate(intValue)
		return nil
	}
	var stringValue string
	if err := json.Unmarshal(content, &stringValue); err != nil {
		return E.Cause(err, "upload_rate must be a number of bytes per second or a string with a unit")
	}
	value, err := ParseByteRate(stringValue)
	if err != nil {
		return err
	}
	*r = value
	return nil
}

// ParseByteRate parses the string form of a ByteRate.
func ParseByteRate(value string) (ByteRate, error) {
	trimmed := strings.TrimSpace(value)
	digitEnd := 0
	for digitEnd < len(trimmed) && trimmed[digitEnd] >= '0' && trimmed[digitEnd] <= '9' {
		digitEnd++
	}
	if digitEnd == 0 {
		return 0, E.New("invalid rate: ", value)
	}
	amount, err := strconv.ParseInt(trimmed[:digitEnd], 10, 64)
	if err != nil {
		return 0, E.Cause(err, "parse ", value)
	}
	// The suffix is normalized so that "8 MiB/s", "8MiB/S" and "8 mib / s" all mean one thing.
	unit := strings.ToLower(strings.Join(strings.Fields(trimmed[digitEnd:]), ""))
	unit = strings.TrimSuffix(unit, "/s")
	if multiplier, isByteUnit := byteRateUnits[unit]; isByteUnit {
		scaled, scaleErr := scaleRate(amount, multiplier, 1)
		if scaleErr != nil {
			return 0, E.Cause(scaleErr, value)
		}
		return ByteRate(scaled), nil
	}
	if multiplier, isBitUnit := bitRateUnits[unit]; isBitUnit {
		scaled, scaleErr := scaleRate(amount, multiplier, 8)
		if scaleErr != nil {
			return 0, E.Cause(scaleErr, value)
		}
		return ByteRate(scaled), nil
	}
	return 0, E.New("unsupported rate unit: ", trimmed[digitEnd:])
}

// scaleRate multiplies with an overflow check.
//
// The multiplication is checked even though the result is divided afterwards, because the
// intermediate is what would wrap: reporting an overflow the caller could have represented is
// preferable to accepting a rate and then shaping to a different one, or to zero.
func scaleRate(amount int64, multiplier int64, divisor int64) (int64, error) {
	if amount > math.MaxInt64/multiplier {
		return 0, E.New("rate overflows: ", amount, " * ", multiplier)
	}
	return amount * multiplier / divisor, nil
}

func (r ByteRate) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	return builder.Define("ByteRate", func() (*schema.Node, error) {
		return schema.AnyOf(
			schema.IntegerNode(),
			schema.StringNode(),
		), nil
	})
}
