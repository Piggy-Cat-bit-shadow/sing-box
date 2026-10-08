package interop

import (
	"sync"

	"github.com/sagernet/sing-box/option"
	badjson "github.com/sagernet/sing/common/json"
)

// The option-layer probe.
//
// # What it is for
//
// The first run of this stand's validation tests failed on every xhttp scenario
// for a reason that had nothing to do with the reference:
// `option.V2RayTransportOptions.UnmarshalJSON` switched on the transport type to
// pick which sub-options struct to decode into, and its switch had no `xhttp`
// case — so a config file selecting `type: xhttp` was rejected with
// `unknown transport type: xhttp` before `box.New` was reached.
// `MarshalJSON` and `DescribeSchema` did know xhttp, which is how the omission
// survived: a test that built options in Go and marshalled them, or that read the
// JSON schema, never saw it. `cmd/sing-box/cmd_run.go` loads a config with
// `json.UnmarshalExtendedContext[option.Options]`, so the gap was on the
// production load path and the transport this fork compiled in and registered was
// unreachable from any config file at all.
//
// The gap was reported and fixed (`8ce22abd7 xhttp: make the transport reachable
// from a config file`). This probe exists because fixing one case does not fix
// the class: it asks the option layer, once per process, whether it can load an
// xhttp transport, and the tests that need to load a config through the parser
// consult it.
//
// # What it does today
//
// The probe returns nil, so nothing skips, and the xhttp scenarios round-trip
// through the parser and through `box.New` like every other scenario. If the
// answer ever becomes an error again, the tests that must parse a config SKIP
// with a message naming `option/v2ray_transport.go`, and
// TestOptionLayerHandlesTheXHTTPTransport fails unless the error is exactly the
// pinned `unknown transport type: xhttp` rejection — a parser that rejects xhttp
// for a NEW reason (a mode-validation error, a renamed field) must not be
// mistaken for the old one.
//
// The raw-JSON assertions in validate_test.go are NOT gated: they run either way,
// because the generator's output is correct regardless of whether this build can
// parse it back.

// xhttpProbeConfig is the smallest client config that selects the xhttp
// transport. It is a literal rather than a generated pair so the probe measures
// the option layer alone and cannot be perturbed by a generator change.
const xhttpProbeConfig = `{
  "outbounds": [
    {
      "type": "vless",
      "server": "127.0.0.1",
      "server_port": 24443,
      "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
      "transport": {
        "type": "xhttp",
        "path": "/interop",
        "mode": "stream-one"
      }
    }
  ]
}`

// nonXHTTPProbeConfig is the positive control: the same shape with a transport
// the option layer does know. It proves the probe is actually parsing rather than
// failing for an unrelated reason (a missing uuid, a malformed document), which
// would make the known-gap pin pass vacuously.
const nonXHTTPProbeConfig = `{
  "outbounds": [
    {
      "type": "vless",
      "server": "127.0.0.1",
      "server_port": 24443,
      "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
      "transport": {
        "type": "ws",
        "path": "/interop"
      }
    }
  ]
}`

var (
	xhttpParseOnce sync.Once
	xhttpParseErr  error
)

// XHTTPTransportParseError reports the error this build's option layer produces
// for an xhttp client transport, or nil when it loads one.
//
// The answer is a property of the compiled build, so it is computed once per
// process.
func XHTTPTransportParseError() error {
	xhttpParseOnce.Do(func() {
		_, xhttpParseErr = badjson.UnmarshalExtendedContext[option.Options](RegistryContext(),
			[]byte(xhttpProbeConfig))
	})
	return xhttpParseErr
}

// XHTTPOptionLayerSkipReason returns the reason a test that must load an xhttp
// config through this build's parser cannot run, or the empty string when it can.
func XHTTPOptionLayerSkipReason() string {
	err := XHTTPTransportParseError()
	if err == nil {
		return ""
	}
	return "the option layer of this build cannot load an `xhttp` transport: " + err.Error() + "\n" +
		"option.V2RayTransportOptions.UnmarshalJSON does not handle `xhttp`, so a JSON config " +
		"selecting it is rejected before box.New is reached (the production load path is the same " +
		"function). This is the defect this stand found once before and that was fixed in " +
		"8ce22abd7; it has regressed. The generated config is still asserted at the raw-JSON " +
		"level; the parse, box-construction and live halves of the xhttp scenarios cannot run " +
		"until option/v2ray_transport.go handles it. See test/interop/README.md, section " +
		"`The gap this stand found`."
}

// NonXHTTPTransportParseError is the control for XHTTPTransportParseError: it
// must be nil for the probe to mean anything.
func NonXHTTPTransportParseError() error {
	_, err := badjson.UnmarshalExtendedContext[option.Options](RegistryContext(),
		[]byte(nonXHTTPProbeConfig))
	return err
}
