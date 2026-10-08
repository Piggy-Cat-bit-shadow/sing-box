package interop

import (
	"encoding/json"
	"os"
	"path/filepath"

	E "github.com/sagernet/sing/common/exceptions"
)

// The configuration generator.
//
// # Why the JSON is described by local structs instead of the option package
//
// The generator deliberately does NOT marshal option.Options for the client side
// and does not marshal an Xray type library for the server side. It describes
// both wire formats with local structs whose json tags are the schema, and the
// default tests then parse the bytes back through this repository's own config
// parser and compare the result with the scenario.
//
// That asymmetry is the whole value: if the generator built option.Options
// directly, the round-trip test would compare a struct with itself and could not
// catch a wrong json tag, a field the parser renames, or a `key_share` that
// serializes as `keyShare`. Writing the JSON as a literal schema keeps the test
// honest — it is an independent transcription of the wire format, and a
// divergence is exactly what it fails on.
//
// # Why files, not just bytes
//
// A maintainer diagnosing a wire mismatch needs to open the exact file the
// reference was started with, edit it, and re-run the reference by hand. The
// generator therefore writes both files into an artifact directory and returns
// their paths; the returned bytes are the same bytes, so a test can assert on
// them without a second read.

// DefaultXHTTPPath is the XHTTP path both sides are configured with. A single
// constant is used because the path is a shared secret between the two files: a
// generator that let them drift would produce a stand that fails for a reason
// that looks like a protocol bug.
const DefaultXHTTPPath = "/interop"

// Input is everything the generator needs. Ports and addresses are explicit
// rather than discovered so that a generated pair can be reproduced from the
// failure message alone.
type Input struct {
	Scenario Scenario

	// ArtifactDir receives the two config files. It must exist.
	ArtifactDir string

	// ServerAddress is the reference binary's listen address (loopback).
	ServerAddress string
	// ServerPort is the reference binary's listen port. It is a UDP port for an
	// H3 scenario and a TCP port otherwise.
	ServerPort uint16

	// ClientAddress and ClientPort are this fork's box mixed inbound.
	ClientAddress string
	ClientPort    uint16

	// TargetAddress and TargetPort are the local echo/HTTP target the reference
	// forwards a proxied connection to.
	TargetAddress string
	TargetPort    uint16

	// ServerName is the TLS SNI: the REALITY server name list entry, or the
	// certificate name for a plain-TLS scenario.
	ServerName string

	// CamouflageAddress is host:port of the local TLS server a REALITY handshake
	// is forwarded to when it does not authenticate.
	CamouflageAddress string

	// RealityPublicKey/RealityPrivateKey/ShortID are one matched REALITY triple:
	// the public half goes to this fork's client, the private half and the short
	// id to the reference.
	RealityPublicKey  string
	RealityPrivateKey string
	ShortID           string

	// UUID is the VLESS user id shared by both files.
	UUID string

	// Encryption is the matched encryption pair. It is required when the
	// scenario enables the layer and ignored otherwise.
	Encryption EncryptionKeyMaterial

	// TLSCertFile/TLSKeyFile are used only by a plain-TLS scenario.
	TLSCertFile string
	TLSKeyFile  string

	// ClientLogPath and ServerLogPath are where each side's output is written.
	ClientLogPath string
	ServerLogPath string

	// XHTTPPath overrides DefaultXHTTPPath; empty selects the default.
	XHTTPPath string

	// LogLevel is the box client's log level. "debug" is the default because the
	// point of the stand is diagnosing a mismatch.
	LogLevel string
}

// Pair is a generated, written pair of configurations.
type Pair struct {
	Scenario Scenario

	ClientConfig []byte
	ServerConfig []byte

	ClientConfigPath string
	ServerConfigPath string

	ClientLogPath string
	ServerLogPath string

	ServerPort uint16
	ServerUDP  bool
}

// ---------------------------------------------------------------------------
// Client schema (this fork's box).
//
// Only the subset this stand needs is transcribed. Unknown fields are not
// emitted, which is deliberate: the generated file should read as a minimal
// reproduction of the scenario, not as a dump of every default.
// ---------------------------------------------------------------------------

type clientConfig struct {
	Log       *clientLog        `json:"log,omitempty"`
	Inbounds  []clientInbound   `json:"inbounds"`
	Outbounds []clientOutbound  `json:"outbounds"`
	Route     *clientRouteBlock `json:"route,omitempty"`
}

type clientLog struct {
	Level     string `json:"level,omitempty"`
	Output    string `json:"output,omitempty"`
	Timestamp bool   `json:"timestamp,omitempty"`
}

type clientInbound struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Listen     string `json:"listen"`
	ListenPort uint16 `json:"listen_port"`
}

type clientOutbound struct {
	Type       string           `json:"type"`
	Tag        string           `json:"tag"`
	Server     string           `json:"server"`
	ServerPort uint16           `json:"server_port"`
	UUID       string           `json:"uuid"`
	Flow       string           `json:"flow,omitempty"`
	Encryption string           `json:"encryption,omitempty"`
	TLS        *clientTLS       `json:"tls,omitempty"`
	Transport  *clientTransport `json:"transport,omitempty"`
}

type clientTLS struct {
	Enabled    bool           `json:"enabled"`
	ServerName string         `json:"server_name,omitempty"`
	Insecure   bool           `json:"insecure,omitempty"`
	ALPN       []string       `json:"alpn,omitempty"`
	UTLS       *clientUTLS    `json:"utls,omitempty"`
	Reality    *clientReality `json:"reality,omitempty"`
}

type clientUTLS struct {
	Enabled     bool   `json:"enabled"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type clientReality struct {
	Enabled   bool   `json:"enabled"`
	PublicKey string `json:"public_key"`
	ShortID   string `json:"short_id"`
	KeyShare  string `json:"key_share,omitempty"`
}

type clientTransport struct {
	Type string `json:"type"`
	Path string `json:"path,omitempty"`
	Mode string `json:"mode,omitempty"`
}

type clientRouteBlock struct {
	Final string `json:"final"`
}

// The tags are constants because the tests and the harness both address the
// generated outbound by tag; a literal in two places would eventually disagree.
const (
	clientInboundTag  = "interop-in"
	clientOutboundTag = "interop-out"
)

// ---------------------------------------------------------------------------
// Server schema (reference Xray-core).
//
// Transcribed from Xray's own configuration shape, NOT from this fork's option
// package: the two are different schemas on purpose (ours is snake_case and
// flattens the transport into `transport`, Xray's is camelCase and nests it in
// `streamSettings`). Conflating them is the classic way an interop stand ends up
// testing the client against itself.
// ---------------------------------------------------------------------------

type xrayServerConfig struct {
	Log       *xrayLog       `json:"log,omitempty"`
	Inbounds  []xrayInbound  `json:"inbounds"`
	Outbounds []xrayOutbound `json:"outbounds"`
}

type xrayLog struct {
	LogLevel string `json:"loglevel"`
}

type xrayInbound struct {
	Listen         string             `json:"listen"`
	Port           uint16             `json:"port"`
	Protocol       string             `json:"protocol"`
	Settings       xrayVLESSSettings  `json:"settings"`
	StreamSettings xrayStreamSettings `json:"streamSettings"`
}

type xrayVLESSSettings struct {
	// Decryption is "none" for a plain VLESS inbound, or the full encryption spec
	// for a server that terminates the post-quantum layer. It sits at the
	// settings level in Xray, once per inbound, NOT per client.
	Decryption string             `json:"decryption"`
	Clients    []xrayVLESSCClient `json:"clients"`
}

type xrayVLESSCClient struct {
	ID   string `json:"id"`
	Flow string `json:"flow,omitempty"`
}

type xrayStreamSettings struct {
	Network         string               `json:"network"`
	Security        string               `json:"security"`
	RealitySettings *xrayRealitySettings `json:"realitySettings,omitempty"`
	TLSSettings     *xrayTLSSettings     `json:"tlsSettings,omitempty"`
	XHTTPSettings   *xrayXHTTPSettings   `json:"xhttpSettings,omitempty"`
}

type xrayRealitySettings struct {
	Show        bool     `json:"show"`
	Dest        string   `json:"dest"`
	Xver        int      `json:"xver"`
	ServerNames []string `json:"serverNames"`
	PrivateKey  string   `json:"privateKey"`
	ShortIDs    []string `json:"shortIds"`
}

type xrayTLSSettings struct {
	ALPN         []string          `json:"alpn,omitempty"`
	Certificates []xrayCertificate `json:"certificates,omitempty"`
}

// xrayCertificate mirrors Xray's `certificates` entry.
type xrayCertificate struct {
	CertificateFile string `json:"certificateFile"`
	KeyFile         string `json:"keyFile"`
}

type xrayXHTTPSettings struct {
	Path string `json:"path"`
	Mode string `json:"mode,omitempty"`
}

type xrayOutbound struct {
	Protocol string               `json:"protocol"`
	Tag      string               `json:"tag,omitempty"`
	Settings *xrayFreedomSettings `json:"settings,omitempty"`
}

// xrayFreedomSettings is the `settings` block of the reference's freedom outbound.
//
// The stand needs exactly one rule in it, and the rule is not optional on a current reference: Xray
// gives the freedom outbound behind a proxied inbound (vless, vmess, trojan, shadowsocks) a DEFAULT
// rule that blocks every private destination and blackholes the connection for a random 30-90
// seconds. A blocked connection is not an error the client can attribute - the tunnel is up, the
// reference logs "blocked target" on its own side, and the client just sees a request that never
// answers, which is the shape of a transport bug. The stand's destination is loopback by design,
// because that is what makes it runnable with no external network, so without this rule every
// scenario fails against such a reference for a reason that has nothing to do with the protocol.
//
// An explicit rule is consulted BEFORE the default one (proxy/freedom's matchFinalRule walks the
// outbound's own rules first), and an older reference that does not know the field ignores it, so
// emitting it unconditionally is what keeps one generated file correct for both sides of the
// version split.
type xrayFreedomSettings struct {
	FinalRules []xrayFreedomFinalRule `json:"finalRules"`
}

type xrayFreedomFinalRule struct {
	Action string   `json:"action"`
	IP     []string `json:"ip"`
}

// xrayLoopbackCIDRs is every destination the stand can hand the reference: the target is always on
// 127.0.0.1, and ::1 is listed so a future IPv6-loopback target does not silently become the one
// blocked case.
var xrayLoopbackCIDRs = []string{"127.0.0.0/8", "::1/128"}

// ---------------------------------------------------------------------------

// Generate builds, writes and returns one matched pair of configurations.
func (in Input) Generate() (Pair, error) {
	scenario := in.Scenario
	if err := in.validate(); err != nil {
		return Pair{}, err
	}
	clientConfig := in.buildClientConfig()
	serverConfig := in.buildServerConfig()

	clientBytes, err := marshalConfig(clientConfig)
	if err != nil {
		return Pair{}, E.Cause(err, "marshal client config")
	}
	serverBytes, err := marshalConfig(serverConfig)
	if err != nil {
		return Pair{}, E.Cause(err, "marshal server config")
	}

	pair := Pair{
		Scenario:         scenario,
		ClientConfig:     clientBytes,
		ServerConfig:     serverBytes,
		ClientConfigPath: filepath.Join(in.ArtifactDir, "client-"+scenario.Name+".json"),
		ServerConfigPath: filepath.Join(in.ArtifactDir, "server-"+scenario.Name+".json"),
		ClientLogPath:    in.ClientLogPath,
		ServerLogPath:    in.ServerLogPath,
		ServerPort:       in.ServerPort,
		ServerUDP:        scenario.H3,
	}
	if err = os.WriteFile(pair.ClientConfigPath, clientBytes, 0o644); err != nil {
		return Pair{}, E.Cause(err, "write client config")
	}
	if err = os.WriteFile(pair.ServerConfigPath, serverBytes, 0o644); err != nil {
		return Pair{}, E.Cause(err, "write server config")
	}
	return pair, nil
}

func (in Input) validate() error {
	scenario := in.Scenario
	if scenario.Name == "" {
		return E.New("scenario has no name")
	}
	if in.ArtifactDir == "" {
		return E.New("scenario ", scenario.Name, ": no artifact directory")
	}
	if in.ServerAddress == "" || in.ServerPort == 0 {
		return E.New("scenario ", scenario.Name, ": no reference listen address")
	}
	if in.ClientAddress == "" || in.ClientPort == 0 {
		return E.New("scenario ", scenario.Name, ": no client listen address")
	}
	if in.TargetAddress == "" || in.TargetPort == 0 {
		return E.New("scenario ", scenario.Name, ": no target address")
	}
	if in.UUID == "" {
		return E.New("scenario ", scenario.Name, ": no VLESS uuid")
	}
	if scenario.Reality {
		if in.RealityPublicKey == "" || in.RealityPrivateKey == "" {
			return E.New("scenario ", scenario.Name, ": REALITY needs a matched key pair")
		}
		if in.ShortID == "" {
			return E.New("scenario ", scenario.Name, ": REALITY needs a short id")
		}
		if in.ServerName == "" {
			return E.New("scenario ", scenario.Name, ": REALITY needs a server name")
		}
		if in.CamouflageAddress == "" {
			return E.New("scenario ", scenario.Name, ": REALITY needs a camouflage address")
		}
	}
	if scenario.PlainTLS {
		if in.ServerName == "" {
			return E.New("scenario ", scenario.Name, ": plain TLS needs a server name")
		}
		if in.TLSCertFile == "" || in.TLSKeyFile == "" {
			return E.New("scenario ", scenario.Name, ": plain TLS needs a certificate and key file")
		}
	}
	if scenario.EncryptionEnabled() {
		spec, err := scenario.EncryptionSpec()
		if err != nil {
			return err
		}
		if spec == "" {
			return E.New("scenario ", scenario.Name, ": encryption is half-configured")
		}
		if in.Encryption.ClientSpec == "" || in.Encryption.ServerSpec == "" {
			return E.New("scenario ", scenario.Name, ": encryption is enabled but no key material was supplied")
		}
	}
	if scenario.Transport == TransportXHTTP {
		switch scenario.XHTTPMode {
		case "", XHTTPModeAuto, XHTTPModePacketUp, XHTTPModeStreamUp, XHTTPModeStreamOne:
		default:
			return E.New("scenario ", scenario.Name, ": unknown XHTTP mode ", scenario.XHTTPMode)
		}
	} else if scenario.XHTTPMode != "" {
		return E.New("scenario ", scenario.Name, ": an XHTTP mode was set without the xhttp transport")
	}
	if scenario.H3 && scenario.XHTTPMode == XHTTPModePacketUp {
		// packet-up's uplink is a POST per write; over QUIC that is legal, but the
		// reference's H3 support is the least verified corner of the stand and
		// combining it with the least verified mode would make a failure
		// unattributable. Refused at generation time, on purpose.
		return E.New("scenario ", scenario.Name, ": H3 with packet-up is not covered by this stand")
	}
	return nil
}

func (in Input) path() string {
	if in.XHTTPPath != "" {
		return in.XHTTPPath
	}
	return DefaultXHTTPPath
}

func (in Input) logLevel() string {
	if in.LogLevel != "" {
		return in.LogLevel
	}
	return "debug"
}

func (in Input) buildClientConfig() clientConfig {
	scenario := in.Scenario
	outbound := clientOutbound{
		Type:       "vless",
		Tag:        clientOutboundTag,
		Server:     in.ServerAddress,
		ServerPort: in.ServerPort,
		UUID:       in.UUID,
		Flow:       scenario.Flow(),
	}
	if scenario.EncryptionEnabled() {
		outbound.Encryption = in.Encryption.ClientSpec
	}
	switch {
	case scenario.Reality:
		outbound.TLS = &clientTLS{
			Enabled:    true,
			ServerName: in.ServerName,
			UTLS: &clientUTLS{
				Enabled:     true,
				Fingerprint: "chrome",
			},
			Reality: &clientReality{
				Enabled:   true,
				PublicKey: in.RealityPublicKey,
				ShortID:   in.ShortID,
				KeyShare:  scenario.KeyShare,
			},
		}
	case scenario.PlainTLS:
		outbound.TLS = &clientTLS{
			Enabled:    true,
			ServerName: in.ServerName,
			// The stand's certificate is self-signed and minted per run; pinning it
			// would test the certificate plumbing rather than the transport. The
			// reference side is still authenticated by the protocol (and by REALITY
			// where it is in play), so this is not a "trust anything" shortcut for
			// the protocol itself.
			Insecure: true,
		}
		if scenario.H3 {
			outbound.TLS.ALPN = []string{"h3"}
		}
	}
	if scenario.Transport == TransportXHTTP {
		outbound.Transport = &clientTransport{
			Type: TransportXHTTP,
			Path: in.path(),
			Mode: scenario.XHTTPMode,
		}
	}
	return clientConfig{
		Log: &clientLog{
			Level:     in.logLevel(),
			Output:    in.ClientLogPath,
			Timestamp: true,
		},
		Inbounds: []clientInbound{{
			Type:       "mixed",
			Tag:        clientInboundTag,
			Listen:     in.ClientAddress,
			ListenPort: in.ClientPort,
		}},
		Outbounds: []clientOutbound{outbound},
		Route:     &clientRouteBlock{Final: clientOutboundTag},
	}
}

func (in Input) buildServerConfig() xrayServerConfig {
	scenario := in.Scenario
	settings := xrayVLESSSettings{
		Decryption: "none",
		Clients: []xrayVLESSCClient{{
			ID:   in.UUID,
			Flow: scenario.Flow(),
		}},
	}
	if scenario.EncryptionEnabled() {
		settings.Decryption = in.Encryption.ServerSpec
	}
	streamSettings := xrayStreamSettings{
		Network:  "tcp",
		Security: "none",
	}
	if scenario.Reality {
		streamSettings.Security = "reality"
		streamSettings.RealitySettings = &xrayRealitySettings{
			Show:        false,
			Dest:        in.CamouflageAddress,
			Xver:        0,
			ServerNames: []string{in.ServerName},
			PrivateKey:  in.RealityPrivateKey,
			ShortIDs:    []string{in.ShortID},
		}
	}
	if scenario.PlainTLS {
		streamSettings.Security = "tls"
		tlsSettings := &xrayTLSSettings{
			Certificates: []xrayCertificate{{
				CertificateFile: in.TLSCertFile,
				KeyFile:         in.TLSKeyFile,
			}},
		}
		if scenario.H3 {
			// Xray keys the QUIC listener on the ALPN: ["h3"] is what makes the
			// inbound bind UDP instead of TCP. Emitting it for a non-H3 scenario
			// would move the listener off the address the readiness probe watches.
			tlsSettings.ALPN = []string{"h3"}
		}
		streamSettings.TLSSettings = tlsSettings
	}
	if scenario.Transport == TransportXHTTP {
		streamSettings.Network = TransportXHTTP
		streamSettings.XHTTPSettings = &xrayXHTTPSettings{
			Path: in.path(),
			Mode: scenario.XHTTPMode,
		}
	}
	return xrayServerConfig{
		Log: &xrayLog{LogLevel: in.logLevel()},
		Inbounds: []xrayInbound{{
			Listen:         in.ServerAddress,
			Port:           in.ServerPort,
			Protocol:       "vless",
			Settings:       settings,
			StreamSettings: streamSettings,
		}},
		Outbounds: []xrayOutbound{{
			Protocol: "freedom",
			Tag:      "direct",
			Settings: &xrayFreedomSettings{FinalRules: []xrayFreedomFinalRule{{
				Action: "allow",
				IP:     xrayLoopbackCIDRs,
			}}},
		}},
	}
}

// marshalConfig renders a config the way a human wants to read it: indented,
// with a trailing newline so the file ends cleanly in an editor and in a diff.
func marshalConfig(value any) ([]byte, error) {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}
