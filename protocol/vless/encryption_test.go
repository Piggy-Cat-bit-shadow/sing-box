package vless

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

// keyOf returns a base64url-encoded synthetic public key of n bytes. Only the
// size matters to the parser; a real key is a server credential that does not
// belong in the tree.
func keyOf(n int) string {
	return base64.RawURLEncoding.EncodeToString(make([]byte, n))
}

func key32() string   { return keyOf(keyLenX25519) }
func key1184() string { return keyOf(keyLenMLKEM768) }

// The grammar is mlkem768x25519plus.<appearance>.<rtt>[.<padding>…].<key>[.<key>…].
// Every shape a real subscription can carry must parse to the exact wire
// parameters, because a mis-parse here is invisible until the node silently
// fails to connect.
func TestParseClientEncryptionAccepts(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		spec    string
		xorMode uint32
		seconds uint32
		keyLens []int
		padding string
	}{
		{
			name:    "native 0rtt, x25519 key",
			spec:    "mlkem768x25519plus.native.0rtt." + key32(),
			xorMode: xorModeNative, seconds: 1, keyLens: []int{32},
		},
		{
			name:    "xorpub 1rtt, mlkem768 key",
			spec:    "mlkem768x25519plus.xorpub.1rtt." + key1184(),
			xorMode: xorModeXorPub, seconds: 0, keyLens: []int{1184},
		},
		{
			name:    "random appearance",
			spec:    "mlkem768x25519plus.random.0rtt." + key32(),
			xorMode: xorModeRandom, seconds: 1, keyLens: []int{32},
		},
		{
			// A relay chain mixes both key sizes, in config order.
			name:    "mlkem then x25519 chain, 0rtt",
			spec:    "mlkem768x25519plus.native.0rtt." + key1184() + "." + key32(),
			xorMode: xorModeNative, seconds: 1, keyLens: []int{1184, 32},
		},
		{
			name:    "x25519 then mlkem chain, 1rtt",
			spec:    "mlkem768x25519plus.native.1rtt." + key32() + "." + key1184(),
			xorMode: xorModeNative, seconds: 0, keyLens: []int{32, 1184},
		},
		{
			// Padding blocks precede the keys and are only meaningful in 1-RTT.
			name:    "padding blocks then key",
			spec:    "mlkem768x25519plus.native.1rtt.100-111-1111.75-0-111." + key32(),
			xorMode: xorModeNative, seconds: 0, keyLens: []int{32},
			padding: "100-111-1111.75-0-111",
		},
		{
			name:    "single padding block then key",
			spec:    "mlkem768x25519plus.random.1rtt.100-111-1111." + key1184(),
			xorMode: xorModeRandom, seconds: 0, keyLens: []int{1184},
			padding: "100-111-1111",
		},
		{
			// A subscription may carry surrounding whitespace.
			name:    "padded with spaces",
			spec:    "  mlkem768x25519plus.native.0rtt." + key32() + "  ",
			xorMode: xorModeNative, seconds: 1, keyLens: []int{32},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := parseClientEncryption(testCase.spec)
			require.NoError(t, err)
			require.Equal(t, testCase.xorMode, cfg.xorMode)
			require.Equal(t, testCase.seconds, cfg.seconds)
			require.Len(t, cfg.keys, len(testCase.keyLens))
			for i, keyLen := range testCase.keyLens {
				require.Len(t, cfg.keys[i], keyLen, "key %d", i)
			}
			require.Equal(t, testCase.padding, cfg.padding)
		})
	}
}

// A bad spec must fail at config time with a message naming the offending part
// — the alternative is a connection that silently never establishes.
func TestParseClientEncryptionRejects(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		spec    string
		wantSub string
	}{
		{name: "empty", spec: "", wantSub: "empty encryption string"},
		{name: "whitespace only", spec: "   ", wantSub: "empty encryption string"},
		{
			name:    "too few segments",
			spec:    "mlkem768x25519plus.native.0rtt",
			wantSub: "expected at least method.appearance.rtt.key",
		},
		{
			name:    "unknown method",
			spec:    "x25519only.native.0rtt." + key32(),
			wantSub: "unsupported encryption method",
		},
		{
			name:    "unknown appearance",
			spec:    "mlkem768x25519plus.plaid.0rtt." + key32(),
			wantSub: "unknown encryption appearance",
		},
		{
			name:    "unknown rtt mode",
			spec:    "mlkem768x25519plus.native.7rtt." + key32(),
			wantSub: "unknown encryption RTT mode",
		},
		{
			name:    "empty trailing segment",
			spec:    "mlkem768x25519plus.native.0rtt." + key32() + ".",
			wantSub: "empty segment",
		},
		{
			name:    "empty middle segment",
			spec:    "mlkem768x25519plus.native.0rtt.." + key32(),
			wantSub: "empty segment",
		},
		{
			// Long enough to be read as a key, but not valid base64url.
			name:    "key not base64url",
			spec:    "mlkem768x25519plus.native.0rtt." + strings.Repeat("!", 44),
			wantSub: "invalid encryption key (not base64url)",
		},
		{
			// Decodes cleanly but is neither 32 nor 1184 bytes.
			name:    "wrong key length",
			spec:    "mlkem768x25519plus.native.0rtt." + keyOf(64),
			wantSub: "invalid encryption key length: 64",
		},
		{
			// Padding blocks only, no key at all.
			name:    "no keys",
			spec:    "mlkem768x25519plus.native.1rtt.100-111-1111",
			wantSub: "no encryption keys in encryption string",
		},
		{
			// 0-RTT reconnects from a cached ticket and never sends padding, so
			// a padding block there would be accepted and then silently ignored.
			name:    "padding with 0rtt",
			spec:    "mlkem768x25519plus.native.0rtt.100-111-1111." + key32(),
			wantSub: "padding blocks are only supported with 1rtt",
		},
		{
			// Once a key has been seen the padding phase is over: a later
			// padding-shaped segment must not be swallowed as padding.
			name:    "padding after key",
			spec:    "mlkem768x25519plus.native.1rtt." + key32() + ".100-111-1111",
			wantSub: "invalid encryption key length",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseClientEncryption(testCase.spec)
			require.Error(t, err)
			require.ErrorContains(t, err, testCase.wantSub)
		})
	}
}

// Fail-closed means every distinct malformed shape has its own diagnosis: a
// user who edits one segment should not have to guess which one the parser
// disliked, and a future rewrite must not collapse two failures into one
// message.
func TestParseClientEncryptionErrorsAreDistinct(t *testing.T) {
	t.Parallel()

	specs := []string{
		"",                                  // empty encryption string
		"mlkem768x25519plus.native.0rtt",    // too few segments
		"x25519only.native.0rtt." + key32(), // unknown method
		"mlkem768x25519plus.plaid.0rtt." + key32(),                  // unknown appearance
		"mlkem768x25519plus.native.7rtt." + key32(),                 // unknown RTT mode
		"mlkem768x25519plus.native.0rtt." + key32() + ".",           // empty segment
		"mlkem768x25519plus.native.0rtt." + strings.Repeat("!", 44), // not base64url
		"mlkem768x25519plus.native.0rtt." + keyOf(64),               // wrong key length
		"mlkem768x25519plus.native.1rtt.100-111-1111",               // no keys
		"mlkem768x25519plus.native.0rtt.100-111-1111." + key32(),    // padding with 0rtt
	}
	seen := make(map[string]string, len(specs))
	for _, spec := range specs {
		_, err := parseClientEncryption(spec)
		require.Error(t, err, "spec %q", spec)
		message := err.Error()
		if earlier, duplicate := seen[message]; duplicate {
			t.Fatalf("two distinct failures share the message %q: %q and %q", message, earlier, spec)
		}
		seen[message] = spec
	}
}

// TestParseClientEncryptionFieldShape mirrors the shape seen in the field:
// native/0rtt with a single ML-KEM-768 key, which base64url-encodes to a
// 1579-character segment. The key itself is synthetic — only its size matters
// to the parser.
func TestParseClientEncryptionFieldShape(t *testing.T) {
	t.Parallel()

	key := keyOf(keyLenMLKEM768)
	require.Len(t, key, 1579)

	cfg, err := parseClientEncryption("mlkem768x25519plus.native.0rtt." + key)
	require.NoError(t, err)
	require.Equal(t, uint32(xorModeNative), cfg.xorMode)
	require.Equal(t, uint32(1), cfg.seconds)
	require.Len(t, cfg.keys, 1)
	require.Len(t, cfg.keys[0], keyLenMLKEM768)
}

// newTestOutboundOptions is the smallest accepted VLESS outbound: a localhost
// server, a fixed UUID and no TLS/transport, so NewOutbound builds the client
// and the encryption layer without opening a socket.
func newTestOutboundOptions(encryption string) option.VLESSOutboundOptions {
	return option.VLESSOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     "127.0.0.1",
			ServerPort: 41393,
		},
		UUID:       "a3482e88-686a-4a58-9376-8adb0e7f38a9",
		Encryption: encryption,
	}
}

// The outbound must actually build the layer, not merely accept the field:
// without this, a parsed config compiles and then dials without encryption.
func TestNewOutboundBuildsEncryptionLayer(t *testing.T) {
	t.Parallel()

	created, err := NewOutbound(
		context.Background(),
		nil,
		log.NewNOPFactory().NewLogger("vless"),
		"vless-encryption",
		newTestOutboundOptions("mlkem768x25519plus.native.0rtt."+key32()),
	)
	require.NoError(t, err)
	outbound, isOutbound := created.(*Outbound)
	require.True(t, isOutbound)
	require.NotNil(t, outbound.encryption)
	require.Equal(t, uint32(xorModeNative), outbound.encryption.XorMode)
	require.Equal(t, uint32(1), outbound.encryption.Seconds)
	require.Len(t, outbound.encryption.NfsPKeys, 1)
}

// Empty and "none" are both "layer off", byte-for-byte the behaviour of a
// config that never knew about the field.
func TestNewOutboundEncryptionLayerOff(t *testing.T) {
	t.Parallel()

	for _, spec := range []string{"", "none"} {
		created, err := NewOutbound(
			context.Background(),
			nil,
			log.NewNOPFactory().NewLogger("vless"),
			"vless-plain",
			newTestOutboundOptions(spec),
		)
		require.NoError(t, err, "spec %q", spec)
		outbound, isOutbound := created.(*Outbound)
		require.True(t, isOutbound)
		require.Nil(t, outbound.encryption, "spec %q must leave the layer off", spec)
	}
}

// A malformed spec must fail at construction, where the error names the
// segment, not at the first dial.
func TestNewOutboundRejectsBadEncryptionSpec(t *testing.T) {
	t.Parallel()

	_, err := NewOutbound(
		context.Background(),
		nil,
		log.NewNOPFactory().NewLogger("vless"),
		"vless-bad-encryption",
		newTestOutboundOptions("mlkem768x25519plus.plaid.0rtt."+key32()),
	)
	require.Error(t, err)
	require.ErrorContains(t, err, "parse encryption")
	require.ErrorContains(t, err, "unknown encryption appearance")
}
