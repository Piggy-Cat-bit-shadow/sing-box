package encryption

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The wire appearance values live in package vless; mirrored here so the
// encryption package's own tests can name them.
const (
	testXorModeNative uint32 = 0
	testXorModeXorPub uint32 = 1
	testXorModeRandom uint32 = 2
)

// ParsePadding and CreatePadding had no tests at all in the reference port.
// They are the only part of the layer a user writes by hand, and a silently
// clamped or mis-split block changes the traffic shape the config claims to
// produce, so every accepted and rejected shape is pinned here.

func TestParsePaddingAccepts(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		padding  string
		wantLens [][3]int
		wantGaps [][3]int
	}{
		{name: "empty means defaults later", padding: ""},
		{
			name:     "single lens block",
			padding:  "100-111-1111",
			wantLens: [][3]int{{100, 111, 1111}},
		},
		{
			name:     "lens then gap",
			padding:  "100-111-1111.75-0-111",
			wantLens: [][3]int{{100, 111, 1111}},
			wantGaps: [][3]int{{75, 0, 111}},
		},
		{
			name:     "lens, gap, lens",
			padding:  "100-111-1111.75-0-111.50-0-3333",
			wantLens: [][3]int{{100, 111, 1111}, {50, 0, 3333}},
			wantGaps: [][3]int{{75, 0, 111}},
		},
		{
			name:     "first block exactly at the floor",
			padding:  "100-35-35",
			wantLens: [][3]int{{100, 35, 35}},
		},
		{
			// The floor only applies to the first block; a later block may be
			// smaller.
			name:     "later block below the floor",
			padding:  "100-111-1111.0-0-0.50-0-10",
			wantLens: [][3]int{{100, 111, 1111}, {50, 0, 10}},
			wantGaps: [][3]int{{0, 0, 0}},
		},
		{
			name:     "maxima exactly at the total cap",
			padding:  "100-32777-32777.0-0-0.100-32776-32776",
			wantLens: [][3]int{{100, 32777, 32777}, {100, 32776, 32776}},
			wantGaps: [][3]int{{0, 0, 0}},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			var lens, gaps [][3]int
			require.NoError(t, ParsePadding(testCase.padding, &lens, &gaps))
			require.Equal(t, testCase.wantLens, lens)
			require.Equal(t, testCase.wantGaps, gaps)
		})
	}
}

func TestParsePaddingRejects(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		padding string
		wantSub string
	}{
		{
			name:    "too few fields",
			padding: "100-111",
			wantSub: "invalid padding length/gap parameter",
		},
		{
			// The reference silently used the first three fields of a longer
			// block; a block that is not probability-from-to is malformed.
			name:    "too many fields",
			padding: "100-111-1111-7",
			wantSub: "invalid padding length/gap parameter",
		},
		{
			name:    "empty middle field",
			padding: "100--1111",
			wantSub: "invalid padding length/gap parameter",
		},
		{
			name:    "empty trailing field",
			padding: "100-111-",
			wantSub: "invalid padding length/gap parameter",
		},
		{
			name:    "not a number",
			padding: "abc-1-2",
			wantSub: "invalid syntax",
		},
		{
			name:    "first probability below 100",
			padding: "99-111-1111",
			wantSub: "first padding length must not be smaller than 35",
		},
		{
			name:    "first block minimum below the floor",
			padding: "100-34-1111",
			wantSub: "first padding length must not be smaller than 35",
		},
		{
			name:    "first block maximum below the floor",
			padding: "100-111-34",
			wantSub: "first padding length must not be smaller than 35",
		},
		{
			name:    "total padding above the cap",
			padding: "100-40000-40000.0-0-0.100-30000-30000",
			wantSub: "total padding length must not be larger than 65553",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			var lens, gaps [][3]int
			err := ParsePadding(testCase.padding, &lens, &gaps)
			require.Error(t, err)
			require.ErrorContains(t, err, testCase.wantSub)
		})
	}
}

// With no configured blocks CreatePadding must fall back to the reference's
// defaults, not to zero padding: the layer still has to produce a variable
// traffic pattern for a config that specifies none.
func TestCreatePaddingDefaults(t *testing.T) {
	t.Parallel()

	for range 20 {
		length, lens, gaps := CreatePadding(nil, nil)
		require.Len(t, lens, 2, "default profile has two fragment blocks")
		require.Len(t, gaps, 1, "default profile has one gap block")

		// The first default block draws unconditionally (probability 100).
		require.GreaterOrEqual(t, lens[0], 111)
		require.Less(t, lens[0], 1111)
		// The second draws 50% of the time, so its floor is zero.
		require.GreaterOrEqual(t, lens[1], 0)
		require.Less(t, lens[1], 3333)
		// The default gap is {75,0,111}: at most 110ms.
		require.GreaterOrEqual(t, gaps[0], time.Duration(0))
		require.Less(t, gaps[0], 111*time.Millisecond)

		require.Equal(t, length, lens[0]+lens[1], "length is the sum of the fragments")
	}
}

// Configured blocks are drawn from their own ranges: the fragment length is in
// [from,to) and the gap is in [from,to) milliseconds.
func TestCreatePaddingConfiguredBlocks(t *testing.T) {
	t.Parallel()

	for range 20 {
		length, lens, gaps := CreatePadding([][3]int{{100, 5, 6}, {100, 7, 8}}, [][3]int{{100, 2, 3}, {100, 4, 5}})
		require.Equal(t, []int{5, 7}, lens)
		require.Equal(t, []time.Duration{2 * time.Millisecond, 4 * time.Millisecond}, gaps)
		require.Equal(t, 12, length)
	}
}

// A lens profile without gap blocks draws no delays at all.
func TestCreatePaddingWithoutGaps(t *testing.T) {
	t.Parallel()

	_, lens, gaps := CreatePadding([][3]int{{100, 1, 2}}, nil)
	require.Equal(t, []int{1}, lens)
	require.Empty(t, gaps)
}

// The AEAD is the layer's confidentiality primitive; a broken derivation or a
// swapped suite would silently produce records the peer cannot open.
func TestNewAEADRoundTrip(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	transcript := []byte("VLESS-transcript")
	plaintext := []byte("hello post-quantum world")
	additional := []byte("header")

	for _, useAES := range []bool{false, true} {
		name := "chacha20poly1305"
		if useAES {
			name = "aes-256-gcm"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			sealer := NewAEAD(transcript, key, useAES)
			sealed := sealer.Seal(nil, nil, plaintext, additional)
			require.Len(t, sealed, len(plaintext)+16)

			opener := NewAEAD(transcript, key, useAES)
			opened, err := opener.Open(nil, nil, sealed, additional)
			require.NoError(t, err)
			require.Equal(t, plaintext, opened)

			// A different transcript derives a different key and must fail closed.
			wrongContext := NewAEAD([]byte("other-transcript"), key, useAES)
			_, err = wrongContext.Open(nil, nil, sealed, additional)
			require.Error(t, err)

			// Tampered additional data must fail authentication too.
			otherOpener := NewAEAD(transcript, key, useAES)
			_, err = otherOpener.Open(nil, nil, sealed, []byte("elsewhere"))
			require.Error(t, err)
		})
	}
}

// The five-byte header is what makes the native appearance look like TLS 1.3;
// the bounds are the peer's read bounds, so both edges are pinned.
func TestEncodeDecodeHeader(t *testing.T) {
	t.Parallel()

	for _, length := range []int{17, 18, 8192 + 16, 17000} {
		header := make([]byte, 5)
		EncodeHeader(header, length)
		require.Equal(t, byte(23), header[0])
		require.Equal(t, byte(3), header[1])
		require.Equal(t, byte(3), header[2])
		decoded, err := DecodeHeader(header)
		require.NoError(t, err)
		require.Equal(t, length, decoded)
	}

	// A header that is not TLS application data yields no usable length.
	badShape := []byte{0, 0, 0, 0, 100}
	decoded, err := DecodeHeader(badShape)
	require.ErrorIs(t, err, ErrInvalidHeader)
	require.Zero(t, decoded, "a wrong-shaped header must not report a length")

	// A correct shape with an out-of-range length still reports the length it
	// carried, so the error message is actionable.
	short := make([]byte, 5)
	EncodeHeader(short, 16)
	decoded, err = DecodeHeader(short)
	require.ErrorIs(t, err, ErrInvalidHeader)
	require.Equal(t, 16, decoded)
}

// Nonces are counters; the rekey trigger depends on the wrap behaving exactly
// like an incrementing big-endian counter.
func TestIncreaseNonce(t *testing.T) {
	t.Parallel()

	nonce := make([]byte, 12)
	IncreaseNonce(nonce)
	require.Equal(t, byte(1), nonce[11])
	require.Zero(t, nonce[10])

	for i := range 11 {
		nonce[i] = 255
	}
	nonce[11] = 255
	IncreaseNonce(nonce)
	require.Equal(t, make([]byte, 12), nonce, "MaxNonce wraps to zero")
}

// Init is the start-time gate between a parsed string and the handshake: every
// key size must land in the right primitive and a malformed key must fail here
// rather than on the first dial.
func TestClientInstanceInit(t *testing.T) {
	t.Parallel()

	x25519Key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	mlkemKey, err := mlkem.GenerateKey768()
	require.NoError(t, err)

	t.Run("x25519 key", func(t *testing.T) {
		t.Parallel()
		instance := &ClientInstance{}
		require.NoError(t, instance.Init([][]byte{x25519Key.PublicKey().Bytes()}, testXorModeNative, 0, ""))
		require.IsType(t, &ecdh.PublicKey{}, instance.NfsPKeys[0])
		require.Equal(t, 32, instance.RelaysLength)
	})

	t.Run("mlkem768 key", func(t *testing.T) {
		t.Parallel()
		instance := &ClientInstance{}
		require.NoError(t, instance.Init([][]byte{mlkemKey.EncapsulationKey().Bytes()}, testXorModeXorPub, 1, ""))
		require.IsType(t, &mlkem.EncapsulationKey768{}, instance.NfsPKeys[0])
		require.Equal(t, 1088, instance.RelaysLength)
	})

	t.Run("mixed chain", func(t *testing.T) {
		t.Parallel()
		instance := &ClientInstance{}
		require.NoError(t, instance.Init(
			[][]byte{x25519Key.PublicKey().Bytes(), mlkemKey.EncapsulationKey().Bytes()},
			testXorModeRandom, 1, "",
		))
		// Each relay adds its key plus 32 bytes, and the final relay's trailing
		// hash is dropped from the hello.
		require.Equal(t, 32+1088+32, instance.RelaysLength)
		require.Equal(t, uint32(testXorModeRandom), instance.XorMode)
		require.Equal(t, uint32(1), instance.Seconds)
	})

	t.Run("padding is parsed with the instance", func(t *testing.T) {
		t.Parallel()
		instance := &ClientInstance{}
		require.NoError(t, instance.Init([][]byte{x25519Key.PublicKey().Bytes()}, testXorModeNative, 0, "100-111-1111.75-0-111"))
		require.Equal(t, [][3]int{{100, 111, 1111}}, instance.PaddingLens)
		require.Equal(t, [][3]int{{75, 0, 111}}, instance.PaddingGaps)
	})

	t.Run("empty key list", func(t *testing.T) {
		t.Parallel()
		instance := &ClientInstance{}
		err := instance.Init(nil, testXorModeNative, 0, "")
		require.ErrorContains(t, err, "empty nfsPKeysBytes")
	})

	t.Run("malformed key", func(t *testing.T) {
		t.Parallel()
		instance := &ClientInstance{}
		err := instance.Init([][]byte{make([]byte, 64)}, testXorModeNative, 0, "")
		require.Error(t, err)
	})

	t.Run("already initialized", func(t *testing.T) {
		t.Parallel()
		instance := &ClientInstance{}
		require.NoError(t, instance.Init([][]byte{x25519Key.PublicKey().Bytes()}, testXorModeNative, 0, ""))
		err := instance.Init([][]byte{x25519Key.PublicKey().Bytes()}, testXorModeNative, 0, "")
		require.ErrorContains(t, err, "already initialized")
	})
}

// A handshake over an uninitialized instance must not touch the conn.
func TestClientInstanceHandshakeUninitialized(t *testing.T) {
	t.Parallel()

	_, err := (&ClientInstance{}).Handshake(nil)
	require.ErrorContains(t, err, "uninitialized")
}
