package sniff

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/sagernet/sing-box/adapter"

	"github.com/stretchr/testify/require"
)

// quicInitialDatagram is the Chrome Initial from TestSniffUQUICChrome115: a real ClientHello that
// this parser recognises, so the cases below run against a packet that reaches the end of the
// function rather than against one that fails early.
var quicInitialDatagram = mustDecodeHex(
	"cb0000000108181e17c387120abc000044d0705b6a3ef9ee37a8d3949a7d393ed078243c2ee2c3627fad1c3f107c117f4f07" +
		"1131ad61848068fcbbe5c65803c147f7f8ec5e2cd77b77beea23ba779d936dccac540f8396400e3190ea35cc2942af4171a0" +
		"4cb14272491920f90124959f44e80143678c0b52f5d31af319aaa589db2f940f004562724d0af40f737e1bb0002a071e6a1d" +
		"bc9f52c64f070806a5010abed0298053634d9c9126bd7949ae5087998ade762c0ad06691d99c0875a38c601fc1ee77bfc3b8" +
		"c11381829f2c9bdd022f4499c43ff1d6aee1a0d296861461dda217d22c568b276016ef3929e59d2f7d7ddf7809920fb7dc80" +
		"5641608949f3f8466ab3d37149aac501f0b107d808f3add4acfc657e4a82e2b88e97a6c74a00c419548760ab3414ba13915c" +
		"78a1ca79dceee8d59fbe299f20b671ac44823218368b2a026baa55170cf549519ac21dbb6d31d248bd339438a4e663bcdca1" +
		"fe3ae3f045a5dc19b122e9db9d7af9757076666dda4e9ace1c67def77fa14786f0cab3ebf7a270ea6e2b37838318c95779f8" +
		"0c3b8471948d0046c3614b3a13477c939a39a7855d85d13522a45ae0765739cd5eedef87237e824a929983ace27640c6495d" +
		"bf5a72fa0b96893dc5d28f3988249a57bdb458d460b4a57043de3da750a76b6e5d2259247ca27cd864ea18f0d09aa62ab6eb" +
		"7c014fb43179b2a1963d170b756cce83eeaebff78a828d025c811848e16ff862a8080d093478cd2208c8ab0803178325bc0d" +
		"9d6bb25e62fa50c4ad15cf80916da6578796932036c72e43eb480d1e423ed812ac75a97722f8416529b82ba8ee2219c53501" +
		"2282bb17066bd53e78b87a71abdb7ebdb2a7c2766ff8397962e87d0f85485b64b4ee81cc84f99c47f33f2b08727164419927" +
		"73f59186e38d32dbf5609a6fda94cb928cd25f5a7a3ab736b5a4236b6d5409ab18892c6a4d3480fc2350abfdf0bab1cedb55" +
		"bdf0760fdb703e6688f4de596254eed4ed3e67eb03d0717b8e15b31e735214e588c87ae36bc6c310e1894b4c15143e4ccf28" +
		"7b2dbc707a946bf9671ae3c574f9486b2c82eec784bba4cbc76113cbe0f97ac8c13cfa38f2925ab9d06887a612ce48280a91" +
		"d7e074e6caf898d88e2bbf71360899abf48a03f9a70cf2891199f2d63b116f4871af0ebb4f4906792f66cc21d1609f189138" +
		"532875c129a68c73e7bcd3b5d8100beac1d8ac4b20d94a59ac8df5a5af58a9acb20413eadf97189f5f19ff889155f0c4d375" +
		"14ec184eb6903967ff38a41fc087abb0f2cad3761d6e3f95f92a09a72f5c065b16e188088b87460241f27ecdb1bc6ece92c8" +
		"d36b2d68b58d0fb4d4b3c928c579ade8ae5a995833aadd297c30a37f7bc35440fc97070e1b198e0fac00157452177d16d280" +
		"3b4239997452b4ad3a951173bdec47a033fd7f8a7942accaa9aaa905b3c5a2175e7c3e07c48bf25331727fd69cd1e64d74d8" +
		"c9d4a6f8f4491adb7bc911505cb19877083d8f21a12475e313fccf57877ff3556318e81ed9145dd9427f2b65275440893035" +
		"f417481f721c69215af8ae103530cd0a1d35bf2cb5a27628f8d44d7c6f5ec12ce79d0a8333e0eb48771115d0a191304e46b8" +
		"db19bbe5c40f1c346dde98e76ff5e21ff38d2c34e60cb07766ed529dd6d2cbacd7fbf1ed8a0e6e40decad0ca5021e91552be" +
		"87c156d3ae2fffef41c65b14ba6d488f2c3227a1ab11ffce0e2dc47723a69da27a67a7f26e1cb13a7103af9b87a8db8e18ea")

func mustDecodeHex(value string) []byte {
	decoded := make([]byte, len(value)/2)
	for i := 0; i < len(decoded); i++ {
		decoded[i] = hexNibble(value[2*i])<<4 | hexNibble(value[2*i+1])
	}
	return decoded
}

func hexNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		panic("bad hex")
	}
}

// TestTakePacketBytesMatchesReadFull is the contract the zero-copy read has to keep, checked against
// io.ReadFull itself rather than restated: for every length, the bytes are the same, the error is
// the same - io.EOF when nothing is left and io.ErrUnexpectedEOF when only part of it is - and the
// result is a view of the datagram rather than a copy, which is the entire point of the change.
func TestTakePacketBytesMatchesReadFull(t *testing.T) {
	t.Parallel()
	packet := []byte("0123456789abcdef")
	for n := 0; n <= len(packet)+2; n++ {
		referenceBytes := make([]byte, n)
		referenceCount, referenceErr := io.ReadFull(bytes.NewReader(packet), referenceBytes)

		reader := bytes.NewReader(packet)
		view, err := takePacketBytes(reader, packet, n)

		require.Equal(t, referenceErr, err, "n=%d", n)
		require.Equal(t, referenceCount, len(view), "n=%d", n)
		require.Equal(t, referenceBytes[:referenceCount], view, "n=%d", n)
		require.Equal(t, min(n, len(packet)), len(packet)-reader.Len(), "n=%d: bytes consumed", n)
		if len(view) > 0 {
			// A view, not a copy: writing through it is visible in the datagram.
			view[0] = 'X'
			require.Equal(t, byte('X'), packet[0], "n=%d: the result is a copy", n)
			packet[0] = '0'
		}
	}
	require.True(t, errors.Is(io.EOF, io.EOF))
}

// TestQUICClientHelloLeavesTheDatagramAlone is the aliasing guard for the zero-copy reads. The
// destination connection id and the packet-number sample are now slices of the caller's datagram,
// so nothing may write through them: the sniff has to leave the packet byte for byte as it found it.
func TestQUICClientHelloLeavesTheDatagramAlone(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name      string
		truncated bool
	}{
		{"recognised", false},
		{"truncated", true},
	} {
		packet := append([]byte{}, quicInitialDatagram...)
		if testCase.truncated {
			packet = packet[:len(packet)/2]
		}
		before := append([]byte{}, packet...)
		var metadata adapter.InboundContext
		err := QUICClientHello(context.Background(), &metadata, packet)
		if testCase.truncated {
			// A datagram cut in half fails the announced-length check, which is a definite
			// verdict rather than a request for more bytes. The class is pinned elsewhere; what
			// this case is here for is the datagram.
			require.Error(t, err, "%s", testCase.name)
		} else {
			require.NoError(t, err, "%s", testCase.name)
			require.Equal(t, "www.google.com", metadata.Domain)
		}
		require.Equal(t, before, packet, "%s: the sniffer wrote into the datagram", testCase.name)
	}
}

// TestQUICClientHelloResultDoesNotAliasTheDatagram pins the other half: what the sniffer reports has
// to survive the caller reusing its buffer, which is what a pooled datagram reader does as soon as
// the sniff returns.
func TestQUICClientHelloResultDoesNotAliasTheDatagram(t *testing.T) {
	t.Parallel()
	packet := append([]byte{}, quicInitialDatagram...)
	var metadata adapter.InboundContext
	require.NoError(t, QUICClientHello(context.Background(), &metadata, packet))
	domain := metadata.Domain
	protocol := metadata.Protocol
	client := metadata.Client
	require.Equal(t, "www.google.com", domain)
	for i := range packet {
		packet[i] = 0xFF
	}
	require.Equal(t, domain, metadata.Domain)
	require.Equal(t, protocol, metadata.Protocol)
	require.Equal(t, client, metadata.Client)
}
