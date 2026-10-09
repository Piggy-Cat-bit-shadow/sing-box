package sniff

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// frameSequenceReference is the classification the frame list used to be walked for, kept here as
// the thing frameSummary has to agree with. It is written against the sequence itself, in the same
// order and with the same degenerate cases the old code had: the "after the first" and "before the
// last" ranges are empty for a one-frame sequence and both empty ranges counted as all-padding.
type frameSequenceReference struct {
	frameTypeList []byte
}

func (r frameSequenceReference) singleFrame() bool {
	return len(r.frameTypeList) == 1
}

func (r frameSequenceReference) cryptoThenPadding() bool {
	return r.frameTypeList[0] == frameTypeCrypto && isZeroReference(r.frameTypeList[1:])
}

func (r frameSequenceReference) paddingThenCrypto() bool {
	return r.frameTypeList[len(r.frameTypeList)-1] == frameTypeCrypto && isZeroReference(r.frameTypeList[:len(r.frameTypeList)-1])
}

func (r frameSequenceReference) multiCryptoOrPing() bool {
	var cryptoCount, pingCount int
	for _, frameType := range r.frameTypeList {
		switch frameType {
		case frameTypeCrypto:
			cryptoCount++
		case frameTypePing:
			pingCount++
		}
	}
	return cryptoCount > 1 || pingCount > 0
}

func isZeroReference(frameTypes []byte) bool {
	for _, frameType := range frameTypes {
		if frameType != 0 {
			return false
		}
	}
	return true
}

// TestFrameSummaryMatchesTheSequenceItReplaces checks the equivalence §4.1 E demands - the
// classification must be identical - by exhaustively comparing the summary against the sequence
// walk for every frame sequence up to length six over the frame types this parser distinguishes,
// plus the padding runs that make the ratio worth measuring at all.
//
// The client classification is a chain of four questions about the sequence, so reproducing those
// four answers for every sequence is the whole of the equivalence claim; the end-to-end half is
// carried by the Chrome, Chromium, Firefox, Safari and QUIC-Go samples in quic_test.go and
// quic_capture_test.go.
func TestFrameSummaryMatchesTheSequenceItReplaces(t *testing.T) {
	t.Parallel()
	alphabet := []byte{frameTypePadding, frameTypePing, frameTypeCrypto, frameTypeAck, frameTypeConnectionClose}
	checked := 0
	for length := 1; length <= 6; length++ {
		sequence := make([]byte, length)
		var walk func(depth int)
		walk = func(depth int) {
			if depth == length {
				checked++
				compareFrameSummary(t, sequence)
				return
			}
			for _, frameType := range alphabet {
				sequence[depth] = frameType
				walk(depth + 1)
			}
		}
		walk(0)
	}
	// A padded Initial, which is what the summary exists for: one CRYPTO frame and a long run of
	// padding, in both orders.
	for _, sequence := range [][]byte{
		append([]byte{frameTypeCrypto}, make([]byte, 1500)...),
		append(make([]byte, 1500), frameTypeCrypto),
		append(append([]byte{frameTypePadding}, frameTypeCrypto), make([]byte, 1500)...),
	} {
		// The table walk above covers short sequences only, so these are compared directly.
		checked++
		compareFrameSummary(t, sequence)
	}
	require.Greater(t, checked, 10000)
}

func compareFrameSummary(t *testing.T, sequence []byte) {
	t.Helper()
	reference := frameSequenceReference{frameTypeList: sequence}
	var summary frameSummary
	for _, frameType := range sequence {
		summary.observe(frameType)
	}
	require.Equal(t, len(sequence), summary.count, "sequence % x", sequence)
	require.Equal(t, sequence[0], summary.first, "sequence % x", sequence)
	require.Equal(t, sequence[len(sequence)-1], summary.last, "sequence % x", sequence)
	require.Equal(t, reference.singleFrame(), summary.count == 1, "sequence % x", sequence)
	require.Equal(t, reference.cryptoThenPadding(), summary.first == frameTypeCrypto && !summary.nonZeroAfterFirst, "sequence % x", sequence)
	require.Equal(t, reference.paddingThenCrypto(), summary.last == frameTypeCrypto && !summary.nonZeroBeforeLast, "sequence % x", sequence)
	require.Equal(t, reference.multiCryptoOrPing(), summary.cryptoCount > 1 || summary.pingCount > 0, "sequence % x", sequence)
}

// TestFrameSummaryCountsFrames pins the summary's own counters against sequences built for each
// count, so that a summary that got the range flags right while losing track of the counts would
// not pass on the classification questions alone.
func TestFrameSummaryCountsFrames(t *testing.T) {
	t.Parallel()
	var summary frameSummary
	summary.observe(frameTypeCrypto)
	summary.observe(frameTypePadding)
	summary.observe(frameTypeCrypto)
	summary.observe(frameTypePing)
	summary.observe(frameTypePing)
	summary.observe(frameTypeAck)
	require.Equal(t, 6, summary.count)
	require.Equal(t, byte(frameTypeCrypto), summary.first)
	require.Equal(t, byte(frameTypeAck), summary.last)
	require.Equal(t, 2, summary.cryptoCount)
	require.Equal(t, 2, summary.pingCount)
	require.True(t, summary.nonZeroAfterFirst)
	require.True(t, summary.nonZeroBeforeLast)
}
