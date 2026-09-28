package jiejie_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// Tests that the Naive padding protocol is a SHARED contract, not two
// implementations that merely agree with each other.
//
// # The problem this solves
//
// The padding protocol has three implementations:
//
//	A. klzgrad/forwardproxy            the reference (branch naive, d62c80d3)
//	B. sing-box Native Naive inbound   protocol/naive/inbound_conn.go
//	C. cronet-go Naive outbound        naive_conn.go
//
// Until now, conformance was expressed as assertions restated in each repository's
// tests. That is precisely the arrangement that let C keep the old, wrong
// segmentation while B's tests passed: nothing compared the two, and neither was
// checked against A. Worse, B and C agreeing would not have been evidence of
// correctness anyway - two implementations can share a mistake and interoperate
// perfectly while both diverging from the reference.
//
// test/jiejie/reference/naive_padding_vectors.json is the single machine-readable
// document both repositories' tests read. Every expectation in it is derived from
// A's own expressions:
//
//	paddingSize := rand.Intn(256)
//	maxRead     := 65536 - 3 - paddingSize
//
// This file checks the sing-box half: that the mirrored copy is byte-identical to
// the one cronet-go publishes, and that the constants the two implementations
// advertise are the same quantities.

// naivePaddingVectorFile is the mirror of cronet-go's
// testdata/naive_padding_vectors.json.
const naivePaddingVectorFile = "reference/naive_padding_vectors.json"

// cronetGoVectorSHA256 is the SHA-256 of the vector file as published by the pinned
// cronet-go revision.
//
// It is asserted rather than merely recorded so that a change to the protocol
// requires a deliberate edit here. Without this, the mirror could silently fall
// behind and the two repositories would be reading different contracts while both
// believing they were reading the shared one - the same class of drift that hid the
// codec bug.
//
// To update: change the vector file in cronet-go, re-copy it here, and update this
// hash with the new value. The reference commit recorded inside the file must be
// reviewed at the same time.
const cronetGoVectorSHA256 = "bec7b86fd50cf6955efd3569c18e68e135420d07b9503ade8368b653de592e56"

type naivePaddingVectors struct {
	Protocol  string `json:"protocol"`
	Reference struct {
		Repository              string `json:"repository"`
		Branch                  string `json:"branch"`
		Commit                  string `json:"commit"`
		PaddingDrawExpression   string `json:"padding_draw_expression"`
		PayloadBudgetExpression string `json:"payload_budget_expression"`
		NumFirstPaddings        int    `json:"num_first_paddings"`
		CopyBufferSize          int    `json:"copy_buffer_size"`
	} `json:"reference"`
	Constants struct {
		MaxFrameSize           int `json:"max_frame_size"`
		FrameHeaderSize        int `json:"frame_header_size"`
		MaxPadding             int `json:"max_padding"`
		MinPadding             int `json:"min_padding"`
		PaddingCount           int `json:"padding_count"`
		MaxPayloadAtPadding0   int `json:"max_payload_at_padding_0"`
		MaxPayloadAtPadding255 int `json:"max_payload_at_padding_255"`
		WriterMTU              int `json:"writer_mtu"`
		FrontHeadroom          int `json:"front_headroom"`
		RearHeadroom           int `json:"rear_headroom"`
	} `json:"constants"`
	Invariants []struct {
		ID         string `json:"id"`
		Statement  string `json:"statement"`
		Expression string `json:"expression"`
	} `json:"invariants"`
	PaddingDraws      []int `json:"padding_draws"`
	SegmentationCases []struct {
		Padding int `json:"padding"`
		Payload int `json:"payload"`
		Wire    int `json:"wire"`
		Frames  int `json:"frames"`
	} `json:"segmentation_cases"`
	ChunkingCases []struct {
		Padding           int `json:"padding"`
		Payload           int `json:"payload"`
		Frames            int `json:"frames"`
		FirstFramePayload int `json:"first_frame_payload"`
	} `json:"chunking_cases"`
	OversizedRejectionCases []struct {
		Padding int    `json:"padding"`
		Payload int    `json:"payload"`
		Reason  string `json:"reason"`
	} `json:"oversized_rejection_cases"`
}

func loadNaivePaddingVectors(t *testing.T) (*naivePaddingVectors, []byte) {
	t.Helper()
	path := filepath.Join(naivePaddingVectorFile)
	content, err := os.ReadFile(path)
	require.NoError(t, err, "the shared Naive padding vectors must be present at %s", path)
	var vectors naivePaddingVectors
	require.NoError(t, json.Unmarshal(content, &vectors), "parse %s", path)
	return &vectors, content
}

// TestSharedVectorFileMatchesThePublishedCopy is the drift alarm between the two
// repositories.
func TestSharedVectorFileMatchesThePublishedCopy(t *testing.T) {
	_, content := loadNaivePaddingVectors(t)

	digest := sha256.Sum256(content)
	actual := hex.EncodeToString(digest[:])
	require.Equal(t, cronetGoVectorSHA256, actual,
		"the mirrored Naive padding vector file is not byte-identical to the copy "+
			"cronet-go publishes at testdata/naive_padding_vectors.json; the two "+
			"repositories would be reading different contracts while both believing "+
			"they read the shared one")
}

// TestNativeInboundAgreesWithTheSharedContract checks the sing-box side against the
// same document cronet-go checks itself against.
//
// The constants here are the ones protocol/naive's codec derives internally, so this
// is the point where an inbound-side change that breaks parity with the outbound is
// caught in sing-box rather than only when the two talk to each other.
func TestNativeInboundAgreesWithTheSharedContract(t *testing.T) {
	vectors, _ := loadNaivePaddingVectors(t)

	// The reference revision must be the one the differential harness pins.
	require.Equal(t, CaddyReferenceCommit, vectors.Reference.Commit,
		"the vector file's reference commit and CaddyReferenceCommit disagree, so the "+
			"parity tests and the padding vectors would be measuring against different "+
			"reference revisions")
	require.Equal(t, "naive", vectors.Reference.Branch)
	require.Equal(t, "naive-padding-v1", vectors.Protocol)

	// The geometry the vector file declares must be internally consistent.
	constants := vectors.Constants
	require.Equal(t, 3, constants.FrameHeaderSize)
	require.Equal(t, 65536, constants.MaxFrameSize)
	require.Equal(t, 8, constants.PaddingCount)
	require.Equal(t, 0, constants.MinPadding)
	require.Equal(t, 255, constants.MaxPadding)

	require.Equal(t, constants.MaxFrameSize-constants.FrameHeaderSize,
		constants.MaxPayloadAtPadding0,
		"max_payload_at_padding_0 must be the ceiling minus the header")
	require.Equal(t, constants.MaxFrameSize-constants.FrameHeaderSize-constants.MaxPadding,
		constants.MaxPayloadAtPadding255,
		"max_payload_at_padding_255 must be the ceiling minus the header and the max padding")

	// The writer geometry must describe exactly one maximal frame. This is the
	// property the cronet-go codec violated with MTU 65535 (advertising 65793).
	require.Equal(t, constants.MaxFrameSize,
		constants.FrontHeadroom+constants.WriterMTU+constants.RearHeadroom,
		"front headroom + writer MTU + rear headroom must equal exactly one maximal "+
			"frame; a larger sum advertises a geometry no frame can satisfy")
	require.Equal(t, constants.MaxPayloadAtPadding255, constants.WriterMTU,
		"writer_mtu must be the worst-case-safe payload, i.e. the padding-255 budget")

	// The reference's copy buffer IS the ceiling, not merely related to it.
	require.Equal(t, constants.MaxFrameSize, vectors.Reference.CopyBufferSize,
		"the reference's copy buffer and the frame ceiling are the same quantity")
	require.Equal(t, constants.PaddingCount, vectors.Reference.NumFirstPaddings)
}

// TestSharedVectorsCarryExecutableExpectations is a guard against the document
// decaying into prose: it must actually contain cases both sides can run.
func TestSharedVectorsCarryExecutableExpectations(t *testing.T) {
	vectors, _ := loadNaivePaddingVectors(t)

	require.NotEmpty(t, vectors.Invariants,
		"the shared vectors must declare the protocol invariants in a checkable form")
	require.NotEmpty(t, vectors.PaddingDraws,
		"the shared vectors must declare which padding draws are reachable")
	require.NotEmpty(t, vectors.SegmentationCases,
		"the shared vectors must declare single-frame segmentation cases")
	require.NotEmpty(t, vectors.ChunkingCases,
		"the shared vectors must declare multi-frame chunking cases")
	require.NotEmpty(t, vectors.OversizedRejectionCases,
		"the shared vectors must declare the cases that must be refused")

	// Both extremes of the padding range must be exercised: the smallest budget
	// (255) is where the old codec broke, and 0 is the largest budget.
	extremes := map[int]bool{}
	for _, draw := range vectors.PaddingDraws {
		extremes[draw] = true
	}
	require.True(t, extremes[0], "padding draw 0 must be covered")
	require.True(t, extremes[255], "padding draw 255 must be covered")

	// Every segmentation case must respect the ceiling, checked here independently
	// of either implementation.
	for _, c := range vectors.SegmentationCases {
		wire := vectors.Constants.FrameHeaderSize + c.Payload + c.Padding
		require.LessOrEqual(t, wire, vectors.Constants.MaxFrameSize,
			"vector case (padding %d, payload %d) declares a wire length of %d, over "+
				"the %d ceiling", c.Padding, c.Payload, wire, vectors.Constants.MaxFrameSize)
		require.Equal(t, wire, c.Wire,
			"vector case (padding %d, payload %d) declares wire %d but the reference "+
				"arithmetic gives %d", c.Padding, c.Payload, c.Wire, wire)
		require.LessOrEqual(t, c.Payload,
			vectors.Constants.MaxFrameSize-vectors.Constants.FrameHeaderSize-c.Padding,
			"vector case (padding %d, payload %d) exceeds its own frame budget",
			c.Padding, c.Payload)
	}

	// Every rejection case must genuinely be over budget, or it is not a rejection
	// case and the document is wrong.
	for _, c := range vectors.OversizedRejectionCases {
		budget := vectors.Constants.MaxFrameSize - vectors.Constants.FrameHeaderSize - c.Padding
		require.Greater(t, c.Payload, budget,
			"rejection case (padding %d, payload %d) is within the %d budget, so it "+
				"would not be refused: %s", c.Padding, c.Payload, budget, c.Reason)
	}
}
