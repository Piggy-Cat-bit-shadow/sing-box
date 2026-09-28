package jiejie_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// AUDIT: a structural guard against the class of bug behind the retracted
// "UoT v2 non-connect P0".
//
// Several tests open an HTTP/1 tunnel with naiveTLSConn and then write payloads
// through naivePaddingFrame. That is always wrong: HTTP/1 is a raw tunnel, so the
// frame bytes are parsed as protocol data and the test either fails with a
// misleading error or -- worse -- still passes while exercising a path it did not
// intend to exercise.
//
// The guard is deliberately a source-level check rather than a runtime one. A
// runtime check can only see the tunnel it is given; this sees every call site,
// including ones whose tunnel is currently refused before the write happens, which
// is exactly how these hide.

// h1FramingAllowlist names call sites where a framed write on a connection from
// naiveTLSConn is CORRECT.
//
// Each entry must say why. An unexamined entry is how this list becomes a
// rubber stamp, so the reasons name the mechanism, not the file.
var h1FramingAllowlist = map[string]string{
	// This file DEFINES naivePaddingFrame and tests the frame codec itself.
	"jiejie_naive_inbound_test.go": "defines and unit-tests the frame codec",
	// The transport matrix asserts the rule; its framed writes are on HTTP/2
	// sessions, and the HTTP/1 cases assert framing is OFF.
	"jiejie_naive_uot_transport_matrix_test.go": "asserts the transport-derived framing rule",
	// The trace harness drives HTTP/2 streams (h2.ClientConn), not naiveTLSConn.
	"jiejie_naive_trace_harness_test.go": "drives HTTP/2 streams",
	// H3 half-close drives an HTTP/3 client.
	"jiejie_naive_h3_half_close_test.go": "drives HTTP/3",
	// These build their own HTTP/2 client connection.
	// These two files contain the TRANSPORT-AWARE write helpers. Their framed
	// writes are guarded by s.padding, which newUoTSession derives from the
	// session's transport, so an HTTP/1 session never reaches naivePaddingFrame.
	// A source-level check cannot see that guard, hence the exemption.
	"jiejie_naive_uot_test.go":              "writeDatagram frames only when s.padding is set, which HTTP/1 sessions never are",
	"jiejie_naive_audit_uot2_test.go":       "writeFrame frames only when s.padding is set, which HTTP/1 sessions never are",
	"jiejie_naive_audit_conc_test.go":       "drives HTTP/2 streams",
	"jiejie_naive_audit_auth2_test.go":      "drives HTTP/2 streams",
	"jiejie_naive_audit_lifecycle2_test.go": "drives HTTP/2 streams",
	"jiejie_naive_degraded_tunnel_test.go":  "drives HTTP/2 streams",
	"jiejie_naive_linux_resources_test.go":  "drives HTTP/2 streams",
	"jiejie_naive_connect_security_test.go": "drives HTTP/2 streams",
	"jiejie_naive_half_close_test.go":       "drives HTTP/2 streams",
}

// TestNoHTTP1TunnelWritesPaddedFrames fails when a file both opens an HTTP/1
// tunnel (naiveTLSConn) and writes a Naive padding frame, unless it is a known
// and justified exception.
func TestNoHTTP1TunnelWritesPaddedFrames(t *testing.T) {
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)

	var offenders []string
	for _, file := range files {
		if !strings.HasSuffix(file, "_test.go") {
			continue
		}
		source, err := os.ReadFile(file)
		require.NoError(t, err)
		text := string(source)

		// naiveTLSConn with no NextProtos argument is HTTP/1. A file that passes
		// http2.NextProtoTLS is driving HTTP/2 and may legitimately frame.
		opensHTTP1 := regexp.MustCompile(`naiveTLSConn\(t,\s*[A-Za-z0-9_.]+\)`).MatchString(text)
		writesFrames := strings.Contains(text, "naivePaddingFrame(")
		if !opensHTTP1 || !writesFrames {
			continue
		}
		if _, allowed := h1FramingAllowlist[file]; allowed {
			continue
		}
		offenders = append(offenders, file)
	}

	require.Empty(t, offenders,
		"these files open an HTTP/1 tunnel with naiveTLSConn and also write Naive "+
			"padding frames. HTTP/1 is a RAW tunnel, so a framed write sends bytes "+
			"the server parses as protocol data -- this is the class of bug behind "+
			"the retracted UoT v2 non-connect P0.\n\n"+
			"Write the payload raw, drive the test over HTTP/2 (naiveTLSConn(t, port, "+
			"http2.NextProtoTLS)) if framing is what you mean to exercise, or add the "+
			"file to h1FramingAllowlist WITH A REASON that names the mechanism.\n\n"+
			"offenders: %v", offenders)
}

// TestH1FramingAllowlistEntriesStillExist keeps the allowlist from rotting: an
// entry for a file that no longer frames anything is stale, and a stale
// allowlist is how the guard above quietly stops covering a real file.
func TestH1FramingAllowlistEntriesStillExist(t *testing.T) {
	for file, reason := range h1FramingAllowlist {
		require.FileExists(t, file, "allowlist names a file that does not exist")
		source, err := os.ReadFile(file)
		require.NoError(t, err)
		require.Contains(t, string(source), "naivePaddingFrame(",
			"%s is allowlisted (%q) but no longer writes padding frames; remove the entry",
			file, reason)
	}
}

// TestNaivePaddingFrameHasExactlyOneDefinition guards against a second copy of
// the encoder appearing, which would let one copy be fixed and the other not.
func TestNaivePaddingFrameHasExactlyOneDefinition(t *testing.T) {
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)

	var definitions []string
	fileSet := token.NewFileSet()
	for _, file := range files {
		parsed, parseErr := parser.ParseFile(fileSet, file, nil, 0)
		if parseErr != nil {
			continue
		}
		for _, declaration := range parsed.Decls {
			function, isFunc := declaration.(*ast.FuncDecl)
			if !isFunc || function.Name.Name != "naivePaddingFrame" {
				continue
			}
			definitions = append(definitions, file)
		}
	}
	require.Len(t, definitions, 1,
		"naivePaddingFrame must have exactly one definition so the frame format "+
			"cannot diverge between helpers; found in %v", definitions)
}
