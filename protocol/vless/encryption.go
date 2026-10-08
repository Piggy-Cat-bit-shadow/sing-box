package vless

// Client-side parsing and wiring for the VLESS `encryption` spec string. It is
// kept in its own file so the upstream-owned outbound.go carries only the
// two-line insertion, and a future upstream implementation of this feature
// conflicts there rather than in the parser.
//
// This file is adapted from github.com/starifly/sing-box
// (protocol/vless/encryption), the upstream this code originates from, via the
// reference fork github.com/Leadaxe/sing-box-lx
// (protocol/vless/lx_encryption.go). Both are GPL-3.0, the same license as this
// repository, and share its upstream base.

import (
	"context"
	"encoding/base64"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

// Ownership contract for the encryption layer's conn.
//
// Before DialContext returns, the dial context bounds everything: it is the
// only cancellation the caller has, and the handshake is the last unbounded
// wait inside the dial path. wrapEncryption therefore applies the dial deadline
// to the write direction and arms guardHandshake to close the conn if the
// context dies.
//
// After DialContext returns, the dial context has no effect on the connection —
// the net.Dialer contract, pinned for the XHTTP transport in
// transport/v2rayxhttp/dial_ctx_contract_test.go. Only Close and read/write
// deadlines bound it. wrapEncryption stops the guard before it returns,
// precisely so that a pooled consumer cancelling its dial context right after
// the dial (the DNS transport pool does) cannot tear down a healthy conn.

// wrapEncryption performs the post-quantum handshake over an already-dialed
// conn, returning it unchanged when the layer is not configured. It sits above
// the transport/TLS and below the vless client, which stays unaware of it.
// A failed handshake closes the conn: the caller only propagates the error.
//
// Handshake takes a bare net.Conn (the wire format is fixed by the spec and
// upstream Xray, so it grows no context parameter) and internally writes
// fragmented padding with sleeps in between. On a half-alive node those writes
// block forever, so the dial deadline is applied to the conn for the duration
// of the handshake and cleared afterwards, letting the caller's context govern
// it.
//
// WRITE side only, deliberately. A read deadline would cost correctness: an
// XHTTP read deadline is one-shot (it closes the late-bound download body, and
// clearing it cannot reopen that), so a handshake that overran the dial
// deadline but still succeeded would hand back a conn whose download side is
// already dead. SetDeadline covers both directions, hence the narrower call.
// The read side is bounded by guardHandshake instead, which closes the conn
// only on the failure path.
func (h *vlessDialer) wrapEncryption(ctx context.Context, conn net.Conn) (net.Conn, error) {
	if h.encryption == nil {
		return conn, nil
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetWriteDeadline(deadline); err == nil {
			defer conn.SetWriteDeadline(time.Time{})
		}
	}
	finish := guardHandshake(ctx, conn)
	encryptedConn, err := h.encryption.Handshake(conn)
	if !finish() {
		// The guard won the race and owns the conn: it closed it, which is what
		// unblocked the handshake. Whatever Handshake returned rides on a dead
		// conn, so drop it without closing — closing here would race the guard.
		return nil, E.Cause(ctx.Err(), "encryption handshake")
	}
	if err != nil {
		common.Close(conn)
		return nil, E.Cause(err, "encryption handshake")
	}
	return encryptedConn, nil
}

// guardHandshake bounds the READ side of the handshake by the dial context and
// returns a finish func reporting whether the handshake, not the guard, won.
//
// Handshake ends in a blocking io.ReadFull for the server's reply. On a node
// that accepts the connection and then says nothing that read never returns: a
// bare TCP conn has no read deadline of its own, and on XHTTP the response body
// is late-bound, so Read parks before there is even anything to time out.
// Nothing above can intervene, because the conn has not been handed up yet —
// the caller is still inside DialContext. Closing the conn is the only lever
// that reaches a parked read, so the guard owns the conn until the handshake
// returns. The claim is atomic in both directions: a handshake that completes
// at the instant the context dies still wins and keeps its conn, and a guard
// that fires first reports a dead conn rather than a result that merely looks
// healthy.
//
// The guard is stopped before wrapEncryption returns, so it can never observe a
// cancellation that arrives after the dial: the net.Dialer contract above holds
// unchanged. See the ownership contract at the top of this file.
func guardHandshake(ctx context.Context, conn net.Conn) func() bool {
	done := ctx.Done()
	if done == nil {
		return func() bool { return true }
	}
	var claimed atomic.Bool
	finished := make(chan struct{})
	go func() {
		select {
		case <-done:
			if claimed.CompareAndSwap(false, true) {
				common.Close(conn)
			}
		case <-finished:
		}
	}()
	return func() bool {
		won := claimed.CompareAndSwap(false, true)
		close(finished)
		return won
	}
}

// encryptionPrefix is the only handshake method that exists today.
const encryptionPrefix = "mlkem768x25519plus"

// xorMode selects how the layer looks on the wire: AEAD headers shaped like
// TLSv1.3 (native), XOR-ed by public key (xorpub), or fully random.
const (
	xorModeNative uint32 = 0
	xorModeXorPub uint32 = 1
	xorModeRandom uint32 = 2
)

// keyLenX25519 and keyLenMLKEM768 are the two accepted public-key sizes; a
// segment decoding to anything else is a malformed key rather than padding.
const (
	keyLenX25519   = 32
	keyLenMLKEM768 = 1184
)

// paddingSegmentMaxLen bounds how long a segment may be and still be read as a
// padding block. Keys are base64 of 32 or 1184 bytes, so they are always longer;
// padding blocks look like "100-111-1111".
const paddingSegmentMaxLen = 20

type clientEncryptionConfig struct {
	keys    [][]byte
	xorMode uint32
	seconds uint32
	padding string
}

// parseClientEncryption reads the spec string:
//
//	mlkem768x25519plus.<native|xorpub|random>.<0rtt|1rtt>[.<padding>…].<key>[.<key>…]
//
// Errors name the offending segment so a bad config fails at check/start time
// with something actionable, rather than silently failing to connect later.
//
// Drift from the reference port, pinned by encryption_test.go: padding blocks
// together with 0rtt are rejected here, matching the feature's stated
// guarantee. The reference parsed such a string and then silently ignored the
// padding, because the 0-RTT path never uses it — the traffic shape would not
// be what the config claims.
func parseClientEncryption(raw string) (clientEncryptionConfig, error) {
	var cfg clientEncryptionConfig
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return cfg, E.New("empty encryption string")
	}
	parts := strings.Split(raw, ".")
	if len(parts) < 4 {
		return cfg, E.New("invalid encryption string: expected at least method.appearance.rtt.key, got ", len(parts), " segments")
	}
	if parts[0] != encryptionPrefix {
		return cfg, E.New("unsupported encryption method: ", parts[0], " (only ", encryptionPrefix, " exists)")
	}
	switch parts[1] {
	case "native":
		cfg.xorMode = xorModeNative
	case "xorpub":
		cfg.xorMode = xorModeXorPub
	case "random":
		cfg.xorMode = xorModeRandom
	default:
		return cfg, E.New("unknown encryption appearance: ", parts[1], " (expected native|xorpub|random)")
	}
	switch parts[2] {
	case "0rtt":
		cfg.seconds = 1
	case "1rtt":
		cfg.seconds = 0
	default:
		return cfg, E.New("unknown encryption RTT mode: ", parts[2], " (expected 0rtt|1rtt)")
	}

	// Remaining segments are padding blocks first, then keys. Once a key is seen
	// the padding phase is over — that is how the reference implementation tells
	// the two apart, since both are dot-separated and otherwise unlabelled.
	paddingPhase := true
	var paddingParts []string
	for _, segment := range parts[3:] {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			return cfg, E.New("empty segment in encryption string")
		}
		if paddingPhase && len(segment) < paddingSegmentMaxLen {
			paddingParts = append(paddingParts, segment)
			continue
		}
		data, err := base64.RawURLEncoding.DecodeString(segment)
		if err != nil {
			return cfg, E.New("invalid encryption key (not base64url): ", segment)
		}
		if len(data) != keyLenX25519 && len(data) != keyLenMLKEM768 {
			return cfg, E.New("invalid encryption key length: ", len(data), " (expected ", keyLenX25519, " or ", keyLenMLKEM768, ")")
		}
		cfg.keys = append(cfg.keys, data)
		paddingPhase = false
	}
	if len(cfg.keys) == 0 {
		return cfg, E.New("no encryption keys in encryption string")
	}
	if len(paddingParts) > 0 {
		if cfg.seconds > 0 {
			return cfg, E.New("padding blocks are only supported with 1rtt, not 0rtt")
		}
		cfg.padding = strings.Join(paddingParts, ".")
	}
	return cfg, nil
}
