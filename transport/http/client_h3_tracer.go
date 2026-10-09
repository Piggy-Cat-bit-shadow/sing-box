package http

// This file deliberately carries NO build constraint.
//
// # Why the tracer interface is not gated on with_quic
//
// The interface used to be declared in client_h3.go under `//go:build with_quic`, which made the
// package fail to COMPILE without the tag:
//
//	transport/http/client.go:239:33: undefined: http3LifecycleTracer
//
// client.go is untagged and is where the HTTP/3 client is CONSTRUCTED. Its version==3 branch is
// guarded by `NewHTTP3Client == nil` (client.go declares that hook untagged, and client_h3.go
// assigns it under with_quic), so a build without QUIC returns ErrQUICNotIncluded there and never
// reaches the assertion at runtime - but the assertion still has to TYPE-CHECK, which means the
// interface it names has to exist in every build.
//
// The interface itself is a logging contract: one method taking a logger.ContextLogger. It has no
// QUIC dependency, so "none" is the correct constraint. The implementation stays with_quic, in
// client_h3.go, together with the http3ClientImpl type it is defined on.
//
// It is optional on purpose: a client built by a test, or by a build without QUIC, does not have
// to provide one, and client.go skips the call when it is absent.

import (
	"github.com/sagernet/sing/common/logger"
)

// http3LifecycleTracer is implemented by HTTP/3 clients that accept a logger for lifecycle
// tracing.
type http3LifecycleTracer interface {
	SetLifecycleLogger(logger.ContextLogger)
}
