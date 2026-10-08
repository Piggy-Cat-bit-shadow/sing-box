//go:build with_gvisor

package main

import (
	gvisorTCP "github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
)

// gvisorProbeSymbols references the gVisor TCP transport so it is linked into the probe and
// recorded in the artifact's module provenance.
//
// It also pins the symbols the 048 nil-handshake guard depends on: handleConnecting lives in this
// package and switches on exactly these connecting states. If a future gVisor pin renames or
// removes them, this file stops compiling, which is a better failure than a release check that
// silently finds no gVisor in an artifact that is supposed to contain it.
var _ = []gvisorTCP.EndpointState{
	gvisorTCP.StateSynSent,
	gvisorTCP.StateSynRecv,
}

var _ = (&gvisorTCP.Endpoint{}).EndpointState
