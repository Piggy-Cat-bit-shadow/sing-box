package interop

import (
	"context"
	"sync"

	"github.com/sagernet/sing-box/include"
)

// The compiled-in registry context.
//
// Every box in this package is built from a JSON configuration parsed through
// this repository's own option parser and then handed to box.New, which resolves
// protocol types through the registries carried on the context. Building it once
// and sharing it is what lets a scenario be started, stopped and started again
// without paying registry construction per attempt — and, more importantly,
// means all boxes in a run are built from the SAME registry, so a scenario
// cannot accidentally be exercised against a different set of registered
// transports than its neighbours.
var (
	registryOnce    sync.Once
	registryContext context.Context
)

// RegistryContext returns the process-wide registry context.
//
// It is built from the compiled-in registries, so it reflects exactly the build
// tags of the test binary: without `with_xhttp` there is no xhttp transport
// registered, and the scenarios that need it skip rather than fail (see
// gate.go).
func RegistryContext() context.Context {
	registryOnce.Do(func() {
		registryContext = include.Context(context.Background())
	})
	return registryContext
}
