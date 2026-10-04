package trafficsched

import (
	E "github.com/sagernet/sing/common/exceptions"
)

// ErrClosed is returned by a flow whose scheduler or connection is shutting down.
//
// It is a real error rather than a silent pass: treating a closed scheduler as a free permit
// would make a shutting-down process look like a working fast path, and the copy loop closes the
// connection on it, which is the correct outcome for both cases.
var ErrClosed = E.New("traffic scheduler closed")
