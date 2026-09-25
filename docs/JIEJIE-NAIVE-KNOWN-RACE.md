# Known race: LazyConn handshake vs Close (upstream `sing`)

**Status: NOT FIXED HERE.** This records a defect in a dependency, found while
adding the shared-lifecycle regression for the ALPN views. It is not caused by
anything in this repository and is not fixed by it.

## What races

`sing/common/tls/listener.go`:

```go
type LazyConn struct {
    net.Conn              // Close is promoted from HERE
    tlsConfig     ServerConfig
    access        sync.Mutex
    needHandshake bool
}

func (c *LazyConn) HandshakeContext(ctx context.Context) error {
    if !c.needHandshake {
        return nil
    }
    c.access.Lock()
    defer c.access.Unlock()
    if c.needHandshake {
        tlsConn, err := ServerHandshake(ctx, c.Conn, c.tlsConfig)
        if err != nil {
            return err
        }
        c.Conn = tlsConn          // write, under c.access
        c.needHandshake = false
    }
    return nil
}
```

There is **no** `func (c *LazyConn) Close()`. The method is promoted from the
embedded `net.Conn`, so it reads `c.Conn` **without** taking `c.access`. A
handshake in progress writes that field while a teardown reads it.

## How it is reached

Two goroutines, both through ordinary library paths:

- `net/http` server goroutine → `LazyConn.Read` → `HandshakeContext` → writes
  `c.Conn`
- `Inbound.Close` → `common.Close` → `http.Server.Close` → `LazyConn.Close` →
  reads `c.Conn`

The second happens whenever an inbound is torn down while a connection is still
handshaking, which is normal at shutdown and in tests that start and stop
instances repeatedly.

## Reproduction

**Intermittent, not deterministic.** Measured on this machine:

```bash
cd test/jiejie
TAGS="with_quic,badlinkname,tfogo_checklinkname0"
go test -tags "$TAGS" -race -count=5 \
  -run 'TestJiejieNaiveTCPAndUDPALPNIsolation' -timeout 1200s .
```

Five repetitions of that command produced a data race in **2 of 5** runs. Under
`-count=1` it did not reproduce at all, and a tcp-only inbound did not reproduce
it either - the tcp+udp shape starts more listeners and more concurrent
handshakes, which widens the window.

The intermittency is why this is documented rather than silenced: a test that
fails one run in three is exactly the kind of signal that gets "fixed" by
retrying, and the underlying defect in the dependency would then stay
unrecorded.

## Why it is not fixed here

The fix belongs in the dependency: `LazyConn` needs a `Close` that takes
`c.access` before touching `c.Conn`, or a store of `c.Conn` behind an accessor.
Patching it from this repository is not possible without forking the library, and
the ALPN work this was found alongside is unrelated to it - changing a shared
TLS helper's locking on the strength of one test's timing would be a larger and
riskier change than the defect warrants in this round.

## What is NOT affected

The ALPN isolation itself is correct and unaffected: `-count=20` without the race
detector passes, and every isolation assertion holds. The two concerns are
independent, which is why they are recorded separately rather than one being
used to excuse the other.
