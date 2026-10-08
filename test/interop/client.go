package interop

import (
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	badjson "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

// The client half of the stand: this fork's `box`, started from the generated
// JSON, with a way to prove it is usable.
//
// # Why the box is built from JSON and not from option structs
//
// The generated client file is the deliverable. Building the box from it — the
// same bytes a maintainer would open and edit — means the test exercises the
// parser and the config semantics a user gets, not a Go literal the test wrote
// for itself. It also means a scenario that produces a config the parser
// rejects fails HERE, with the file path in the message, rather than silently
// testing a different configuration.

// boxProbeAttemptTimeout bounds one readiness attempt. The attempts are
// repeated inside the caller's deadline, so a short per-attempt timeout is what
// turns "the reference is not up yet" into a retry rather than a hang; the
// overall bound belongs to the caller.
const boxProbeAttemptTimeout = 2 * time.Second

// BoxClient is one in-process box built from a generated client config.
type BoxClient struct {
	configPath     string
	rawConfig      []byte
	inboundAddress string
	inboundPort    uint16

	instance *box.Box
	cancel   context.CancelFunc

	// The proxied HTTP client is built once and shared. It is safe for concurrent
	// use, it holds no pooled connections (keep-alives are off), and it survives a
	// Stop/Start because the mixed inbound rebinds the same port — which is what
	// makes the restart subtest exercise the transport rather than a fresh client.
	httpOnce   sync.Once
	httpClient *http.Client
}

// NewBoxClient prepares a client from the generated config bytes. Nothing is
// started until Start is called, so a test can assert on the parsed
// configuration before any process exists.
func NewBoxClient(rawConfig []byte, configPath string, inboundAddress string, inboundPort uint16) *BoxClient {
	return &BoxClient{
		configPath:     configPath,
		rawConfig:      rawConfig,
		inboundAddress: inboundAddress,
		inboundPort:    inboundPort,
	}
}

// Start parses the generated config and starts the box.
//
// It is called again after Stop to reproduce a client restart over a live
// reference. That reproduces the lifecycle the fork's own report calls the
// zombie reproduction: a stopped core that leaves a session or a pooled HTTP
// connection alive at the reference would make the SECOND start fail or the
// first post-restart request misbehave, and neither is visible from a
// single-start test.
func (c *BoxClient) Start() error {
	if c.instance != nil {
		return E.New("box client is already started")
	}
	var parsed option.Options
	parsed, err := badjson.UnmarshalExtendedContext[option.Options](RegistryContext(), c.rawConfig)
	if err != nil {
		return E.Cause(err, "parse generated client config ", c.configPath)
	}
	ctx, cancel := context.WithCancel(RegistryContext())
	instance, err := box.New(box.Options{
		Context: ctx,
		Options: parsed,
	})
	if err != nil {
		cancel()
		return E.Cause(err, "build box from ", c.configPath)
	}
	if err = instance.Start(); err != nil {
		_ = instance.Close()
		cancel()
		return E.Cause(err, "start box from ", c.configPath)
	}
	c.instance = instance
	c.cancel = cancel
	return nil
}

// Stop closes the box. It is safe to call when already stopped, and safe to call
// twice: the failure path stops the client explicitly to flush its log, and the
// test cleanup stops it again.
func (c *BoxClient) Stop() error {
	if c.instance == nil {
		return nil
	}
	err := c.instance.Close()
	if c.cancel != nil {
		c.cancel()
	}
	c.instance = nil
	c.cancel = nil
	return err
}

// HTTPClient returns an HTTP client that reaches the world through the box's
// mixed inbound on loopback.
//
// Keep-alives are disabled so that each request maps to one new connection
// through the tunnel. That is deliberate: "multiple sequential connections" only
// means something if the connections are genuinely separate, and a pooled client
// would silently test one connection many times over.
func (c *BoxClient) HTTPClient() *http.Client {
	c.httpOnce.Do(func() {
		socksDialer := socks.NewClient(
			N.SystemDialer,
			M.ParseSocksaddrHostPort(c.inboundAddress, c.inboundPort),
			socks.Version5,
			"",
			"",
		)
		c.httpClient = &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
					return socksDialer.DialContext(ctx, network, M.ParseSocksaddr(address))
				},
				DisableKeepAlives: true,
			},
		}
	})
	return c.httpClient
}

// WaitReady blocks until the box can carry an HTTP request to probeURL, the
// context expires, or the box stops accepting connections.
//
// Readiness for the CLIENT is not "the listening port is bound": the mixed
// inbound binds its port whether or not the outbound can reach anything, so a
// port check would report a working stand while every request fails. The only
// honest readiness is an actual request through the tunnel to the local target,
// and that is what this performs. The bounded deadline and the last error are
// both part of the contract: a caller that gets an error needs to know whether
// it was the tunnel or the reference, and the error carries the last attempt's
// message for exactly that.
func (c *BoxClient) WaitReady(ctx context.Context, probeURL string) error {
	client := c.HTTPClient()
	var lastErr error
	attempt := func() bool {
		attemptCtx, cancel := context.WithTimeout(ctx, boxProbeAttemptTimeout)
		defer cancel()
		request, err := http.NewRequestWithContext(attemptCtx, http.MethodGet, probeURL, nil)
		if err != nil {
			lastErr = err
			return false
		}
		response, err := client.Do(request)
		if err != nil {
			lastErr = err
			return false
		}
		_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 1<<16))
		closeErr := response.Body.Close()
		if readErr != nil {
			lastErr = readErr
			return false
		}
		if closeErr != nil {
			lastErr = closeErr
			return false
		}
		if response.StatusCode != http.StatusOK {
			lastErr = E.New("probe answered HTTP ", strconv.Itoa(response.StatusCode))
			return false
		}
		return true
	}
	if attempt() {
		return nil
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return E.Cause(ctx.Err(), "box client never became usable: the last proxied attempt failed with: ",
				describeLastError(lastErr))
		case <-ticker.C:
			if attempt() {
				return nil
			}
		}
	}
}

func describeLastError(err error) string {
	if err == nil {
		return "(no attempt completed)"
	}
	return err.Error()
}
