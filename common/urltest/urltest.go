package urltest

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/common/observable"
)

type HistoryStorage struct {
	access       sync.RWMutex
	delayHistory map[string]*adapter.URLTestHistory
	updateHooks  []*observable.Subscriber[struct{}]
}

func NewHistoryStorage() *HistoryStorage {
	return &HistoryStorage{
		delayHistory: make(map[string]*adapter.URLTestHistory),
	}
}

func (s *HistoryStorage) AddUpdateHook(hook *observable.Subscriber[struct{}]) {
	s.access.Lock()
	defer s.access.Unlock()
	s.updateHooks = append(s.updateHooks, hook)
}

func (s *HistoryStorage) NotifyUpdated() {
	s.access.RLock()
	defer s.access.RUnlock()
	s.notifyUpdated()
}

func (s *HistoryStorage) LoadURLTestHistory(tag string) *adapter.URLTestHistory {
	if s == nil {
		return nil
	}
	s.access.RLock()
	defer s.access.RUnlock()
	return s.delayHistory[tag]
}

func (s *HistoryStorage) DeleteURLTestHistory(tag string) {
	s.access.Lock()
	delete(s.delayHistory, tag)
	s.notifyUpdated()
	s.access.Unlock()
}

func (s *HistoryStorage) StoreURLTestHistory(tag string, history *adapter.URLTestHistory) {
	s.access.Lock()
	s.delayHistory[tag] = history
	s.notifyUpdated()
	s.access.Unlock()
}

func (s *HistoryStorage) notifyUpdated() {
	for _, updateHook := range s.updateHooks {
		updateHook.Emit(struct{}{})
	}
}

func (s *HistoryStorage) Close() error {
	s.access.Lock()
	defer s.access.Unlock()
	s.updateHooks = nil
	return nil
}

// URLTest measures the delay to a node using the unified-delay semantics.
//
// (The displayed delay follows Mihomo unified-delay=true semantics: the first HEAD warms the
// proxy, TCP, TLS and HTTP path; the second HEAD on the reusable transport is the one timed.)
//
// This is a proxy round-trip measurement, not an ICMP ping and not a physical link RTT.
//
// # The algorithm, and why it is exactly this
//
//	start := now
//	dial once
//	one http.Transport + one http.Client
//	HEAD #1                     <- warm-up, NOT timed
//	secondStart := now
//	HEAD #2                     <- timed, reusing the same connection
//	delay = now - secondStart   (on success)
//
// The first request is what pays for everything with a fixed cost: the proxy handshake, the
// target TCP connect, the TLS handshake, and whatever protocol warm-up a transport needs. Those
// costs are real but they are not what the user is being shown - the user is being shown how
// long the node takes once it is already up, which is what makes the number comparable between
// nodes with very different handshake prices.
//
// # Why the previous implementation is gone
//
// It timed from just after DialContext, with one protocol-specific exception:
//
//	if N.NeedHandshakeForWrite(instance) { start = time.Now() }
//
// That reset the clock for early/lazy-handshake protocols but not for ordinary ones, so two
// nodes could report the same number while one included its dial and handshake and the other
// did not. The unified-delay scheme removes the need for any such special case: the warm-up
// request absorbs the difference, and the timed request measures only the steady state.
//
// The previous multiplex pre-warm is also gone. It ran an ADDITIONAL full urlTest before this
// one when multiplexing was enabled, because a cold multiplex session would otherwise be paid
// on the first request. The first HEAD now provides that warm-up for every protocol, so keeping
// both would have meant three or more round trips and a number that matches no other client.
func URLTest(ctx context.Context, link string, detour N.Dialer) (uint16, error) {
	return urlTest(ctx, link, detour)
}

func urlTest(ctx context.Context, link string, detour N.Dialer) (t uint16, err error) {
	if link == "" {
		// The default target is unchanged: this work changes the TIMING, not the destination,
		// so a before/after difference is attributable to the algorithm.
		link = "https://www.gstatic.com/generate_204"
	}
	linkURL, err := url.Parse(link)
	if err != nil {
		return
	}
	hostname := linkURL.Hostname()
	port := linkURL.Port()
	if port == "" {
		switch linkURL.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}

	// start marks the beginning of the whole attempt. It is used only by the fallback path when
	// the second request fails; the normal result is measured from secondStart instead.
	start := time.Now()

	// One dial for the whole measurement. Both requests share it through the transport below.
	instance, err := detour.DialContext(ctx, "tcp", M.ParseSocksaddrHostPortStr(hostname, port))
	if err != nil {
		return
	}
	defer instance.Close()

	// ONE transport for both requests. Creating a second transport, or closing this one between
	// requests, would force the second request to dial and hand shake again - which is precisely
	// the cost the warm-up exists to exclude, and would make the measurement meaningless.
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return instance, nil
		},
		TLSClientConfig: &tls.Config{
			Time:    ntp.TimeFuncFromContext(ctx),
			RootCAs: adapter.RootPoolFromContext(ctx),
		},
	}
	client := http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: C.TCPTimeout,
	}
	defer client.CloseIdleConnections()

	// --- request 1: the warm-up, not timed ---
	firstRequest, err := http.NewRequest(http.MethodHead, link, nil)
	if err != nil {
		return
	}
	firstStart := time.Now()
	firstResponse, err := client.Do(firstRequest.WithContext(ctx))
	firstElapsed := time.Since(firstStart)
	if err != nil {
		// A node that cannot complete the warm-up is not usable. There is nothing to measure,
		// and continuing to a second request would only produce a number for a broken path.
		return
	}
	firstResponse.Body.Close()

	// --- request 2: the measured one ---
	secondStart := time.Now()
	secondRequest, err := http.NewRequest(http.MethodHead, link, nil)
	if err != nil {
		return
	}
	secondResponse, secondErr := client.Do(secondRequest.WithContext(ctx))
	if secondErr == nil {
		secondResponse.Body.Close()
		warmElapsed := time.Since(secondStart)
		// Debug only: this runs once per measurement, not per packet, but the durations are
		// still computed lazily so an unlogged call pays nothing for them.
		if commonLogDebug {
			debugURLTest(firstElapsed, warmElapsed, true)
		}
		return uint16(warmElapsed / time.Millisecond), nil
	}

	// The second request failed. Mihomo does not move `start` to secondStart in this case, so
	// the result falls back to the FIRST request's path rather than being reported as a failure:
	// the node demonstrably answered once, and a warm-up request that cannot be repeated is not
	// evidence that the node is down.
	//
	// `start` here is the beginning of the whole attempt, which is what the pre-unified-delay
	// path measured - the same fallback semantics Mihomo has, reproduced deliberately rather
	// than "improved", so the two clients agree.
	fallbackElapsed := time.Since(start)
	if commonLogDebug {
		debugURLTest(firstElapsed, fallbackElapsed, false)
	}
	return uint16(fallbackElapsed / time.Millisecond), nil
}
