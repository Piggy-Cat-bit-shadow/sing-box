package jiejie_test

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// referenceWebReadHeaderTimeout bounds a stalled preamble request.
const referenceWebReadHeaderTimeout = 5 * time.Second

// referenceDecoyMarker appears in the fronting document so a test can tell
// "the web backend served this" from "the proxy answered".
const referenceDecoyMarker = "reference-decoy-site"

// A counting web backend for the reference's masquerade/fronting side.
//
// The official reference deployment serves ordinary web traffic with the
// fronting site, and that is precisely the behaviour a preamble test needs to
// observe: a browser loading the decoy fetches the document and then its
// sub-resources, and every one of those requests has to reach the web backend
// instead of being answered by the proxy or challenged with a 407.
//
// The backend therefore records what it was asked for rather than only what it
// returned. A test that asserted on the response body alone could pass while the
// request never left the proxy, which is the failure mode this guards.

// referenceWebBackend answers the decoy site and records every request.
type referenceWebBackend struct {
	mutex sync.Mutex
	// requests records "METHOD path" for every request served, in order.
	requests []string
	// headers records the request headers of the document request, so a test can
	// assert that no proxy credential was forwarded to the web backend.
	headers http.Header
}

func newReferenceWebBackend() *referenceWebBackend {
	return &referenceWebBackend{}
}

// record notes a request and returns the response it should receive.
func (b *referenceWebBackend) record(request *http.Request) (status int, contentType string, body string) {
	b.mutex.Lock()
	b.requests = append(b.requests, request.Method+" "+request.URL.Path)
	if b.headers == nil {
		b.headers = request.Header.Clone()
	}
	b.mutex.Unlock()

	switch {
	case request.URL.Path == "/" || request.URL.Path == "":
		// Referencing sub-resources is what makes the preamble meaningful: a
		// real browser fetches them, so a proxy that only forwards the document
		// would still be distinguished by these follow-up requests.
		return http.StatusOK, "text/html; charset=utf-8",
			`<!doctype html><html><head><!-- ` + referenceDecoyMarker + ` -->` +
				`<link rel="stylesheet" href="/a.css">` +
				`<script src="/a.js"></script>` +
				`</head><body><img src="/a.png" alt="a"></body></html>`
	case request.URL.Path == "/a.css":
		return http.StatusOK, "text/css", "body{color:#000}"
	case request.URL.Path == "/a.js":
		return http.StatusOK, "application/javascript", "// a.js"
	case request.URL.Path == "/a.png":
		return http.StatusOK, "image/png", "not-a-real-png"
	default:
		return http.StatusNotFound, "text/plain", "not found"
	}
}

// servedPaths returns a copy of the recorded requests.
func (b *referenceWebBackend) servedPaths() []string {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	out := make([]string, len(b.requests))
	copy(out, b.requests)
	return out
}

// servedCount reports how many requests reached the backend.
func (b *referenceWebBackend) servedCount() int {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return len(b.requests)
}

// hasPath reports whether a path was requested.
func (b *referenceWebBackend) hasPath(path string) bool {
	for _, entry := range b.servedPaths() {
		if strings.HasSuffix(entry, " "+path) {
			return true
		}
	}
	return false
}

// sawProxyCredential reports whether any request carried a proxy credential.
//
// A masquerade/fronting backend must never receive one: Proxy-Authorization
// carries the proxy password in the clear, and forwarding it to a web backend
// would leak the credential to whatever that backend is.
func (b *referenceWebBackend) sawProxyCredential() bool {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.headers.Get("Proxy-Authorization") != ""
}

// newReferenceWebServer wraps the backend in an http.Server.
func newReferenceWebServer(backend *referenceWebBackend) *http.Server {
	mux := http.NewServeMux()
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		status, contentType, body := backend.record(request)
		writer.Header().Set("Content-Type", contentType)
		writer.Header().Set("Content-Length", fmt.Sprint(len(body)))
		writer.WriteHeader(status)
		_, _ = writer.Write([]byte(body))
	})
	mux.Handle("/", handler)
	return &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: referenceWebReadHeaderTimeout,
	}
}
