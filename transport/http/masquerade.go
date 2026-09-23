package http

import (
	"context"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service/filemanager"
)

// NewMasqueradeHandler creates the decoy web handler shared by HTTP/2 and
// HTTP/3. It intentionally has no access to the proxy or MASQUE data paths.
func NewMasqueradeHandler(ctx context.Context, options *option.Hysteria2Masquerade) (http.Handler, error) {
	if options == nil || options.Type == "" {
		return nil, nil
	}
	switch options.Type {
	case C.Hysterai2MasqueradeTypeFile:
		directory := filemanager.BasePath(ctx, os.ExpandEnv(options.FileOptions.Directory))
		if _, err := filemanager.ReadDir(ctx, directory); err != nil {
			return nil, E.Cause(err, "read masquerade directory")
		}
		return http.FileServer(http.Dir(directory)), nil
	case C.Hysterai2MasqueradeTypeProxy:
		target, err := url.Parse(options.ProxyOptions.URL)
		if err != nil || target.Scheme == "" || target.Host == "" || (target.Scheme != "http" && target.Scheme != "https") {
			if err != nil {
				return nil, E.Cause(err, "parse masquerade URL")
			}
			return nil, E.New("invalid masquerade URL: ", options.ProxyOptions.URL)
		}
		return &httputil.ReverseProxy{
			Rewrite: func(request *httputil.ProxyRequest) {
				request.SetURL(target)
				if !options.ProxyOptions.RewriteHost {
					request.Out.Host = request.In.Host
				}
			},
			ErrorHandler: func(writer http.ResponseWriter, _ *http.Request, _ error) {
				writer.WriteHeader(http.StatusBadGateway)
			},
		}, nil
	case C.Hysterai2MasqueradeTypeString:
		return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			for key, values := range options.StringOptions.Headers {
				for _, value := range values {
					writer.Header().Add(key, value)
				}
			}
			if options.StringOptions.StatusCode != 0 {
				writer.WriteHeader(options.StringOptions.StatusCode)
			}
			_, _ = writer.Write([]byte(options.StringOptions.Content))
		}), nil
	default:
		return nil, E.New("unknown masquerade type: ", options.Type)
	}
}

// OverLimitDecoy builds the response used when a request both fails
// authentication and exceeds the unauthenticated budget.
//
// The purpose of the limiter is to bound the RESOURCES an unauthenticated peer
// can consume. Serving the normal masquerade handler over-limit does not achieve
// that: for a `proxy` masquerade every over-limit request still triggers a full
// backend HTTP request, so an attacker keeps driving the backend at will. This
// decoy is generated locally instead, so an over-limit request costs a few bytes
// of formatting and no outbound connection.
//
// It is deliberately indistinguishable from an ordinary web server response: a
// plain 429, a text/html content type and a small static body. It must never
// carry Proxy-Authenticate, WWW-Authenticate or any other proxy-shaped signal,
// because that would let a prober fingerprint the endpoint by tripping the
// limiter.
//
// It is intentionally NOT a cached copy of the backend page. Caching the backend
// would require fetching it, and a stale or per-user page would be a worse
// disguise than a generic server response.
func NewOverLimitDecoy() http.Handler {
	const body = "<!DOCTYPE html><html><head><title>429 Too Many Requests</title></head>" +
		"<body><h1>429 Too Many Requests</h1>" +
		"<p>Too many requests. Please try again later.</p></body></html>\n"
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		header := writer.Header()
		header.Set("Content-Type", "text/html; charset=utf-8")
		header.Set("Cache-Control", "no-store")
		header.Set("Retry-After", "10")
		writer.WriteHeader(http.StatusTooManyRequests)
		if request.Method == http.MethodHead {
			return
		}
		_, _ = io.WriteString(writer, body)
	})
}
