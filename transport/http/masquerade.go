package http

import (
	"context"
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
