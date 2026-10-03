package clashapi

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing/common"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json/badjson"
	N "github.com/sagernet/sing/common/network"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func proxyRouter(server *Server, router adapter.Router) http.Handler {
	r := chi.NewRouter()
	r.Get("/", getProxies(server))

	r.Route("/{name}", func(r chi.Router) {
		r.Use(parseProxyName, findProxyByName(server))
		r.Get("/", getProxy(server))
		r.Get("/delay", getProxyDelay(server))
		r.Put("/", updateProxy)
	})
	return r
}

func parseProxyName(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := getEscapeParam(r, "name")
		ctx := context.WithValue(r.Context(), CtxKeyProxyName, name)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func findProxyByName(server *Server) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			name := r.Context().Value(CtxKeyProxyName).(string)
			proxy, exist := server.outbound.Outbound(name)
			if !exist {
				render.Status(r, http.StatusNotFound)
				render.JSON(w, r, ErrNotFound)
				return
			}
			ctx := context.WithValue(r.Context(), CtxKeyProxy, proxy)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func proxyInfo(server *Server, detour adapter.Outbound) *badjson.JSONObject {
	var info badjson.JSONObject
	var clashType string
	switch detour.Type() {
	case C.TypeBlock:
		clashType = "Reject"
	default:
		clashType = C.ProxyDisplayName(detour.Type())
	}
	info.Put("type", clashType)
	info.Put("name", detour.Tag())
	info.Put("udp", common.Contains(detour.Network(), N.NetworkUDP))
	delayHistory := server.urlTestHistory.LoadURLTestHistory(group.RealTag(detour, N.NetworkTCP))
	if delayHistory != nil {
		info.Put("history", []*adapter.URLTestHistory{delayHistory})
	} else {
		info.Put("history", []*adapter.URLTestHistory{})
	}
	if group, isGroup := detour.(adapter.OutboundGroup); isGroup {
		var now string
		if selected := group.Selected(N.NetworkTCP); selected != nil {
			now = selected.Tag()
		}
		info.Put("now", now)
		info.Put("all", group.All())
	}
	return &info
}

func getProxies(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var proxyMap badjson.JSONObject
		outbounds := common.Filter(server.outbound.Outbounds(), func(detour adapter.Outbound) bool {
			return detour.Tag() != ""
		})
		outbounds = append(outbounds, common.Map(common.Filter(server.endpoint.Endpoints(), func(detour adapter.Endpoint) bool {
			return detour.Tag() != ""
		}), func(it adapter.Endpoint) adapter.Outbound {
			return it
		})...)

		allProxies := make([]string, 0, len(outbounds))

		for _, detour := range outbounds {
			switch detour.Type() {
			case C.TypeDirect, C.TypeBlock, C.TypeDNS:
				continue
			}
			allProxies = append(allProxies, detour.Tag())
		}

		defaultTag := server.outbound.Default().Tag()

		sort.SliceStable(allProxies, func(i, j int) bool {
			return allProxies[i] == defaultTag
		})

		// fix clash dashboard
		proxyMap.Put("GLOBAL", map[string]any{
			"type":    "Fallback",
			"name":    "GLOBAL",
			"udp":     true,
			"history": []*adapter.URLTestHistory{},
			"all":     allProxies,
			"now":     defaultTag,
		})

		for i, detour := range outbounds {
			var tag string
			if detour.Tag() == "" {
				tag = F.ToString(i)
			} else {
				tag = detour.Tag()
			}
			proxyMap.Put(tag, proxyInfo(server, detour))
		}
		var responseMap badjson.JSONObject
		responseMap.Put("proxies", &proxyMap)
		response, err := responseMap.MarshalJSON()
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		w.Write(response)
	}
}

func getProxy(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		proxy := r.Context().Value(CtxKeyProxy).(adapter.Outbound)
		response, err := proxyInfo(server, proxy).MarshalJSON()
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		w.Write(response)
	}
}

type UpdateProxyRequest struct {
	Name string `json:"name"`
}

func updateProxy(w http.ResponseWriter, r *http.Request) {
	req := UpdateProxyRequest{}
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	proxy := r.Context().Value(CtxKeyProxy).(adapter.Outbound)
	selector, ok := proxy.(*group.Selector)
	if !ok {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("Must be a Selector"))
		return
	}

	if !selector.SelectOutbound(req.Name) {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("Selector update error: not found"))
		return
	}

	render.NoContent(w, r)
}

func getProxyDelay(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		// The requested URL is used as given.
		//
		// This used to blank out any `http://` URL, which then fell through to the default
		// `https://www.gstatic.com/generate_204`. A client explicitly asking to measure against
		// a plain-HTTP endpoint therefore measured a TLS endpoint instead - a different
		// destination, an extra TLS handshake, and a number that cannot be compared with another
		// client's measurement of the same URL.
		//
		// An empty URL still means "use the default"; an explicit scheme is honoured.
		url := query.Get("url")
		// The timeout must be a POSITIVE number of milliseconds.
		//
		// ParseInt accepted a negative value, and a negative duration makes the context already
		// expired - so "timeout=-1" produced an instant, meaningless "measurement" that looked
		// like a failed probe rather than a bad request.
		timeout, err := strconv.ParseInt(query.Get("timeout"), 10, 16)
		if err != nil || timeout <= 0 {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}

		// `expected` restricts which HTTP status counts as a successful measurement, using the
		// Mihomo syntax (204, 200-299, 200/204/301-399, *, or empty for no constraint).
		// A malformed expression is the caller's error, so it is refused here rather than being
		// silently ignored and producing a measurement against the wrong acceptance rule.
		expected, err := urltest.ParseExpectedStatus(query.Get("expected"))
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}

		proxy := r.Context().Value(CtxKeyProxy).(adapter.Outbound)

		// Resolve the leaf ONCE, before measuring.
		//
		// A group's selection can move while the measurement is in flight, so resolving afterwards
		// - which is what RealTag did at the end - could attribute the delay to a node that was
		// never measured. The attribution must be a fact about the connection that was tested, so
		// the leaf is fixed up front and the measurement runs against it.
		proxy, leafErr := group.ResolveURLTestLeaf(proxy, N.NetworkTCP)
		if leafErr != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, ErrBadRequest)
			return
		}

		// The measurement context is derived from the SERVER's context, not from Background.
		//
		// Measure reads the Box's own services out of the context - the certificate roots it must
		// trust and the NTP clock it timestamps with. Starting from Background discarded both, so
		// an HTTPS probe through a private root or against a skewed clock failed here while the
		// identical native or group measurement succeeded: same engine, same node, different
		// answer purely because of which context reached it.
		//
		// The request's own context is wired in as well, so a client that disconnects cancels the
		// measurement instead of leaving it to run on.
		ctx, cancel := context.WithCancel(server.ctx)
		stopRequestWatch := context.AfterFunc(r.Context(), cancel)
		defer stopRequestWatch()
		defer cancel()

		// The caller's requested timeout applies on top, inside the Box's lifetime.
		ctx, cancelTimeout := context.WithTimeout(ctx, time.Millisecond*time.Duration(timeout))
		defer cancelTimeout()

		measurement, measureErr := urltest.Measure(ctx, urltest.MeasureOptions{
			Link:           url,
			ExpectedStatus: expected,
		}, proxy)

		// This records the outcome of THIS request and nothing else.
		//
		// It previously walked every URLTest group containing this node and forced an immediate
		// re-selection. That coupled a manual probe of one node against one target to the
		// selection of unrelated groups: a measurement taken for a diagnostic could move live
		// traffic, and a group measuring a different target would re-select from a result that
		// was never about its target. A group maintains its own selection from its own periodic
		// checks, and when this probe happens to use the same target, the scoped result is simply
		// available to the group's next check.
		// The leaf was resolved before the measurement, so its tag is the node that was measured.
		realTag := proxy.Tag()
		if measureErr == nil {
			// DISPLAY ONLY.
			//
			// A manual probe asks "how fast is this node against the URL I typed". It is not
			// measured against any group's target, so it must not become selection evidence - and
			// writing it into the health map would let a user grow that map without bound by
			// testing arbitrary URLs.
			//
			// A failure records nothing at all. Failing this URL does not disprove a previous
			// success against another one, and the request already reports the failure.
			server.urlTestHistory.StoreDisplayHistory(realTag, measurement.Scope, &adapter.URLTestHistory{
				Time:  time.Now(),
				Delay: measurement.Delay,
			})
		}
		delay, err := measurement.Delay, measureErr

		if ctx.Err() != nil {
			render.Status(r, http.StatusGatewayTimeout)
			render.JSON(w, r, ErrRequestTimeout)
			return
		}

		if err != nil || delay == 0 {
			render.Status(r, http.StatusServiceUnavailable)
			render.JSON(w, r, newError("An error occurred in the delay test"))
			return
		}

		render.JSON(w, r, render.M{
			"delay": delay,
		})
	}
}
