package clashapi

import (
	"net/http"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badjson"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func groupRouter(server *Server) http.Handler {
	r := chi.NewRouter()
	r.Get("/", getGroups(server))
	r.Route("/{name}", func(r chi.Router) {
		r.Use(parseProxyName, findProxyByName(server))
		r.Get("/", getGroup(server))
		r.Get("/delay", getGroupDelay(server))
	})
	return r
}

func getGroups(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		groups := common.Map(common.Filter(server.outbound.Outbounds(), func(it adapter.Outbound) bool {
			_, isGroup := it.(adapter.OutboundGroup)
			return isGroup
		}), func(it adapter.Outbound) *badjson.JSONObject {
			return proxyInfo(server, it)
		})
		render.JSON(w, r, render.M{
			"proxies": groups,
		})
	}
}

func getGroup(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		proxy := r.Context().Value(CtxKeyProxy).(adapter.Outbound)
		if _, ok := proxy.(adapter.OutboundGroup); ok {
			render.JSON(w, r, proxyInfo(server, proxy))
			return
		}
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, ErrNotFound)
	}
}

// getGroupDelay measures every member of a group.
//
// # What this endpoint is
//
// It is a MANUAL DIAGNOSTIC: a user asking "how fast are this group's members right now, against the
// URL I named". That makes two things mandatory, and both were missing here.
//
// It must not write health evidence. A measurement taken against an arbitrary URL is not evidence
// about any group's configured target, so it must not become selection input - and writing it would
// let a user grow the health map without bound by testing arbitrary URLs.
//
// It must run under the Box's context. Measure reads the certificate roots, the time service and the
// per-Box Coordinator out of the context, and the HTTP request's context carries none of them.
func getGroupDelay(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		proxy := r.Context().Value(CtxKeyProxy).(adapter.Outbound)
		outboundGroup, ok := proxy.(adapter.OutboundGroup)
		if !ok {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, ErrNotFound)
			return
		}

		query, valid := parseClashDelayQuery(r.URL.Query())
		if !valid {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}

		ctx, cancel := clashMeasurementContext(server.ctx, r.Context(), query.Timeout)
		defer cancel()

		// A URLTest group is measured through its own entry point, because it OWNS a configured
		// target and a measurement scope that this endpoint cannot reconstruct.
		//
		// # Why an override is refused rather than honoured
		//
		// The parameters are not silently ignored: supplying `url` or `expected` here is refused with
		// a 400, because this group cannot honour them without measuring something its health check
		// does not mean, and returning 200 for a measurement of a target the client never named would
		// be worse than refusing.
		//
		// # The contract this follows, checked rather than assumed
		//
		// Mihomo's /group/{name}/delay DOES pass both parameters into the group:
		//
		//	dm, err := group.URLTest(ctx, url, expectedStatus)
		//
		// so the parameters are not meaningless in that API. But its URLTest group does not use the
		// URL it is handed:
		//
		//	func (u *URLTest) URLTest(ctx, url string, expectedStatus ...) {
		//	    return u.GroupBase.URLTest(ctx, u.testUrl, expectedStatus)
		//	}
		//
		// It substitutes its own configured target and ignores the argument, so a Mihomo client that
		// passes `url` receives a result measured against a different target, with no indication of
		// it. That is the silent ignore this endpoint exists to avoid.
		//
		// The decision here is therefore: keep measuring the group's own configured target (the
		// semantics that are actually implemented, and the only ones this group can honour), and say
		// so when a caller asks for something else, instead of reporting a result for a target that
		// was never measured.
		if _, isURLTestGroup := outboundGroup.(adapter.URLTestGroup); isURLTestGroup {
			if r.URL.Query().Get("url") != "" || r.URL.Query().Get("expected") != "" {
				render.Status(r, http.StatusBadRequest)
				render.JSON(w, r, newError("a URLTest group measures its configured target; url and expected cannot be overridden"))
				return
			}
			result, err := outboundGroup.(adapter.URLTestGroup).URLTest(ctx)
			if err != nil {
				render.Status(r, http.StatusGatewayTimeout)
				render.JSON(w, r, newError(err.Error()))
				return
			}
			render.JSON(w, r, result)
			return
		}

		outbounds := common.FilterNotNil(common.Map(outboundGroup.All(), func(it string) adapter.Outbound {
			itOutbound, _ := server.outbound.Outbound(it)
			return itOutbound
		}))

		// DISPLAY ONLY.
		//
		// The legacy wrapper defaulted to writing health evidence, which is wrong for a manual
		// probe: a diagnostic would silently change which member the group selects, and an arbitrary
		// URL would accumulate in the health map. Each member's own automatic check is the only
		// thing that should move selection.
		result := group.URLTestOutboundsWithTarget(ctx, server.outbound, server.urlTestHistory,
			server.logger, outbounds, query.URL, query.Expected, 0, true, group.TestHistoryDisplayOnly)

		// A request that produced no measurement at all is a failure, not an empty success.
		//
		// The node-level endpoint already answers this way: it reports 503 when the measurement
		// failed, which includes the target not satisfying `expected`. The group endpoint used to
		// answer 200 with an empty map for the same situation, so a client could not tell "no member
		// satisfied the rule I asked for" from "here are the members, all without a delay".
		if len(result) == 0 {
			if ctx.Err() != nil {
				render.Status(r, http.StatusGatewayTimeout)
				render.JSON(w, r, ErrRequestTimeout)
				return
			}
			render.Status(r, http.StatusServiceUnavailable)
			render.JSON(w, r, newError("An error occurred in the delay test"))
			return
		}

		render.JSON(w, r, result)
	}
}
