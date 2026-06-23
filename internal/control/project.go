package control

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/Veyal/interceptor/internal/harx"
	"github.com/Veyal/interceptor/internal/store"
)

// projectBundle is a portable session: captured flows (as HAR), match-&-replace
// rules, target-scope rules, and selected settings.
type projectBundle struct {
	Version  string            `json:"version"`
	HAR      json.RawMessage   `json:"har"`
	Rules    []store.Rule      `json:"rules"`
	Scope    []store.ScopeRule `json:"scope"`
	Settings map[string]string `json:"settings"`
}

func (h *Hub) exportProject(w http.ResponseWriter, r *http.Request) {
	flows, err := h.st.QueryFlowsFilter(store.FlowFilter{Limit: 10000, ExcludeFlags: store.FlagIntruder})
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	rules, _ := h.st.ListRules()
	scope, _ := h.st.ListScopeRules()
	up, _, _ := h.st.GetSetting("upstream.proxy")
	bundle := projectBundle{
		Version:  "1",
		HAR:      json.RawMessage(harx.Build(flows, h.bodyBytes)),
		Rules:    rules,
		Scope:    scope,
		Settings: map[string]string{"upstream.proxy": up},
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="interceptor-project.json"`)
	json.NewEncoder(w).Encode(bundle)
}

// importProject merges a project into the current session (additive for flows,
// rules, and scope; applies the upstream-proxy setting). It does not rebind the
// proxy listener.
func (h *Hub) importProject(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(io.LimitReader(r.Body, 128<<20))
	if err != nil {
		httpErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var bundle projectBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		httpErr(w, http.StatusBadRequest, "not a valid project: "+err.Error())
		return
	}

	flows := 0
	if len(bundle.HAR) > 0 {
		if entries, perr := harx.Parse(bundle.HAR); perr == nil {
			for _, e := range entries {
				u, err := url.Parse(e.URL)
				if err != nil || !u.IsAbs() || u.Host == "" {
					continue
				}
				ts := e.TS
				if ts.IsZero() {
					ts = time.Now()
				}
				fl := &store.Flow{
					TS: ts, Method: e.Method, Scheme: u.Scheme, Host: u.Hostname(),
					Port: atoiOr(u.Port(), defaultPortFor(u.Scheme)), Path: u.RequestURI(),
					HTTPVersion: orVal(e.HTTPVersion, "HTTP/1.1"), Status: e.Status,
					ReqHeaders: e.ReqHeaders, ResHeaders: e.ResHeaders, Mime: e.Mime,
					DurationMs: e.DurationMs, Flags: store.FlagImported,
				}
				fl.ReqBodyHash, fl.ReqLen = h.storeBody(e.ReqBody)
				fl.ResBodyHash, fl.ResLen = h.storeBody(e.ResBody)
				if _, err := h.st.InsertFlow(fl); err == nil {
					flows++
				}
			}
		}
	}
	for i := range bundle.Rules {
		bundle.Rules[i].ID = 0
		h.st.CreateRule(&bundle.Rules[i])
	}
	for i := range bundle.Scope {
		bundle.Scope[i].ID = 0
		h.st.CreateScopeRule(&bundle.Scope[i])
	}
	if up, ok := bundle.Settings["upstream.proxy"]; ok && up != "" {
		if h.Upstream != nil {
			_ = h.Upstream(up)
		}
		_ = h.st.SetSetting("upstream.proxy", up)
	}

	h.refreshRules()
	h.refreshScope()
	if flows > 0 {
		h.broadcast(map[string]any{"type": "flow.new"})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"importedFlows": flows, "importedRules": len(bundle.Rules), "importedScope": len(bundle.Scope),
	})
}
