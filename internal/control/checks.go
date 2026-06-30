package control

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/Veyal/interceptor/internal/activescan"
	"github.com/Veyal/interceptor/internal/checkscript"
	"github.com/Veyal/interceptor/internal/scanner"
	"github.com/Veyal/interceptor/internal/store"
)

// maxCheckSource bounds a user/AI-supplied Starlark check source before it is
// decoded and handed to the parser — a multi-hundred-MB body would otherwise be
// lexed in full (memory/CPU exhaustion on the control goroutine). 512 KiB is far
// larger than any real check.
const maxCheckSource = 512 << 10

// Custom-check management: list / read / save / delete user Starlark checks in
// ChecksDir, plus a test endpoint that compiles + runs a check against a flow
// without saving — so a human (or the AI) can iterate before committing it.

func (h *Hub) listChecks(w http.ResponseWriter, r *http.Request) {
	checks := []checkscript.Source{}
	if h.ChecksDir != "" {
		if got := checkscript.List(h.ChecksDir); got != nil {
			checks = got
		}
	}
	// Built-in passive checks (toggleable, not deletable) + active probes
	// (read-only) so the Checks manager can show every module in one place.
	writeJSON(w, http.StatusOK, map[string]any{
		"checks":   checks,
		"builtin":  scanner.BuiltinChecks,
		"active":   activeCheckList(),
		"dir":      h.ChecksDir,
		"disabled": h.checksDisabledList(),
	})
}

// activeCheckList exposes the built-in active-scan probes for the Checks manager
// (toggleable like passive checks, but only fired when you arm & run an active
// scan — they send real attack traffic, which is why the run stays consent-gated).
func activeCheckList() []map[string]string {
	out := make([]map[string]string, 0, len(activescan.Checks))
	for _, c := range activescan.Checks {
		out = append(out, map[string]string{
			"id": c.ID, "class": c.Class, "severity": c.Severity, "title": c.Title, "fix": c.Fix,
		})
	}
	return out
}

func (h *Hub) checksDisabledList() []string {
	raw, ok, _ := h.st.GetSetting("checks.disabled")
	if !ok || raw == "" {
		return nil
	}
	var ids []string
	_ = json.Unmarshal([]byte(raw), &ids)
	return ids
}

func (h *Hub) checksDisabledSet() map[string]bool {
	dis := map[string]bool{}
	for _, id := range h.checksDisabledList() {
		dis[id] = true
	}
	return dis
}

func (h *Hub) setChecksDisabled(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Disabled []string `json:"disabled"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxCheckSource)).Decode(&in); err != nil {
		httpErr(w, http.StatusBadRequest, "bad json")
		return
	}
	b, _ := json.Marshal(in.Disabled)
	if err := h.st.SetSetting("checks.disabled", string(b)); err != nil {
		httpErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.broadcast(map[string]any{"type": "checks.update"})
	writeJSON(w, http.StatusOK, map[string]any{"disabled": in.Disabled})
}

func (h *Hub) getCheck(w http.ResponseWriter, r *http.Request) {
	src, err := checkscript.Read(h.ChecksDir, r.PathValue("id"))
	if err != nil {
		httpErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": r.PathValue("id"), "source": src})
}

func (h *Hub) saveCheck(w http.ResponseWriter, r *http.Request) {
	if h.ChecksDir == "" {
		httpErr(w, http.StatusBadRequest, "checks directory not configured")
		return
	}
	var in struct {
		Source string `json:"source"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxCheckSource)).Decode(&in); err != nil {
		httpErr(w, http.StatusBadRequest, "bad json")
		return
	}
	if err := checkscript.Save(h.ChecksDir, r.PathValue("id"), in.Source); err != nil {
		httpErr(w, http.StatusBadRequest, err.Error()) // includes compile errors
		return
	}
	h.broadcast(map[string]any{"type": "checks.update"})
	writeJSON(w, http.StatusOK, map[string]any{"id": r.PathValue("id"), "saved": true})
}

func (h *Hub) deleteCheck(w http.ResponseWriter, r *http.Request) {
	if err := checkscript.Delete(h.ChecksDir, r.PathValue("id")); err != nil {
		httpErr(w, http.StatusBadRequest, err.Error())
		return
	}
	h.broadcast(map[string]any{"type": "checks.update"})
	w.WriteHeader(http.StatusNoContent)
}

// testCheck compiles source and runs it against a flow (the given id, else the
// most recent flow), returning findings or the compile/runtime error — never 500
// for a bad check, so callers can show the error inline.
func (h *Hub) testCheck(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Source string `json:"source"`
		FlowID int64  `json:"flowId"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxCheckSource)).Decode(&in); err != nil {
		httpErr(w, http.StatusBadRequest, "bad json")
		return
	}
	c, err := checkscript.Compile("test", in.Source)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"error": err.Error()})
		return
	}
	var f *store.Flow
	if in.FlowID > 0 {
		if f, err = h.st.GetFlow(in.FlowID); err != nil {
			httpErr(w, http.StatusNotFound, "flow not found")
			return
		}
	} else if flows, _ := h.st.QueryFlowsFilter(store.FlowFilter{Limit: 1}); len(flows) > 0 {
		f = flows[0]
	}
	if f == nil {
		writeJSON(w, http.StatusOK, map[string]any{"findings": []store.Issue{}, "note": "no captured flow to test against yet"})
		return
	}
	issues, rerr := c.Run(h.flowForCheck(f))
	if rerr != nil {
		writeJSON(w, http.StatusOK, map[string]any{"error": rerr.Error()})
		return
	}
	if issues == nil {
		issues = []store.Issue{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": issues, "flowId": f.ID})
}

func (h *Hub) flowForCheck(f *store.Flow) checkscript.Flow {
	return checkscript.Flow{
		ID: f.ID, Method: f.Method, Scheme: f.Scheme, Host: f.Host, Port: f.Port,
		Path: f.Path, Status: f.Status, Mime: f.Mime,
		ReqHeaders: f.ReqHeaders, ResHeaders: f.ResHeaders,
		ReqBody: string(h.bodyBytes(f.ReqBodyHash)), ResBody: string(h.bodyBytes(f.ResBodyHash)),
	}
}
