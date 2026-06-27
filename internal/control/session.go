package control

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/Veyal/interceptor/internal/sender"
)

// parseSessionHeaders turns "Key: Value" lines into sender.Header entries.
func parseSessionHeaders(text string) []sender.Header {
	var out []sender.Header
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		out = append(out, sender.Header{Key: k, Value: strings.TrimSpace(v)})
	}
	return out
}

// loadMacro reads the persisted token-refresh macro ("" setting → disabled).
func (h *Hub) loadMacro() sender.Macro {
	raw, _, _ := h.st.GetSetting("session.macro")
	var m sender.Macro
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &m)
	}
	return m
}

// loadLoginMacro reads the persisted login macro ("" → disabled).
func (h *Hub) loadLoginMacro() sender.LoginMacro {
	raw, _, _ := h.st.GetSetting("session.loginMacro")
	var m sender.LoginMacro
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &m)
	}
	return m
}

// persistSessionHeaders saves session header lines from sender.Header slice.
func persistSessionHeaders(hdrs []sender.Header) string {
	var lines []string
	for _, h := range hdrs {
		if h.Key != "" {
			lines = append(lines, h.Key+": "+h.Value)
		}
	}
	return strings.Join(lines, "\n")
}

// applySessionFromStore loads persisted session config, macros, and login macro.
func (h *Hub) applySessionFromStore() {
	enabled, _, _ := h.st.GetSetting("session.enabled")
	text, _, _ := h.st.GetSetting("session.headers")
	h.snd.SetSession(enabled == "1", parseSessionHeaders(text))
	h.snd.SetMacro(h.loadMacro())
	h.snd.SetLoginMacro(h.loadLoginMacro())
}
// wireSessionRefresh connects login-macro output to persisted session headers.
func (h *Hub) wireSessionRefresh() {
	h.snd.SetSessionRefresh(func(hdrs []sender.Header) {
		text := persistSessionHeaders(hdrs)
		_ = h.st.SetSetting("session.enabled", "1")
		_ = h.st.SetSetting("session.headers", text)
		h.snd.SetSession(true, hdrs)
		h.broadcast(map[string]any{"type": "session.update"})
	})
}

func (h *Hub) getSession(w http.ResponseWriter, r *http.Request) {
	enabled, _, _ := h.st.GetSetting("session.enabled")
	text, _, _ := h.st.GetSetting("session.headers")
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": enabled == "1", "headers": text,
		"macro": h.loadMacro(), "loginMacro": h.loadLoginMacro(),
	})
}

func (h *Hub) setSession(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled    bool               `json:"enabled"`
		Headers    string             `json:"headers"`
		Macro      *sender.Macro      `json:"macro"`
		LoginMacro *sender.LoginMacro `json:"loginMacro"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		httpErr(w, http.StatusBadRequest, "bad json")
		return
	}
	en := ""
	if in.Enabled {
		en = "1"
	}
	_ = h.st.SetSetting("session.enabled", en)
	_ = h.st.SetSetting("session.headers", in.Headers)
	h.snd.SetSession(in.Enabled, parseSessionHeaders(in.Headers))
	if in.Macro != nil {
		b, _ := json.Marshal(*in.Macro)
		_ = h.st.SetSetting("session.macro", string(b))
		h.snd.SetMacro(*in.Macro)
	}
	if in.LoginMacro != nil {
		b, _ := json.Marshal(*in.LoginMacro)
		_ = h.st.SetSetting("session.loginMacro", string(b))
		h.snd.SetLoginMacro(*in.LoginMacro)
	}
	h.broadcast(map[string]any{"type": "session.update"})
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": in.Enabled, "headers": in.Headers,
		"macro": h.loadMacro(), "loginMacro": h.loadLoginMacro(),
	})
}

// runLoginMacro executes the recorded login request now and refreshes session headers.
func (h *Hub) runLoginMacro(w http.ResponseWriter, r *http.Request) {
	h.snd.SetLoginMacro(h.loadLoginMacro())
	hdrs, err := h.snd.RunLoginMacroNow()
	if err != nil {
		httpErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if len(hdrs) == 0 {
		httpErr(w, http.StatusBadRequest, "login macro produced no session headers — check the macro is enabled and the login response sets Cookie or Authorization")
		return
	}
	text, _, _ := h.st.GetSetting("session.headers")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "headers": text, "applied": len(hdrs),
	})
}

// testLoginMacro dry-runs the saved login macro without touching the live session:
// it returns the login response status and the session headers it would capture, so
// the operator can see what the macro does before relying on it.
func (h *Hub) testLoginMacro(w http.ResponseWriter, r *http.Request) {
	status, hdrs, err := h.snd.TestLoginMacro(h.loadLoginMacro())
	if err != nil {
		httpErr(w, http.StatusBadGateway, err.Error())
		return
	}
	out := make([]map[string]string, 0, len(hdrs))
	for _, hd := range hdrs {
		out = append(out, map[string]string{"key": hd.Key, "value": hd.Value})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": status, "headers": out, "applied": len(hdrs),
	})
}

// loginMacroFromFlow captures a flow's request as the login macro.
func (h *Hub) loginMacroFromFlow(w http.ResponseWriter, r *http.Request) {
	f, ok := h.loadFlow(w, r)
	if !ok {
		return
	}
	def := (f.Scheme == "https" && f.Port == 443) || (f.Scheme == "http" && f.Port == 80)
	target := fmt.Sprintf("%s://%s", f.Scheme, f.Host)
	if !def {
		target = fmt.Sprintf("%s://%s:%d", f.Scheme, f.Host, f.Port)
	}
	raw := string(h.rawRequest(f))
	m := sender.LoginMacro{
		Enabled: true, Target: target, Request: raw, ReauthOn401: true,
	}
	b, _ := json.Marshal(m)
	_ = h.st.SetSetting("session.loginMacro", string(b))
	h.snd.SetLoginMacro(m)
	h.broadcast(map[string]any{"type": "session.update"})
	writeJSON(w, http.StatusOK, map[string]any{"loginMacro": m})
}
