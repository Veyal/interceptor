package control

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/Veyal/interceptor/internal/store"
)

// ---- API keys ----

func (h *Hub) listKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := h.st.ListAPIKeys()
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if keys == nil {
		keys = []store.APIKey{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

func (h *Hub) createKey(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Label string `json:"label"`
	}
	json.NewDecoder(r.Body).Decode(&in)
	if in.Label == "" {
		in.Label = "key"
	}
	token, key, err := h.st.CreateAPIKey(in.Label)
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// The token is returned exactly once.
	writeJSON(w, http.StatusCreated, map[string]any{"token": token, "key": key})
}

func (h *Hub) deleteKey(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httpErr(w, http.StatusBadRequest, "bad id")
		return
	}
	if err := h.st.DeleteAPIKey(id); err != nil {
		httpErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- REST reference ----

type apiRoute struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Desc   string `json:"desc"`
}

var apiRoutes = []apiRoute{
	{"GET", "/api/flows", "List captured proxy flows (filters: method, host, search, scheme, status, before, limit)"},
	{"GET", "/api/flows/{id}", "Flow detail (headers, body hashes, flags)"},
	{"GET", "/api/flows/{id}/raw", "Reconstructed raw request/response (?side=req|res)"},
	{"GET", "/api/flows/{id}/ws", "Captured WebSocket frames for a flow"},
	{"GET", "/api/rules", "List match-&-replace rules"},
	{"POST", "/api/rules", "Create a rule"},
	{"PUT", "/api/rules/{id}", "Update a rule"},
	{"DELETE", "/api/rules/{id}", "Delete a rule"},
	{"GET", "/api/intercept", "Intercept state + hold queue"},
	{"POST", "/api/intercept/toggle", "Enable/disable intercept"},
	{"POST", "/api/intercept/{id}/forward", "Forward a held request (optionally edited)"},
	{"POST", "/api/intercept/{id}/drop", "Drop a held request"},
	{"POST", "/api/repeater/send", "Send a request from Repeater"},
	{"GET", "/api/repeater/history", "Repeater send history"},
	{"POST", "/api/intruder/start", "Start a Sniper/Pitchfork attack"},
	{"GET", "/api/intruder/state", "Current attack progress + results"},
	{"POST", "/api/scanner/run", "Run passive checks over captured flows"},
	{"GET", "/api/scanner/issues", "List scanner findings"},
	{"GET", "/api/settings", "Get proxy/intercept settings"},
	{"PUT", "/api/settings", "Update settings (rebinds the proxy listener)"},
	{"GET", "/api/ca.crt", "Download the local CA certificate"},
	{"GET", "/api/keys", "List API keys"},
	{"POST", "/api/keys", "Create an API key"},
	{"DELETE", "/api/keys/{id}", "Revoke an API key"},
	{"GET", "/api/events", "Server-Sent Events stream of live updates"},
}

func (h *Hub) apiReference(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"baseUrl": "http://" + r.Host, "routes": apiRoutes})
}

// ---- MCP descriptor ----

var mcpDescriptor = map[string]any{
	"name":    "interceptor",
	"version": "0.1.0",
	"status":  "preview",
	"note":    "A full Model Context Protocol server is planned. The descriptor below maps the intended MCP tools onto the existing REST control API, which an agent can already drive directly.",
	"transport": map[string]any{
		"rest": "http://127.0.0.1:9966/api",
		"sse":  "http://127.0.0.1:9966/api/events",
	},
	"tools": []map[string]string{
		{"name": "list_flows", "maps": "GET /api/flows", "desc": "List or search captured traffic"},
		{"name": "get_flow", "maps": "GET /api/flows/{id}/raw", "desc": "Read a request/response"},
		{"name": "send_request", "maps": "POST /api/repeater/send", "desc": "Send a request (Repeater)"},
		{"name": "run_intruder", "maps": "POST /api/intruder/start", "desc": "Run a payload attack"},
		{"name": "run_scanner", "maps": "POST /api/scanner/run", "desc": "Run passive security checks"},
		{"name": "set_intercept", "maps": "POST /api/intercept/toggle", "desc": "Toggle request interception"},
		{"name": "add_rule", "maps": "POST /api/rules", "desc": "Add a match-&-replace rule"},
	},
}

func (h *Hub) apiMCP(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, mcpDescriptor)
}
