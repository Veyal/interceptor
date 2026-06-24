package control

import (
	"encoding/json"
	"net/http"
	"time"
)

// activityMax bounds the in-memory AI-activity feed (a session-scoped ring).
const activityMax = 300

// activityItem is one recorded AI (MCP) tool call, surfaced live in the UI so a
// human can watch what the AI is doing as it happens.
type activityItem struct {
	ID      int64  `json:"id"`
	TS      int64  `json:"ts"` // unix millis (server clock)
	Tool    string `json:"tool"`
	Summary string `json:"summary"`
	OK      bool   `json:"ok"`
	Result  string `json:"result"`
	Ms      int64  `json:"ms"`
}

// recordActivity appends an item to the ring and returns it with its assigned
// id/timestamp. Caller broadcasts outside the lock.
func (h *Hub) recordActivity(it activityItem) activityItem {
	h.actMu.Lock()
	defer h.actMu.Unlock()
	h.actSeq++
	it.ID = h.actSeq
	it.TS = time.Now().UnixMilli()
	h.actLog = append(h.actLog, it)
	if len(h.actLog) > activityMax {
		h.actLog = h.actLog[len(h.actLog)-activityMax:]
	}
	return it
}

// postActivity records one AI tool call (POSTed by the MCP server after every
// call) and pushes it to all live UI subscribers.
func (h *Hub) postActivity(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Tool    string `json:"tool"`
		Summary string `json:"summary"`
		OK      bool   `json:"ok"`
		Result  string `json:"result"`
		Ms      int64  `json:"ms"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Tool == "" {
		httpErr(w, http.StatusBadRequest, "tool required")
		return
	}
	it := h.recordActivity(activityItem{Tool: in.Tool, Summary: in.Summary, OK: in.OK, Result: in.Result, Ms: in.Ms})
	h.broadcast(map[string]any{"type": "activity", "item": it})
	w.WriteHeader(http.StatusNoContent)
}

// listActivity returns the recorded AI activity, newest first.
func (h *Hub) listActivity(w http.ResponseWriter, r *http.Request) {
	h.actMu.Lock()
	out := make([]activityItem, len(h.actLog))
	for i, it := range h.actLog {
		out[len(h.actLog)-1-i] = it // reverse → newest first
	}
	h.actMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"activity": out})
}
