package control

import (
	"encoding/json"
	"net/http"
)

// getNotes returns the project's markdown notebook — a per-project scratchpad for
// credentials, findings, scope notes and to-dos, editable in the UI and by the AI.
func (h *Hub) getNotes(w http.ResponseWriter, r *http.Request) {
	notes, _, _ := h.st.GetSetting("project.notes")
	writeJSON(w, http.StatusOK, map[string]any{"notes": notes})
}

// putNotes replaces the project's markdown notebook and tells every client to refresh.
func (h *Hub) putNotes(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Notes string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		httpErr(w, http.StatusBadRequest, "bad json")
		return
	}
	if err := h.st.SetSetting("project.notes", in.Notes); err != nil {
		httpErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.broadcast(map[string]any{"type": "notes.update"})
	w.WriteHeader(http.StatusNoContent)
}
