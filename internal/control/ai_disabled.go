package control

import "net/http"

const aiDisabledMsg = "AI features are disabled in Settings → AI assist"

// aiDisabled reports whether the operator turned off all AI features for this project.
func (h *Hub) aiDisabled() bool {
	v, ok, _ := h.st.GetSetting("ai.disabled")
	return ok && v == "1"
}

// denyIfAIDisabled writes 403 and returns true when AI is off.
func (h *Hub) denyIfAIDisabled(w http.ResponseWriter) bool {
	if !h.aiDisabled() {
		return false
	}
	httpErr(w, http.StatusForbidden, aiDisabledMsg)
	return true
}
