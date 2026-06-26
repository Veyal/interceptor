package control

import "net/http"

const oobDisabledMsg = "OOB catcher is disabled — enable in Settings → Scanner"

// oobEnabled reports whether the operator turned on the OOB interaction catcher.
// Off by default: localhost URLs are useless for blind callbacks from remote targets.
func (h *Hub) oobEnabled() bool {
	v, ok, _ := h.st.GetSetting("oob.enabled")
	return ok && v == "1"
}

// denyIfOOBDisabled writes 403 and returns true when OOB is off.
func (h *Hub) denyIfOOBDisabled(w http.ResponseWriter) bool {
	if h.oobEnabled() {
		return false
	}
	httpErr(w, http.StatusForbidden, oobDisabledMsg)
	return true
}
