package control

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/Veyal/interceptor/internal/aiassist"
	"github.com/Veyal/interceptor/internal/scanner"
)

// aiAssist asks a bring-your-own-key LLM to explain a flow, suggest payloads, or
// summarize findings. Disabled unless an API key is configured (Settings or the
// provider's env var). The exchange is sent to the provider only here, on an
// explicit request. Provider is "anthropic" (default) or "openrouter".
func (h *Hub) aiAssist(w http.ResponseWriter, r *http.Request) {
	provider, _, _ := h.st.GetSetting("ai.provider")
	if provider == "" {
		provider = aiassist.ProviderAnthropic
	}
	key, _, _ := h.st.GetSetting("ai.apiKey")
	if key == "" {
		if provider == aiassist.ProviderOpenRouter {
			key = os.Getenv("OPENROUTER_API_KEY")
		} else {
			key = os.Getenv("ANTHROPIC_API_KEY")
		}
	}
	if key == "" {
		httpErr(w, http.StatusBadRequest, "no AI API key — set one in Settings → AI assist (or the ANTHROPIC_API_KEY / OPENROUTER_API_KEY env var)")
		return
	}
	var in struct {
		FlowID  int64   `json:"flowId"`  // single-flow (back-compat)
		FlowIDs []int64 `json:"flowIds"` // a selection
		Kind    string  `json:"kind"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		httpErr(w, http.StatusBadRequest, "bad json")
		return
	}
	ids := in.FlowIDs
	if len(ids) == 0 && in.FlowID != 0 {
		ids = []int64{in.FlowID}
	}
	if len(ids) == 0 {
		httpErr(w, http.StatusBadRequest, "no flow selected")
		return
	}
	const maxFlows = 20
	if len(ids) > maxFlows {
		ids = ids[:maxFlows] // bound prompt size
	}
	per := 4000
	if len(ids) > 1 {
		per = 1500 // keep a multi-flow prompt manageable
	}

	var flows []assistFlow
	for _, id := range ids {
		f, err := h.st.GetFlow(id)
		if err != nil {
			continue
		}
		af := assistFlow{
			Label: fmt.Sprintf("#%d %s %s://%s%s", f.ID, f.Method, f.Scheme, f.Host, f.Path),
			Req:   clip(string(h.rawRequest(f)), per),
			Res:   clip(string(h.rawResponse(f)), per),
		}
		if in.Kind == "summarize" {
			for _, is := range scanner.Analyze(f, h.bodyBytes(f.ReqBodyHash), h.bodyBytes(f.ResBodyHash)) {
				af.Findings += "- " + is.Severity + ": " + is.Title + "\n"
			}
		}
		flows = append(flows, af)
	}
	if len(flows) == 0 {
		httpErr(w, http.StatusNotFound, "flow not found")
		return
	}

	const system = "Concise web-app security testing assistant for a pentester. Be specific and practical; no disclaimers or preamble."
	model, _, _ := h.st.GetSetting("ai.model")
	text, err := aiassist.New(provider, key, model).Complete(system, assistPrompt(in.Kind, flows))
	if err != nil {
		httpErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"text": text})
}

// assistFlow is one flow's raw text fed to the AI assist.
type assistFlow struct {
	Label    string // "#42 GET https://h/x"
	Req      string
	Res      string
	Findings string // passive findings, for the "summarize" kind
}

// assistPrompt builds the AI-assist user prompt. One flow keeps the original
// focused wording; several selected flows become a combined per-endpoint review.
func assistPrompt(kind string, flows []assistFlow) string {
	if len(flows) == 1 {
		f := flows[0]
		switch kind {
		case "suggest":
			return "Suggest specific test payloads (injection, IDOR, auth bypass, etc.) for the parameters in this request, with a one-line rationale each:\n\n" + f.Req
		case "summarize":
			return "Summarize the security posture of this exchange in a few bullets. Passive findings:\n" + f.Findings + "\nRequest:\n" + f.Req + "\n\nResponse:\n" + f.Res
		default:
			return "Explain what this HTTP request/response does and anything security-relevant a tester should check:\n\nRequest:\n" + f.Req + "\n\nResponse:\n" + f.Res
		}
	}
	lead := map[string]string{
		"suggest":   "Across these requests, suggest specific test payloads (injection, IDOR, auth bypass, etc.) worth trying, grouped by endpoint, each with a one-line rationale.",
		"summarize": "Review these captured exchanges together and summarize the security posture and the highest-value things to test, in a few bullets.",
	}[kind]
	if lead == "" {
		lead = "Review these captured exchanges and call out anything security-relevant a tester should check, grouped by endpoint."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n%d exchanges:\n", lead, len(flows))
	for i, f := range flows {
		fmt.Fprintf(&b, "\n=== [%d] %s ===\n", i+1, f.Label)
		if f.Findings != "" {
			b.WriteString("Passive findings:\n" + f.Findings)
		}
		b.WriteString("Request:\n" + f.Req + "\n")
		if kind != "suggest" && f.Res != "" {
			b.WriteString("Response:\n" + f.Res + "\n")
		}
	}
	return b.String()
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "\n…(truncated)"
	}
	return s
}
