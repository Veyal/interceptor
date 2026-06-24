package control

import (
	"strings"
	"testing"
)

// assistPrompt builds the AI-assist user prompt. A single flow keeps the focused
// wording; multiple selected flows become a combined, per-endpoint review.
func TestAssistPrompt(t *testing.T) {
	flows := []assistFlow{
		{Label: "#1 GET https://h/a", Req: "GET /a", Res: "200 ok"},
		{Label: "#2 POST https://h/b", Req: "POST /b", Res: "500 err"},
	}

	multi := assistPrompt("explain", flows)
	for _, want := range []string{"2 exchanges", "#1 GET https://h/a", "#2 POST https://h/b", "GET /a", "POST /b"} {
		if !strings.Contains(multi, want) {
			t.Fatalf("multi-flow prompt missing %q:\n%s", want, multi)
		}
	}

	single := assistPrompt("explain", flows[:1])
	if !strings.Contains(single, "Explain what this HTTP request/response does") {
		t.Fatalf("single-flow prompt lost its focused wording:\n%s", single)
	}
}
