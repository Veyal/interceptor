package activescript

import (
	"strings"
	"testing"

	"github.com/Veyal/interceptor/internal/activescan"
)

func TestCompileRunFindsVuln(t *testing.T) {
	src := `def check(point, baseline, probe):
    r = probe("'")
    if re_search("(?i)SQL syntax", r.body):
        return [finding("High", "SQL injection (custom)", evidence=r.body[:40], fix="parameterize")]
    return []
`
	c, err := Compile("sqli-custom", src)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// Fake prober: returns a DB error only when the payload contains a quote.
	probe := func(payload string) activescan.Response {
		if strings.Contains(payload, "'") {
			return activescan.Response{Status: 500, FlowID: 42, Body: "You have an error in your SQL syntax near 'x'"}
		}
		return activescan.Response{Status: 200, Body: "ok"}
	}
	hit := c.Run(activescan.Point{Kind: "query", Name: "id", Value: "1"}, activescan.Response{Status: 200, Body: "ok"}, probe)
	if hit == nil {
		t.Fatal("expected a hit from the vulnerable probe")
	}
	if hit.Title != "SQL injection (custom)" || hit.Severity != "High" {
		t.Fatalf("hit carried wrong metadata: %+v", hit)
	}
	if hit.FlowID != 42 {
		t.Fatalf("probe's flow id should propagate to the hit; got %d", hit.FlowID)
	}

	// Negative: a clean response → no hit.
	clean := func(payload string) activescan.Response { return activescan.Response{Status: 200, Body: "ok"} }
	if c.Run(activescan.Point{Kind: "query", Name: "id", Value: "1"}, activescan.Response{Status: 200, Body: "ok"}, clean) != nil {
		t.Fatal("clean response must not produce a hit")
	}
}

func TestCompileRejectsMissingCheck(t *testing.T) {
	if _, err := Compile("bad", "# no check function\nx = 1"); err == nil {
		t.Fatal("expected an error when check() is missing")
	}
}
