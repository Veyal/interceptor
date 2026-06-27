package report

import (
	"strings"
	"testing"

	"github.com/Veyal/interceptor/internal/store"
)

func TestFindingsEmpty(t *testing.T) {
	out := Findings(nil)
	if !strings.Contains(out, "No findings") {
		t.Fatalf("empty report should say so: %s", out)
	}
}

func TestFindingsGroupsAndOrders(t *testing.T) {
	issues := []store.Issue{
		{Severity: "Low", Title: "Cookie weak", Target: "GET a/b", Detail: "d", Evidence: "Set-Cookie: x", Fix: "harden"},
		{Severity: "High", Title: "Token leak", Target: "POST a/login", Detail: "leaked", Evidence: "eyJ...", Fix: "use cookie"},
		{Severity: "Medium", Title: "Missing CSP", Target: "GET a/", Fix: "add csp"},
	}
	out := Findings(issues)

	// Summary line reflects counts.
	if !strings.Contains(out, "3 findings: 1 High, 1 Medium, 1 Low") {
		t.Fatalf("bad summary: %s", out)
	}
	// High section precedes Medium precedes Low.
	hi, md, lo := strings.Index(out, "## High"), strings.Index(out, "## Medium"), strings.Index(out, "## Low")
	if !(hi >= 0 && md > hi && lo > md) {
		t.Fatalf("severity order wrong (hi=%d md=%d lo=%d):\n%s", hi, md, lo, out)
	}
	// Fields render.
	for _, want := range []string{"### 1. Token leak", "- **Target:** `POST a/login`", "- **Remediation:** use cookie", "- **Evidence:** `eyJ...`"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	// Deterministic.
	if Findings(issues) != out {
		t.Fatal("output not deterministic")
	}
}

func TestProjectRendersFindingsAndPoCsAndAppendix(t *testing.T) {
	findings := []store.Finding{
		{ID: 2, Severity: "Low", Status: "open", Source: "ai", Title: "Verbose errors", Target: "GET /api/x", Detail: "stack traces", Fix: "hide"},
		{ID: 1, Severity: "High", Status: "verified", Source: "human", Title: "IDOR on user", Target: "GET /api/user/1",
			Detail: "swap id", Evidence: "id=2 leaks", Fix: "authorize",
			Flows: []store.FindingFlow{{FlowID: 7, Method: "GET", Host: "app.test", Path: "/api/user/2", Status: 200, Note: "leaks other user"}}},
	}
	issues := []store.Issue{{Severity: "Medium", Title: "Missing CSP", Target: "GET /"}}
	out := Project(findings, issues)

	// Title + summary counts curated findings.
	if !strings.Contains(out, "# Interceptor — Engagement Report") {
		t.Fatalf("missing title:\n%s", out)
	}
	if !strings.Contains(out, "2 findings: 1 High, 1 Low") {
		t.Fatalf("bad summary:\n%s", out)
	}
	// High precedes Low (severity ordering), regardless of input order.
	hi, lo := strings.Index(out, "## High"), strings.Index(out, "## Low")
	if !(hi >= 0 && lo > hi) {
		t.Fatalf("severity order wrong (hi=%d lo=%d):\n%s", hi, lo, out)
	}
	// Status + PoC flow render under the finding.
	for _, want := range []string{"### 1. IDOR on user", "**Status:** verified", "**PoC flows:**", "GET app.test/api/user/2", "→ 200", "leaks other user"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	// Passive-scan appendix is present.
	if !strings.Contains(out, "## Appendix: Passive Scan Issues") || !strings.Contains(out, "Missing CSP") {
		t.Fatalf("missing appendix:\n%s", out)
	}
	// Deterministic.
	if Project(findings, issues) != out {
		t.Fatal("output not deterministic")
	}
}

func TestProjectSeverityOrderSummaryAndFalsePositives(t *testing.T) {
	findings := []store.Finding{
		{ID: 1, Severity: "Low", Status: "open", Title: "Verbose errors", Target: "GET /x", Detail: "stack traces"},
		{ID: 2, Severity: "Critical", Status: "verified", Title: "RCE", Target: "POST /exec", Detail: "shell"},
		{ID: 3, Severity: "Medium", Status: "open", Title: "Missing header", Target: "GET /"},
		{ID: 4, Severity: "High", Status: "verified", Title: "IDOR", Target: "GET /u/1", Detail: "swap id"},
		{ID: 5, Severity: "High", Status: "false_positive", Title: "Bogus SQLi", Target: "GET /search", Detail: "not exploitable"},
	}
	out := Project(findings, nil)

	// Summary line counts only the 4 active findings (the High false_positive is excluded).
	if !strings.Contains(out, "4 findings: 1 Critical, 1 High, 1 Medium, 1 Low") {
		t.Fatalf("bad summary line:\n%s", out)
	}

	// Executive summary table: severity counts + total + status breakdown.
	for _, want := range []string{
		"## Summary",
		"| Severity | Count |",
		"| Critical | 1 |",
		"| High | 1 |",
		"| Medium | 1 |",
		"| Low | 1 |",
		"| **Total** | **4** |",
		"| Status | Count |",
		"| verified | 2 |",
		"| open | 2 |",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing summary-table row %q in:\n%s", want, out)
		}
	}

	// Severity ordering in the body: Critical → High → Medium → Low.
	cr := strings.Index(out, "## Critical")
	hi := strings.Index(out, "## High")
	md := strings.Index(out, "## Medium")
	lo := strings.Index(out, "## Low")
	if !(cr >= 0 && hi > cr && md > hi && lo > md) {
		t.Fatalf("severity order wrong (cr=%d hi=%d md=%d lo=%d):\n%s", cr, hi, md, lo, out)
	}

	// The false positive is NOT in the main body, only in the excluded section.
	excl := strings.Index(out, "## Excluded — False Positives")
	if excl < 0 {
		t.Fatalf("missing excluded section:\n%s", out)
	}
	bogus := strings.Index(out, "Bogus SQLi")
	if bogus < excl {
		t.Fatalf("false positive should appear only after the excluded heading (bogus=%d excl=%d):\n%s", bogus, excl, out)
	}
	// Excluded section sits after the main findings body (after the Low section).
	if excl < lo {
		t.Fatalf("excluded section should follow the main body (excl=%d lo=%d):\n%s", excl, lo, out)
	}

	// Deterministic.
	if Project(findings, nil) != out {
		t.Fatal("output not deterministic")
	}
}

func TestProjectAllFalsePositives(t *testing.T) {
	findings := []store.Finding{
		{ID: 1, Severity: "High", Status: "false_positive", Title: "Bogus", Target: "GET /x"},
	}
	out := Project(findings, nil)
	if !strings.Contains(out, "all recorded findings were marked false positives") {
		t.Fatalf("should note all-FP case:\n%s", out)
	}
	if !strings.Contains(out, "## Excluded — False Positives") || !strings.Contains(out, "Bogus") {
		t.Fatalf("excluded FP should still be listed:\n%s", out)
	}
	// No summary table when there are no active findings.
	if strings.Contains(out, "## Summary") {
		t.Fatalf("should not render a summary table with no active findings:\n%s", out)
	}
}

func TestProjectRendersMissingPoCFlow(t *testing.T) {
	// A finding whose narrative body references a purged PoC flow (Missing=true)
	// should render a clear "evidence no longer in history" note instead of an
	// empty/broken flow quote, while present flow blocks render normally.
	findings := []store.Finding{
		{ID: 1, Severity: "High", Status: "open", Source: "ai", Title: "IDOR with stale PoC", Target: "GET /api/user/1",
			Blocks: []store.FindingBlock{
				{Type: "text", MD: "Swapping the id leaks another user."},
				{Type: "flow", FlowID: 9, Method: "GET", Host: "app.test", Path: "/api/user/2", Status: 200, Note: "present evidence"},
				{Type: "flow", FlowID: 42, Note: "purged exploit request", Missing: true},
			}},
	}
	out := Project(findings, nil)

	// Missing flow renders the dedicated note (with its preserved annotation),
	// not a normal flow quote.
	if !strings.Contains(out, "⚠ PoC flow #42 — evidence no longer in history") {
		t.Fatalf("missing-PoC note absent:\n%s", out)
	}
	if !strings.Contains(out, "purged exploit request") {
		t.Fatalf("missing-PoC annotation not preserved:\n%s", out)
	}
	// Present flow still renders normally.
	if !strings.Contains(out, "GET app.test/api/user/2") {
		t.Fatalf("present flow should render normally:\n%s", out)
	}
	// Deterministic.
	if Project(findings, nil) != out {
		t.Fatal("output not deterministic")
	}
}

func TestProjectRendersMissingPoCFlowLegacy(t *testing.T) {
	// Legacy fallback path (no Blocks): a Missing flow in f.Flows renders the note.
	findings := []store.Finding{
		{ID: 1, Severity: "Medium", Status: "open", Title: "Legacy stale PoC", Detail: "see PoC",
			Flows: []store.FindingFlow{
				{FlowID: 7, Method: "GET", Host: "app.test", Path: "/ok", Status: 200},
				{FlowID: 8, Note: "gone", Missing: true},
			}},
	}
	out := Project(findings, nil)
	if !strings.Contains(out, "⚠ PoC flow #8 — evidence no longer in history") {
		t.Fatalf("legacy missing-PoC note absent:\n%s", out)
	}
	if !strings.Contains(out, "GET app.test/ok") {
		t.Fatalf("legacy present flow should render normally:\n%s", out)
	}
}

func TestProjectEmpty(t *testing.T) {
	out := Project(nil, nil)
	if !strings.Contains(out, "No findings recorded") {
		t.Fatalf("empty project report should say so: %s", out)
	}
}

func TestFindingsSanitizesEvidence(t *testing.T) {
	out := Findings([]store.Issue{{Severity: "Low", Title: "x", Evidence: "line1\nline2`with`ticks"}})
	if strings.Contains(out, "`with`") || strings.Contains(out, "line1\nline2") {
		t.Fatalf("evidence not sanitized for inline code: %s", out)
	}
}
