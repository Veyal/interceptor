package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidateFindingFormatRejectsWallOfText(t *testing.T) {
	wall := strings.Repeat("The application exposes an unauthenticated admin panel that allows full config dump including database credentials and SMTP passwords which an attacker can use. ", 3)
	err, _ := validateFindingFormat(findingFormatInput{
		Severity: "High",
		Detail:   wall,
	})
	if err == nil {
		t.Fatal("expected hard reject for wall-of-text detail without impact/why fields")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "impact") {
		t.Fatalf("error should point at impact/why fields, got: %v", err)
	}
}

func TestValidateFindingFormatAcceptsPointFirst(t *testing.T) {
	body := `[{"type":"text","md":"**Before**: own profile"},{"type":"flow","flowId":12,"note":"Before: own account"},{"type":"text","md":"**Action**: swap id"},{"type":"flow","flowId":13,"note":"After: other user PII"}]`
	err, warns := validateFindingFormat(findingFormatInput{
		Severity: "High",
		Impact:   "full PII disclosure",
		Why:      "Broken object-level authorization",
		Target:   "GET api.example.com/users/{id}",
		Body:     body,
	})
	if err != nil {
		t.Fatalf("well-formed finding should pass: %v", err)
	}
	if len(warns) > 0 {
		t.Fatalf("well-formed finding should have no warnings, got %v", warns)
	}
}

func TestValidateFindingFormatWarnsMissingImpact(t *testing.T) {
	body := `[{"type":"flow","flowId":1,"note":"After: leak"}]`
	err, warns := validateFindingFormat(findingFormatInput{
		Severity: "High",
		Why:      "broken authz",
		Target:   "example.com",
		Body:     body,
	})
	if err != nil {
		t.Fatalf("should warn not reject: %v", err)
	}
	joined := strings.Join(warns, "\n")
	if !strings.Contains(strings.ToLower(joined), "impact") {
		t.Fatalf("expected impact warning, got %v", warns)
	}
}

func TestValidateFindingFormatWarnsHighWithoutFlow(t *testing.T) {
	err, warns := validateFindingFormat(findingFormatInput{
		Severity: "Critical",
		Impact:   "admin takeover",
		Why:      "default credentials",
		Target:   "admin.example.com",
		Detail:   "Login with admin/admin worked.",
	})
	if err != nil {
		t.Fatalf("should warn not reject: %v", err)
	}
	joined := strings.Join(warns, "\n")
	if !strings.Contains(strings.ToLower(joined), "flow") && !strings.Contains(joined, "PoC") {
		t.Fatalf("expected flow/PoC warning for Critical, got %v", warns)
	}
}

func TestValidateFindingFormatWarnsNeedsVerificationWithoutInstructions(t *testing.T) {
	err, warns := validateFindingFormat(findingFormatInput{
		Severity: "Medium",
		Status:   "needs_verification",
		Impact:   "possible PII exposure",
		Why:      "open bucket",
		Target:   "s3.example.com",
	})
	if err != nil {
		t.Fatalf("should warn not reject: %v", err)
	}
	joined := strings.Join(warns, "\n")
	if !strings.Contains(joined, "verificationInstructions") {
		t.Fatalf("expected verificationInstructions warning, got %v", warns)
	}
}

func TestValidateFindingFormatAllowsShortOpening(t *testing.T) {
	err, _ := validateFindingFormat(findingFormatInput{
		Severity: "High",
		Detail:   "IDOR on /api/users/{id} — attaching PoC next.",
	})
	if err != nil {
		t.Fatalf("short opening must not be rejected: %v", err)
	}
}

func TestValidateFindingFormatWarnsCredentialsNotHighlighted(t *testing.T) {
	body := `[{"type":"text","md":"The config contains password=s3cretValue in plaintext."},{"type":"flow","flowId":1,"note":"After: dump"}]`
	err, warns := validateFindingFormat(findingFormatInput{
		Severity: "High",
		Impact:   "DB access",
		Why:      "secrets in cleartext",
		Target:   "nacos",
		Body:     body,
	})
	if err != nil {
		t.Fatalf("should warn not reject: %v", err)
	}
	joined := strings.Join(warns, "\n")
	if !strings.Contains(strings.ToLower(joined), "credential") && !strings.Contains(strings.ToLower(joined), "bold") {
		t.Fatalf("expected credentials-highlight warning, got %v", warns)
	}
}

func TestMCPInstructionsRequireFindingFormat(t *testing.T) {
	instr := mcpInstructions()
	for _, want := range []string{"REQUIRED FORMAT", "impact", "why", "target", "PoC", "NOT confirmed", "Before"} {
		if !strings.Contains(instr, want) {
			t.Fatalf("mcpInstructions missing %q:\n%s", want, instr)
		}
	}
}

func TestCreateFindingForwardsWhyAndFormat(t *testing.T) {
	var gotBody map[string]any
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/findings" {
			json.NewDecoder(r.Body).Decode(&gotBody)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":42,"title":"t","ready":false}`))
			return
		}
		w.WriteHeader(404)
	}))
	defer mock.Close()
	s := New(mock.URL)
	s.report = func(Activity) {}
	script := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_finding","arguments":{"title":"IDOR","severity":"High","impact":"PII leak","why":"broken authz","target":"api.example.com","cwe":"CWE-639","environment":"staging"}}}` + "\n"
	var out strings.Builder
	if err := s.Serve(strings.NewReader(script), &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if gotBody["why"] != "broken authz" || gotBody["impact"] != "PII leak" || gotBody["cwe"] != "CWE-639" {
		t.Fatalf("body = %+v", gotBody)
	}
}
