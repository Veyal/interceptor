package scanner

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Veyal/interceptor/internal/store"
)

func titles(issues []store.Issue) string {
	var b []string
	for _, i := range issues {
		b = append(b, i.Severity+":"+i.Title)
	}
	return strings.Join(b, " | ")
}

func has(issues []store.Issue, title string) bool {
	for _, i := range issues {
		if i.Title == title {
			return true
		}
	}
	return false
}

func TestAnalyzeHeaderHygiene(t *testing.T) {
	flow := &store.Flow{
		Scheme: "https", Method: "GET", Host: "app.example.com", Path: "/", Status: 200, Mime: "text/html",
		ResHeaders: map[string][]string(http.Header{
			"Content-Type":                {"text/html; charset=utf-8"},
			"Access-Control-Allow-Origin": {"*"},
			"Server":                      {"nginx/1.21.0"},
		}),
	}
	got := Analyze(flow, nil, []byte("<html></html>"))
	for _, want := range []string{
		"Missing Content-Security-Policy header",
		"Missing Strict-Transport-Security (HSTS)",
		"Overly permissive CORS policy",
		"Server software version disclosed",
	} {
		if !has(got, want) {
			t.Fatalf("expected %q; got: %s", want, titles(got))
		}
	}
}

func TestAnalyzeSecretsInBodies(t *testing.T) {
	flow := &store.Flow{
		Scheme: "https", Method: "POST", Host: "api.example.com", Path: "/login", Status: 200,
		ResHeaders: map[string][]string(http.Header{"Content-Type": {"application/json"}, "Strict-Transport-Security": {"max-age=1"}}),
	}
	got := Analyze(flow,
		[]byte(`{"email":"a@b.com","password":"hunter2-correct-horse"}`),
		[]byte(`{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.abc123"}`))
	if !has(got, "Password transmitted in request body") {
		t.Fatalf("expected password finding; got: %s", titles(got))
	}
	if !has(got, "Session token leaked in response body") {
		t.Fatalf("expected token finding; got: %s", titles(got))
	}
}

func TestAnalyzeInsecureCookieAndVerboseError(t *testing.T) {
	flow := &store.Flow{
		Scheme: "https", Method: "GET", Host: "api.example.com", Path: "/reports", Status: 500,
		ResHeaders: map[string][]string(http.Header{
			"Set-Cookie":                {"session=abc; Path=/"},
			"Strict-Transport-Security": {"max-age=1"},
			"Content-Type":              {"application/json"},
		}),
	}
	got := Analyze(flow, nil, []byte(`{"error":"boom","traceId":"3f9a-22b1","stack":"..."}`))
	if !has(got, "Cookie set without Secure and HttpOnly") {
		t.Fatalf("expected cookie finding; got: %s", titles(got))
	}
	if !has(got, "Verbose error discloses internal details") {
		t.Fatalf("expected verbose-error finding; got: %s", titles(got))
	}
}

func TestAnalyzeReflectionAuthAndFraming(t *testing.T) {
	flow := &store.Flow{
		Scheme: "https", Method: "GET", Host: "app.test", Path: "/search?q=hello<scriptmark>",
		Status: 200, Mime: "text/html",
		ReqHeaders: map[string][]string(http.Header{"Authorization": {"Basic dXNlcjpwYXNz"}}),
		ResHeaders: map[string][]string(http.Header{
			"Content-Type":              {"text/html; charset=utf-8"},
			"Content-Security-Policy":   {"default-src 'self'"}, // present, but no frame-ancestors
			"Strict-Transport-Security": {"max-age=63072000"},
		}),
	}
	got := Analyze(flow, nil, []byte("<html>results for hello<scriptmark> ...</html>"))
	for _, want := range []string{
		"Request parameter reflected in HTML response",
		"HTTP Basic authentication in use",
		"Missing X-Content-Type-Options: nosniff",
		"Missing clickjacking protection",
	} {
		if !has(got, want) {
			t.Fatalf("expected %q; got: %s", want, titles(got))
		}
	}
}

func TestAnalyzeReflectionAvoidsTrivialValues(t *testing.T) {
	// Short / non-alpha values should not be flagged as reflections (noise control).
	flow := &store.Flow{
		Scheme: "https", Method: "GET", Host: "app.test", Path: "/p?id=12345&ok=1", Status: 200, Mime: "text/html",
		ResHeaders: map[string][]string(http.Header{
			"Content-Type": {"text/html"}, "X-Frame-Options": {"DENY"},
			"X-Content-Type-Options": {"nosniff"}, "Strict-Transport-Security": {"max-age=1"},
		}),
	}
	got := Analyze(flow, nil, []byte("<html>id 12345 ok 1</html>"))
	if has(got, "Request parameter reflected in HTML response") {
		t.Fatalf("trivial values should not flag reflection; got: %s", titles(got))
	}
}

func TestAnalyzeCleanFlowHasNoIssues(t *testing.T) {
	flow := &store.Flow{
		Scheme: "https", Method: "GET", Host: "api.example.com", Path: "/health", Status: 200,
		ResHeaders: map[string][]string(http.Header{
			"Content-Type":              {"application/json"},
			"Strict-Transport-Security": {"max-age=63072000"},
		}),
	}
	if got := Analyze(flow, nil, []byte(`{"ok":true}`)); len(got) != 0 {
		t.Fatalf("expected no issues, got: %s", titles(got))
	}
}

// --- Check 13: CORS with credentials ---

func TestCORSCredentialsWildcard(t *testing.T) {
	// Positive: ACAO=* + Allow-Credentials: true → High severity
	flow := &store.Flow{
		Scheme: "https", Method: "GET", Host: "api.example.com", Path: "/data", Status: 200,
		ReqHeaders: map[string][]string(http.Header{"Origin": {"https://attacker.example"}}),
		ResHeaders: map[string][]string(http.Header{
			"Content-Type":                       {"application/json"},
			"Strict-Transport-Security":          {"max-age=1"},
			"Access-Control-Allow-Origin":        {"*"},
			"Access-Control-Allow-Credentials":   {"true"},
		}),
	}
	got := Analyze(flow, nil, []byte(`{"data":"secret"}`))
	if !has(got, "CORS wildcard with credentials enabled") {
		t.Fatalf("expected CORS wildcard+credentials finding; got: %s", titles(got))
	}
	// verify severity is High
	for _, i := range got {
		if i.Title == "CORS wildcard with credentials enabled" && i.Severity != "High" {
			t.Fatalf("expected High severity, got %s", i.Severity)
		}
	}
}

func TestCORSCredentialsReflectedOrigin(t *testing.T) {
	// Positive: ACAO reflects request Origin + Allow-Credentials: true → High severity
	flow := &store.Flow{
		Scheme: "https", Method: "GET", Host: "api.example.com", Path: "/data", Status: 200,
		ReqHeaders: map[string][]string(http.Header{"Origin": {"https://attacker.example"}}),
		ResHeaders: map[string][]string(http.Header{
			"Content-Type":                     {"application/json"},
			"Strict-Transport-Security":        {"max-age=1"},
			"Access-Control-Allow-Origin":      {"https://attacker.example"},
			"Access-Control-Allow-Credentials": {"true"},
		}),
	}
	got := Analyze(flow, nil, []byte(`{"data":"secret"}`))
	if !has(got, "CORS reflects request Origin with credentials enabled") {
		t.Fatalf("expected CORS reflected-origin+credentials finding; got: %s", titles(got))
	}
}

func TestCORSCredentialsNegative(t *testing.T) {
	// Negative: Allow-Credentials present but ACAO is an explicit non-reflected trusted origin → no issue.
	flow := &store.Flow{
		Scheme: "https", Method: "GET", Host: "api.example.com", Path: "/data", Status: 200,
		ReqHeaders: map[string][]string(http.Header{"Origin": {"https://app.example.com"}}),
		ResHeaders: map[string][]string(http.Header{
			"Content-Type":                     {"application/json"},
			"Strict-Transport-Security":        {"max-age=1"},
			"Access-Control-Allow-Origin":      {"https://trusted.example.com"},
			"Access-Control-Allow-Credentials": {"true"},
		}),
	}
	got := Analyze(flow, nil, []byte(`{"ok":true}`))
	if has(got, "CORS wildcard with credentials enabled") || has(got, "CORS reflects request Origin with credentials enabled") {
		t.Fatalf("should not flag CORS when ACAO is a fixed trusted origin; got: %s", titles(got))
	}
}

// --- Check 14: Sensitive token in URL ---

func TestSensitiveTokenInURL(t *testing.T) {
	cases := []struct {
		name string
		path string
	}{
		{"access_token", "/api/resource?access_token=eyJhbGciOiJIUzI1NiJ9.payload.sig"},
		{"api_key", "/v1/data?api_key=supersecretkey123"},
		{"token", "/callback?token=verylongtoken12345"},
		{"session", "/profile?session=sess_abc123xyz"},
		{"password", "/reset?password=newPass123!"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flow := &store.Flow{
				Scheme: "https", Method: "GET", Host: "api.example.com", Path: tc.path, Status: 200,
				ResHeaders: map[string][]string(http.Header{
					"Content-Type":              {"application/json"},
					"Strict-Transport-Security": {"max-age=1"},
				}),
			}
			got := Analyze(flow, nil, []byte(`{"ok":true}`))
			if !has(got, "Sensitive token or credential in URL") {
				t.Fatalf("path %q: expected token-in-URL finding; got: %s", tc.path, titles(got))
			}
		})
	}
}

func TestSensitiveTokenInURLNegative(t *testing.T) {
	// Negative: normal query parameters should not fire.
	flow := &store.Flow{
		Scheme: "https", Method: "GET", Host: "api.example.com", Path: "/search?q=hello&page=2", Status: 200,
		ResHeaders: map[string][]string(http.Header{
			"Content-Type":              {"application/json"},
			"Strict-Transport-Security": {"max-age=1"},
		}),
	}
	got := Analyze(flow, nil, []byte(`{"results":[]}`))
	if has(got, "Sensitive token or credential in URL") {
		t.Fatalf("should not flag benign query params; got: %s", titles(got))
	}
}

// --- Check 15: Cookie missing SameSite ---

func TestCookieMissingSameSite(t *testing.T) {
	// Positive: cookie has Secure and HttpOnly but no SameSite → Low finding.
	flow := &store.Flow{
		Scheme: "https", Method: "POST", Host: "app.example.com", Path: "/login", Status: 200,
		ResHeaders: map[string][]string(http.Header{
			"Content-Type":              {"application/json"},
			"Strict-Transport-Security": {"max-age=1"},
			// Secure + HttpOnly present, SameSite absent.
			"Set-Cookie": {"session=abc123; Secure; HttpOnly; Path=/"},
		}),
	}
	got := Analyze(flow, nil, []byte(`{"ok":true}`))
	if !has(got, "Cookie missing SameSite attribute") {
		t.Fatalf("expected SameSite finding; got: %s", titles(got))
	}
}

func TestCookieMissingSameSiteNegative(t *testing.T) {
	// Negative: cookie has SameSite=Strict → no SameSite finding.
	flow := &store.Flow{
		Scheme: "https", Method: "POST", Host: "app.example.com", Path: "/login", Status: 200,
		ResHeaders: map[string][]string(http.Header{
			"Content-Type":              {"application/json"},
			"Strict-Transport-Security": {"max-age=1"},
			"Set-Cookie":                {"session=abc123; Secure; HttpOnly; SameSite=Strict; Path=/"},
		}),
	}
	got := Analyze(flow, nil, []byte(`{"ok":true}`))
	if has(got, "Cookie missing SameSite attribute") {
		t.Fatalf("should not flag cookie that has SameSite; got: %s", titles(got))
	}
}

// --- Check 16: Authenticated response not marked no-store / private ---

func TestAuthenticatedResponseCacheable(t *testing.T) {
	// Positive: response sets cookie but Cache-Control is absent → Low finding.
	flow := &store.Flow{
		Scheme: "https", Method: "POST", Host: "app.example.com", Path: "/login", Status: 200,
		ResHeaders: map[string][]string(http.Header{
			"Content-Type":              {"application/json"},
			"Strict-Transport-Security": {"max-age=1"},
			"Set-Cookie":                {"session=abc123; Secure; HttpOnly; SameSite=Strict; Path=/"},
			// No Cache-Control header at all.
		}),
	}
	got := Analyze(flow, nil, []byte(`{"ok":true}`))
	if !has(got, "Authenticated response may be cached by shared proxies") {
		t.Fatalf("expected cache-control finding; got: %s", titles(got))
	}
}

func TestAuthenticatedResponseCacheableNoStore(t *testing.T) {
	// Negative: no-store present → no finding.
	flow := &store.Flow{
		Scheme: "https", Method: "POST", Host: "app.example.com", Path: "/login", Status: 200,
		ResHeaders: map[string][]string(http.Header{
			"Content-Type":              {"application/json"},
			"Strict-Transport-Security": {"max-age=1"},
			"Set-Cookie":                {"session=abc123; Secure; HttpOnly; SameSite=Strict; Path=/"},
			"Cache-Control":             {"no-store"},
		}),
	}
	got := Analyze(flow, nil, []byte(`{"ok":true}`))
	if has(got, "Authenticated response may be cached by shared proxies") {
		t.Fatalf("should not flag when Cache-Control: no-store is present; got: %s", titles(got))
	}
}

func TestAuthenticatedResponseCacheablePrivate(t *testing.T) {
	// Negative: Cache-Control: private is also acceptable.
	flow := &store.Flow{
		Scheme: "https", Method: "POST", Host: "app.example.com", Path: "/login", Status: 200,
		ResHeaders: map[string][]string(http.Header{
			"Content-Type":              {"application/json"},
			"Strict-Transport-Security": {"max-age=1"},
			"Set-Cookie":                {"session=abc123; Secure; HttpOnly; SameSite=Strict; Path=/"},
			"Cache-Control":             {"private, max-age=0"},
		}),
	}
	got := Analyze(flow, nil, []byte(`{"ok":true}`))
	if has(got, "Authenticated response may be cached by shared proxies") {
		t.Fatalf("should not flag when Cache-Control: private is present; got: %s", titles(got))
	}
}

func TestNoCookieNoCacheIssue(t *testing.T) {
	// Negative: response has no Set-Cookie → no cache-control finding regardless of Cache-Control value.
	flow := &store.Flow{
		Scheme: "https", Method: "GET", Host: "api.example.com", Path: "/public", Status: 200,
		ResHeaders: map[string][]string(http.Header{
			"Content-Type":              {"application/json"},
			"Strict-Transport-Security": {"max-age=1"},
			// No Set-Cookie, no Cache-Control — cache finding should not fire.
		}),
	}
	got := Analyze(flow, nil, []byte(`{"items":[]}`))
	if has(got, "Authenticated response may be cached by shared proxies") {
		t.Fatalf("should not flag when no cookie is set; got: %s", titles(got))
	}
}
