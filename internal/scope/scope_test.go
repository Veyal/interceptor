package scope

import (
	"testing"

	"github.com/Veyal/interceptor/internal/store"
)

func flow(host, path, scheme string, port int) *store.Flow {
	return &store.Flow{Host: host, Path: path, Scheme: scheme, Port: port}
}

func TestIncludeExcludeWildcard(t *testing.T) {
	e := New()
	e.SetRules([]store.ScopeRule{
		{Enabled: true, Action: "include", Host: "*.acme.com"},
		{Enabled: true, Action: "exclude", Host: "analytics.acme.com"},
	})
	cases := map[string]bool{
		"app.acme.com":       true,  // subdomain included
		"acme.com":           true,  // base matched by *.acme.com
		"analytics.acme.com": false, // excluded wins
		"cdn.other.com":      false, // not included
	}
	for host, want := range cases {
		if got := e.InScope(flow(host, "/", "https", 443)); got != want {
			t.Fatalf("InScope(%s) = %v, want %v", host, got, want)
		}
	}
}

func TestExcludeOnlyMeansEverythingElseInScope(t *testing.T) {
	e := New()
	e.SetRules([]store.ScopeRule{{Enabled: true, Action: "exclude", Host: "*.doubleclick.net"}})
	if !e.InScope(flow("victim.test", "/", "https", 443)) {
		t.Fatal("with exclude-only, an unrelated host should be in scope")
	}
	if e.InScope(flow("ad.doubleclick.net", "/", "https", 443)) {
		t.Fatal("excluded host should be out of scope")
	}
}

func TestNoRulesEverythingInScope(t *testing.T) {
	if !New().InScope(flow("anything.test", "/x", "http", 80)) {
		t.Fatal("with no rules, everything is in scope")
	}
}

func TestPathSchemePort(t *testing.T) {
	e := New()
	e.SetRules([]store.ScopeRule{{Enabled: true, Action: "include", Host: "api.x", Path: "/v1", Scheme: "https"}})
	if !e.InScope(flow("api.x", "/v1/users", "https", 443)) {
		t.Fatal("path prefix should match")
	}
	if e.InScope(flow("api.x", "/v2", "https", 443)) {
		t.Fatal("different path should be out")
	}
	if e.InScope(flow("api.x", "/v1", "http", 443)) {
		t.Fatal("scheme mismatch should be out")
	}
}

func TestDisabledRulesIgnored(t *testing.T) {
	e := New()
	e.SetRules([]store.ScopeRule{{Enabled: false, Action: "include", Host: "only.this"}})
	// The only rule is disabled → no active includes → everything in scope.
	if !e.InScope(flow("other.host", "/", "https", 443)) {
		t.Fatal("disabled rules must be ignored")
	}
}
