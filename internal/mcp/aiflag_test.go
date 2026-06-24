package mcp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Every control-plane call the MCP server makes must be stamped
// X-Interceptor-Source: ai, so the control plane can tag AI-originated
// Repeater/Intruder/scan sends and surface them in Proxy/History.
func TestAPIStampsAISourceHeader(t *testing.T) {
	var got string
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Interceptor-Source")
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"flows":[]}`)
	}))
	defer mock.Close()

	s := New(mock.URL)
	if _, err := s.api(http.MethodGet, "/api/flows", nil); err != nil {
		t.Fatalf("api: %v", err)
	}
	if got != "ai" {
		t.Fatalf("X-Interceptor-Source = %q, want \"ai\"", got)
	}
}
