package control

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Veyal/interseptor/internal/store"
)

func TestCollectProjectAssistFlowsUsesBoundedSafeActiveProjectContext(t *testing.T) {
	// Given
	h, s, _ := newHub(t)
	h.ProjectName = "acme"
	_, err := s.PersistNotes("engagement notes " + strings.Repeat("n", 12000))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.CreateScopeRule(&store.ScopeRule{Enabled: true, Action: "include", Scheme: "https", Host: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	h.refreshScope()
	_, err = s.CreateFinding(&store.Finding{
		Title: "IDOR", Severity: "High", Status: "verified", Target: "example.com/users",
		Detail: "user records exposed", Evidence: "Authorization: Bearer finding-secret", Impact: "account takeover",
	})
	if err != nil {
		t.Fatal(err)
	}
	insertProjectFlow(t, s, store.Flow{TS: time.UnixMilli(1), Method: "GET", Scheme: "https", Host: "example.com", Path: "/older", Status: 200, Note: "ordinary note", ReqHeaders: map[string][]string{"Cookie": {"flow-secret"}}, ReqBodyHash: "raw-secret"})
	insertProjectFlow(t, s, store.Flow{TS: time.UnixMilli(2), Method: "POST", Scheme: "https", Host: "example.com", Path: "/newest", Status: 201})
	outOfScope := store.Flow{TS: time.UnixMilli(3), Method: "GET", Scheme: "https", Host: "outside.test", Path: "/excluded", Status: 200}
	if h.sc.InScope(&outOfScope) {
		t.Fatal("test precondition failed: outside.test is in scope")
	}
	insertProjectFlow(t, s, outOfScope)
	insertProjectFlow(t, s, store.Flow{TS: time.UnixMilli(4), Method: "GET", Scheme: "https", Host: "example.com", Path: "/repeater", Status: 200, Flags: store.FlagRepeater})

	// When
	flows, err := (&aiAPI{Hub: h}).collectProjectAssistFlows()

	// Then
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 1 {
		t.Fatalf("project context entries = %d, want 1", len(flows))
	}
	context := flows[0].Req
	for _, want := range []string{"Project: acme", "engagement notes", "include https://example.com", "High verified: IDOR", "Impact: account takeover", "#2 POST https://example.com/newest", "#1 GET https://example.com/older", "ordinary note"} {
		if !strings.Contains(context, want) {
			t.Fatalf("project context missing %q:\n%s", want, context)
		}
	}
	for _, forbidden := range []string{"user records exposed", "finding-secret", "flow-secret", "raw-secret", "outside.test", "/repeater", "Evidence:"} {
		if strings.Contains(context, forbidden) {
			t.Fatalf("project context leaked %q:\n%s", forbidden, context)
		}
	}
	if len(context) > maxProjectContextBytes {
		t.Fatalf("project context length = %d, max %d", len(context), maxProjectContextBytes)
	}
	if !strings.Contains(context, projectTruncationMarker) {
		t.Fatalf("clipped project context missing truncation marker:\n%s", context)
	}
	if strings.Index(context, "/newest") > strings.Index(context, "/older") {
		t.Fatalf("flows are not newest-first:\n%s", context)
	}
}

func TestClipProjectTextMarksTruncationWithinLimit(t *testing.T) {
	// Given
	text := strings.Repeat("x", maxProjectContextBytes+100)

	// When
	clipped := clipProjectText(text, maxProjectContextBytes)

	// Then
	if len(clipped) > maxProjectContextBytes {
		t.Fatalf("clipped length = %d, max %d", len(clipped), maxProjectContextBytes)
	}
	if !strings.HasSuffix(clipped, projectTruncationMarker) {
		t.Fatalf("clipped text missing suffix marker: %q", clipped[len(clipped)-40:])
	}
}

func TestAIAssistProjectContextWorksWithoutSelectedID(t *testing.T) {
	// Given
	h, s, _ := newHub(t)
	h.ProjectName = "active-project"
	_, _ = s.PersistNotes("only active project notes")
	requests := make(chan map[string]json.RawMessage, 1)
	provider := newAIProvider(t, requests, false)
	configureAIProvider(t, s, provider.URL)
	server := httptest.NewServer(h.Handler())
	defer server.Close()

	// When
	resp, err := http.Post(server.URL+"/api/ai/assist", "application/json", strings.NewReader(`{"context":"project","kind":"ask","question":"What should I test?"}`))

	// Then
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, readAll(resp.Body))
	}
	request := <-requests
	if !strings.Contains(string(request["messages"]), "Project: active-project") || !strings.Contains(string(request["messages"]), "only active project notes") {
		t.Fatalf("provider request missing project context: %s", request["messages"])
	}
}

func TestAIAssistRejectsUnknownContext(t *testing.T) {
	// Given
	h, s, _ := newHub(t)
	provider := newAIProvider(t, make(chan map[string]json.RawMessage, 1), false)
	configureAIProvider(t, s, provider.URL)
	server := httptest.NewServer(h.Handler())
	defer server.Close()

	for _, path := range []string{"/api/ai/assist", "/api/ai/assist/stream"} {
		// When
		resp, err := http.Post(server.URL+path, "application/json", strings.NewReader(`{"context":"workspace","kind":"ask","question":"test"}`))

		// Then
		if err != nil {
			t.Fatal(err)
		}
		body := readAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "unknown context") {
			t.Fatalf("%s status = %d body = %q, want 400 unknown context", path, resp.StatusCode, body)
		}
	}
}

func TestAIAssistProjectStreamIgnoresCraftedAgentMode(t *testing.T) {
	// Given
	h, s, _ := newHub(t)
	requests := make(chan map[string]json.RawMessage, 1)
	provider := newAIProvider(t, requests, true)
	configureAIProvider(t, s, provider.URL)
	server := httptest.NewServer(h.Handler())
	defer server.Close()

	// When
	resp, err := http.Post(server.URL+"/api/ai/assist/stream", "application/json", strings.NewReader(`{"context":"project","kind":"ask","question":"summarize","agent":true}`))

	// Then
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body := readAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "read-only answer") || !strings.Contains(body, "event: done") {
		t.Fatalf("status = %d body = %q", resp.StatusCode, body)
	}
	request := <-requests
	if _, ok := request["tools"]; ok {
		t.Fatalf("project mode invoked agent tools: %+v", request)
	}
	if string(request["stream"]) != "true" {
		t.Fatalf("project mode did not use ordinary stream completion: %+v", request)
	}
}

func insertProjectFlow(t *testing.T, s *store.Store, flow store.Flow) {
	t.Helper()
	note := flow.Note
	id, err := s.InsertFlow(&flow)
	if err != nil {
		t.Fatal(err)
	}
	if note != "" {
		if err := s.SetFlowNote(id, note); err != nil {
			t.Fatal(err)
		}
	}
}

func configureAIProvider(t *testing.T, s *store.Store, endpoint string) {
	t.Helper()
	for key, value := range map[string]string{"ai.provider": "openai", "ai.apiKey": "test-key", "ai.endpoint": endpoint} {
		if err := s.SetSetting(key, value); err != nil {
			t.Fatal(err)
		}
	}
}

func newAIProvider(t *testing.T, requests chan<- map[string]json.RawMessage, stream bool) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		var request map[string]json.RawMessage
		if err := json.Unmarshal(body, &request); err != nil {
			t.Error(err)
			return
		}
		requests <- request
		if stream {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"read-only answer\"}}]}\n\ndata: [DONE]\n\n")
			return
		}
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"ok"}}]}`)
	}))
	t.Cleanup(server.Close)
	return server
}
