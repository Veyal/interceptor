package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAIAssistRejectedWhenDisabled(t *testing.T) {
	h, s, _ := newHub(t)
	if err := s.SetSetting("ai.disabled", "1"); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(h.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/ai/assist", "application/json",
		strings.NewReader(`{"flowId":1,"kind":"explain"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("assist status %d, want 403", resp.StatusCode)
	}
}

func TestMCPWorksWhenAIDisabled(t *testing.T) {
	h, s, _ := newHub(t)
	if err := s.SetSetting("ai.disabled", "1"); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(h.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		t.Fatalf("mcp should stay available when AI is disabled (non-AI tools), got 403")
	}
}

func TestSettingsAiDisabledRoundTrip(t *testing.T) {
	h, s, _ := newHub(t)
	ts := httptest.NewServer(h.Handler())
	defer ts.Close()

	put, err := http.NewRequest(http.MethodPut, ts.URL+"/api/settings",
		strings.NewReader(`{"aiDisabled":true}`))
	if err != nil {
		t.Fatal(err)
	}
	put.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(put)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("put settings %d, want 200", resp.StatusCode)
	}
	v, ok, _ := s.GetSetting("ai.disabled")
	if !ok || v != "1" {
		t.Fatalf("ai.disabled = %q ok=%v, want 1", v, ok)
	}
	get, err := http.Get(ts.URL + "/api/settings")
	if err != nil {
		t.Fatal(err)
	}
	defer get.Body.Close()
	var out settingsJSON
	if err := json.NewDecoder(get.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !out.AiDisabled {
		t.Fatal("getSettings aiDisabled=false, want true")
	}
}
