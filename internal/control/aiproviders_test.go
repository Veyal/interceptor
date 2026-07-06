package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Saving profiles, activating one mirrors its fields into the canonical ai.*
// settings (the single source aiCreds/autopwn/etc read), keys are redacted on
// list, and deleting the active profile clears the active pointer.
func TestAiProviderProfilesLifecycle(t *testing.T) {
	h, st, _ := newHub(t)
	ts := httptest.NewServer(h.Handler())
	defer ts.Close()

	post := func(path, body string) (int, string) {
		resp, err := http.Post(ts.URL+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		defer resp.Body.Close()
		return resp.StatusCode, readAll(resp.Body)
	}

	// Create two profiles.
	code, out := post("/api/ai/providers", `{"name":"Claude","provider":"anthropic","apiKey":"sk-ant-1","model":"claude-haiku-4-5-20251001"}`)
	if code != http.StatusOK {
		t.Fatalf("create p1: %d %s", code, out)
	}
	var created struct{ ID string }
	_ = json.Unmarshal([]byte(out), &created)
	if created.ID == "" {
		t.Fatal("expected a profile id")
	}
	if code, _ := post("/api/ai/providers", `{"name":"Grok","provider":"openai","apiKey":"sk-2","model":"grok-4.3","endpoint":"https://yunwu.ai/v1/chat/completions"}`); code != http.StatusOK {
		t.Fatalf("create p2: %d", code)
	}

	// List: two profiles, keys redacted (hasKey true, no apiKey field).
	resp, _ := http.Get(ts.URL + "/api/ai/providers")
	body := readAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(body, "sk-ant-1") || strings.Contains(body, "sk-2") {
		t.Fatalf("API keys must never be returned to the client: %s", body)
	}
	var list struct {
		Providers []struct {
			ID     string `json:"id"`
			HasKey bool   `json:"hasKey"`
		} `json:"providers"`
		ActiveID string `json:"activeId"`
	}
	_ = json.Unmarshal([]byte(body), &list)
	if len(list.Providers) != 2 {
		t.Fatalf("expected 2 profiles, got %d", len(list.Providers))
	}
	if !list.Providers[0].HasKey {
		t.Fatal("expected hasKey=true")
	}

	// Activate the first: canonical ai.* settings must now reflect it.
	if code, out := post("/api/ai/providers/"+created.ID+"/activate", ``); code != http.StatusOK {
		t.Fatalf("activate: %d %s", code, out)
	}
	if v, _, _ := st.GetSetting("ai.provider"); v != "anthropic" {
		t.Fatalf("ai.provider = %q, want anthropic", v)
	}
	if v, _, _ := st.GetSetting("ai.apiKey"); v != "sk-ant-1" {
		t.Fatalf("ai.apiKey not mirrored from profile: %q", v)
	}
	if v, _, _ := st.GetSetting("ai.model"); v != "claude-haiku-4-5-20251001" {
		t.Fatalf("ai.model = %q", v)
	}
	if v, _, _ := st.GetSetting("ai.activeProfile"); v != created.ID {
		t.Fatalf("ai.activeProfile = %q, want %q", v, created.ID)
	}

	// Delete the active profile → active pointer cleared.
	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/ai/providers/"+created.ID, nil)
	dr, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	dr.Body.Close()
	if dr.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status %d", dr.StatusCode)
	}
	if v, _, _ := st.GetSetting("ai.activeProfile"); v != "" {
		t.Fatalf("active profile should be cleared after deleting it, got %q", v)
	}
}
