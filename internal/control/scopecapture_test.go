package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// PUT /api/settings {captureScopeOnly:true} persists the choice, calls the wired
// proxy hook, and GET /api/settings reflects it.
func TestCaptureScopeOnlySetting(t *testing.T) {
	h, _, _ := newHub(t)
	var got, called bool
	h.SetCaptureScopeOnly = func(v bool) { got, called = v, true }

	ts := httptest.NewServer(h.Handler())
	defer ts.Close()

	body, _ := json.Marshal(map[string]any{"captureScopeOnly": true})
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/settings", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT settings: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT settings status %d", resp.StatusCode)
	}
	if !called || !got {
		t.Fatalf("SetCaptureScopeOnly called=%v got=%v, want true/true", called, got)
	}

	gresp, err := http.Get(ts.URL + "/api/settings")
	if err != nil {
		t.Fatal(err)
	}
	defer gresp.Body.Close()
	var s map[string]any
	json.NewDecoder(gresp.Body).Decode(&s)
	if s["captureScopeOnly"] != true {
		t.Fatalf("getSettings captureScopeOnly = %v, want true", s["captureScopeOnly"])
	}
}

// PUT /api/settings {invisibleProxy:true} persists the choice, calls the wired
// proxy hook, and GET /api/settings reflects it.
func TestInvisibleProxySetting(t *testing.T) {
	h, _, _ := newHub(t)
	var got, called bool
	h.SetInvisibleProxy = func(v bool) { got, called = v, true }

	ts := httptest.NewServer(h.Handler())
	defer ts.Close()

	body, _ := json.Marshal(map[string]any{"invisibleProxy": true})
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/settings", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT settings: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT settings status %d", resp.StatusCode)
	}
	if !called || !got {
		t.Fatalf("SetInvisibleProxy called=%v got=%v, want true/true", called, got)
	}

	gresp, err := http.Get(ts.URL + "/api/settings")
	if err != nil {
		t.Fatal(err)
	}
	defer gresp.Body.Close()
	var s map[string]any
	json.NewDecoder(gresp.Body).Decode(&s)
	if s["invisibleProxy"] != true {
		t.Fatalf("getSettings invisibleProxy = %v, want true", s["invisibleProxy"])
	}
}

// PUT /api/settings {tlsBypassHosts, autoBypassOnPinFailure} normalizes + persists
// the list, calls the wired proxy hooks, and GET reflects the choices.
func TestTLSBypassSettings(t *testing.T) {
	h, _, _ := newHub(t)
	var gotHosts []string
	var gotAuto, autoCalled bool
	h.SetTLSBypassHosts = func(v []string) { gotHosts = v }
	h.SetAutoBypassOnPinFailure = func(v bool) { gotAuto, autoCalled = v, true }

	ts := httptest.NewServer(h.Handler())
	defer ts.Close()

	// Duplicates / blanks / mixed case must be normalized on the way in.
	body, _ := json.Marshal(map[string]any{
		"tlsBypassHosts":         []string{" *.Pinned.com ", "pinned.com", "*.pinned.com", ""},
		"autoBypassOnPinFailure": true,
	})
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/settings", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT settings: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT settings status %d", resp.StatusCode)
	}
	if len(gotHosts) != 2 { // "*.pinned.com" + "pinned.com", deduped/lowercased
		t.Fatalf("SetTLSBypassHosts got %v, want 2 normalized entries", gotHosts)
	}
	if !autoCalled || !gotAuto {
		t.Fatalf("SetAutoBypassOnPinFailure called=%v got=%v, want true/true", autoCalled, gotAuto)
	}

	gresp, err := http.Get(ts.URL + "/api/settings")
	if err != nil {
		t.Fatal(err)
	}
	defer gresp.Body.Close()
	var s map[string]any
	json.NewDecoder(gresp.Body).Decode(&s)
	if s["autoBypassOnPinFailure"] != true {
		t.Fatalf("getSettings autoBypassOnPinFailure = %v, want true", s["autoBypassOnPinFailure"])
	}
	if hosts, _ := s["tlsBypassHosts"].([]any); len(hosts) != 2 {
		t.Fatalf("getSettings tlsBypassHosts = %v, want 2 entries", s["tlsBypassHosts"])
	}
}
