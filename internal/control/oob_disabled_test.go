package control

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOOBDisabledByDefault(t *testing.T) {
	h, _, _ := newHub(t)
	if h.oobEnabled() {
		t.Fatal("OOB should be disabled by default")
	}
	ts := httptest.NewServer(h.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/oob/state")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("state status %d, want 403", resp.StatusCode)
	}
}

func TestOOBEnabledViaSettings(t *testing.T) {
	h, s, _ := newHub(t)
	if err := s.SetSetting("oob.enabled", "1"); err != nil {
		t.Fatal(err)
	}
	if !h.oobEnabled() {
		t.Fatal("OOB should be enabled after setting")
	}
	ts := httptest.NewServer(h.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/oob/state")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("state status %d, want 200", resp.StatusCode)
	}
}

func TestPutSettingsOobEnabled(t *testing.T) {
	h, s, _ := newHub(t)
	ts := httptest.NewServer(h.Handler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/settings",
		strings.NewReader(`{"oobEnabled":true}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("put settings status %d, want 200", resp.StatusCode)
	}
	v, ok, _ := s.GetSetting("oob.enabled")
	if !ok || v != "1" {
		t.Fatalf("oob.enabled = %q ok=%v, want 1", v, ok)
	}
}

func TestOOBCatch404WhenDisabled(t *testing.T) {
	h, _, _ := newHub(t)
	ts := httptest.NewServer(h.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/oob/deadbeeftest")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("catch status %d, want 404 when disabled", resp.StatusCode)
	}
}
