package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// POST /api/intruder/start must reject a non-positive Threads value with a
// clear 400 instead of silently letting the engine clamp it to 1 — the
// caller should know their input was ignored, not guess from the result.
func TestIntruderStartRejectsInvalidThreads(t *testing.T) {
	h, _, _ := newHub(t)
	ts := httptest.NewServer(h.Handler())
	defer ts.Close()

	post := func(threads int) (int, string) {
		body, _ := json.Marshal(map[string]any{
			"target":     "http://example.com",
			"template":   "GET /?id=§1§ HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"attackType": "sniper",
			"payloads":   [][]string{{"a", "b"}},
			"threads":    threads,
		})
		resp, err := http.Post(ts.URL+"/api/intruder/start", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer resp.Body.Close()
		var out struct {
			Error string `json:"error"`
		}
		json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out.Error
	}

	for _, threads := range []int{0, -5} {
		code, errMsg := post(threads)
		if code != http.StatusBadRequest {
			t.Fatalf("threads=%d: expected 400, got %d (err=%q)", threads, code, errMsg)
		}
		if errMsg == "" {
			t.Fatalf("threads=%d: expected a clear error message, got empty", threads)
		}
	}
}

// A valid thread count starts the attack normally.
func TestIntruderStartAcceptsValidThreads(t *testing.T) {
	h, _, _ := newHub(t)
	ts := httptest.NewServer(h.Handler())
	defer ts.Close()

	body, _ := json.Marshal(map[string]any{
		"target":     "http://example.com",
		"template":   "GET /?id=§1§ HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"attackType": "sniper",
		"payloads":   [][]string{{"a", "b"}},
		"threads":    4,
	})
	resp, err := http.Post(ts.URL+"/api/intruder/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}
