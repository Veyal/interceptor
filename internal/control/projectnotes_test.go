package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The project notebook round-trips through PUT/GET /api/notes (per-project markdown
// for creds, findings, scratch).
func TestProjectNotesEndpoint(t *testing.T) {
	h, _, _ := newHub(t)
	ts := httptest.NewServer(h.Handler())
	defer ts.Close()

	// Empty by default.
	resp, err := http.Get(ts.URL + "/api/notes")
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Notes string `json:"notes"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if out.Notes != "" {
		t.Fatalf("default notes = %q, want empty", out.Notes)
	}

	// Save.
	body, _ := json.Marshal(map[string]string{"notes": "# Creds\nadmin:hunter2\n\n## Findings\n- IDOR on /api/users"})
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/notes", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	wresp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	wresp.Body.Close()
	if wresp.StatusCode/100 != 2 {
		t.Fatalf("PUT notes status %d", wresp.StatusCode)
	}

	// Read back.
	resp2, err := http.Get(ts.URL + "/api/notes")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	json.NewDecoder(resp2.Body).Decode(&out)
	if !strings.Contains(out.Notes, "admin:hunter2") || !strings.Contains(out.Notes, "IDOR") {
		t.Fatalf("notes not persisted: %q", out.Notes)
	}
}
