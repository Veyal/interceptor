package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// The project notebook round-trips through PUT/GET /api/notes (per-project markdown
// for creds, findings, scratch). Inline data-URL images migrate to SQLite refs.
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

func TestProjectNotesImageUploadAndServe(t *testing.T) {
	h, _, _ := newHub(t)
	ts := httptest.NewServer(h.Handler())
	defer ts.Close()

	up, _ := json.Marshal(map[string]string{
		"mime": "image/png",
		"data": "aGVsbG8=", // "hello"
	})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/notes/images", strings.NewReader(string(up)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST image status %d", resp.StatusCode)
	}
	var created struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil || created.ID <= 0 {
		t.Fatalf("create image: id=%d err=%v", created.ID, err)
	}

	imgResp, err := http.Get(ts.URL + "/api/notes/images/" + strconv.FormatInt(created.ID, 10))
	if err != nil {
		t.Fatal(err)
	}
	defer imgResp.Body.Close()
	if imgResp.StatusCode != http.StatusOK {
		t.Fatalf("GET image status %d", imgResp.StatusCode)
	}
	if ct := imgResp.Header.Get("Content-Type"); ct != "image/png" {
		t.Fatalf("content-type = %q", ct)
	}
}

func TestProjectNotesMigratesInlineDataURL(t *testing.T) {
	h, _, _ := newHub(t)
	ts := httptest.NewServer(h.Handler())
	defer ts.Close()

	inline := "![shot](data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7)"
	body, _ := json.Marshal(map[string]string{"notes": inline})
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

	resp, err := http.Get(ts.URL + "/api/notes")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Notes string `json:"notes"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if strings.Contains(out.Notes, "data:image/") {
		t.Fatalf("expected migrated notes, got %q", out.Notes)
	}
	if !strings.Contains(out.Notes, "/api/notes/images/") {
		t.Fatalf("expected image ref, got %q", out.Notes)
	}
}
