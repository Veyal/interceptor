package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// The project-notebook tools let the AI read, replace, and append to the project's
// markdown notes via /api/notes.
func TestProjectNotesTools(t *testing.T) {
	var mu sync.Mutex
	notes := ""
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/notes":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"notes":%q}`, notes)
		case r.Method == http.MethodPut && r.URL.Path == "/api/notes":
			var b struct {
				Notes string `json:"notes"`
			}
			json.NewDecoder(r.Body).Decode(&b)
			notes = b.Notes
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mock.Close()

	s := New(mock.URL)
	drive := func(call string) string {
		var out bytes.Buffer
		s.Serve(strings.NewReader(call+"\n"), &out)
		return out.String()
	}

	drive(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"set_notes","arguments":{"notes":"# Findings"}}}`)
	if notes != "# Findings" {
		t.Fatalf("set_notes → %q", notes)
	}

	drive(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"append_notes","arguments":{"text":"- IDOR on /users"}}}`)
	if !strings.Contains(notes, "# Findings") || !strings.Contains(notes, "- IDOR on /users") {
		t.Fatalf("append_notes should keep prior content and add the new line, got %q", notes)
	}

	out := drive(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_notes","arguments":{}}}`)
	if !strings.Contains(out, "IDOR") {
		t.Fatalf("get_notes output missing content: %s", out)
	}
}
