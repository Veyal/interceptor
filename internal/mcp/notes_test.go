package mcp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The set_note tool lets the AI annotate a flow; it PUTs the note to the control
// plane's /api/flows/{id}/note endpoint.
func TestSetNoteTool(t *testing.T) {
	var gotMethod, gotPath, gotNote string
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		var b struct {
			Note string `json:"note"`
		}
		json.NewDecoder(r.Body).Decode(&b)
		gotNote = b.Note
		w.WriteHeader(http.StatusNoContent)
	}))
	defer mock.Close()

	s := New(mock.URL)
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"set_note","arguments":{"id":42,"note":"IDOR here"}}}` + "\n")
	var out bytes.Buffer
	if err := s.Serve(in, &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if gotMethod != http.MethodPut || gotPath != "/api/flows/42/note" {
		t.Fatalf("got %s %s, want PUT /api/flows/42/note", gotMethod, gotPath)
	}
	if gotNote != "IDOR here" {
		t.Fatalf("note = %q, want %q", gotNote, "IDOR here")
	}
}
