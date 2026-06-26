package control

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNotesOrganizePrompt(t *testing.T) {
	p := notesOrganizePrompt("## creds\nadmin:pw")
	if !strings.Contains(p, "rich, well-formatted") {
		t.Fatalf("missing lead: %s", p)
	}
	if !strings.Contains(p, "admin:pw") {
		t.Fatalf("missing notes body: %s", p)
	}
}

func TestNotesOrganizeSystemFormat(t *testing.T) {
	for _, sub := range []string{"table", "backticks", "- [ ]", "blockquotes"} {
		if !strings.Contains(notesOrganizeSystem, sub) {
			t.Fatalf("notesOrganizeSystem missing %q", sub)
		}
	}
}

func TestExtractFencedMarkdown(t *testing.T) {
	cases := []struct{ in, want string }{
		{"# Hello\n\n- item", "# Hello\n\n- item"},
		{"```markdown\n# Hello\n```", "# Hello"},
		{"```\n# Hello\n```", "# Hello"},
		{"Here:\n```\n# Hi\n```", "Here:\n```\n# Hi\n```"},
	}
	for _, c := range cases {
		if got := extractFencedMarkdown(c.in); got != c.want {
			t.Fatalf("extractFencedMarkdown(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestNotesOrganizeRejectedWhenDisabled(t *testing.T) {
	h, s, _ := newHub(t)
	if err := s.SetSetting("ai.disabled", "1"); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(h.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/ai/notes/organize", "application/json",
		strings.NewReader(`{"notes":"# test"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("organize status %d, want 403", resp.StatusCode)
	}
}

func TestNotesOrganizeEmptyNotes(t *testing.T) {
	h, _, _ := newHub(t)
	ts := httptest.NewServer(h.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/ai/notes/organize", "application/json",
		strings.NewReader(`{"notes":"   "}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty notes status %d, want 400", resp.StatusCode)
	}
}

func TestNotesOrganizeNoKey(t *testing.T) {
	h, _, _ := newHub(t)
	ts := httptest.NewServer(h.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/ai/notes/organize", "application/json",
		strings.NewReader(`{"notes":"# findings\n- xss"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("no key status %d, want 400", resp.StatusCode)
	}
}
