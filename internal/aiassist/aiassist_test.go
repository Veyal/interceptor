package aiassist

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCompleteBuildsRequestAndParsesReply(t *testing.T) {
	var gotKey, gotVersion string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-api-key")
		gotVersion = r.Header.Get("anthropic-version")
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &gotBody)
		io.WriteString(w, `{"content":[{"type":"text","text":"This is a login request."}]}`)
	}))
	defer srv.Close()

	c := New("sk-test", "")
	c.endpoint = srv.URL
	out, err := c.Complete("you are a security assistant", "explain this request")
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if out != "This is a login request." {
		t.Fatalf("unexpected reply: %q", out)
	}
	if gotKey != "sk-test" || gotVersion != "2023-06-01" {
		t.Fatalf("headers wrong: key=%q version=%q", gotKey, gotVersion)
	}
	if gotBody["model"] != DefaultModel || gotBody["system"] != "you are a security assistant" {
		t.Fatalf("request body wrong: %v", gotBody)
	}
	msgs, _ := gotBody["messages"].([]any)
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %v", gotBody["messages"])
	}
}

func TestCompleteRequiresKey(t *testing.T) {
	if _, err := New("", "").Complete("s", "u"); err == nil {
		t.Fatal("expected error with no API key")
	}
}

func TestCompleteSurfacesAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"error":{"message":"invalid x-api-key"}}`)
	}))
	defer srv.Close()
	c := New("bad", "")
	c.endpoint = srv.URL
	if _, err := c.Complete("s", "u"); err == nil {
		t.Fatal("expected API error to surface")
	}
}
