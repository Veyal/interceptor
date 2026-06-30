package jwtextract

import "testing"

func TestExtractBearer(t *testing.T) {
	tok, src := Extract(Input{
		ReqHeaders: map[string][]string{
			"Authorization": {"Bearer eyJhbG.a.b"},
		},
	})
	if tok != "eyJhbG.a.b" || src != "bearer" {
		t.Fatalf("got %q %q", tok, src)
	}
}

func TestExtractJSONLoginToken(t *testing.T) {
	body := []byte(`{"login_token":"eyJhbG.a.b","success":true}`)
	tok, src := Extract(Input{ResBody: body})
	if tok != "eyJhbG.a.b" || src != "json:login_token" {
		t.Fatalf("got %q %q", tok, src)
	}
}

func TestExtractPathSegment(t *testing.T) {
	tok, src := Extract(Input{Path: "/authBroker/eyJhbG.a.b/callback"})
	if tok != "eyJhbG.a.b" || src != "path" {
		t.Fatalf("got %q %q", tok, src)
	}
}

func TestExtractLoginURL(t *testing.T) {
	body := []byte(`{"login_url":"https://sso.example.com/authBroker/eyJhbG.a.b?x=1"}`)
	tok, src := Extract(Input{ResBody: body})
	if tok != "eyJhbG.a.b" || src != "json:login_url:path" {
		t.Fatalf("got %q %q", tok, src)
	}
}

func TestExtractQuery(t *testing.T) {
	tok, src := Extract(Input{RawQuery: "token=eyJhbG.a.b&x=1"})
	if tok != "eyJhbG.a.b" || src != "query:token" {
		t.Fatalf("got %q %q", tok, src)
	}
}

func TestReplayPath(t *testing.T) {
	if p := ReplayPath("/authBroker/old.jwt.here", "old.jwt.here"); p != "/authBroker/old.jwt.here" {
		t.Fatalf("embedded: %q", p)
	}
	if p := ReplayPath("/api/login", "tok.a.b"); p != "/authBroker/tok.a.b" {
		t.Fatalf("default: %q", p)
	}
}
