package store

import (
	"strings"
	"testing"
)

func TestAPIKeyLifecycle(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	token, key, err := s.CreateAPIKey("ci-runner")
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	if !strings.HasPrefix(token, "ick_") || len(token) != 52 {
		t.Fatalf("unexpected token format: %q", token)
	}
	if key.Label != "ci-runner" || !strings.HasPrefix(token, key.Prefix) {
		t.Fatalf("unexpected key meta: %+v", key)
	}

	keys, err := s.ListAPIKeys()
	if err != nil || len(keys) != 1 || keys[0].Label != "ci-runner" {
		t.Fatalf("ListAPIKeys: %v %+v", err, keys)
	}

	if ok, _ := s.VerifyAPIKey(token); !ok {
		t.Fatal("expected the issued token to verify")
	}
	if ok, _ := s.VerifyAPIKey("ick_deadbeef"); ok {
		t.Fatal("expected a bogus token to fail verification")
	}

	if err := s.DeleteAPIKey(key.ID); err != nil {
		t.Fatalf("DeleteAPIKey: %v", err)
	}
	if keys, _ := s.ListAPIKeys(); len(keys) != 0 {
		t.Fatalf("expected key revoked, got %d", len(keys))
	}
}
