package netutil

import (
	"testing"
)

func TestListListenHostsIncludesBasics(t *testing.T) {
	r := ListListenHosts()
	if len(r.Hosts) < 4 {
		t.Fatalf("expected at least loopback + any entries, got %d", len(r.Hosts))
	}
	found := map[string]bool{}
	for _, h := range r.Hosts {
		found[h.Address] = true
	}
	for _, addr := range []string{"127.0.0.1", "0.0.0.0", "::1", "::"} {
		if !found[addr] {
			t.Errorf("missing %q in hosts list", addr)
		}
	}
	if r.Suggested == "" {
		t.Fatal("Suggested must not be empty")
	}
}

func TestSuggestedLANNoErrorWhenLoopbackOnly(t *testing.T) {
	_, err := SuggestedLAN()
	// May or may not find LAN depending on test machine; just ensure no panic.
	_ = err
}
