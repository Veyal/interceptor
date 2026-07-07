package launcher

import (
	"net"
	"strconv"
	"testing"
)

func TestFindFreePortSkipsUsed(t *testing.T) {
	// Occupy start with a real listener; FindFreePort must skip past it even
	// though "used" doesn't mention it, and also skip anything we do list.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	start, _ := strconv.Atoi(portStr)

	got, err := FindFreePort("127.0.0.1", start, 50, nil)
	if err != nil {
		t.Fatalf("FindFreePort: %v", err)
	}
	if got == start {
		t.Fatalf("FindFreePort returned the already-bound port %d", start)
	}
	if got <= start || got >= start+50 {
		t.Fatalf("FindFreePort returned %d, want in (%d, %d)", got, start, start+50)
	}
}

func TestFindFreePortRespectsUsedMap(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	start := ln.Addr().(*net.TCPAddr).Port
	ln.Close() // free it up so only the "used" map should exclude it

	used := map[int]bool{start: true}
	got, err := FindFreePort("127.0.0.1", start, 50, used)
	if err != nil {
		t.Fatalf("FindFreePort: %v", err)
	}
	if got == start {
		t.Fatalf("FindFreePort returned a port marked used: %d", got)
	}
}

func TestFindFreePortExhausted(t *testing.T) {
	used := map[int]bool{}
	for p := 40000; p < 40010; p++ {
		used[p] = true
	}
	if _, err := FindFreePort("127.0.0.1", 40000, 10, used); err == nil {
		t.Fatalf("expected error when every candidate port is used")
	}
}
