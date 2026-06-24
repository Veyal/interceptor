package store

import (
	"testing"
	"time"
)

// Endpoints aggregates flows into unique (host, method, path) endpoints — so
// repeated hits (and noise like many 404s) collapse to one row carrying the hit
// count, the distinct statuses seen, and the latest status/flow.
func TestEndpointsAggregate(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	// GET a.com/x hit three times: 200, 200, then 404 (latest).
	s.InsertFlow(&Flow{TS: time.UnixMilli(1), Method: "GET", Host: "a.com", Path: "/x", Status: 200})
	s.InsertFlow(&Flow{TS: time.UnixMilli(2), Method: "GET", Host: "a.com", Path: "/x", Status: 200})
	s.InsertFlow(&Flow{TS: time.UnixMilli(3), Method: "GET", Host: "a.com", Path: "/x", Status: 404})
	// A distinct endpoint, and one attack-traffic flow that must be excluded.
	s.InsertFlow(&Flow{TS: time.UnixMilli(4), Method: "POST", Host: "a.com", Path: "/y", Status: 201})
	s.InsertFlow(&Flow{TS: time.UnixMilli(5), Method: "GET", Host: "b.com", Path: "/z", Status: 500, Flags: FlagIntruder})

	eps, err := s.Endpoints(EndpointFilter{ExcludeFlags: FlagIntruder | FlagActiveScan})
	if err != nil {
		t.Fatalf("Endpoints: %v", err)
	}
	if len(eps) != 2 {
		t.Fatalf("got %d endpoints, want 2 (b.com/z is attack traffic)", len(eps))
	}

	var x *Endpoint
	for i := range eps {
		if eps[i].Host == "a.com" && eps[i].Path == "/x" {
			x = &eps[i]
		}
	}
	if x == nil {
		t.Fatal("missing GET a.com/x endpoint")
	}
	if x.Hits != 3 {
		t.Fatalf("hits = %d, want 3", x.Hits)
	}
	if x.LastStatus != 404 {
		t.Fatalf("lastStatus = %d, want 404 (latest)", x.LastStatus)
	}
	if len(x.Statuses) != 2 {
		t.Fatalf("statuses = %v, want two distinct (200, 404)", x.Statuses)
	}
	if x.LastFlowID == 0 {
		t.Fatal("lastFlowID should point at the most recent hit")
	}
}
