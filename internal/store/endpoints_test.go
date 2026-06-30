package store

import (
	"testing"
	"time"
)

func writeTestBody(t *testing.T, s *Store, content string) string {
	t.Helper()
	w, err := s.NewBodyWriter()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	hash, _, err := w.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

// Endpoints aggregates flows into unique (host, method, path) endpoints — so
// repeated hits (and noise like many 404s) collapse to one row carrying the hit
// count, the distinct statuses seen, and the latest status/flow.
func TestEndpointsAggregate(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	s.InsertFlow(&Flow{TS: time.UnixMilli(1), Method: "GET", Host: "a.com", Path: "/x", Status: 200})
	s.InsertFlow(&Flow{TS: time.UnixMilli(2), Method: "GET", Host: "a.com", Path: "/x", Status: 200})
	s.InsertFlow(&Flow{TS: time.UnixMilli(3), Method: "GET", Host: "a.com", Path: "/x", Status: 404})
	s.InsertFlow(&Flow{TS: time.UnixMilli(4), Method: "POST", Host: "a.com", Path: "/y", Status: 201})
	s.InsertFlow(&Flow{TS: time.UnixMilli(5), Method: "GET", Host: "b.com", Path: "/z", Status: 500, Flags: FlagIntruder})

	eps, _, err := s.Endpoints(EndpointFilter{ExcludeFlags: FlagIntruder | FlagActiveScan})
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

func TestEndpointsHeaderSearch(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	s.InsertFlow(&Flow{
		TS: time.UnixMilli(1), Method: "GET", Host: "api.test", Path: "/v1/users", Status: 200,
		ReqHeaders: map[string][]string{"Authorization": {"Bearer SECRET123"}},
	})
	s.InsertFlow(&Flow{
		TS: time.UnixMilli(2), Method: "GET", Host: "api.test", Path: "/v1/other", Status: 200,
	})

	eps, _, err := s.Endpoints(EndpointFilter{
		Search: "SECRET123", SearchScope: EndpointSearchHeaders,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 1 || eps[0].Path != "/v1/users" {
		t.Fatalf("header search: got %+v", eps)
	}
}

func TestEndpointsBodySearch(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	bodyHash := writeTestBody(t, s, `{"flag":"UNIQUE_BODY_TOKEN"}`)
	s.InsertFlow(&Flow{
		TS: time.UnixMilli(1), Method: "POST", Host: "app.test", Path: "/api/data", Status: 200,
		ResBodyHash: bodyHash, ResLen: 28,
	})
	s.InsertFlow(&Flow{
		TS: time.UnixMilli(2), Method: "GET", Host: "app.test", Path: "/health", Status: 200,
	})

	eps, _, err := s.Endpoints(EndpointFilter{
		Search: "UNIQUE_BODY_TOKEN", SearchScope: EndpointSearchBody,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 1 || eps[0].Path != "/api/data" {
		t.Fatalf("body search: got %+v", eps)
	}
}

func TestEndpointsAllSearch(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	bodyHash := writeTestBody(t, s, "plain body needle")
	s.InsertFlow(&Flow{
		TS: time.UnixMilli(1), Method: "GET", Host: "h.test", Path: "/a", Status: 200,
		ResBodyHash: bodyHash,
	})
	s.InsertFlow(&Flow{
		TS: time.UnixMilli(2), Method: "GET", Host: "h.test", Path: "/b", Status: 200,
		ReqHeaders: map[string][]string{"X-Custom": {"needle-header"}},
	})

	eps, _, err := s.Endpoints(EndpointFilter{Search: "needle", SearchScope: EndpointSearchAll})
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 2 {
		t.Fatalf("all search: got %d endpoints, want 2", len(eps))
	}
}

func TestEndpointsHideNoiseOnly(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	s.InsertFlow(&Flow{TS: time.UnixMilli(1), Method: "GET", Host: "app.test", Path: "/alive", Status: 200})
	s.InsertFlow(&Flow{TS: time.UnixMilli(2), Method: "GET", Host: "app.test", Path: "/missing", Status: 404})
	s.InsertFlow(&Flow{TS: time.UnixMilli(3), Method: "GET", Host: "app.test", Path: "/forbidden", Status: 403})
	s.InsertFlow(&Flow{TS: time.UnixMilli(4), Method: "GET", Host: "app.test", Path: "/mixed", Status: 404})
	s.InsertFlow(&Flow{TS: time.UnixMilli(5), Method: "GET", Host: "app.test", Path: "/mixed", Status: 200})

	all, _, err := s.Endpoints(EndpointFilter{ExcludeFlags: FlagIntruder | FlagActiveScan})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 4 {
		t.Fatalf("unfiltered: got %d endpoints, want 4", len(all))
	}

	filtered, _, err := s.Endpoints(EndpointFilter{
		ExcludeFlags:  FlagIntruder | FlagActiveScan,
		HideNoiseOnly: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 2 {
		t.Fatalf("hide noise: got %d endpoints, want 2 (/alive and /mixed)", len(filtered))
	}
	for _, e := range filtered {
		if e.Path == "/missing" || e.Path == "/forbidden" {
			t.Fatalf("noise endpoint should be hidden: %+v", e)
		}
	}
}
