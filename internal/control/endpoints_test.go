package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Veyal/interceptor/internal/store"
)

// GET /api/endpoints returns unique endpoints aggregated from history.
func TestEndpointsEndpoint(t *testing.T) {
	h, s, _ := newHub(t)
	s.InsertFlow(&store.Flow{TS: time.UnixMilli(1), Method: "GET", Host: "a.com", Path: "/x", Status: 200})
	s.InsertFlow(&store.Flow{TS: time.UnixMilli(2), Method: "GET", Host: "a.com", Path: "/x", Status: 404})
	s.InsertFlow(&store.Flow{TS: time.UnixMilli(3), Method: "POST", Host: "a.com", Path: "/y", Status: 201})
	s.InsertFlow(&store.Flow{TS: time.UnixMilli(4), Method: "GET", Host: "a.com", Path: "/z", Status: 200, Flags: store.FlagActiveScan})

	ts := httptest.NewServer(h.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/endpoints")
	if err != nil {
		t.Fatalf("GET endpoints: %v", err)
	}
	defer resp.Body.Close()
	var out struct {
		Endpoints []struct {
			Host string `json:"host"`
			Path string `json:"path"`
			Hits int    `json:"hits"`
		} `json:"endpoints"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if len(out.Endpoints) != 2 {
		t.Fatalf("got %d endpoints, want 2 (scan traffic excluded, hits collapsed)", len(out.Endpoints))
	}
}
