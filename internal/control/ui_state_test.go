package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Veyal/interseptor/internal/store"
)

func TestUIStateRoundTrip(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	h := &Hub{st: st}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/ui/{panel}", h.getUIState)
	mux.HandleFunc("PUT /api/ui/{panel}", h.putUIState)

	payload := map[string]any{"seq": 2, "active": 1, "tabs": []map[string]any{{"tid": 1, "url": "https://example.com/a"}}}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPut, "/api/ui/repeater", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT status %d: %s", rr.Code, rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/ui/repeater", nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET status %d: %s", rr.Code, rr.Body.String())
	}
	var out struct {
		Value map[string]any `json:"value"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Value["seq"] != float64(2) {
		t.Fatalf("value = %+v", out.Value)
	}
}

func TestUIStateUnknownPanel(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	h := &Hub{st: st}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/ui/{panel}", h.getUIState)
	req := httptest.NewRequest(http.MethodGet, "/api/ui/nope", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status %d", rr.Code)
	}
}
