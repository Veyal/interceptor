package control_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Veyal/interceptor/internal/control"
	"github.com/Veyal/interceptor/internal/intercept"
	"github.com/Veyal/interceptor/internal/mcp"
	"github.com/Veyal/interceptor/internal/store"
)

// Full chain: a send_request driven through the MCP server (as the stdio
// transport does) lands in Proxy/History tagged FlagAI — so an operator sees the
// AI's request inline with their own captured traffic, not just in Activity.
func TestMCPSendRequestShowsInHistoryAsAI(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()
	hub := control.New(st, intercept.New(), nil, nil, nil)
	ctl := httptest.NewServer(hub.Handler())
	defer ctl.Close()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer target.Close()

	// Drive the MCP server pointed at the real control plane.
	s := mcp.New(ctl.URL)
	in := strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n" +
			`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"send_request","arguments":{"method":"GET","url":"` + target.URL + `/ai-path"}}}` + "\n")
	var out bytes.Buffer
	if err := s.Serve(in, &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}

	resp, err := http.Get(ctl.URL + "/api/flows")
	if err != nil {
		t.Fatalf("GET flows: %v", err)
	}
	defer resp.Body.Close()
	var fl struct {
		Flows []struct {
			Path  string `json:"path"`
			Flags int64  `json:"flags"`
		} `json:"flows"`
	}
	json.NewDecoder(resp.Body).Decode(&fl)

	var seen bool
	for _, f := range fl.Flows {
		if strings.HasSuffix(f.Path, "/ai-path") {
			seen = true
			if f.Flags&store.FlagAI == 0 {
				t.Fatalf("AI send should carry FlagAI in History, got flags=%d", f.Flags)
			}
		}
	}
	if !seen {
		t.Fatal("AI send_request did not appear in Proxy/History")
	}
}
