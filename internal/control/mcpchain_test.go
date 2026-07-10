package control_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Veyal/interseptor/internal/control"
	"github.com/Veyal/interseptor/internal/intercept"
	"github.com/Veyal/interseptor/internal/mcp"
	"github.com/Veyal/interseptor/internal/store"
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

// scope_from_url self-scopes from a target URL; check_readiness reports the
// resulting setup checklist.
func TestMCPScopeFromURLAndReadiness(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()
	hub := control.New(st, intercept.New(), nil, nil, nil)
	ctl := httptest.NewServer(hub.Handler())
	defer ctl.Close()

	s := mcp.New(ctl.URL)
	in := strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n" +
			`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"scope_from_url","arguments":{"url":"https://app.acme.com/login"}}}` + "\n" +
			`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"check_readiness","arguments":{}}}` + "\n")
	var out bytes.Buffer
	if err := s.Serve(in, &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}

	resp, err := http.Get(ctl.URL + "/api/scope")
	if err != nil {
		t.Fatalf("GET scope: %v", err)
	}
	defer resp.Body.Close()
	var sc struct {
		Rules []struct {
			Action string `json:"action"`
			Host   string `json:"host"`
			Scheme string `json:"scheme"`
		} `json:"rules"`
	}
	json.NewDecoder(resp.Body).Decode(&sc)
	var found bool
	for _, r := range sc.Rules {
		if r.Action == "include" && r.Host == "app.acme.com" && r.Scheme == "https" {
			found = true
		}
	}
	if !found {
		t.Fatalf("scope_from_url should add include app.acme.com https; got %+v", sc.Rules)
	}

	if o := out.String(); !strings.Contains(o, "blockers") || !strings.Contains(o, "auth_identities") {
		t.Fatalf("check_readiness output missing structured checklist: %s", o)
	}
}

// End-to-end MCP → control → store for issues #4/#5:
// list_flows includes ActiveScan by default; add_finding_poc rejects missing
// flow ids; add_finding_image uploads and serves a screenshot.
func TestMCPListFlowsAndFindingEvidenceE2E(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()
	hub := control.New(st, intercept.New(), nil, nil, nil)
	ctl := httptest.NewServer(hub.Handler())
	defer ctl.Close()

	proxyID, err := st.InsertFlow(&store.Flow{TS: time.Now(), Method: "GET", Host: "example.com", Path: "/app", Status: 200})
	if err != nil {
		t.Fatalf("InsertFlow proxy: %v", err)
	}
	if _, err := st.InsertFlow(&store.Flow{TS: time.Now(), Method: "GET", Host: "example.com", Path: "/scan", Status: 200, Flags: store.FlagActiveScan}); err != nil {
		t.Fatalf("InsertFlow scan: %v", err)
	}

	s := mcp.New(ctl.URL)
	// Disable async /api/activity writes — under -race they contend with
	// AttachFlow on the same SQLite DB and can surface "database is locked".
	s.SetActivityReporter(nil)

	out, err := s.Call("list_flows", map[string]any{"limit": 10})
	if err != nil {
		t.Fatalf("list_flows: %v", err)
	}
	var list struct {
		Flows []struct {
			Path string `json:"path"`
		} `json:"flows"`
	}
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		t.Fatalf("decode list_flows: %v\n%s", err, out)
	}
	if len(list.Flows) != 2 {
		t.Fatalf("list_flows default should include ActiveScan: got %d flows %s", len(list.Flows), out)
	}

	out, err = s.Call("list_flows", map[string]any{"limit": 10, "includeTools": false})
	if err != nil {
		t.Fatalf("list_flows History: %v", err)
	}
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list.Flows) != 1 || list.Flows[0].Path != "/app" {
		t.Fatalf("includeTools:false want /app only, got %s", out)
	}

	out, err = s.Call("create_finding", map[string]any{
		"title": "e2e xss", "severity": "High", "detail": "intro", "target": "example.com",
	})
	if err != nil {
		t.Fatalf("create_finding: %v", err)
	}
	jsonPart := out
	if i := strings.Index(out, "\n\nUI:"); i >= 0 {
		jsonPart = out[:i]
	}
	var finding struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal([]byte(jsonPart), &finding); err != nil || finding.ID == 0 {
		t.Fatalf("create_finding id: %v %s", err, out)
	}

	out, err = s.Call("add_finding_poc", map[string]any{
		"findingId": finding.ID, "flowId": proxyID, "note": "baseline",
	})
	if err != nil {
		t.Fatalf("add_finding_poc: %v", err)
	}
	if strings.Contains(out, `"missing":true`) {
		t.Fatalf("PoC should not be missing: %s", out)
	}

	if _, err := s.Call("add_finding_poc", map[string]any{
		"findingId": finding.ID, "flowId": int64(999999),
	}); err == nil {
		t.Fatal("add_finding_poc bad flowId should error")
	}

	const pngB64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
	out, err = s.Call("add_finding_image", map[string]any{
		"findingId": finding.ID,
		"data":      "data:image/png;base64," + pngB64,
		"caption":   "alert",
	})
	if err != nil {
		t.Fatalf("add_finding_image: %v", err)
	}
	var withImg store.Finding
	if err := json.Unmarshal([]byte(out), &withImg); err != nil {
		t.Fatalf("decode finding: %v\n%s", err, out)
	}
	var url string
	for _, b := range withImg.Blocks {
		if b.Type == "image" {
			url = b.URL
			if b.Missing || b.Caption != "alert" {
				t.Fatalf("image block: %+v", b)
			}
		}
	}
	if url == "" {
		t.Fatalf("no image block: %s", out)
	}
	resp, err := http.Get(ctl.URL + url)
	if err != nil {
		t.Fatalf("GET image: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || len(body) == 0 || resp.Header.Get("Content-Type") != "image/png" {
		t.Fatalf("GET image status=%d ct=%s n=%d", resp.StatusCode, resp.Header.Get("Content-Type"), len(body))
	}
}
