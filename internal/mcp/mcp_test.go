package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func decodeResponses(t *testing.T, out string) []rpcResponse {
	t.Helper()
	var resps []rpcResponse
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var r rpcResponse
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("bad response line %q: %v", line, err)
		}
		if r.JSONRPC != "2.0" {
			t.Fatalf("response missing jsonrpc 2.0: %q", line)
		}
		resps = append(resps, r)
	}
	return resps
}

func TestMCPProtocolAndTools(t *testing.T) {
	var sentRepeater bool
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/flows":
			io.WriteString(w, `{"flows":[{"id":1,"method":"GET","host":"victim.test","path":"/login","status":200}]}`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/repeater/send":
			sentRepeater = true
			io.WriteString(w, `{"id":7,"status":201,"method":"POST","host":"victim.test","path":"/login"}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer mock.Close()

	srv := New(mock.URL)
	script := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_flows","arguments":{"host":"victim.test"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"send_request","arguments":{"method":"POST","url":"https://victim.test/login","body":"x=1"}}}`,
	}, "\n") + "\n"

	var out bytes.Buffer
	if err := srv.Serve(strings.NewReader(script), &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	resps := decodeResponses(t, out.String())
	// 4 requests carry an id (the notification produces no response).
	if len(resps) != 4 {
		t.Fatalf("expected 4 responses, got %d: %s", len(resps), out.String())
	}

	// initialize
	var initRes struct {
		ProtocolVersion string `json:"protocolVersion"`
		Capabilities    struct {
			Tools json.RawMessage `json:"tools"`
		} `json:"capabilities"`
		ServerInfo struct {
			Name string `json:"name"`
		} `json:"serverInfo"`
	}
	json.Unmarshal(resps[0].Result, &initRes)
	if initRes.ProtocolVersion == "" || initRes.ServerInfo.Name != "interceptor" || initRes.Capabilities.Tools == nil {
		t.Fatalf("bad initialize result: %s", resps[0].Result)
	}

	// tools/list contains the key tools
	var listRes struct {
		Tools []struct {
			Name        string          `json:"name"`
			Description string          `json:"description"`
			InputSchema json.RawMessage `json:"inputSchema"`
		} `json:"tools"`
	}
	json.Unmarshal(resps[1].Result, &listRes)
	names := map[string]bool{}
	for _, tl := range listRes.Tools {
		if tl.Description == "" || tl.InputSchema == nil {
			t.Fatalf("tool %q missing description/schema", tl.Name)
		}
		names[tl.Name] = true
	}
	for _, want := range []string{"list_flows", "get_flow", "send_request", "run_scanner", "set_intercept", "start_intruder"} {
		if !names[want] {
			t.Fatalf("tools/list missing %q; got %v", want, names)
		}
	}

	// tools/call list_flows → content text mentions the mock flow
	var callRes struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	json.Unmarshal(resps[2].Result, &callRes)
	if callRes.IsError || len(callRes.Content) == 0 || !strings.Contains(callRes.Content[0].Text, "victim.test") {
		t.Fatalf("list_flows call result wrong: %s", resps[2].Result)
	}

	// tools/call send_request actually hit the repeater endpoint
	if !sentRepeater {
		t.Fatal("send_request did not call /api/repeater/send")
	}
}

func TestMCPUnknownToolIsToolError(t *testing.T) {
	srv := New("http://127.0.0.1:1") // unused
	script := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nope","arguments":{}}}` + "\n"
	var out bytes.Buffer
	srv.Serve(strings.NewReader(script), &out)
	resps := decodeResponses(t, out.String())
	if len(resps) != 1 {
		t.Fatalf("expected 1 response, got %d", len(resps))
	}
	var res struct {
		IsError bool `json:"isError"`
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	json.Unmarshal(resps[0].Result, &res)
	if !res.IsError {
		t.Fatalf("unknown tool should be a tool error, got: %s", resps[0].Result)
	}
}
