package aiassist

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSupportsAgentTools(t *testing.T) {
	for _, p := range []string{ProviderAnthropic, ProviderGLM, ProviderOpenRouter, ProviderOpenAI} {
		if !New(p, "k", "").SupportsAgentTools() {
			t.Fatalf("%s should support agent tools", p)
		}
	}
}

func TestCompleteAgentTurnParsesToolUse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var body map[string]any
		json.Unmarshal(b, &body)
		tools, _ := body["tools"].([]any)
		if len(tools) != 1 {
			t.Fatalf("expected 1 tool, got %v", body["tools"])
		}
		io.WriteString(w, `{"stop_reason":"tool_use","content":[{"type":"text","text":"Probing."},{"type":"tool_use","id":"tu_1","name":"send_request","input":{"method":"GET","url":"https://x.test/"}}]}`)
	}))
	defer srv.Close()

	c := New(ProviderAnthropic, "sk-test", "")
	c.endpoint = srv.URL
	turn, err := c.CompleteAgentTurn(context.Background(), "sys", []AgentMessage{
		{Role: "user", Content: "check access"},
	}, []Tool{{Name: "send_request", Description: "send", InputSchema: map[string]any{"type": "object"}}})
	if err != nil {
		t.Fatalf("CompleteAgentTurn: %v", err)
	}
	if turn.StopReason != "tool_use" || len(turn.ToolCalls) != 1 {
		t.Fatalf("unexpected turn: %+v", turn)
	}
	if turn.ToolCalls[0].Name != "send_request" || turn.ToolCalls[0].Input["url"] != "https://x.test/" {
		t.Fatalf("tool call wrong: %+v", turn.ToolCalls[0])
	}
	if turn.Text != "Probing." {
		t.Fatalf("text=%q", turn.Text)
	}
}

func TestCompleteAgentTurnGLMUsesAnthropicWire(t *testing.T) {
	var gotAuth, gotAPIKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAPIKey = r.Header.Get("x-api-key")
		io.WriteString(w, `{"stop_reason":"end_turn","content":[{"type":"text","text":"ok"}]}`)
	}))
	defer srv.Close()

	c := New(ProviderGLM, "glm-key", "")
	c.endpoint = srv.URL
	turn, err := c.CompleteAgentTurn(context.Background(), "sys", []AgentMessage{{Role: "user", Content: "q"}}, agentToolsFixture())
	if err != nil {
		t.Fatalf("CompleteAgentTurn: %v", err)
	}
	if turn.Text != "ok" {
		t.Fatalf("text=%q", turn.Text)
	}
	if gotAuth != "Bearer glm-key" {
		t.Fatalf("GLM should use Bearer auth, got %q", gotAuth)
	}
	if gotAPIKey != "" {
		t.Fatalf("GLM should not send x-api-key, got %q", gotAPIKey)
	}
}

func TestCompleteAgentTurnOpenAIToolCalls(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &gotBody)
		io.WriteString(w, `{"choices":[{"finish_reason":"tool_calls","message":{"content":"Checking.","tool_calls":[{"id":"call_1","type":"function","function":{"name":"send_request","arguments":"{\"url\":\"https://x.test/\"}"}}]}}]}`)
	}))
	defer srv.Close()

	c := New(ProviderOpenAI, "sk-oai", "")
	c.endpoint = srv.URL
	turn, err := c.CompleteAgentTurn(context.Background(), "sys", []AgentMessage{{Role: "user", Content: "check"}},
		[]Tool{{Name: "send_request", Description: "send", InputSchema: map[string]any{"type": "object"}}})
	if err != nil {
		t.Fatalf("CompleteAgentTurn: %v", err)
	}
	if len(turn.ToolCalls) != 1 || turn.ToolCalls[0].Name != "send_request" {
		t.Fatalf("unexpected tool calls: %+v", turn.ToolCalls)
	}
	if turn.ToolCalls[0].Input["url"] != "https://x.test/" {
		t.Fatalf("tool call input wrong: %+v", turn.ToolCalls[0].Input)
	}
	if turn.Text != "Checking." {
		t.Fatalf("text=%q", turn.Text)
	}
	// Tools must be sent in OpenAI function shape.
	tools, _ := gotBody["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("expected 1 tool in request, got %v", gotBody["tools"])
	}
	first, _ := tools[0].(map[string]any)
	if first["type"] != "function" {
		t.Fatalf("tool type wrong: %v", first)
	}
}

// TestCompleteAgentTurnOpenAIRoundtripsToolResults asserts assistant tool_use +
// user tool_result blocks are flattened into the OpenAI schema without error.
func TestCompleteAgentTurnOpenAIRoundtripsToolResults(t *testing.T) {
	var gotMsgs []any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &body)
		gotMsgs, _ = body["messages"].([]any)
		io.WriteString(w, `{"choices":[{"finish_reason":"stop","message":{"content":"Done."}}]}`)
	}))
	defer srv.Close()

	c := New(ProviderOpenRouter, "k", "")
	c.endpoint = srv.URL
	msgs := []AgentMessage{
		{Role: "user", Content: "start"},
		{Role: "assistant", Content: []ContentBlock{{Type: "tool_use", ID: "call_1", Name: "get_flow", Input: map[string]any{"id": 1}}}},
		{Role: "user", Content: []ContentBlock{{Type: "tool_result", ToolUseID: "call_1", Content: "flow body"}}},
	}
	turn, err := c.CompleteAgentTurn(context.Background(), "sys", msgs, agentToolsFixture())
	if err != nil {
		t.Fatalf("CompleteAgentTurn: %v", err)
	}
	if turn.Text != "Done." {
		t.Fatalf("text=%q", turn.Text)
	}
	// system + user + assistant(tool_calls) + tool = 4 messages.
	if len(gotMsgs) != 4 {
		t.Fatalf("expected 4 messages, got %d: %v", len(gotMsgs), gotMsgs)
	}
	toolMsg, _ := gotMsgs[3].(map[string]any)
	if toolMsg["role"] != "tool" || toolMsg["tool_call_id"] != "call_1" {
		t.Fatalf("tool result message wrong: %v", toolMsg)
	}
}

func TestCompleteAgentTurnEndTurn(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"stop_reason":"end_turn","content":[{"type":"text","text":"No IDOR."}]}`)
	}))
	defer srv.Close()

	c := New(ProviderAnthropic, "sk-test", "")
	c.endpoint = srv.URL
	turn, err := c.CompleteAgentTurn(context.Background(), "sys", []AgentMessage{{Role: "user", Content: "q"}}, agentToolsFixture())
	if err != nil {
		t.Fatalf("CompleteAgentTurn: %v", err)
	}
	if len(turn.ToolCalls) != 0 || turn.Text != "No IDOR." {
		t.Fatalf("unexpected turn: %+v", turn)
	}
}

func TestCompleteStreamAgentMessages(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &body)
		if body["stream"] != true {
			t.Fatalf("expected stream:true, got %v", body["stream"])
		}
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, `data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Done."}}`+"\n\n")
	}))
	defer srv.Close()

	c := New(ProviderAnthropic, "sk-test", "")
	c.endpoint = srv.URL
	var got strings.Builder
	err := c.CompleteStreamAgentMessages(context.Background(), "sys", []AgentMessage{{Role: "user", Content: "q"}}, func(d string) { got.WriteString(d) })
	if err != nil {
		t.Fatalf("CompleteStreamAgentMessages: %v", err)
	}
	if got.String() != "Done." {
		t.Fatalf("got %q", got.String())
	}
}

func agentToolsFixture() []Tool {
	return []Tool{{Name: "get_flow", Description: "read", InputSchema: map[string]any{"type": "object"}}}
}
