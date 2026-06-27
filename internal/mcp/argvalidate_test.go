package mcp

import (
	"strings"
	"testing"
)

// The AI only ever sees the error string, so a present-but-wrong argument must
// be reported with both the expected type AND the offending value (truncated,
// secrets masked) — otherwise the model loops instead of self-correcting.

func TestReqStr(t *testing.T) {
	// Missing → names the arg and the expectation, no value to echo.
	if _, err := reqStr(map[string]any{}, "url"); err == nil || !strings.Contains(err.Error(), "url is required") {
		t.Fatalf("missing url: %v", err)
	}
	// Present-but-empty → says so.
	if _, err := reqStr(map[string]any{"url": "   "}, "url"); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty url: %v", err)
	}
	// Wrong type (number where string expected) → echoes what was received.
	_, err := reqStr(map[string]any{"url": float64(42)}, "url")
	if err == nil || !strings.Contains(err.Error(), "must be a string") || !strings.Contains(err.Error(), "42") {
		t.Fatalf("wrong-type url should echo the value: %v", err)
	}
	// Happy path.
	if v, err := reqStr(map[string]any{"url": "https://x"}, "url"); err != nil || v != "https://x" {
		t.Fatalf("good url: %q %v", v, err)
	}
}

func TestReqIntWrongTypeEchoesValue(t *testing.T) {
	// The headline case: a string where an integer is expected.
	_, err := reqInt(map[string]any{"flowId": "abc"}, "flowId")
	if err == nil {
		t.Fatal("expected an error for flowId=\"abc\"")
	}
	msg := err.Error()
	if !strings.Contains(msg, "flowId must be an integer") {
		t.Fatalf("message should name the expected type: %q", msg)
	}
	if !strings.Contains(msg, `"abc"`) {
		t.Fatalf("message should echo the received value: %q", msg)
	}

	// Missing → required, no value.
	if _, err := reqInt(map[string]any{}, "id"); err == nil || !strings.Contains(err.Error(), "id is required") {
		t.Fatalf("missing id: %v", err)
	}
	// Numeric string and JSON number both accepted.
	if n, err := reqInt(map[string]any{"id": "7"}, "id"); err != nil || n != 7 {
		t.Fatalf("numeric string: %d %v", n, err)
	}
	if n, err := reqInt(map[string]any{"id": float64(9)}, "id"); err != nil || n != 9 {
		t.Fatalf("json number: %d %v", n, err)
	}
}

func TestReqFlowIDAcceptsEitherKey(t *testing.T) {
	if n, err := reqFlowID(map[string]any{"flowId": float64(5)}); err != nil || n != 5 {
		t.Fatalf("flowId key: %d %v", n, err)
	}
	if n, err := reqFlowID(map[string]any{"id": float64(3)}); err != nil || n != 3 {
		t.Fatalf("id key: %d %v", n, err)
	}
	// Wrong type → message mentions both accepted keys AND echoes the value.
	_, err := reqFlowID(map[string]any{"id": "nope"})
	if err == nil || !strings.Contains(err.Error(), "id (or flowId)") || !strings.Contains(err.Error(), `"nope"`) {
		t.Fatalf("wrong-type flow id: %v", err)
	}
	// Neither key present.
	if _, err := reqFlowID(map[string]any{}); err == nil || !strings.Contains(err.Error(), "id (or flowId) is required") {
		t.Fatalf("missing flow id: %v", err)
	}
}

func TestDescribeValueTruncatesAndMasks(t *testing.T) {
	// A long value is capped to argValueCap runes with an ellipsis — never echo
	// a huge body into an error.
	long := strings.Repeat("A", 500)
	got := describeValue("note", long)
	// Strip the surrounding quotes a string value carries.
	unquoted := strings.Trim(got, `"`)
	if len([]rune(unquoted)) > argValueCap+1 { // +1 for the ellipsis rune
		t.Fatalf("value not truncated: %d runes", len([]rune(unquoted)))
	}
	if !strings.HasSuffix(unquoted, "…") {
		t.Fatalf("truncated value should end with an ellipsis: %q", got)
	}
	if !strings.HasPrefix(unquoted, "AAAA") {
		t.Fatalf("truncated value should keep the prefix: %q", got)
	}

	// Secret-named args are masked, not echoed.
	for _, key := range []string{"token", "apiKey", "Authorization", "password", "Cookie"} {
		if got := describeValue(key, "s3cr3t-value"); strings.Contains(got, "s3cr3t") {
			t.Fatalf("%s value leaked: %q", key, got)
		}
	}
	// Ordinary args are echoed (truncated/quoted) so the AI can see them.
	if got := describeValue("flowId", "abc"); got != `"abc"` {
		t.Fatalf("ordinary value should be echoed: %q", got)
	}
}

// A required-int tool surfaces the rich message all the way through callTool, so
// the AI receives "must be an integer (got ...)" as an isError tool result.
func TestWrongTypeReachesToolError(t *testing.T) {
	srv := New("http://127.0.0.1:1") // control plane never contacted: validation fails first
	res := srv.callTool([]byte(`{"name":"analyze_flow","arguments":{"flowId":"abc"}}`))
	m, ok := res.(map[string]any)
	if !ok {
		t.Fatalf("unexpected result type %T", res)
	}
	if m["isError"] != true {
		t.Fatalf("wrong-type arg should be a tool error: %v", m)
	}
	content, _ := m["content"].([]map[string]any)
	if len(content) == 0 {
		t.Fatalf("no content: %v", m)
	}
	text, _ := content[0]["text"].(string)
	if !strings.Contains(text, "must be an integer") || !strings.Contains(text, `"abc"`) {
		t.Fatalf("tool error should explain the wrong type and echo the value: %q", text)
	}
}
