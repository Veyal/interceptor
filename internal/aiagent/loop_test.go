package aiagent

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fakeCaller scripts a sequence of turns; each Complete call returns the next one.
// A ToolCaller.Complete with tools==nil (the final synthesis turn) returns synth.
type fakeCaller struct {
	turns    []Turn
	i        int
	err      error // if set, Complete returns this error on the first call
	calls    int   // total Complete invocations
	lastMsgs []Message
	synth    Turn // returned when tools is empty (budget synthesis turn)
	onCall   func(n int)
}

func (f *fakeCaller) Complete(ctx context.Context, system string, msgs []Message, tools []ToolSpec) (Turn, error) {
	f.calls++
	f.lastMsgs = msgs
	if f.onCall != nil {
		f.onCall(f.calls)
	}
	if f.err != nil {
		return Turn{}, f.err
	}
	if len(tools) == 0 && (f.synth.Text != "" || len(f.synth.Calls) > 0) {
		return f.synth, nil
	}
	if f.i >= len(f.turns) {
		return Turn{Text: "fallback final"}, nil
	}
	t := f.turns[f.i]
	f.i++
	return t, nil
}

// fakeExec records executed calls and returns a canned result. If err is set it
// returns that error for every call.
type fakeExec struct {
	results map[string]string
	execd   []ToolCall
	err     error
}

func (f *fakeExec) Exec(ctx context.Context, call ToolCall) (string, error) {
	f.execd = append(f.execd, call)
	if f.err != nil {
		return "", f.err
	}
	if r, ok := f.results[call.Name]; ok {
		return r, nil
	}
	return "ok", nil
}

// fakeClock advances by a fixed step each time Now is read.
type fakeClock struct {
	t    time.Time
	step time.Duration
}

func (c *fakeClock) Now() time.Time {
	now := c.t
	c.t = c.t.Add(c.step)
	return now
}

func toolCall(id, name string) ToolCall { return ToolCall{ID: id, Name: name, Args: map[string]any{}} }

// specs is a non-empty tools slice so the fakeCaller can distinguish a normal
// turn (tools present) from the tool-less budget-synthesis turn (tools empty).
var specs = []ToolSpec{{Name: "t", Description: "d", Schema: map[string]any{"type": "object"}}}

func TestRunNormalCompletion(t *testing.T) {
	fc := &fakeCaller{turns: []Turn{
		{Text: "probing", Calls: []ToolCall{toolCall("c1", "send_request")}},
		{Text: "probing more", Calls: []ToolCall{toolCall("c2", "get_flow")}},
		{Text: "final answer"},
	}}
	fx := &fakeExec{}
	res, err := Run(context.Background(), fc, fx, "sys", "do the task", specs, Budget{}, &fakeClock{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.StoppedBy != StoppedDone {
		t.Fatalf("StoppedBy=%q want done", res.StoppedBy)
	}
	if res.FinalText != "final answer" {
		t.Fatalf("FinalText=%q", res.FinalText)
	}
	if res.Steps != 3 || res.ToolCalls != 2 {
		t.Fatalf("Steps=%d ToolCalls=%d", res.Steps, res.ToolCalls)
	}
	if len(fx.execd) != 2 {
		t.Fatalf("executed %d calls", len(fx.execd))
	}
	// Transcript: task + (assistant+tool)*2 + final assistant = 1+4+1 = 6.
	if len(res.Transcript) != 6 {
		t.Fatalf("transcript len=%d: %+v", len(res.Transcript), res.Transcript)
	}
	if res.Transcript[0].Role != "user" || res.Transcript[0].Text != "do the task" {
		t.Fatalf("seed message wrong: %+v", res.Transcript[0])
	}
	// The tool result message must reference the call id.
	if res.Transcript[2].Role != "tool" || res.Transcript[2].ToolCallID != "c1" {
		t.Fatalf("tool result message wrong: %+v", res.Transcript[2])
	}
}

func TestRunMaxStepsBudget(t *testing.T) {
	// Every turn asks for a tool, so only MaxSteps stops it.
	fc := &fakeCaller{turns: []Turn{
		{Calls: []ToolCall{toolCall("c1", "t")}},
		{Calls: []ToolCall{toolCall("c2", "t")}},
		{Calls: []ToolCall{toolCall("c3", "t")}},
	}, synth: Turn{Text: "synth summary"}}
	fx := &fakeExec{}
	res, err := Run(context.Background(), fc, fx, "sys", "task", specs, Budget{MaxSteps: 2}, &fakeClock{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.StoppedBy != StoppedBudget {
		t.Fatalf("StoppedBy=%q want budget", res.StoppedBy)
	}
	if res.Steps < 2 {
		t.Fatalf("Steps=%d want >=2", res.Steps)
	}
	// A synthesis turn is not possible once MaxSteps is reached, so no summary.
	if res.FinalText == "synth summary" {
		t.Fatalf("should not synthesize past MaxSteps")
	}
}

func TestRunMaxToolCallsBudget(t *testing.T) {
	fc := &fakeCaller{turns: []Turn{
		{Calls: []ToolCall{toolCall("c1", "t"), toolCall("c2", "t")}},
		{Calls: []ToolCall{toolCall("c3", "t")}},
	}, synth: Turn{Text: "wrapped up within budget"}}
	fx := &fakeExec{}
	res, err := Run(context.Background(), fc, fx, "sys", "task", specs, Budget{MaxToolCalls: 2, MaxSteps: 10}, &fakeClock{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.StoppedBy != StoppedBudget {
		t.Fatalf("StoppedBy=%q want budget", res.StoppedBy)
	}
	if res.ToolCalls != 2 {
		t.Fatalf("ToolCalls=%d want 2", res.ToolCalls)
	}
	// Steps < MaxSteps and no wall/token cap, so a synthesis turn should run.
	if res.FinalText != "wrapped up within budget" {
		t.Fatalf("expected synthesis final text, got %q", res.FinalText)
	}
}

func TestRunMaxWallMsBudget(t *testing.T) {
	// Clock advances 100ms per read; MaxWallMs=50 trips on the first budget check.
	fc := &fakeCaller{turns: []Turn{
		{Calls: []ToolCall{toolCall("c1", "t")}},
	}}
	fx := &fakeExec{}
	clk := &fakeClock{step: 100 * time.Millisecond}
	res, err := Run(context.Background(), fc, fx, "sys", "task", specs, Budget{MaxWallMs: 50}, clk)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.StoppedBy != StoppedBudget {
		t.Fatalf("StoppedBy=%q want budget", res.StoppedBy)
	}
	// Budget hit BEFORE the first model turn, so no tool calls happened.
	if res.ToolCalls != 0 {
		t.Fatalf("ToolCalls=%d want 0", res.ToolCalls)
	}
}

func TestRunCtxCancelMidLoop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	fc := &fakeCaller{turns: []Turn{
		{Calls: []ToolCall{toolCall("c1", "t")}},
		{Text: "should not reach"},
	}}
	// Cancel after the first Complete call so cancellation lands mid-loop.
	fc.onCall = func(n int) {
		if n == 1 {
			cancel()
		}
	}
	fx := &fakeExec{}
	res, err := Run(ctx, fc, fx, "sys", "task", specs, Budget{}, &fakeClock{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v want context.Canceled", err)
	}
	if res.StoppedBy != StoppedCtx {
		t.Fatalf("StoppedBy=%q want ctx", res.StoppedBy)
	}
}

func TestRunCtxAlreadyCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fc := &fakeCaller{turns: []Turn{{Text: "unused"}}}
	res, err := Run(ctx, fc, &fakeExec{}, "sys", "task", specs, Budget{}, &fakeClock{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v want context.Canceled", err)
	}
	if res.StoppedBy != StoppedCtx {
		t.Fatalf("StoppedBy=%q want ctx", res.StoppedBy)
	}
	if fc.calls != 0 {
		t.Fatalf("caller invoked %d times; want 0 (ctx checked first)", fc.calls)
	}
}

func TestRunToolCallerError(t *testing.T) {
	fc := &fakeCaller{err: errors.New("provider 500")}
	res, err := Run(context.Background(), fc, &fakeExec{}, "sys", "task", specs, Budget{}, &fakeClock{})
	if err == nil || res.StoppedBy != StoppedError {
		t.Fatalf("err=%v StoppedBy=%q want error", err, res.StoppedBy)
	}
}

func TestRunToolExecutorError(t *testing.T) {
	fc := &fakeCaller{turns: []Turn{
		{Calls: []ToolCall{toolCall("c1", "boom")}},
	}}
	fx := &fakeExec{err: errors.New("exec failed")}
	res, err := Run(context.Background(), fc, fx, "sys", "task", specs, Budget{}, &fakeClock{})
	if err == nil || res.StoppedBy != StoppedError {
		t.Fatalf("err=%v StoppedBy=%q want error", err, res.StoppedBy)
	}
	// Transcript should include the assistant turn that requested the failing call.
	if len(res.Transcript) < 2 {
		t.Fatalf("expected task + assistant turn in transcript, got %+v", res.Transcript)
	}
}

func TestRunMaxTokensBudget(t *testing.T) {
	fc := &fakeCaller{turns: []Turn{
		{Calls: []ToolCall{toolCall("c1", "t")}, Usage: TokenUsage{InputTokens: 60, OutputTokens: 60}},
		{Text: "should not reach"},
	}}
	fx := &fakeExec{}
	res, err := Run(context.Background(), fc, fx, "sys", "task", specs, Budget{MaxTokens: 100, MaxSteps: 10}, &fakeClock{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.StoppedBy != StoppedBudget {
		t.Fatalf("StoppedBy=%q want budget", res.StoppedBy)
	}
	if res.Tokens < 100 {
		t.Fatalf("Tokens=%d want >=100", res.Tokens)
	}
	// MaxTokens already exceeded, so no synthesis turn.
	if res.FinalText == "should not reach" {
		t.Fatalf("should not run another turn past token budget")
	}
}

func TestRunUnboundedBudgetRunsToDone(t *testing.T) {
	fc := &fakeCaller{turns: []Turn{
		{Calls: []ToolCall{toolCall("c1", "t")}},
		{Text: "done now"},
	}}
	res, err := Run(context.Background(), fc, &fakeExec{}, "sys", "task", specs, Budget{}, &fakeClock{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.StoppedBy != StoppedDone || res.FinalText != "done now" {
		t.Fatalf("StoppedBy=%q FinalText=%q", res.StoppedBy, res.FinalText)
	}
}
