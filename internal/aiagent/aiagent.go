// Package aiagent provides a provider-agnostic, budgeted tool-calling agent loop
// for the autonomous-pentest engine. It sits one level above internal/aiassist:
// the ToolCaller interface normalizes the Anthropic Messages format (Anthropic +
// GLM) and the OpenAI chat-completions format (OpenRouter + OpenAI) into a single
// {assistant text + tool calls} shape, and Run drives that shape as a hard-budgeted
// loop against an injected ToolExecutor. All external dependencies (the model
// caller, the tool executor, and the wall clock) are interfaces so the loop is
// unit-testable with fakes — no real API calls and no real wall-clock in tests.
package aiagent

import "context"

// ToolSpec describes one tool made available to the model for a turn.
type ToolSpec struct {
	Name        string
	Description string
	Schema      map[string]any // JSON Schema for the tool's input object
}

// ToolCall is a single tool invocation the model requested.
type ToolCall struct {
	ID   string
	Name string
	Args map[string]any
}

// Message is one entry in the running conversation history. Role is "user",
// "assistant", or "tool". For an assistant turn that requested tools, Calls holds
// the requested calls (so the ToolCaller can replay them to the provider in the
// correct wire format). For a tool-result message, ToolCallID ties the result back
// to the call that produced it.
type Message struct {
	Role       string
	Text       string
	Calls      []ToolCall // assistant messages: tool calls requested this turn
	ToolCallID string     // tool messages: the ToolCall.ID this result answers
}

// Turn is one model turn: the assistant's text plus any tool calls it requested.
// When Calls is empty the turn is a final answer.
type Turn struct {
	Text  string
	Calls []ToolCall
	// Usage is best-effort token accounting reported by the provider (0 when the
	// provider or transport does not surface it). MaxTokens budgeting is advisory
	// and driven off this field.
	Usage TokenUsage
}

// TokenUsage is best-effort per-turn token accounting.
type TokenUsage struct {
	InputTokens  int
	OutputTokens int
}

// Total returns input+output tokens for the turn.
func (u TokenUsage) Total() int { return u.InputTokens + u.OutputTokens }

// ToolCaller runs one model turn. Complete is given the system prompt, the running
// message history, and the tools available this turn; it returns the assistant's
// text plus any tool calls. Implementations translate to/from a provider wire
// format but expose only this normalized shape.
type ToolCaller interface {
	Complete(ctx context.Context, system string, msgs []Message, tools []ToolSpec) (Turn, error)
}
