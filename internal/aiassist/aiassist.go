// Package aiassist is an optional, bring-your-own-key bridge to an LLM that
// explains requests, suggests payloads, and summarizes findings. It is off until
// the user supplies an API key, and it only ever talks to the configured
// provider — captured traffic is sent only when the user explicitly asks.
package aiassist

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DefaultModel is a fast, inexpensive model suitable for assist tasks.
const DefaultModel = "claude-haiku-4-5-20251001"

const defaultEndpoint = "https://api.anthropic.com/v1/messages"

// Client calls the Anthropic Messages API with a user-provided key.
type Client struct {
	key      string
	model    string
	endpoint string
	cl       *http.Client
}

// New returns a client. An empty model uses DefaultModel.
func New(key, model string) *Client {
	if model == "" {
		model = DefaultModel
	}
	return &Client{key: key, model: model, endpoint: defaultEndpoint, cl: &http.Client{Timeout: 60 * time.Second}}
}

type messagesRequest struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	System    string    `json:"system,omitempty"`
	Messages  []message `json:"messages"`
}
type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
type messagesResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// Complete sends a system + user prompt and returns the model's text reply.
func (c *Client) Complete(system, user string) (string, error) {
	if c.key == "" {
		return "", fmt.Errorf("no API key configured")
	}
	body, _ := json.Marshal(messagesRequest{
		Model: c.model, MaxTokens: 1024, System: system,
		Messages: []message{{Role: "user", Content: user}},
	})
	req, err := http.NewRequest(http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("x-api-key", c.key)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("content-type", "application/json")

	resp, err := c.cl.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var mr messagesResponse
	if err := json.Unmarshal(raw, &mr); err != nil {
		return "", fmt.Errorf("ai response: %s", string(raw))
	}
	if mr.Error != nil {
		return "", fmt.Errorf("ai: %s", mr.Error.Message)
	}
	var out string
	for _, c := range mr.Content {
		if c.Type == "text" {
			out += c.Text
		}
	}
	return out, nil
}
