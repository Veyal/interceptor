package aiassist

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

var (
	openRouterAuthKeyURL = "https://openrouter.ai/api/v1/auth/key"
	openRouterModelsURL  = "https://openrouter.ai/api/v1/models"
)

// OpenRouterModel is one entry from the OpenRouter model catalog.
type OpenRouterModel struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ValidateOpenRouterKey checks the API key against OpenRouter's auth endpoint.
// The public /models endpoint returns 200 even for invalid keys, so /auth/key is required.
func ValidateOpenRouterKey(ctx context.Context, key string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return fmt.Errorf("OpenRouter API key is required")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, openRouterAuthKeyURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("OpenRouter key check: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("invalid OpenRouter API key")
	}
	if resp.StatusCode >= 400 {
		if msg := apiErrorMessage(raw); msg != "" {
			return fmt.Errorf("OpenRouter key check: %s", msg)
		}
		return fmt.Errorf("OpenRouter key check: HTTP %d", resp.StatusCode)
	}
	return nil
}

// ListOpenRouterModels returns chat models from the OpenRouter catalog.
func ListOpenRouterModels(ctx context.Context) ([]OpenRouterModel, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, openRouterModelsURL, nil)
	if err != nil {
		return nil, err
	}
	cl := &http.Client{Timeout: 30 * time.Second}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OpenRouter models: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		if msg := apiErrorMessage(raw); msg != "" {
			return nil, fmt.Errorf("OpenRouter models: %s", msg)
		}
		return nil, fmt.Errorf("OpenRouter models: HTTP %d", resp.StatusCode)
	}
	var body struct {
		Data []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("OpenRouter models: bad response")
	}
	out := make([]OpenRouterModel, 0, len(body.Data))
	for _, m := range body.Data {
		if m.ID == "" {
			continue
		}
		name := m.Name
		if name == "" {
			name = m.ID
		}
		out = append(out, OpenRouterModel{ID: m.ID, Name: name})
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out, nil
}

// ValidateOpenRouterModel ensures model is non-empty and present in the catalog.
func ValidateOpenRouterModel(ctx context.Context, model string) error {
	model = strings.TrimSpace(model)
	if model == "" {
		return fmt.Errorf("OpenRouter model is required — pick one from the list")
	}
	models, err := ListOpenRouterModels(ctx)
	if err != nil {
		return err
	}
	for _, m := range models {
		if m.ID == model {
			return nil
		}
	}
	return fmt.Errorf("unknown OpenRouter model %q — reload the model list and pick a valid entry", model)
}

// ValidateOpenRouter checks key and model before saving OpenRouter settings.
func ValidateOpenRouter(ctx context.Context, key, model string) error {
	if err := ValidateOpenRouterKey(ctx, key); err != nil {
		return err
	}
	return ValidateOpenRouterModel(ctx, model)
}
