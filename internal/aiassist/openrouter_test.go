package aiassist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidateOpenRouterKeyRejectsUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth/key" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer bad" {
			t.Fatalf("auth header %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	old := openRouterAuthKeyURL
	openRouterAuthKeyURL = srv.URL + "/api/v1/auth/key"
	defer func() { openRouterAuthKeyURL = old }()

	if err := ValidateOpenRouterKey(context.Background(), "bad"); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("expected invalid key error, got %v", err)
	}
}

func TestValidateOpenRouterKeyAcceptsOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	old := openRouterAuthKeyURL
	openRouterAuthKeyURL = srv.URL + "/api/v1/auth/key"
	defer func() { openRouterAuthKeyURL = old }()

	if err := ValidateOpenRouterKey(context.Background(), "sk-or-good"); err != nil {
		t.Fatalf("ValidateOpenRouterKey: %v", err)
	}
}

func TestListOpenRouterModelsParsesCatalog(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/models" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"z/model","name":"Zed"},{"id":"a/model","name":"Alpha"}]}`))
	}))
	defer srv.Close()

	old := openRouterModelsURL
	openRouterModelsURL = srv.URL + "/api/v1/models"
	defer func() { openRouterModelsURL = old }()

	models, err := ListOpenRouterModels(context.Background())
	if err != nil {
		t.Fatalf("ListOpenRouterModels: %v", err)
	}
	if len(models) != 2 || models[0].ID != "a/model" || models[1].ID != "z/model" {
		t.Fatalf("unexpected models: %+v", models)
	}
}

func TestValidateOpenRouterModelRequiresKnownID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"id":"openai/gpt-4o-mini","name":"Mini"}]}`))
	}))
	defer srv.Close()

	old := openRouterModelsURL
	openRouterModelsURL = srv.URL + "/api/v1/models"
	defer func() { openRouterModelsURL = old }()

	if err := ValidateOpenRouterModel(context.Background(), ""); err == nil {
		t.Fatal("expected empty model error")
	}
	if err := ValidateOpenRouterModel(context.Background(), "nope/model"); err == nil {
		t.Fatal("expected unknown model error")
	}
	if err := ValidateOpenRouterModel(context.Background(), "openai/gpt-4o-mini"); err != nil {
		t.Fatalf("expected known model ok, got %v", err)
	}
}

func TestValidateOpenRouterCombinesKeyAndModel(t *testing.T) {
	var authHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/auth/key":
			authHits++
			w.WriteHeader(http.StatusOK)
		case "/api/v1/models":
			_, _ = w.Write([]byte(`{"data":[{"id":"anthropic/claude-3.5-haiku","name":"Haiku"}]}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	oldAuth, oldModels := openRouterAuthKeyURL, openRouterModelsURL
	openRouterAuthKeyURL = srv.URL + "/api/v1/auth/key"
	openRouterModelsURL = srv.URL + "/api/v1/models"
	defer func() {
		openRouterAuthKeyURL = oldAuth
		openRouterModelsURL = oldModels
	}()

	if err := ValidateOpenRouter(context.Background(), "sk-or-x", "anthropic/claude-3.5-haiku"); err != nil {
		t.Fatalf("ValidateOpenRouter: %v", err)
	}
	if authHits != 1 {
		t.Fatalf("expected one auth check, got %d", authHits)
	}
}
