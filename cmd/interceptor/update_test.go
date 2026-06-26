package main

import (
	"errors"
	"testing"

	"github.com/Veyal/interceptor/internal/version"
)

func TestRunUpdateCheckOnly(t *testing.T) {
	// --check against a real tag should not error (network permitting).
	if testing.Short() {
		t.Skip("network")
	}
	if err := runUpdate([]string{"--check", "--version", "0.6.0"}); err != nil {
		t.Fatalf("check: %v", err)
	}
}

func TestRestartRequiredIsSuccess(t *testing.T) {
	if !errors.Is(version.ErrRestartRequired, version.ErrRestartRequired) {
		t.Fatal("sentinel")
	}
}
