package ios

import (
	"testing"
)

func TestBuildProfileURL(t *testing.T) {
	t.Parallel()
	got := BuildProfileURL("http://192.168.1.5:9966", "192.168.1.5", 8080)
	want := "http://192.168.1.5:9966/api/ios/profile.mobileconfig?host=192.168.1.5&port=8080"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestShellQuote(t *testing.T) {
	t.Parallel()
	if shellQuote("http://x") != "'http://x'" {
		t.Fatal(shellQuote("http://x"))
	}
	if shellQuote("it's") != "'it'\\''s'" {
		t.Fatal(shellQuote("it's"))
	}
}

func TestResolveSSHOpts(t *testing.T) {
	t.Parallel()
	_, err := resolveSSHOpts(SSHOpts{})
	if err == nil {
		t.Fatal("expected host error")
	}
	opts, err := resolveSSHOpts(SSHOpts{Host: "10.0.0.2", Password: "alpine"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.User != defaultSSHUser || opts.Port != defaultSSHPort {
		t.Fatalf("defaults: %+v", opts)
	}
}

func TestSSHAvailable(t *testing.T) {
	if !SSHAvailable() {
		t.Fatal("expected SSH client available")
	}
}

func TestTCPReachableInvalid(t *testing.T) {
	if TCPReachable("", 22) {
		t.Fatal("empty host should not be reachable")
	}
}
