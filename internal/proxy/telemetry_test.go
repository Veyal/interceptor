package proxy

import (
	"testing"

	"github.com/Veyal/interseptor/internal/store"
)

func TestIsBrowserTelemetry(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"incoming.telemetry.mozilla.org", true},
		{"Incoming.Telemetry.Mozilla.Org:443", true},
		{"safebrowsing.googleapis.com", true},
		{"example.com", false},
		{"telemetry.example.com", false},
	}
	for _, c := range cases {
		if got := isBrowserTelemetry(c.host); got != c.want {
			t.Errorf("isBrowserTelemetry(%q)=%v, want %v", c.host, got, c.want)
		}
	}
}

func TestIsAndroidTelemetry(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"android.clients.google.com", true},
		{"Android.Clients.Google.Com:443", true},
		{"play.googleapis.com", true},
		{"connectivitycheck.gstatic.com", true},
		{"crashlyticsreports-pa.googleapis.com", true},
		{"reports.crashlytics.com", true},
		{"firebase-settings.crashlytics.com", true},
		{"region1.app-measurement.com", true},
		{"app-measurement.com", true},
		{"firebaselogging-pa.googleapis.com", true},
		{"googleads.g.doubleclick.net", true},
		// Must not suppress app backends / auth / push that testers need.
		{"example.com", false},
		{"api.example.com", false},
		{"firebase.googleapis.com", false},
		{"firestore.googleapis.com", false},
		{"accounts.google.com", false},
		{"mtalk.google.com", false},
		{"www.googleapis.com", false},
	}
	for _, c := range cases {
		if got := isAndroidTelemetry(c.host); got != c.want {
			t.Errorf("isAndroidTelemetry(%q)=%v, want %v", c.host, got, c.want)
		}
	}
}

func TestPersistableSuppressesAndroidTelemetry(t *testing.T) {
	s := &Server{}
	flow := &store.Flow{Host: "android.clients.google.com", Port: 443}

	// Default atomic false: still persist until cmd wires the setting on.
	if !s.persistable(flow) {
		t.Fatal("android telemetry should persist when suppression is off")
	}

	s.SetSuppressAndroidTelemetry(true)
	if s.persistable(flow) {
		t.Fatal("android telemetry must be dropped when suppression is on")
	}

	// Ordinary app host still persists.
	app := &store.Flow{Host: "api.example.com", Port: 443}
	if !s.persistable(app) {
		t.Fatal("non-telemetry host must still persist")
	}

	// Browser suppress must not affect Android hosts (and vice versa).
	s.SetSuppressAndroidTelemetry(false)
	s.SetSuppressBrowserTelemetry(true)
	if !s.persistable(flow) {
		t.Fatal("browser-only suppress must not drop android hosts")
	}
	browser := &store.Flow{Host: "incoming.telemetry.mozilla.org", Port: 443}
	if s.persistable(browser) {
		t.Fatal("browser telemetry must still be dropped by browser suppress")
	}
}
