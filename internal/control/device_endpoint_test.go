package control

import "testing"

func TestResolveDeviceProxyEndpointAutoLANListener(t *testing.T) {
	ep := ResolveDeviceProxyEndpoint(
		[]string{"127.0.0.1:8080", "192.168.1.5:8080"},
		"auto", "",
	)
	if ep.Endpoint != "192.168.1.5:8080" {
		t.Fatalf("endpoint = %q, want 192.168.1.5:8080 (source %s)", ep.Endpoint, ep.Source)
	}
	if ep.Source != "lan_listener" && ep.Source != "external_listener" {
		t.Fatalf("source = %q", ep.Source)
	}
}

func TestResolveDeviceProxyEndpointAutoAllInterfaces(t *testing.T) {
	ep := ResolveDeviceProxyEndpoint(
		[]string{"127.0.0.1:8080", "0.0.0.0:8080"},
		"auto", "",
	)
	if ep.Host == "127.0.0.1" {
		t.Fatalf("expected LAN-mapped host, got loopback %q", ep.Endpoint)
	}
	if ep.Port != 8080 {
		t.Fatalf("port = %d", ep.Port)
	}
	if ep.Source != "all_interfaces" {
		t.Fatalf("source = %q", ep.Source)
	}
}

func TestResolveDeviceProxyEndpointLoopbackOnly(t *testing.T) {
	ep := ResolveDeviceProxyEndpoint([]string{"127.0.0.1:8080"}, "auto", "")
	if ep.Endpoint != "127.0.0.1:8080" {
		t.Fatalf("endpoint = %q", ep.Endpoint)
	}
	if ep.Source != "loopback" {
		t.Fatalf("source = %q", ep.Source)
	}
}

func TestResolveDeviceProxyEndpointManualOverride(t *testing.T) {
	ep := ResolveDeviceProxyEndpoint(
		[]string{"127.0.0.1:8080", "0.0.0.0:8080"},
		"manual", "10.0.0.50",
	)
	if ep.Endpoint != "10.0.0.50:8080" {
		t.Fatalf("endpoint = %q", ep.Endpoint)
	}
	if ep.Mode != "manual" || ep.Source != "manual" {
		t.Fatalf("mode=%q source=%q", ep.Mode, ep.Source)
	}
}

func TestResolveDeviceProxyEndpointManualHostPort(t *testing.T) {
	ep := ResolveDeviceProxyEndpoint([]string{"0.0.0.0:9090"}, "manual", "10.0.0.50:9090")
	if ep.Endpoint != "10.0.0.50:9090" {
		t.Fatalf("endpoint = %q", ep.Endpoint)
	}
}

func TestResolveDeviceProxyEndpointEmptyManualFallsBackAuto(t *testing.T) {
	ep := ResolveDeviceProxyEndpoint([]string{"0.0.0.0:8080"}, "manual", "")
	if ep.Mode != "auto" {
		t.Fatalf("empty manual host should behave as auto, mode=%q", ep.Mode)
	}
}
