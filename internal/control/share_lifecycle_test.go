package control

import (
	"context"
	"reflect"
	"testing"

	"github.com/Veyal/interseptor/internal/tunnel"
)

type lifecycleTunnel struct {
	calls []string
}

func (t *lifecycleTunnel) Status() tunnel.Status { return tunnel.Status{} }
func (t *lifecycleTunnel) Installed() bool       { return true }
func (t *lifecycleTunnel) SetOnURL(func(string)) {}
func (t *lifecycleTunnel) Start(context.Context) (tunnel.Status, error) {
	return tunnel.Status{}, nil
}
func (t *lifecycleTunnel) Stop() error {
	t.calls = append(t.calls, "stop")
	return nil
}
func (t *lifecycleTunnel) Close() {
	t.calls = append(t.calls, "close")
}

func TestHubCloseStopsThenClosesTunnelExactlyOnce(t *testing.T) {
	tun := &lifecycleTunnel{}
	h := &Hub{tun: tun}

	h.Close()
	h.Close()

	want := []string{"stop", "close"}
	if !reflect.DeepEqual(tun.calls, want) {
		t.Fatalf("tunnel lifecycle calls = %v, want %v", tun.calls, want)
	}
}
