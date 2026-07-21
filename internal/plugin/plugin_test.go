package plugin

import (
	"sync"
	"testing"
)

func TestFlowHookFires(t *testing.T) {
	Reset()
	var got int64
	OnFlowCaptured(func(id int64) { got = id })
	EmitFlowCaptured(42)
	if got != 42 {
		t.Fatalf("got %d", got)
	}
}

func TestScanIssueHookFires(t *testing.T) {
	Reset()
	var (
		gotID        int64
		gotSev, gotT string
	)
	OnScanIssue(func(id int64, sev, title string) { gotID, gotSev, gotT = id, sev, title })
	EmitScanIssue(7, "High", "Reflected XSS")
	if gotID != 7 || gotSev != "High" || gotT != "Reflected XSS" {
		t.Fatalf("got %d %q %q", gotID, gotSev, gotT)
	}
}

func TestNilHooksIgnored(t *testing.T) {
	Reset()
	OnFlowCaptured(nil)
	OnScanIssue(nil)
	// Emitting with no registered hooks must not panic.
	EmitFlowCaptured(1)
	EmitScanIssue(1, "Low", "x")
}

func TestMultipleHooksAllFire(t *testing.T) {
	Reset()
	var mu sync.Mutex
	n := 0
	for i := 0; i < 3; i++ {
		OnFlowCaptured(func(int64) {
			mu.Lock()
			n++
			mu.Unlock()
		})
	}
	EmitFlowCaptured(1)
	if n != 3 {
		t.Fatalf("expected 3 hooks fired, got %d", n)
	}
}
