package control

import (
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

// A stray projects/default directory must not duplicate the reserved "default"
// entry (the root project) that availableProjects always lists first.
func TestAvailableProjectsSkipsReservedDefault(t *testing.T) {
	tmp := t.TempDir()
	for _, n := range []string{"default", "beta", "acme"} {
		if err := os.MkdirAll(filepath.Join(tmp, "projects", n), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	got := (&projectAPI{&Hub{GlobalDir: tmp}}).availableProjects()
	want := []string{"default", "acme", "beta"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("availableProjects() = %v, want %v", got, want)
	}
}

// scheduleProjectSwitch must dedup: rapid repeated switches cancel earlier
// pending timers so only the LAST target fires exactly once. Without the
// cancelable timer, every request would stack a delayed re-exec.
func TestScheduleProjectSwitchDedups(t *testing.T) {
	var mu sync.Mutex
	var fired []string
	h := &Hub{}
	h.SwitchProject = func(target string) error {
		mu.Lock()
		fired = append(fired, target)
		mu.Unlock()
		return nil
	}

	// Fire several switches in quick succession; each within the delay window.
	for _, target := range []string{"a", "b", "c"} {
		h.scheduleProjectSwitch(target, 40*time.Millisecond)
	}

	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(fired) != 1 {
		t.Fatalf("expected exactly 1 switch to fire, got %d: %v", len(fired), fired)
	}
	if fired[0] != "c" {
		t.Fatalf("expected only the latest target 'c' to fire, got %q", fired[0])
	}
}
