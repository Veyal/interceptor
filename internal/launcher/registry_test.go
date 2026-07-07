package launcher

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRegistryRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "instances.json")

	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(r.All()) != 0 {
		t.Fatalf("expected empty registry, got %v", r.All())
	}

	inst := Instance{Project: "acme", ControlAddr: "127.0.0.1:9967", ProxyAddr: "127.0.0.1:8081", PID: 4242}
	if err := r.Upsert(inst); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	got, ok := r.Get("acme")
	if !ok || got.PID != 4242 {
		t.Fatalf("Get after Upsert = %+v, %v", got, ok)
	}

	// Reload from disk to confirm persistence.
	r2, err := Open(path)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	got2, ok := r2.Get("acme")
	if !ok || got2.ControlAddr != inst.ControlAddr {
		t.Fatalf("Get after re-Open = %+v, %v", got2, ok)
	}

	if err := r2.Remove("acme"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, ok := r2.Get("acme"); ok {
		t.Fatalf("expected acme removed")
	}
}

func TestRegistryOpenMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nope", "instances.json")
	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open missing file should not error: %v", err)
	}
	if len(r.All()) != 0 {
		t.Fatalf("expected empty registry for missing file")
	}
}

func TestRegistryOpenCorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "instances.json")
	if err := os.WriteFile(path, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open corrupt file should not error: %v", err)
	}
	if len(r.All()) != 0 {
		t.Fatalf("expected empty registry for corrupt file")
	}
}

func TestRegistryReconcile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "instances.json")
	r, _ := Open(path)

	_ = r.Upsert(Instance{Project: "alive", PID: 1})
	_ = r.Upsert(Instance{Project: "dead", PID: 2})

	isAlive := func(pid int) bool { return pid == 1 }
	if err := r.Reconcile(isAlive); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if _, ok := r.Get("alive"); !ok {
		t.Fatalf("expected alive instance to remain")
	}
	if _, ok := r.Get("dead"); ok {
		t.Fatalf("expected dead instance to be pruned")
	}

	// Persisted too.
	r2, _ := Open(path)
	if len(r2.All()) != 1 {
		t.Fatalf("expected 1 instance persisted after reconcile, got %v", r2.All())
	}
}
