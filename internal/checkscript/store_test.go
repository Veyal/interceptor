package checkscript

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveListReadDelete(t *testing.T) {
	dir := t.TempDir()

	// Save validates compilation first: a broken check is refused, nothing written.
	if err := Save(dir, "broken", `def check(flow): return open("x")`); err == nil {
		t.Fatal("expected Save to reject a non-compiling check")
	}
	if _, err := os.Stat(filepath.Join(dir, "broken.star")); !os.IsNotExist(err) {
		t.Fatal("a rejected check must not be written to disk")
	}

	// A valid check saves, lists, and reads back.
	src := "def check(flow):\n    return []\n"
	if err := Save(dir, "noop", src); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Read(dir, "noop")
	if err != nil || got != src {
		t.Fatalf("Read mismatch: %q %v", got, err)
	}
	list := List(dir)
	if len(list) != 1 || list[0].ID != "noop" || list[0].Error != "" {
		t.Fatalf("List wrong: %+v", list)
	}

	// Delete removes it.
	if err := Delete(dir, "noop"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(List(dir)) != 0 {
		t.Fatal("expected empty list after delete")
	}
}

func TestListSurfacesCompileErrors(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "bad.star"), []byte(`this is not starlark!`), 0o644)
	list := List(dir)
	if len(list) != 1 || list[0].Error == "" {
		t.Fatalf("expected a surfaced compile error, got %+v", list)
	}
}

func TestIDsAreSandboxed(t *testing.T) {
	dir := t.TempDir()
	for _, bad := range []string{"../evil", "a/b", "..", "", "with space", strings.Repeat("x", 100)} {
		if ValidID(bad) {
			t.Errorf("%q should be an invalid id", bad)
		}
		if err := Save(dir, bad, "def check(flow): return []"); err == nil {
			t.Errorf("Save must reject unsafe id %q", bad)
		}
	}
	for _, ok := range []string{"missing-hsts", "jwt_leak", "Check1"} {
		if !ValidID(ok) {
			t.Errorf("%q should be a valid id", ok)
		}
	}
}

func TestMergeDir(t *testing.T) {
	src := filepath.Join(t.TempDir(), "src")
	dst := t.TempDir()
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "a.star"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	n, err := MergeDir(src, dst)
	if err != nil || n != 1 {
		t.Fatalf("MergeDir = %d, %v", n, err)
	}
	n, err = MergeDir(src, dst)
	if err != nil || n != 0 {
		t.Fatalf("second MergeDir = %d, %v", n, err)
	}
	n, err = MergeDir(filepath.Join(t.TempDir(), "missing"), dst)
	if err != nil || n != 0 {
		t.Fatalf("missing src MergeDir = %d, %v", n, err)
	}
}
