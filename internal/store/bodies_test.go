package store

import (
	"io"
	"testing"
)

func TestBodyWriterStoreDedupAndRead(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	write := func(data string) (string, int64) {
		w, err := s.NewBodyWriter()
		if err != nil {
			t.Fatalf("NewBodyWriter: %v", err)
		}
		if _, err := io.WriteString(w, data); err != nil {
			t.Fatalf("write: %v", err)
		}
		hash, n, err := w.Finalize()
		if err != nil {
			t.Fatalf("Finalize: %v", err)
		}
		return hash, n
	}

	h1, n1 := write("hello world")
	h2, n2 := write("hello world") // identical -> dedup, same hash
	if h1 != h2 {
		t.Fatalf("expected identical hashes, got %s vs %s", h1, h2)
	}
	if n1 != 11 || n2 != 11 {
		t.Fatalf("expected len 11, got %d/%d", n1, n2)
	}

	rc, err := s.OpenBody(h1)
	if err != nil {
		t.Fatalf("OpenBody: %v", err)
	}
	defer rc.Close()
	got, _ := io.ReadAll(rc)
	if string(got) != "hello world" {
		t.Fatalf("body mismatch: %q", got)
	}

	empty, err := s.OpenBody("")
	if err != nil {
		t.Fatalf("OpenBody empty: %v", err)
	}
	defer empty.Close()
	if b, _ := io.ReadAll(empty); len(b) != 0 {
		t.Fatalf("expected empty body for empty hash, got %q", b)
	}
}
