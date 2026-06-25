package store

import "testing"

// AI activity is persisted per-project so it survives restarts; ListActivity
// returns it newest-first, bounded by limit.
func TestActivityStore(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	if got, err := s.ListActivity(50); err != nil || len(got) != 0 {
		t.Fatalf("empty: got %d (err %v)", len(got), err)
	}

	for i := int64(1); i <= 3; i++ {
		id, err := s.InsertActivity(&Activity{TS: i, Tool: "list_flows", Summary: "n=2", OK: true, Result: "ok", Ms: 5})
		if err != nil || id == 0 {
			t.Fatalf("insert %d: id=%d err=%v", i, id, err)
		}
	}

	got, err := s.ListActivity(50)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d, want 3", len(got))
	}
	if got[0].ID <= got[2].ID {
		t.Fatalf("not newest-first: %d then %d", got[0].ID, got[2].ID)
	}
	if got[0].Tool != "list_flows" || !got[0].OK {
		t.Fatalf("round-trip wrong: %+v", got[0])
	}
	if lim, _ := s.ListActivity(2); len(lim) != 2 {
		t.Fatalf("limit: got %d, want 2", len(lim))
	}
}

// DeleteActivity wipes the feed — a persisted clear, so it stays empty on reload.
func TestDeleteActivity(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	for i := int64(1); i <= 3; i++ {
		if _, err := s.InsertActivity(&Activity{TS: i, Tool: "x", OK: true}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.DeleteActivity(); err != nil {
		t.Fatalf("DeleteActivity: %v", err)
	}
	if got, _ := s.ListActivity(50); len(got) != 0 {
		t.Fatalf("after clear: got %d, want 0", len(got))
	}
}
