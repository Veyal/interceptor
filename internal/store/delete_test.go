package store

import (
	"testing"
	"time"
)

// DeleteFlows removes the given flow rows and reports how many were deleted;
// an empty id list is a no-op.
func TestDeleteFlows(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	var ids []int64
	for i := 0; i < 3; i++ {
		id, err := s.InsertFlow(&Flow{TS: time.UnixMilli(int64(i + 1)), Method: "GET", Host: "h", Path: "/x"})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}

	n, err := s.DeleteFlows(ids[:2])
	if err != nil {
		t.Fatalf("DeleteFlows: %v", err)
	}
	if n != 2 {
		t.Fatalf("deleted %d, want 2", n)
	}
	got, err := s.QueryFlowsFilter(FlowFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != ids[2] {
		t.Fatalf("after delete: got %d flows, want only the third", len(got))
	}
	if n, _ := s.DeleteFlows(nil); n != 0 {
		t.Fatalf("empty delete should be a no-op, got n=%d", n)
	}
}
