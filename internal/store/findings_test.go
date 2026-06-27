package store

import (
	"testing"
	"time"
)

func TestFindingsCRUDAndPoCFlows(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	// Two flows to attach as PoC evidence.
	f1, _ := s.InsertFlow(&Flow{TS: time.UnixMilli(1), Method: "GET", Host: "t.com", Path: "/user/1", Status: 200})
	f2, _ := s.InsertFlow(&Flow{TS: time.UnixMilli(2), Method: "GET", Host: "t.com", Path: "/user/2", Status: 200})

	id, err := s.CreateFinding(&Finding{Severity: "high", Status: "open", Source: "ai", Title: "IDOR on /user/{id}", Target: "t.com"})
	if err != nil {
		t.Fatalf("CreateFinding: %v", err)
	}

	// Attach both flows as PoCs; one with a note.
	if err := s.AttachFlow(id, f1, "baseline as user 1"); err != nil {
		t.Fatalf("AttachFlow f1: %v", err)
	}
	if err := s.AttachFlow(id, f2, "read user 2's data"); err != nil {
		t.Fatalf("AttachFlow f2: %v", err)
	}

	got, err := s.GetFinding(id)
	if err != nil {
		t.Fatalf("GetFinding: %v", err)
	}
	if got.Severity != "High" || got.Status != "open" || got.Source != "ai" {
		t.Fatalf("normalization wrong: %+v", got)
	}
	if len(got.Flows) != 2 {
		t.Fatalf("expected 2 PoC flows, got %d", len(got.Flows))
	}
	// PoC flows are enriched with the flow summary and ordered.
	if got.Flows[0].FlowID != f1 || got.Flows[0].Path != "/user/1" || got.Flows[0].Note != "baseline as user 1" {
		t.Fatalf("PoC[0] wrong: %+v", got.Flows[0])
	}
	if got.Flows[1].FlowID != f2 || got.Flows[1].Path != "/user/2" {
		t.Fatalf("PoC[1] wrong: %+v", got.Flows[1])
	}

	// Re-attach updates the note, doesn't duplicate.
	if err := s.AttachFlow(id, f1, "updated note"); err != nil {
		t.Fatalf("re-AttachFlow: %v", err)
	}
	got, _ = s.GetFinding(id)
	if len(got.Flows) != 2 || got.Flows[0].Note != "updated note" {
		t.Fatalf("re-attach should update note, not duplicate: %+v", got.Flows)
	}

	// Update status; list filter by status.
	verified := "verified"
	if err := s.UpdateFinding(id, nil, &verified, nil, nil, nil, nil, nil, nil); err != nil {
		t.Fatalf("UpdateFinding: %v", err)
	}
	open, _ := s.ListFindings("", "open")
	if len(open) != 0 {
		t.Fatalf("status filter: expected 0 open, got %d", len(open))
	}
	ver, _ := s.ListFindings("", "verified")
	if len(ver) != 1 || ver[0].UpdatedTS < ver[0].TS {
		t.Fatalf("status filter: expected 1 verified with bumped updated_ts, got %+v", ver)
	}

	// Detach one PoC.
	if err := s.DetachFlow(id, f1); err != nil {
		t.Fatalf("DetachFlow: %v", err)
	}
	got, _ = s.GetFinding(id)
	if len(got.Flows) != 1 || got.Flows[0].FlowID != f2 {
		t.Fatalf("after detach expected only f2, got %+v", got.Flows)
	}

	// Delete finding removes its attachments.
	if err := s.DeleteFinding(id); err != nil {
		t.Fatalf("DeleteFinding: %v", err)
	}
	all, _ := s.ListFindings("", "")
	if len(all) != 0 {
		t.Fatalf("expected 0 findings after delete, got %d", len(all))
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM finding_flows WHERE finding_id=?`, id).Scan(&n)
	if n != 0 {
		t.Fatalf("expected PoC attachments gone after delete, got %d", n)
	}
}

// TestFindingFlowMissingAfterPurge verifies that when a PoC flow is purged from
// history (deleted from the flows table) but its finding_flows attachment and the
// body flow block survive, reading the finding marks the flow block as Missing.
func TestFindingFlowMissingAfterPurge(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	keep, _ := s.InsertFlow(&Flow{TS: time.UnixMilli(1), Method: "GET", Host: "t.com", Path: "/keep", Status: 200})
	gone, _ := s.InsertFlow(&Flow{TS: time.UnixMilli(2), Method: "GET", Host: "t.com", Path: "/gone", Status: 200})

	id, err := s.CreateFinding(&Finding{Severity: "High", Title: "PoC purge test", Target: "t.com"})
	if err != nil {
		t.Fatalf("CreateFinding: %v", err)
	}
	if err := s.AttachFlow(id, keep, "present evidence"); err != nil {
		t.Fatalf("AttachFlow keep: %v", err)
	}
	if err := s.AttachFlow(id, gone, "soon-purged evidence"); err != nil {
		t.Fatalf("AttachFlow gone: %v", err)
	}

	// Purge one flow from history (simulating prune_history / GC). The finding_flows
	// row and the body flow block are intentionally left intact.
	if _, err := s.db.Exec(`DELETE FROM flows WHERE id=?`, gone); err != nil {
		t.Fatalf("delete flow: %v", err)
	}

	got, err := s.GetFinding(id)
	if err != nil {
		t.Fatalf("GetFinding: %v", err)
	}

	// Both attachment rows survive; only the purged one is Missing.
	if len(got.Flows) != 2 {
		t.Fatalf("expected 2 attachment rows preserved, got %d", len(got.Flows))
	}
	var sawMissing, sawPresent bool
	for _, fl := range got.Flows {
		switch fl.FlowID {
		case keep:
			if fl.Missing {
				t.Fatalf("kept flow should not be Missing: %+v", fl)
			}
			if fl.Path != "/keep" {
				t.Fatalf("kept flow lost metadata: %+v", fl)
			}
			sawPresent = true
		case gone:
			if !fl.Missing {
				t.Fatalf("purged flow should be Missing: %+v", fl)
			}
			if fl.Note != "soon-purged evidence" {
				t.Fatalf("purged flow lost its annotation: %+v", fl)
			}
			sawMissing = true
		}
	}
	if !sawMissing || !sawPresent {
		t.Fatalf("expected one present + one missing flow, got %+v", got.Flows)
	}

	// The narrative body flow block for the purged flow is marked Missing too, with
	// its note preserved; the present flow's block stays enriched.
	var missBlock, keepBlock *FindingBlock
	for i := range got.Blocks {
		if got.Blocks[i].Type != "flow" {
			continue
		}
		switch got.Blocks[i].FlowID {
		case gone:
			missBlock = &got.Blocks[i]
		case keep:
			keepBlock = &got.Blocks[i]
		}
	}
	if missBlock == nil || !missBlock.Missing {
		t.Fatalf("body flow block for purged flow should be Missing: %+v", got.Blocks)
	}
	if missBlock.Note != "soon-purged evidence" {
		t.Fatalf("missing block annotation not preserved: %+v", missBlock)
	}
	if keepBlock == nil || keepBlock.Missing {
		t.Fatalf("body flow block for kept flow should not be Missing: %+v", got.Blocks)
	}
}
