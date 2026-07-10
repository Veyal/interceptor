package store

import (
	"os"
	"strings"
	"testing"
	"time"
)

// Minimal 1x1 PNG (68 bytes).
var tinyPNG = []byte{
	0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d,
	0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
	0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53, 0xde, 0x00, 0x00, 0x00,
	0x0c, 0x49, 0x44, 0x41, 0x54, 0x08, 0xd7, 0x63, 0xf8, 0xcf, 0xc0, 0x00,
	0x00, 0x00, 0x03, 0x00, 0x01, 0x00, 0x05, 0xfe, 0xd4, 0xef, 0x00, 0x00,
	0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
}

func TestPutImageBytesAndAttachImage(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	hash, n, err := s.PutImageBytes("image/png", tinyPNG)
	if err != nil {
		t.Fatalf("PutImageBytes: %v", err)
	}
	if n != int64(len(tinyPNG)) || !isContentHash(hash) {
		t.Fatalf("unexpected hash/n: hash=%q n=%d", hash, n)
	}

	id, err := s.CreateFinding(&Finding{Severity: "High", Title: "xss", Detail: "intro", Target: "t.com"})
	if err != nil {
		t.Fatalf("CreateFinding: %v", err)
	}
	if err := s.AttachImage(id, hash, "image/png", "alert fired", 1); err != nil {
		t.Fatalf("AttachImage: %v", err)
	}

	got, err := s.GetFinding(id)
	if err != nil {
		t.Fatalf("GetFinding: %v", err)
	}
	if len(got.Blocks) < 2 {
		t.Fatalf("expected text+image, got %+v", got.Blocks)
	}
	// position 1 inserts between/after first text depending on length; with one
	// text block, pos=1 appends.
	var img *FindingBlock
	for i := range got.Blocks {
		if got.Blocks[i].Type == "image" {
			img = &got.Blocks[i]
			break
		}
	}
	if img == nil {
		t.Fatalf("no image block: %+v", got.Blocks)
	}
	if img.Hash != hash || img.Caption != "alert fired" || img.Missing {
		t.Fatalf("image block wrong: %+v", img)
	}
	if img.URL != "/api/findings/images/"+hash {
		t.Fatalf("url = %q", img.URL)
	}
	if img.Mime != "image/png" {
		t.Fatalf("mime = %q", img.Mime)
	}
}

func TestAttachImageMissingBlob(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	id, _ := s.CreateFinding(&Finding{Severity: "Low", Title: "t"})
	fake := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := s.AttachImage(id, fake, "image/png", "", -1); err == nil {
		t.Fatal("AttachImage should fail for missing blob")
	}
}

func TestBuildBlocksImageMissingWhenBlobGone(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	hash, _, err := s.PutImageBytes("image/png", tinyPNG)
	if err != nil {
		t.Fatalf("PutImageBytes: %v", err)
	}
	id, _ := s.CreateFinding(&Finding{Severity: "High", Title: "t"})
	if err := s.AttachImage(id, hash, "image/png", "cap", -1); err != nil {
		t.Fatalf("AttachImage: %v", err)
	}
	if err := os.Remove(s.bodyPath(hash)); err != nil {
		t.Fatalf("remove blob: %v", err)
	}
	got, err := s.GetFinding(id)
	if err != nil {
		t.Fatalf("GetFinding: %v", err)
	}
	var saw bool
	for _, b := range got.Blocks {
		if b.Type == "image" && b.Hash == hash {
			saw = true
			if !b.Missing {
				t.Fatalf("expected Missing=true: %+v", b)
			}
		}
	}
	if !saw {
		t.Fatalf("image block gone: %+v", got.Blocks)
	}
}

func TestGCBodiesKeepsFindingImageHash(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	hash, _, err := s.PutImageBytes("image/png", tinyPNG)
	if err != nil {
		t.Fatalf("PutImageBytes: %v", err)
	}
	id, _ := s.CreateFinding(&Finding{Severity: "High", Title: "t", TS: time.Now().UnixMilli()})
	if err := s.AttachImage(id, hash, "image/png", "keep", -1); err != nil {
		t.Fatalf("AttachImage: %v", err)
	}

	removed, _, err := s.GCBodies()
	if err != nil {
		t.Fatalf("GCBodies: %v", err)
	}
	if removed != 0 {
		t.Fatalf("GC should keep finding image, removed=%d", removed)
	}
	if !s.BodyExists(hash) {
		t.Fatal("finding image blob was deleted by GC")
	}
}

func TestPutImageBytesRejectsEmptyAndHuge(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	if _, _, err := s.PutImageBytes("image/png", nil); err == nil {
		t.Fatal("empty should fail")
	}
	huge := make([]byte, maxNotesImageBytes+1)
	if _, _, err := s.PutImageBytes("image/png", huge); err == nil {
		t.Fatal("oversized should fail")
	}
}

func TestMarshalBodyStripsImageURL(t *testing.T) {
	body := marshalBody([]FindingBlock{
		{Type: "image", Hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Mime: "image/png", Caption: "c", URL: "/api/findings/images/aa", Missing: true},
	})
	if body == "" {
		t.Fatal("empty body")
	}
	if strings.Contains(body, `"url"`) || strings.Contains(body, `"missing"`) {
		t.Fatalf("enriched fields leaked into stored body: %s", body)
	}
	if !strings.Contains(body, `"hash"`) || !strings.Contains(body, `"caption"`) {
		t.Fatalf("expected hash/caption persisted: %s", body)
	}
}
