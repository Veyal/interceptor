package rules

import (
	"bytes"
	"testing"
)

func TestListCatalog(t *testing.T) {
	packs, err := ListCatalog()
	if err != nil {
		t.Fatal(err)
	}
	if len(packs) != 3 {
		t.Fatalf("got %d packs: %+v", len(packs), packs)
	}
	if packs[0].Name != "api-jwt" || packs[0].Checks < 1 {
		t.Fatalf("first pack: %+v", packs[0])
	}
}

func TestBuildCatalogPack(t *testing.T) {
	var buf bytes.Buffer
	m, err := BuildCatalogPack("secrets", &buf)
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != "secrets" || len(m.Entries) < 1 {
		t.Fatalf("manifest: %+v", m)
	}
	if buf.Len() < 100 {
		t.Fatalf("pack too small: %d", buf.Len())
	}
}
