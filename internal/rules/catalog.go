package rules

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

//go:embed catalog/*/checks/*.star
var catalogFS embed.FS

// CatalogPack describes a bundled pack available for one-click install.
type CatalogPack struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Author      string `json:"author"`
	Checks      int    `json:"checks"`
}

var catalogMeta = map[string]CatalogPack{
	"secrets": {
		Name: "secrets", Version: "1.0.0", Author: "Interseptor",
		Description: "Flag secret-looking JSON fields and credentials leaking in query strings.",
	},
	"api-jwt": {
		Name: "api-jwt", Version: "1.0.0", Author: "Interseptor",
		Description: "Detect JWTs exposed in responses and Authorization headers worth inspecting.",
	},
	"security-headers": {
		Name: "security-headers", Version: "1.0.0", Author: "Interseptor",
		Description: "Missing security headers, HSTS gaps, and insecure cookie flags.",
	},
}

// ListCatalog returns bundled packs (sorted by name) with check counts.
func ListCatalog() ([]CatalogPack, error) {
	names := make([]string, 0, len(catalogMeta))
	for n := range catalogMeta {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]CatalogPack, 0, len(names))
	for _, n := range names {
		meta := catalogMeta[n]
		entries, err := fs.Glob(catalogFS, "catalog/"+n+"/checks/*.star")
		if err != nil {
			return nil, err
		}
		meta.Checks = len(entries)
		out = append(out, meta)
	}
	return out, nil
}

// BuildCatalogPack writes a verified pack tarball for the named catalog entry
// into w. Sources are embedded; install uses the same sha256 gate as community packs.
func BuildCatalogPack(name string, w *bytes.Buffer) (Manifest, error) {
	meta, ok := catalogMeta[name]
	if !ok {
		return Manifest{}, fmt.Errorf("rules: unknown catalog pack %q", name)
	}
	dir, err := materializeCatalog(name)
	if err != nil {
		return Manifest{}, err
	}
	defer os.RemoveAll(filepath.Dir(dir)) // parent temp root
	return BuildPack(dir, Manifest{
		Name: meta.Name, Version: meta.Version, Description: meta.Description, Author: meta.Author,
		License: "MIT", Homepage: "https://github.com/Veyal/interseptor",
	}, w)
}

// materializeCatalog copies embedded stars into a temp dir shaped for BuildPack
// (…/checks/*.star). Returns the pack root path (parent of checks/).
func materializeCatalog(name string) (string, error) {
	root, err := os.MkdirTemp("", "interseptor-catalog-*")
	if err != nil {
		return "", err
	}
	packRoot := filepath.Join(root, name)
	checksDir := filepath.Join(packRoot, "checks")
	if err := os.MkdirAll(checksDir, 0o755); err != nil {
		os.RemoveAll(root)
		return "", err
	}
	entries, err := fs.Glob(catalogFS, "catalog/"+name+"/checks/*.star")
	if err != nil || len(entries) == 0 {
		os.RemoveAll(root)
		if err == nil {
			err = fmt.Errorf("rules: catalog pack %q has no checks", name)
		}
		return "", err
	}
	for _, ent := range entries {
		b, err := catalogFS.ReadFile(ent)
		if err != nil {
			os.RemoveAll(root)
			return "", err
		}
		dst := filepath.Join(checksDir, filepath.Base(ent))
		if err := os.WriteFile(dst, b, 0o644); err != nil {
			os.RemoveAll(root)
			return "", err
		}
	}
	return packRoot, nil
}
