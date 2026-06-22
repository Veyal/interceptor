package tlsca

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreatePersists(t *testing.T) {
	dir := t.TempDir()
	ca1, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	// Files written.
	for _, name := range []string{"ca.crt", "ca.key"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("expected %s on disk: %v", name, err)
		}
	}
	ca2, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if string(ca1.CertPEM()) != string(ca2.CertPEM()) {
		t.Fatal("expected reloaded CA to equal the persisted one")
	}
}

func TestLeafForHostVerifiesAgainstCA(t *testing.T) {
	ca, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	leaf, err := ca.LeafForHost("example.com")
	if err != nil {
		t.Fatalf("LeafForHost: %v", err)
	}
	x, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca.CertPEM()) {
		t.Fatal("failed to add CA to pool")
	}
	if _, err := x.Verify(x509.VerifyOptions{DNSName: "example.com", Roots: roots}); err != nil {
		t.Fatalf("leaf does not chain to CA: %v", err)
	}

	// Cached: same host returns an identical leaf certificate.
	leaf2, err := ca.LeafForHost("example.com")
	if err != nil {
		t.Fatalf("LeafForHost cached: %v", err)
	}
	if &leaf.Certificate[0] == nil || string(leaf.Certificate[0]) != string(leaf2.Certificate[0]) {
		t.Fatal("expected cached leaf to be reused")
	}
}

func TestTLSConfigUsesSNI(t *testing.T) {
	ca, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	cfg := ca.TLSConfig()
	cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "host.test"})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	x, _ := x509.ParseCertificate(cert.Certificate[0])
	if len(x.DNSNames) == 0 || x.DNSNames[0] != "host.test" {
		t.Fatalf("expected SAN host.test, got %v", x.DNSNames)
	}
}
