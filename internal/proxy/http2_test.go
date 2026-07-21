package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Veyal/interseptor/internal/capture"
	"github.com/Veyal/interseptor/internal/store"
	"github.com/Veyal/interseptor/internal/tlsca"
	"golang.org/x/net/http2"
)

// TestMITMHTTP2ClientLeg exercises the full client↔proxy HTTP/2 MITM path (#19):
// the client negotiates h2 on the forged leaf, the proxy serves it with an
// http2.Server, forwards to an h2 origin, and records the flow with the client
// leg proto (HTTP/2.0) and an accurate method/path/body.
func TestMITMHTTP2ClientLeg(t *testing.T) {
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("origin expected HTTP/2, got %s", r.Proto)
		}
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "hello %s over %s body=%q", r.URL.Path, r.Proto, string(body))
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	defer origin.Close()

	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	ca, err := tlsca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("proxy CA: %v", err)
	}
	srv := New(s, capture.New(s), ca, nil, nil)
	// Trust the httptest origin's self-signed cert on the upstream leg.
	srv.tr.TLSClientConfig = &tls.Config{
		RootCAs:    originPool(origin),
		NextProtos: []string{"h2", "http/1.1"},
	}
	srv.tr.ForceAttemptHTTP2 = true

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go srv.Serve(ln)

	originHost := strings.TrimPrefix(origin.URL, "https://")

	// CONNECT to the origin through the proxy.
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", originHost, originHost)
	connResp, err := http.ReadResponse(bufio.NewReader(raw), &http.Request{Method: "CONNECT"})
	if err != nil || connResp.StatusCode != 200 {
		t.Fatalf("CONNECT failed: %v / %v", err, connResp)
	}

	// TLS to the proxy's minted leaf, offering h2 via ALPN.
	clientPool := x509.NewCertPool()
	clientPool.AppendCertsFromPEM(ca.CertPEM())
	host, _, _ := net.SplitHostPort(originHost)
	tlsClient := tls.Client(raw, &tls.Config{
		RootCAs:    clientPool,
		ServerName: host,
		NextProtos: []string{"h2"},
	})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	if got := tlsClient.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("client leg ALPN = %q, want h2", got)
	}

	// Drive HTTP/2 over the single MITM connection.
	tr := &http2.Transport{}
	cc, err := tr.NewClientConn(tlsClient)
	if err != nil {
		t.Fatalf("h2 NewClientConn: %v", err)
	}
	req, err := http.NewRequest("POST", "https://"+originHost+"/echo", strings.NewReader("payload"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("h2 round trip: %v", err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Fatalf("client response proto = %s, want HTTP/2", resp.Proto)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `body="payload"`) || !strings.Contains(string(body), "/echo") {
		t.Fatalf("unexpected body: %q", body)
	}

	// The flow is recorded with the client leg's HTTP/2 proto and real method/path.
	f := waitFlows(t, s, 1)[0]
	if f.Method != "POST" || f.Path != "/echo" {
		t.Fatalf("flow method/path = %s %s, want POST /echo", f.Method, f.Path)
	}
	if f.HTTPVersion != "HTTP/2.0" {
		t.Fatalf("flow HTTPVersion = %q, want HTTP/2.0", f.HTTPVersion)
	}
	if f.Status != http.StatusOK {
		t.Fatalf("flow status = %d, want 200", f.Status)
	}
	if f.ReqLen != int64(len("payload")) {
		t.Fatalf("flow req len = %d, want %d", f.ReqLen, len("payload"))
	}
}

func originPool(ts *httptest.Server) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	return pool
}
