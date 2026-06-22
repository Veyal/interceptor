package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Veyal/interceptor/internal/capture"
	"github.com/Veyal/interceptor/internal/intercept"
	"github.com/Veyal/interceptor/internal/store"
	"github.com/Veyal/interceptor/internal/tlsca"
)

func waitFlows(t *testing.T, s *store.Store, n int) []*store.Flow {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		flows, _ := s.QueryFlows(50)
		if len(flows) >= n {
			return flows
		}
		time.Sleep(10 * time.Millisecond)
	}
	flows, _ := s.QueryFlows(50)
	t.Fatalf("expected %d flows, got %d", n, len(flows))
	return nil
}

func TestProxyMITMCapturesHTTPS(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "echo:"+string(body))
	}))
	defer upstream.Close()

	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	ca, err := tlsca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	srv := New(s, capture.New(s), ca, nil, nil)

	// The proxy must trust the test upstream's self-signed cert.
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())
	srv.tr.TLSClientConfig = &tls.Config{RootCAs: upstreamPool}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go srv.Serve(ln)

	// The client must trust our CA (it terminates TLS with a minted leaf).
	clientPool := x509.NewCertPool()
	if !clientPool.AppendCertsFromPEM(ca.CertPEM()) {
		t.Fatal("add CA to client pool")
	}
	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: clientPool},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Post(upstream.URL+"/submit", "text/plain", strings.NewReader("ping"))
	if err != nil {
		t.Fatalf("https request through proxy: %v", err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(got) != "echo:ping" {
		t.Fatalf("unexpected response body: %q", got)
	}

	f := waitFlows(t, s, 1)[0]
	if f.Scheme != "https" || f.Method != "POST" || f.Path != "/submit" || f.Status != 200 {
		t.Fatalf("unexpected MITM flow: %+v", f)
	}
	if f.ReqLen != 4 || f.ResBodyHash == "" {
		t.Fatalf("expected captured bodies: reqLen=%d resHash=%q", f.ReqLen, f.ResBodyHash)
	}
}

func TestProxyInterceptHoldThenForward(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	eng := intercept.New()
	eng.SetEnabled(true)
	srv := New(s, capture.New(s), nil, eng, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go srv.Serve(ln)

	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}

	done := make(chan string, 1)
	go func() {
		resp, err := client.Get(upstream.URL + "/held")
		if err != nil {
			done <- "err:" + err.Error()
			return
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		done <- string(b)
	}()

	// Wait until the request is sitting in the hold queue, then forward it.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(eng.Queue()) == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if len(eng.Queue()) != 1 {
		t.Fatalf("expected 1 held request, got %d", len(eng.Queue()))
	}
	if err := eng.Forward(eng.Queue()[0].ID, nil); err != nil {
		t.Fatalf("Forward: %v", err)
	}

	select {
	case body := <-done:
		if body != "ok" {
			t.Fatalf("unexpected client body: %q", body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client never got a response after forward")
	}

	f := waitFlows(t, s, 1)[0]
	if f.Flags&store.FlagIntercepted == 0 {
		t.Fatalf("expected FlagIntercepted set, flags=%d", f.Flags)
	}
}

func TestProxyForwardsAndCapturesFlow(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		io.WriteString(w, "echo:"+string(body))
	}))
	defer upstream.Close()

	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	srv := New(s, capture.New(s), nil, nil, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go srv.Serve(ln)

	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}

	resp, err := client.Post(upstream.URL+"/submit", "text/plain", strings.NewReader("ping"))
	if err != nil {
		t.Fatalf("request through proxy: %v", err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(got) != "echo:ping" {
		t.Fatalf("unexpected response body: %q", got)
	}

	// Allow the proxy goroutine to finish recording the flow.
	deadline := time.Now().Add(2 * time.Second)
	var flows []*store.Flow
	for time.Now().Before(deadline) {
		flows, _ = s.QueryFlows(10)
		if len(flows) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(flows) != 1 {
		t.Fatalf("expected 1 captured flow, got %d", len(flows))
	}
	f := flows[0]
	if f.Method != "POST" || f.Status != 200 || f.Path != "/submit" {
		t.Fatalf("unexpected flow: %+v", f)
	}
	if f.ReqLen != 4 { // "ping"
		t.Fatalf("expected req body len 4, got %d", f.ReqLen)
	}
	if f.ResBodyHash == "" {
		t.Fatal("expected response body to be captured")
	}
}

func TestProxyRecordsErroredFlowOnUpstreamFailure(t *testing.T) {
	// A definitely-refused upstream: bind a port, then close it.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadAddr := dead.Addr().String()
	dead.Close()

	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	srv := New(s, capture.New(s), nil, nil, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go srv.Serve(ln)

	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}

	resp, err := client.Get("http://" + deadAddr + "/gone")
	if err != nil {
		t.Fatalf("request through proxy: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 to client, got %d", resp.StatusCode)
	}

	deadline := time.Now().Add(2 * time.Second)
	var flows []*store.Flow
	for time.Now().Before(deadline) {
		flows, _ = s.QueryFlows(10)
		if len(flows) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(flows) != 1 {
		t.Fatalf("expected 1 errored flow, got %d", len(flows))
	}
	f := flows[0]
	if f.Status != http.StatusBadGateway {
		t.Fatalf("expected flow status 502, got %d", f.Status)
	}
	if f.Error == "" {
		t.Fatal("expected non-empty Error on errored flow")
	}
	if f.Method != "GET" || f.Path != "/gone" {
		t.Fatalf("unexpected errored flow: %+v", f)
	}
}
