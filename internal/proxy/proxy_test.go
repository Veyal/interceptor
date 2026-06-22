package proxy

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Veyal/interceptor/internal/capture"
	"github.com/Veyal/interceptor/internal/store"
)

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
	srv := New(s, capture.New(s))

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
	srv := New(s, capture.New(s))

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
