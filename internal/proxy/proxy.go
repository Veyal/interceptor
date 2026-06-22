// Package proxy implements an HTTP forward proxy that captures every flow.
package proxy

import (
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/Veyal/interceptor/internal/capture"
	"github.com/Veyal/interceptor/internal/store"
)

// Server is the forward-proxy HTTP handler.
type Server struct {
	st  *store.Store
	cap *capture.Capturer
	tr  *http.Transport
}

// New builds a proxy Server backed by st and cap.
func New(st *store.Store, cap *capture.Capturer) *Server {
	return &Server{
		st:  st,
		cap: cap,
		tr: &http.Transport{
			Proxy:                 nil, // dial upstream directly
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		},
	}
}

// Serve accepts connections on ln until it is closed.
func (s *Server) Serve(ln net.Listener) error {
	return (&http.Server{Handler: s}).Serve(ln)
}

// hopHeaders are stripped when forwarding (RFC 7230 §6.1).
var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func removeHopHeaders(h http.Header) {
	for _, k := range hopHeaders {
		h.Del(k)
	}
}

func copyHeader(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		// HTTPS (CONNECT) is implemented in the TLS-MITM plan.
		http.Error(w, "CONNECT not supported yet", http.StatusNotImplemented)
		return
	}
	if !r.URL.IsAbs() {
		http.Error(w, "this is a forward proxy; use an absolute-URI request", http.StatusBadRequest)
		return
	}

	start := time.Now()
	port := 80
	if ps := r.URL.Port(); ps != "" {
		port, _ = strconv.Atoi(ps)
	}
	flow := &store.Flow{
		TS:          start,
		Method:      r.Method,
		Scheme:      "http",
		Host:        r.URL.Hostname(),
		Port:        port,
		Path:        r.URL.RequestURI(),
		HTTPVersion: r.Proto,
		ClientAddr:  r.RemoteAddr,
		ReqHeaders:  r.Header.Clone(),
	}

	out := r.Clone(r.Context())
	out.RequestURI = ""
	removeHopHeaders(out.Header)

	reqTee, reqFinalize, err := s.cap.TeeBody(r.Body)
	if err != nil {
		s.fail(w, flow, "capture init: "+err.Error())
		return
	}
	if reqTee != nil {
		out.Body = io.NopCloser(reqTee)
	}

	resp, err := s.tr.RoundTrip(out)
	if err != nil {
		// Request body has (at most partially) been read; finalize to avoid leaking the temp file.
		reqHash, reqLen, _ := reqFinalize()
		flow.ReqBodyHash, flow.ReqLen = reqHash, reqLen
		s.fail(w, flow, "upstream: "+err.Error())
		return
	}
	defer resp.Body.Close()

	reqHash, reqLen, _ := reqFinalize()
	flow.ReqBodyHash, flow.ReqLen = reqHash, reqLen

	removeHopHeaders(resp.Header)
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	flow.Status = resp.StatusCode
	flow.ResHeaders = resp.Header.Clone()
	flow.Mime = resp.Header.Get("Content-Type")

	resTee, resFinalize, err := s.cap.TeeBody(resp.Body)
	if err != nil {
		// Response headers are already on the wire, so we cannot change the
		// status; record the flow with the error and stop. Calling http.Error
		// here would double-write the header.
		flow.Error = "capture resp: " + err.Error()
		flow.DurationMs = time.Since(start).Milliseconds()
		s.insertFlow(flow)
		return
	}
	if _, err := io.Copy(w, resTee); err != nil {
		flow.Error = "stream resp: " + err.Error()
	}
	resHash, resLen, _ := resFinalize()

	flow.ResBodyHash, flow.ResLen = resHash, resLen
	flow.DurationMs = time.Since(start).Milliseconds()
	s.insertFlow(flow)
}

// fail records an errored flow and writes a 502 to the client. It is only used
// before any response header has been written.
func (s *Server) fail(w http.ResponseWriter, flow *store.Flow, msg string) {
	flow.Status = http.StatusBadGateway
	flow.Error = msg
	flow.DurationMs = time.Since(flow.TS).Milliseconds()
	s.insertFlow(flow)
	http.Error(w, msg, http.StatusBadGateway)
}

// insertFlow persists a flow, logging on error rather than dropping it silently.
func (s *Server) insertFlow(flow *store.Flow) {
	if _, err := s.st.InsertFlow(flow); err != nil {
		log.Printf("proxy: persist flow %s %s%s: %v", flow.Method, flow.Host, flow.Path, err)
	}
}
