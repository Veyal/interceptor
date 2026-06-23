package wsrepeater

import (
	"bufio"
	"fmt"
	"net"
	"net/textproto"
	"testing"
	"time"
)

func TestAcceptKeyRFCVector(t *testing.T) {
	// RFC 6455 §1.3 worked example.
	if got := acceptKey("dGhlIHNhbXBsZSBub25jZQ=="); got != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("acceptKey vector wrong: %s", got)
	}
}

func TestClientFrameRoundTrip(t *testing.T) {
	enc := encodeClientFrame(opText, []byte("hello world"))
	// Client frames must set the mask bit.
	if enc[1]&0x80 == 0 {
		t.Fatal("client frame must be masked")
	}
	op, payload, err := readFrame(bufio.NewReader(bytesReader(enc)))
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if op != opText || string(payload) != "hello world" {
		t.Fatalf("round-trip mismatch: op=%d payload=%q", op, payload)
	}
}

func TestSendAgainstEchoServer(t *testing.T) {
	addr, stop := wsEchoServer(t)
	defer stop()

	res, err := Send(Request{URL: "ws://" + addr + "/chat", Message: "ping-42", ReadFor: time.Second})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if res.Status != 101 {
		t.Fatalf("expected 101, got %d", res.Status)
	}
	var sawSend, sawEcho bool
	for _, f := range res.Frames {
		if f.Dir == "send" && f.Text == "ping-42" {
			sawSend = true
		}
		if f.Dir == "recv" && f.Text == "ping-42" {
			sawEcho = true
		}
	}
	if !sawSend || !sawEcho {
		t.Fatalf("expected send+echo of ping-42, got %+v", res.Frames)
	}
}

func TestSendBadHandshake(t *testing.T) {
	// A plain HTTP server that never upgrades.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		bufio.NewReader(c).ReadString('\n')
		fmt.Fprint(c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
	}()
	res, err := Send(Request{URL: "ws://" + ln.Addr().String() + "/", Message: "x", ReadFor: 300 * time.Millisecond})
	if err == nil {
		t.Fatal("expected error on non-101 handshake")
	}
	if res == nil || res.Status != 400 {
		t.Fatalf("expected status 400 in result, got %+v", res)
	}
}

// ---- test helpers ----

// wsEchoServer accepts one connection, completes the WS handshake, and echoes
// the first client frame back as an unmasked server frame.
func wsEchoServer(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		tp := textproto.NewReader(br)
		tp.ReadLine() // request line
		hdr, err := tp.ReadMIMEHeader()
		if err != nil {
			return
		}
		fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", acceptKey(hdr.Get("Sec-WebSocket-Key")))
		op, payload, err := readFrame(br)
		if err != nil {
			return
		}
		conn.Write(encodeServerFrame(byte(op), payload))
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// encodeServerFrame builds an unmasked frame (server→client), test-only.
func encodeServerFrame(opcode byte, payload []byte) []byte {
	out := []byte{0x80 | opcode, byte(len(payload))}
	return append(out, payload...)
}

type br struct {
	b []byte
	i int
}

func (r *br) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, fmt.Errorf("EOF")
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}

func bytesReader(b []byte) *br { return &br{b: b} }
