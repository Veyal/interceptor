package preview

import (
	"bytes"
	"image/png"
	"strings"
	"testing"
)

func TestRenderBothSidesProducesValidPNG(t *testing.T) {
	req := []byte("GET /api/user HTTP/1.1\r\nHost: example.com\r\n\r\n")
	res := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":1}\n")
	pngBytes, err := Render(req, res, Options{
		Side:  SideBoth,
		Title: "GET example.com/api/user → 200",
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if len(pngBytes) < 200 {
		t.Fatalf("PNG too small: %d bytes", len(pngBytes))
	}
	img, err := png.Decode(bytes.NewReader(pngBytes))
	if err != nil {
		t.Fatalf("png.Decode: %v", err)
	}
	b := img.Bounds()
	if b.Dx() < 400 || b.Dy() < 150 {
		t.Fatalf("unexpected dimensions %dx%d", b.Dx(), b.Dy())
	}
}

func TestRenderReqOnly(t *testing.T) {
	req := []byte("POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nuser=a")
	pngBytes, err := Render(req, nil, Options{Side: SideReq, Title: "POST example.com/login"})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if _, err := png.Decode(bytes.NewReader(pngBytes)); err != nil {
		t.Fatalf("png.Decode: %v", err)
	}
}

func TestRenderTruncatesLongBody(t *testing.T) {
	var body strings.Builder
	for i := 0; i < 500; i++ {
		body.WriteString("line of response body content that is long enough\n")
	}
	res := []byte("HTTP/1.1 200 OK\r\n\r\n" + body.String())
	pngBytes, err := Render(nil, res, Options{Side: SideRes, MaxLines: 20})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	img, err := png.Decode(bytes.NewReader(pngBytes))
	if err != nil {
		t.Fatalf("png.Decode: %v", err)
	}
	// Truncated content must keep height bounded (20 lines + chrome, not 500).
	if img.Bounds().Dy() > 900 {
		t.Fatalf("height %d too large for MaxLines=20 — truncation failed", img.Bounds().Dy())
	}
	// Re-render with text probe: truncateLines must mark truncation.
	lines := truncateLines(strings.Split(string(res), "\n"), 20)
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "[truncated]") {
		t.Fatalf("expected truncation marker in lines:\n%s", joined)
	}
}

func TestRenderStaysUnderImageCap(t *testing.T) {
	var body strings.Builder
	for i := 0; i < 2000; i++ {
		body.WriteString(strings.Repeat("x", 80) + "\n")
	}
	res := []byte("HTTP/1.1 200 OK\r\n\r\n" + body.String())
	pngBytes, err := Render(nil, res, Options{Side: SideRes, MaxLines: 120})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if len(pngBytes) > MaxPNGBytes {
		t.Fatalf("PNG %d exceeds MaxPNGBytes %d", len(pngBytes), MaxPNGBytes)
	}
}

func TestNormalizeSide(t *testing.T) {
	if got := NormalizeSide("REQ"); got != SideReq {
		t.Fatalf("NormalizeSide(REQ)=%q", got)
	}
	if got := NormalizeSide(""); got != SideBoth {
		t.Fatalf("NormalizeSide(\"\")=%q", got)
	}
	if got := NormalizeSide("weird"); got != SideBoth {
		t.Fatalf("NormalizeSide(weird)=%q", got)
	}
}

func TestNormalizeLayoutTheme(t *testing.T) {
	if got := NormalizeLayout("vertical"); got != LayoutVertical {
		t.Fatalf("NormalizeLayout(vertical)=%q", got)
	}
	if got := NormalizeLayout(""); got != LayoutHorizontal {
		t.Fatalf("NormalizeLayout(\"\")=%q want horizontal", got)
	}
	if got := NormalizeTheme("dark"); got != ThemeDark {
		t.Fatalf("NormalizeTheme(dark)=%q", got)
	}
	if got := NormalizeTheme(""); got != ThemeLight {
		t.Fatalf("NormalizeTheme(\"\")=%q want light", got)
	}
}

func TestPrettyPrintJSONBody(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":1,\"name\":\"a\"}")
	out := prettyHTTP(raw)
	if !bytes.Contains(out, []byte("\n  \"id\": 1")) {
		t.Fatalf("expected indented JSON, got:\n%s", out)
	}
	if !bytes.Contains(out, []byte("HTTP/1.1 200 OK")) {
		t.Fatalf("headers must be preserved:\n%s", out)
	}
}

func TestRenderHorizontalIsWiderThanVertical(t *testing.T) {
	req := []byte("GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n")
	res := []byte("HTTP/1.1 200 OK\r\n\r\n{\"ok\":true}")
	vert, err := Render(req, res, Options{Side: SideBoth, Layout: LayoutVertical, MaxCols: 40, MaxLines: 20})
	if err != nil {
		t.Fatalf("vertical: %v", err)
	}
	horiz, err := Render(req, res, Options{Side: SideBoth, Layout: LayoutHorizontal, MaxCols: 40, MaxLines: 20})
	if err != nil {
		t.Fatalf("horizontal: %v", err)
	}
	vImg, _ := png.Decode(bytes.NewReader(vert))
	hImg, _ := png.Decode(bytes.NewReader(horiz))
	if hImg.Bounds().Dx() <= vImg.Bounds().Dx() {
		t.Fatalf("horizontal width %d should exceed vertical %d", hImg.Bounds().Dx(), vImg.Bounds().Dx())
	}
	if hImg.Bounds().Dy() >= vImg.Bounds().Dy() {
		t.Fatalf("horizontal height %d should be shorter than vertical %d", hImg.Bounds().Dy(), vImg.Bounds().Dy())
	}
}

func TestRenderDefaultsAreLightHorizontalPretty(t *testing.T) {
	req := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	res := []byte("HTTP/1.1 200 OK\r\n\r\n{\"id\":1}")
	// Empty options → light theme, horizontal layout, pretty bodies.
	pngBytes, err := Render(req, res, Options{Side: SideBoth, MaxCols: 40, MaxLines: 20})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	img, err := png.Decode(bytes.NewReader(pngBytes))
	if err != nil {
		t.Fatal(err)
	}
	r, g, b, _ := img.At(20, 50).RGBA()
	if (r+g+b)/3 < 0x8000 {
		t.Fatalf("default theme should be light, got #%02x%02x%02x", r>>8, g>>8, b>>8)
	}
	vert, err := Render(req, res, Options{Side: SideBoth, Layout: LayoutVertical, MaxCols: 40, MaxLines: 20})
	if err != nil {
		t.Fatal(err)
	}
	vImg, _ := png.Decode(bytes.NewReader(vert))
	if img.Bounds().Dx() <= vImg.Bounds().Dx() {
		t.Fatalf("default (horizontal) width %d should exceed vertical %d", img.Bounds().Dx(), vImg.Bounds().Dx())
	}
}

func TestParsePrettyQuery(t *testing.T) {
	if !ParseBool("1", false) || !ParseBool("true", false) || ParseBool("0", true) {
		t.Fatal("ParseBool mismatch")
	}
	if ParseBool("", false) || !ParseBool("", true) {
		t.Fatal("ParseBool default mismatch")
	}
}
