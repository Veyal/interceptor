package control

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"strconv"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// decodeMax caps decompressed output so a compression bomb (tiny body → huge
// expansion) can't exhaust memory when a flow is opened for inspection.
const decodeMax = 24 << 20 // 24 MiB

// decodeForDisplay returns headers and body suitable for human inspection. When
// the body carries a recognized Content-Encoding (gzip / deflate / br / zstd) it
// is decompressed, the encoding header dropped, Content-Length corrected, and an
// X-Interceptor-Decoded marker added so the reader knows it was unpacked — so
// the inspector shows readable text instead of compressed bytes (which look like
// undecrypted garbage). On any failure the originals are returned unchanged;
// display must never break, and a non-compressed body passes through untouched.
func decodeForDisplay(headers map[string][]string, body []byte) (map[string][]string, []byte) {
	if len(body) == 0 {
		return headers, body
	}
	enc := strings.ToLower(strings.TrimSpace(firstHeader(headers, "Content-Encoding")))
	if enc == "" || enc == "identity" {
		return headers, body
	}
	dec, ok := decompress(enc, body)
	if !ok {
		return headers, body
	}
	out := make(map[string][]string, len(headers)+1)
	for k, v := range headers {
		switch strings.ToLower(k) {
		case "content-encoding", "content-length":
			// dropped/replaced below so the displayed message stays coherent
		default:
			out[k] = v
		}
	}
	out["Content-Length"] = []string{strconv.Itoa(len(dec))}
	out["X-Interceptor-Decoded"] = []string{enc}
	return out, dec
}

// decompress inflates body per a Content-Encoding token. For a comma-separated
// list it applies the last (outermost) encoding, which covers the common case.
func decompress(enc string, body []byte) ([]byte, bool) {
	parts := strings.Split(enc, ",")
	e := strings.TrimSpace(parts[len(parts)-1])
	var rc io.Reader
	switch e {
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, false
		}
		rc = zr
	case "br":
		rc = brotli.NewReader(bytes.NewReader(body))
	case "zstd":
		zr, err := zstd.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, false
		}
		defer zr.Close()
		rc = zr
	case "deflate":
		// "deflate" is ambiguous: usually zlib-wrapped, sometimes raw DEFLATE.
		if zr, err := zlib.NewReader(bytes.NewReader(body)); err == nil {
			rc = zr
		} else {
			rc = flate.NewReader(bytes.NewReader(body))
		}
	default:
		return nil, false
	}
	out, err := io.ReadAll(io.LimitReader(rc, decodeMax))
	if (err != nil && err != io.ErrUnexpectedEOF) || len(out) == 0 {
		return nil, false
	}
	return out, true
}

func firstHeader(h map[string][]string, key string) string {
	for k, v := range h {
		if strings.EqualFold(k, key) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}
