// Package codec — body.go: HTTP response-body decompression helpers shared by
// control (display decoding) and intruder (grep decoding).
package codec

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// decompressMax caps decompressed output so a compression bomb cannot exhaust
// memory. 24 MiB matches the limit used by the control display decoder.
const decompressMax = 24 << 20 // 24 MiB

// DecompressBody inflates body according to the Content-Encoding header value.
// It supports gzip, deflate, br (brotli), and zstd. On success it returns the
// decompressed bytes and true. On any failure (unknown encoding, corrupt data,
// empty result) it returns nil, false — callers must fall back to the raw body.
//
// For a comma-separated encoding chain the outermost (last) encoding is applied,
// which is the common case for HTTP/1.1 responses.
func DecompressBody(contentEncoding string, body []byte) ([]byte, bool) {
	if len(body) == 0 || contentEncoding == "" {
		return nil, false
	}
	// Strip to the last token for chained encodings (e.g. "gzip, br").
	parts := strings.Split(contentEncoding, ",")
	enc := strings.ToLower(strings.TrimSpace(parts[len(parts)-1]))

	var rc io.Reader
	switch enc {
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

	out, err := io.ReadAll(io.LimitReader(rc, decompressMax))
	if (err != nil && err != io.ErrUnexpectedEOF) || len(out) == 0 {
		return nil, false
	}
	return out, true
}

// IsBinaryContentType returns true when the Content-Type header value indicates
// binary content (image, audio, video, font, octet-stream, zip, wasm, pdf)
// that cannot be meaningfully grepped as text.
func IsBinaryContentType(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	// Strip parameters like "; charset=utf-8"
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	switch {
	case strings.HasPrefix(ct, "image/"),
		strings.HasPrefix(ct, "audio/"),
		strings.HasPrefix(ct, "video/"),
		strings.HasPrefix(ct, "font/"),
		ct == "application/octet-stream",
		ct == "application/zip",
		ct == "application/x-zip-compressed",
		ct == "application/gzip",
		ct == "application/x-gzip",
		ct == "application/wasm",
		ct == "application/pdf":
		return true
	}
	return false
}
