package csrf

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// Headers holds extra headers to attach to mutating active-scan probes.
type Headers struct {
	Cookie       string
	XSRFToken    string // X-XSRF-TOKEN value
	ExtraHeaders map[string]string
}

// Empty reports whether there is nothing to inject.
func (h Headers) Empty() bool {
	return h.Cookie == "" && h.XSRFToken == "" && len(h.ExtraHeaders) == 0
}

// Apply merges CSRF/session headers into a probe header map.
func (h Headers) Apply(hdrs map[string][]string) map[string][]string {
	if h.Empty() {
		return hdrs
	}
	out := cloneHeaders(hdrs)
	if h.Cookie != "" {
		mergeCookie(out, h.Cookie)
	}
	if h.XSRFToken != "" {
		out["X-Xsrf-Token"] = []string{h.XSRFToken}
		out["X-CSRF-TOKEN"] = []string{h.XSRFToken}
	}
	for k, v := range h.ExtraHeaders {
		if k != "" && v != "" {
			out[http.CanonicalHeaderKey(k)] = []string{v}
		}
	}
	return out
}

// FromFlowRequest extracts Laravel-style CSRF material from a captured request.
func FromFlowRequest(reqHdr map[string][]string) Headers {
	var h Headers
	if reqHdr == nil {
		return h
	}
	for _, line := range reqHdr["Cookie"] {
		if strings.Contains(line, "XSRF-TOKEN") || strings.Contains(strings.ToLower(line), "session") {
			h.Cookie = line
			break
		}
	}
	for _, k := range []string{"X-Xsrf-Token", "X-CSRF-TOKEN", "X-XSRF-TOKEN"} {
		if vs := reqHdr[k]; len(vs) > 0 && strings.TrimSpace(vs[0]) != "" {
			h.XSRFToken = strings.TrimSpace(vs[0])
			break
		}
	}
	if h.XSRFToken == "" && h.Cookie != "" {
		h.XSRFToken = XSRFFromCookie(h.Cookie)
	}
	return h
}

// FromSetCookies builds session + XSRF headers from Set-Cookie lines (e.g. GET bootstrap).
func FromSetCookies(setCookies []string) Headers {
	var h Headers
	var parts []string
	for _, sc := range setCookies {
		nameVal, _, _ := strings.Cut(sc, ";")
		nameVal = strings.TrimSpace(nameVal)
		if nameVal == "" {
			continue
		}
		parts = append(parts, nameVal)
	}
	if len(parts) > 0 {
		h.Cookie = strings.Join(parts, "; ")
		h.XSRFToken = XSRFFromCookie(h.Cookie)
	}
	return h
}

// XSRFFromCookie decodes Laravel XSRF-TOKEN cookie → header value.
func XSRFFromCookie(cookieLine string) string {
	for _, part := range strings.Split(cookieLine, ";") {
		part = strings.TrimSpace(part)
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(k), "XSRF-TOKEN") {
			continue
		}
		v, _ = url.QueryUnescape(strings.TrimSpace(v))
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		// Laravel stores JSON {"token":"..."} in the cookie.
		if strings.HasPrefix(v, "{") {
			var m struct {
				Token string `json:"token"`
			}
			if json.Unmarshal([]byte(v), &m) == nil && m.Token != "" {
				return m.Token
			}
		}
		return v
	}
	return ""
}

func mergeCookie(hdrs map[string][]string, add string) {
	existing := ""
	if vs := hdrs["Cookie"]; len(vs) > 0 {
		existing = vs[0]
	}
	if existing == "" {
		hdrs["Cookie"] = []string{add}
		return
	}
	seen := map[string]bool{}
	var merged []string
	for _, line := range []string{existing, add} {
		for _, part := range strings.Split(line, ";") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			name, _, _ := strings.Cut(part, "=")
			name = strings.TrimSpace(name)
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			merged = append(merged, part)
		}
	}
	hdrs["Cookie"] = []string{strings.Join(merged, "; ")}
}

func cloneHeaders(h map[string][]string) map[string][]string {
	out := make(map[string][]string, len(h)+2)
	for k, vs := range h {
		out[k] = append([]string(nil), vs...)
	}
	return out
}
