// Package scanner runs passive security checks over captured flows. It never
// sends traffic — it only inspects request/response metadata and bodies that
// were already recorded, keeping analysis off the proxy hot path.
package scanner

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/Veyal/interceptor/internal/store"
)

var (
	jwtRe      = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}`)
	passwordRe = regexp.MustCompile(`(?i)"?password"?\s*[:=]\s*"?[^"&\s,}]{3,}`)
	tokenRe    = regexp.MustCompile(`(?i)"(access_?token|token|session|secret|api_?key)"\s*:\s*"[^"]{8,}"`)
	versionRe  = regexp.MustCompile(`\d+\.\d+`)
	urlSensitiveRe = regexp.MustCompile(`(?i)[?&](access_?token|api_?key|token|session|password|secret|passwd|auth)=([^&\s]{6,})`)

	// mixedContentRe matches http:// scheme references inside common HTML resource-loading attributes.
	mixedContentRe = regexp.MustCompile(`(?i)(?:src|href)\s*=\s*["']?http://`)

	// dirListingRe matches the characteristic title of an auto-generated directory listing.
	dirListingRe = regexp.MustCompile(`(?i)<title>\s*index of /`)

	// privateIPRe matches RFC-1918 / loopback / link-local IP addresses disclosed in response text.
	privateIPRe = regexp.MustCompile(`(?:^|[^0-9.])` +
		`(?:127\.0\.0\.\d{1,3}` +
		`|10\.\d{1,3}\.\d{1,3}\.\d{1,3}` +
		`|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}` +
		`|192\.168\.\d{1,3}\.\d{1,3}` +
		`|169\.254\.\d{1,3}\.\d{1,3})` +
		`(?:[^0-9.]|$)`)

	// dbErrorRe matches high-signal database error strings in a response body — a strong
	// passive SQL-injection indicator (user input reached a query un-parameterized).
	// Restricted to error-message phrasing (not bare function names) to keep false positives low.
	dbErrorRe = regexp.MustCompile(`(?i)(SQL syntax|You have an error in your SQL syntax|mysql_fetch|valid MySQL result|ORA-\d{4,5}|PostgreSQL.{0,40}ERROR|pg_query failed|SQLite[/:.\s].{0,20}error|sqlite3\.OperationalError|SQLSTATE\[|Unclosed quotation mark|quoted string not properly terminated|near ".{0,30}": syntax error|System\.Data\.SqlClient\.SqlException|SqlException)`)
)

const maxScanBytes = 256 * 1024 // cap how much of a body we inspect

// BuiltinCheck is metadata for a built-in passive check — shown in the Checks
// manager so users can see and toggle each one (built-ins can be disabled but
// not deleted; only Starlark checks are user-editable).
type BuiltinCheck struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// Stable check IDs (referenced both by the gating logic and by BuiltinChecks).
const (
	checkPasswordInBody    = "password-in-body"
	checkTokenInResp       = "token-in-response"
	checkVerboseError      = "verbose-error"
	checkSecurityHeaders   = "security-headers"
	checkCorsWildcard      = "cors-wildcard"
	checkCorsCreds         = "cors-credentials"
	checkInsecureCookie    = "insecure-cookie"
	checkCookieSameSite    = "cookie-no-samesite"
	checkCacheableAuth     = "cacheable-auth"
	checkVersionDisclosure = "version-disclosure"
	checkReflectedParam    = "reflected-param"
	checkBasicAuth         = "basic-auth"
	checkSensitiveURL      = "sensitive-url-param"
	checkMixedContent      = "mixed-content"
	checkOpenRedirect      = "open-redirect"
	checkDirListing        = "directory-listing"
	checkDBError           = "db-error-sqli"
	checkPrivateIP         = "private-ip-disclosure"
)

// BuiltinChecks lists every built-in passive check. The Category groups them in
// the UI; Severity is the default the check emits.
var BuiltinChecks = []BuiltinCheck{
	{checkPasswordInBody, "Password transmitted in request body", "Secrets", "Medium", "A password field is sent in the request body."},
	{checkTokenInResp, "Session token leaked in response body", "Secrets", "High", "A bearer token / credential is returned in the response body."},
	{checkSensitiveURL, "Sensitive token or credential in URL", "Secrets", "Medium", "A credential-like parameter is in the request URL query string."},
	{checkSecurityHeaders, "Missing security response headers", "Headers", "Medium", "Bundles CSP, HSTS, X-Content-Type-Options, clickjacking & Referrer-Policy into one finding listing whichever are missing."},
	{checkCorsWildcard, "Overly permissive CORS policy", "CORS", "Medium", "Access-Control-Allow-Origin: * lets any origin read the resource."},
	{checkCorsCreds, "CORS with credentials enabled", "CORS", "High", "Wildcard or reflected Origin combined with Allow-Credentials: true."},
	{checkInsecureCookie, "Cookie set without Secure and HttpOnly", "Cookies", "Low", "A cookie lacks the Secure and/or HttpOnly attributes."},
	{checkCookieSameSite, "Cookie missing SameSite attribute", "Cookies", "Low", "A cookie is set without a SameSite attribute (CSRF surface)."},
	{checkCacheableAuth, "Authenticated response may be cached", "Cookies", "Low", "A cookie-setting response lacks Cache-Control: no-store/private."},
	{checkVersionDisclosure, "Server software version disclosed", "Disclosure", "Low", "Server / X-Powered-By / X-AspNet-Version reveals a version."},
	{checkVerboseError, "Verbose error discloses internal details", "Disclosure", "Medium", "A 5xx response leaks trace ids / stack frames."},
	{checkPrivateIP, "Internal IP address disclosed", "Disclosure", "Low", "The response body contains a private/loopback IP address."},
	{checkReflectedParam, "Request parameter reflected in HTML", "Injection", "Low", "A parameter is echoed verbatim into HTML — a possible reflected-XSS sink."},
	{checkDBError, "Possible SQL injection (DB error in response)", "Injection", "High", "The response contains a database error string — a strong SQLi signal."},
	{checkBasicAuth, "HTTP Basic authentication in use", "Auth", "Low", "Credentials are sent as reversible base64 (Authorization: Basic)."},
	{checkMixedContent, "Mixed content: HTTPS page loads HTTP resource", "Config", "Medium", "An HTTPS page references a resource over plain HTTP."},
	{checkOpenRedirect, "Potential open redirect via request parameter", "Redirect", "Medium", "A 3xx Location is influenced by a request parameter, off-host."},
	{checkDirListing, "Directory listing enabled", "Config", "Low", "The response looks like an auto-generated directory index."},
}

// Analyze runs all passive checks (none disabled) — kept for the existing 3-arg
// callers and tests. The real scan path uses AnalyzeWithDisabled so users can
// turn individual built-in checks off.
func Analyze(f *store.Flow, reqBody, resBody []byte) []store.Issue {
	return AnalyzeWithDisabled(f, reqBody, resBody, nil)
}

// AnalyzeWithDisabled runs the built-in passive checks, skipping any whose ID is
// in disabled. disabled may be nil to run everything.
func AnalyzeWithDisabled(f *store.Flow, reqBody, resBody []byte, disabled map[string]bool) []store.Issue {
	res := http.Header(f.ResHeaders)
	target := f.Method + " " + f.Host + f.Path
	req := clip(reqBody)
	resp := clip(resBody)
	on := func(id string) bool { return disabled == nil || !disabled[id] }

	var out []store.Issue
	add := func(sev, title, detail, evidence, fix string) {
		out = append(out, store.Issue{
			FlowID: f.ID, Severity: sev, Title: title, Target: target,
			Detail: detail, Evidence: evidence, Fix: fix,
		})
	}

	// Password in the request body.
	if on(checkPasswordInBody) {
		if m := passwordRe.FindString(req); m != "" {
			sev := "Medium"
			if f.Scheme == "http" {
				sev = "High"
			}
			add(sev, "Password transmitted in request body",
				"The request carries a password field in its body; over plaintext HTTP this is trivially sniffable, and even over TLS it should be kept out of logs.",
				trunc(m, 80),
				"Always submit credentials over HTTPS, keep the body out of access logs, and consider client-side hashing / SRP so the raw secret never transits.")
		}
	}

	// Session token / JWT in the response body.
	if on(checkTokenInResp) {
		if jwt := jwtRe.FindString(resp); jwt != "" {
			add("High", "Session token leaked in response body",
				"A bearer token (JWT) is returned in the response body where intermediaries or caches may retain it.",
				trunc(jwt, 48)+"…",
				"Deliver session tokens via a Set-Cookie with HttpOnly, Secure and SameSite=Strict instead of the JSON body.")
		} else if m := tokenRe.FindString(resp); m != "" {
			add("High", "Session token leaked in response body",
				"A credential-looking field is returned in the response body where intermediaries or caches may retain it.",
				trunc(m, 64),
				"Return session tokens via a Secure, HttpOnly cookie rather than the response body.")
		}
	}

	// Verbose error disclosure.
	if on(checkVerboseError) {
		if f.Status >= 500 && containsAny(resp, "traceId", "trace_id", "stacktrace", "stack", "exception", " at ") {
			add("Medium", "Verbose error discloses internal details",
				"A server error response leaks internal diagnostics (trace identifiers / stack frames) that aid reconnaissance of the backend.",
				trunc(firstMatch(resp, "traceId", "trace_id", "exception", "stack"), 80),
				"Return a generic error to clients and keep trace identifiers and stack traces server-side in logs only.")
		}
	}

	// Security response headers — MERGED into a single finding. The previous
	// behaviour emitted one issue per missing header (CSP, HSTS, nosniff,
	// clickjacking, Referrer-Policy), which drowned the issue list in near-
	// duplicates. Now we collect whichever are missing and emit one finding that
	// lists them, at Medium if CSP or HSTS is among them (they materially raise
	// the XSS / downgrade blast radius) otherwise Low.
	if on(checkSecurityHeaders) {
		var missing []string
		if isHTML(res, f.Mime) && res.Get("Content-Security-Policy") == "" {
			missing = append(missing, "Content-Security-Policy")
		}
		if f.Scheme == "https" && res.Get("Strict-Transport-Security") == "" {
			missing = append(missing, "Strict-Transport-Security (HSTS)")
		}
		if isHTML(res, f.Mime) || containsAny(f.Mime, "javascript") {
			if !strings.Contains(strings.ToLower(res.Get("X-Content-Type-Options")), "nosniff") {
				missing = append(missing, "X-Content-Type-Options: nosniff")
			}
		}
		if isHTML(res, f.Mime) {
			csp := strings.ToLower(res.Get("Content-Security-Policy"))
			if res.Get("X-Frame-Options") == "" && !strings.Contains(csp, "frame-ancestors") {
				missing = append(missing, "X-Frame-Options / CSP frame-ancestors (clickjacking)")
			}
		}
		if isHTML(res, f.Mime) && res.Get("Referrer-Policy") == "" {
			missing = append(missing, "Referrer-Policy")
		}
		if len(missing) > 0 {
			sev := "Low"
			for _, m := range missing {
				if strings.Contains(m, "Content-Security-Policy") || strings.Contains(m, "Strict-Transport-Security") {
					sev = "Medium"
					break
				}
			}
			add(sev, "Missing security response headers",
				"The response is missing one or more standard security response headers ("+strings.Join(missing, ", ")+
					"). Each weakens a different defence-in-depth control (XSS containment, downgrade protection, MIME sniffing, clickjacking, Referer leakage).",
				"Missing: "+strings.Join(missing, ", "),
				"Send the missing headers — CSP, HSTS on HTTPS, X-Content-Type-Options: nosniff, X-Frame-Options (or CSP frame-ancestors), Referrer-Policy: strict-origin-when-cross-origin.")
		}
	}

	// Wildcard CORS.
	if on(checkCorsWildcard) {
		if res.Get("Access-Control-Allow-Origin") == "*" {
			add("Medium", "Overly permissive CORS policy",
				"Access-Control-Allow-Origin: * lets any origin read this resource.",
				"Access-Control-Allow-Origin: *",
				"Replace the wildcard with an explicit allow-list of trusted origins.")
		}
	}

	// CORS with credentials — wildcard or reflected origin combined with Allow-Credentials: true.
	if on(checkCorsCreds) {
		if strings.EqualFold(res.Get("Access-Control-Allow-Credentials"), "true") {
			acao := res.Get("Access-Control-Allow-Origin")
			reqOrigin := http.Header(f.ReqHeaders).Get("Origin")
			switch {
			case acao == "*":
				add("High", "CORS wildcard with credentials enabled",
					"Access-Control-Allow-Origin: * is set alongside Access-Control-Allow-Credentials: true. "+
						"Although browsers block this combination, it is a server-side misconfiguration that signals the developer intended open cross-origin access with credentials.",
					"Access-Control-Allow-Origin: * | Access-Control-Allow-Credentials: true",
					"Restrict Access-Control-Allow-Origin to a specific trusted origin when credentials are required; never use * with credentials.")
			case reqOrigin != "" && acao == reqOrigin:
				add("High", "CORS reflects request Origin with credentials enabled",
					"The server echoes back the caller's Origin header as Access-Control-Allow-Origin and also sets Access-Control-Allow-Credentials: true. "+
						"Any origin — including attacker-controlled pages — can make credentialed cross-origin requests and read the response.",
					"Access-Control-Allow-Origin: "+acao+" | Access-Control-Allow-Credentials: true",
					"Validate the Origin against an explicit server-side allow-list before reflecting it; do not echo arbitrary origins.")
			}
		}
	}

	// Insecure cookies (missing Secure and/or HttpOnly).
	if on(checkInsecureCookie) {
		for _, c := range res.Values("Set-Cookie") {
			lc := strings.ToLower(c)
			if !strings.Contains(lc, "secure") || !strings.Contains(lc, "httponly") {
				add("Low", "Cookie set without Secure and HttpOnly",
					"A cookie is set without both the Secure and HttpOnly attributes, exposing it to plaintext interception or theft via XSS.",
					trunc(c, 80),
					"Set cookies with Secure; HttpOnly; SameSite=Strict (or Lax).")
				break
			}
		}
	}

	// Cookie missing SameSite.
	if on(checkCookieSameSite) {
		for _, c := range res.Values("Set-Cookie") {
			lc := strings.ToLower(c)
			if !strings.Contains(lc, "samesite") {
				add("Low", "Cookie missing SameSite attribute",
					"A cookie is set without a SameSite attribute. Browsers that do not default to Lax will send it on cross-site requests, enabling CSRF attacks.",
					trunc(c, 80),
					"Add SameSite=Strict (or Lax) to all cookies. Use Strict for session tokens.")
				break
			}
		}
	}

	// Authenticated response cached without Cache-Control: no-store / private.
	if on(checkCacheableAuth) {
		if len(res.Values("Set-Cookie")) > 0 {
			cc := strings.ToLower(res.Get("Cache-Control"))
			if !strings.Contains(cc, "no-store") && !strings.Contains(cc, "private") {
				add("Low", "Authenticated response may be cached by shared proxies",
					"The response sets a cookie but does not include Cache-Control: no-store or private. "+
						"A shared proxy or CDN node may cache and serve this response to other users.",
					"Set-Cookie present; Cache-Control: "+res.Get("Cache-Control"),
					"Add Cache-Control: no-store (or at minimum private) to responses that set authentication cookies.")
			}
		}
	}

	// Server software version disclosure.
	if on(checkVersionDisclosure) {
		for _, h := range []string{"Server", "X-Powered-By", "X-AspNet-Version"} {
			if v := res.Get(h); v != "" && versionRe.MatchString(v) {
				add("Low", "Server software version disclosed",
					"A response header reveals the server software and version, aiding targeted exploitation.",
					h+": "+v,
					"Suppress or genericize version-bearing headers ("+h+") at the edge.")
				break
			}
		}
	}

	// Request parameter reflected verbatim in an HTML response (possible XSS sink).
	if on(checkReflectedParam) {
		if isHTML(res, f.Mime) {
			if name, val, ok := reflectedParam(f.Path, req, resp); ok {
				add("Low", "Request parameter reflected in HTML response",
					"A request parameter is echoed verbatim into an HTML response. If it is not contextually output-encoded this is a reflected-XSS sink — confirm by sending a marker payload.",
					trunc(name+"="+val, 80),
					"HTML-encode user input on output (and set a Content-Security-Policy); verify the value cannot break out of its HTML/JS/attribute context.")
			}
		}
	}

	// Possible SQL injection — a database error string in the response body.
	if on(checkDBError) {
		if m := dbErrorRe.FindString(resp); m != "" {
			add("High", "Possible SQL injection (DB error in response)",
				"The response contains a database error message. This strongly suggests user input reached a SQL query without parameterization — inject a single quote and confirm the error changes to validate SQL injection.",
				trunc(m, 80),
				"Use parameterized queries / prepared statements everywhere user input reaches SQL; never string-concatenate. Validate and normalize input, and return generic errors to clients.")
		}
	}

	// Internal IP address disclosed in the response body (topology leak).
	if on(checkPrivateIP) {
		if m := privateIPRe.FindString(resp); m != "" {
			add("Low", "Internal IP address disclosed",
				"The response body contains what looks like a private/internal IP address (RFC1918 / loopback / link-local), revealing internal network topology.",
				strings.TrimSpace(m),
				"Avoid echoing internal hostnames or IP addresses to clients; keep them server-side.")
		}
	}

	// HTTP Basic authentication.
	if on(checkBasicAuth) {
		if av := http.Header(f.ReqHeaders).Get("Authorization"); strings.HasPrefix(strings.ToLower(av), "basic ") {
			sev := "Low"
			if f.Scheme == "http" {
				sev = "High"
			}
			add(sev, "HTTP Basic authentication in use",
				"The request authenticates with HTTP Basic, which transmits credentials as reversible base64. Over plaintext HTTP they are exposed to any on-path observer; even over TLS they are replayable and sent on every request.",
				"Authorization: Basic …",
				"Prefer a token/session-cookie scheme; if Basic is required, enforce HTTPS and short-lived credentials.")
		}
	}

	// Sensitive token or credential in the request URL query string.
	if on(checkSensitiveURL) {
		if m := urlSensitiveRe.FindString(f.Path); m != "" {
			kv := strings.SplitN(strings.TrimLeft(m, "?&"), "=", 2)
			paramName := kv[0]
			add("Medium", "Sensitive token or credential in URL",
				"A credential-like parameter ("+paramName+") is present in the request URL query string. "+
					"Query parameters are recorded in server access logs, browser history, proxy logs, and Referer headers sent to third parties.",
				trunc(m, 80),
				"Pass credentials in the request body (POST) or as Authorization/custom headers, never in the URL.")
		}
	}

	// Mixed content — HTTPS page references HTTP resources.
	if on(checkMixedContent) {
		if f.Scheme == "https" && isHTML(res, f.Mime) {
			if m := mixedContentRe.FindString(resp); m != "" {
				add("Medium", "Mixed content: HTTPS page loads HTTP resource",
					"An HTTPS page references at least one resource (script/style/iframe/image) over "+
						"plain HTTP. Active mixed content (scripts/styles) is blocked by modern browsers, "+
						"but its presence indicates a configuration defect; passive mixed content (images) "+
						"is still loaded and can be replaced by a network attacker.",
					trunc(m, 80),
					"Update all sub-resource URLs to HTTPS, or use protocol-relative URLs (//…).")
			}
		}
	}

	// Open redirect — 3xx Location influenced by a request parameter, off-host.
	if on(checkOpenRedirect) {
		if f.Status >= 300 && f.Status < 400 {
			if loc := res.Get("Location"); loc != "" {
				if name, val, ok := openRedirectParam(f.Host, f.Path, req, loc); ok {
					add("Medium", "Potential open redirect via request parameter",
						"A redirect response sets a Location header whose value is influenced by the request parameter '"+name+"'. "+
							"If the server does not validate the destination, an attacker can craft a link that redirects victims to an attacker-controlled site.",
						trunc(name+"="+val+" → Location: "+loc, 120),
						"Validate redirect destinations against an explicit allow-list of trusted URLs; never accept full URLs from user-controlled input as redirect targets.")
				}
			}
		}
	}

	// Directory listing exposure.
	if on(checkDirListing) {
		if strings.Contains(resp, "<a href=") && dirListingRe.MatchString(resp) {
			add("Low", "Directory listing enabled",
				"The response appears to be an auto-generated directory index (e.g. Apache/nginx autoindex). Directory listings expose file and directory names, software paths, and may reveal sensitive files.",
				trunc(dirListingRe.FindString(resp), 80),
				"Disable directory listing in the web-server configuration (e.g. Options -Indexes in Apache, autoindex off in nginx) and ensure sensitive files are not web-accessible.")
		}
	}

	return out
}

// openRedirectParam checks whether any request query or body parameter value
// appears verbatim in the redirect Location header AND points off-host.
func openRedirectParam(host, path, body, location string) (name, val string, ok bool) {
	var pairs [][2]string
	collect := func(q string) {
		for _, kv := range strings.Split(q, "&") {
			if kv == "" {
				continue
			}
			k, v, _ := strings.Cut(kv, "=")
			if dec, err := url.QueryUnescape(v); err == nil {
				v = dec
			}
			if len(v) < 8 {
				continue
			}
			lk := strings.ToLower(k)
			looksLikeURL := strings.HasPrefix(v, "http") || strings.HasPrefix(v, "//")
			redirectParamName := lk == "next" || lk == "redirect" || lk == "redirect_uri" ||
				lk == "return" || lk == "returnto" || lk == "url" || lk == "goto" ||
				lk == "continue" || lk == "dest" || lk == "destination" || lk == "target"
			if looksLikeURL || redirectParamName {
				pairs = append(pairs, [2]string{k, v})
			}
		}
	}
	if i := strings.IndexByte(path, '?'); i >= 0 {
		collect(path[i+1:])
	}
	collect(body)

	locLower := strings.ToLower(location)
	for _, p := range pairs {
		if !strings.Contains(location, p[1]) {
			continue
		}
		isAbsolute := strings.HasPrefix(locLower, "http") || strings.HasPrefix(locLower, "//")
		if !isAbsolute {
			continue
		}
		if strings.Contains(locLower, strings.ToLower(host)) {
			continue
		}
		return p[0], p[1], true
	}
	return "", "", false
}

// reflectedParam returns the first query/body parameter whose value (≥6 chars,
// containing a letter) appears verbatim in resp — a candidate reflected-XSS sink.
func reflectedParam(path, body, resp string) (name, val string, ok bool) {
	var pairs [][2]string
	collect := func(q string) {
		for _, kv := range strings.Split(q, "&") {
			if kv == "" {
				continue
			}
			k, v, _ := strings.Cut(kv, "=")
			if dec, err := url.QueryUnescape(v); err == nil {
				v = dec
			}
			if len(v) >= 6 && hasLetter(v) {
				pairs = append(pairs, [2]string{k, v})
			}
		}
	}
	if i := strings.IndexByte(path, '?'); i >= 0 {
		collect(path[i+1:])
	}
	collect(body)
	for _, p := range pairs {
		if strings.Contains(resp, p[1]) {
			return p[0], p[1], true
		}
	}
	return "", "", false
}

func hasLetter(s string) bool {
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return true
		}
	}
	return false
}

func clip(b []byte) string {
	if len(b) > maxScanBytes {
		b = b[:maxScanBytes]
	}
	return string(b)
}

func isHTML(h http.Header, mime string) bool {
	ct := h.Get("Content-Type")
	return strings.Contains(ct, "text/html") || strings.Contains(mime, "text/html")
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func firstMatch(s string, subs ...string) string {
	for _, sub := range subs {
		if i := strings.Index(s, sub); i >= 0 {
			end := i + 60
			if end > len(s) {
				end = len(s)
			}
			return s[i:end]
		}
	}
	return ""
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
