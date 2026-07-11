package proxy

import "strings"

// browserTelemetryHosts is the set of exact hostnames that Chrome and Firefox
// use for background telemetry, crash reporting, safe-browsing lookups, update
// pings, and captive-portal detection. Requests to these hosts are suppressed
// from history and the intercept gate when SuppressBrowserTelemetry is on.
var browserTelemetryHosts = map[string]struct{}{
	// Firefox — telemetry & crash
	"incoming.telemetry.mozilla.org": {},
	"telemetry.mozilla.org":          {},
	"crash-reports.mozilla.com":      {},
	"crash-stats.mozilla.com":        {},

	// Firefox — update & remote settings (Normandy / Balrog)
	"aus5.mozilla.org":                             {},
	"normandy.cdn.mozilla.net":                     {},
	"normandy.services.mozilla.com":                {},
	"firefox.settings.services.mozilla.com":        {},
	"remotesettings.services.mozilla.com":          {},
	"firefox-settings-attachments.cdn.mozilla.net": {},

	// Firefox — push & portal detection
	"push.services.mozilla.com": {},
	"detectportal.firefox.com":  {},

	// Firefox — tracking-protection list updates (Safe Browsing)
	"shavar.services.mozilla.com":         {},
	"tracking-protection.cdn.mozilla.net": {},

	// Firefox — client classification & geolocation
	"prod.classify-client.services.mozilla.com": {},
	"location.services.mozilla.com":             {},

	// Chrome / Chromium — Safe Browsing
	"safebrowsing.googleapis.com": {},

	// Chrome — updates
	"update.googleapis.com": {},

	// Chrome — field trials & optimisation hints
	"chrome-variations.googleapis.com":    {},
	"optimizationguide-pa.googleapis.com": {},

	// Chrome — crash reports
	"chromecrashreports-pa.googleapis.com": {},
	"crash.chromium.org":                   {},

	// Chrome — connectivity probe
	"connectivity.gstatic.com": {},
}

// androidTelemetryHosts is the set of exact hostnames that Android OS, Google
// Play Services, Firebase Analytics/Crashlytics SDKs, and related ad/measurement
// stacks use for background phone-home. Suppressed from history and the
// intercept gate when SuppressAndroidTelemetry is on.
//
// Intentionally excludes app backends (firebase.googleapis.com, Firestore),
// auth (accounts.google.com), and FCM push (mtalk.google.com) so mobile
// engagements still see traffic the target app needs.
var androidTelemetryHosts = map[string]struct{}{
	// Play / GMS check-in & store APIs (very noisy on a proxied device)
	"android.clients.google.com": {},
	"android.googleapis.com":     {},
	"play.googleapis.com":        {},

	// Captive-portal / connectivity probes
	"connectivitycheck.gstatic.com": {},
	"connectivitycheck.android.com": {},
	"clients3.google.com":           {},

	// Crashlytics reporting (exact hosts; suffix list covers the rest)
	"crashlyticsreports-pa.googleapis.com":      {},
	"firebasecrashlyticssymbols.googleapis.com": {},
	"mobilecrashreporting.googleapis.com":       {},

	// Firebase Analytics / Clearcut-style logging (not Firestore/RTDB backends)
	"firebaselogging.googleapis.com":    {},
	"firebaselogging-pa.googleapis.com": {},
	"app-measurement.com":               {},
	"www.google-analytics.com":          {},
	"ssl.google-analytics.com":          {},
	"google-analytics.com":              {},
	"region1.google-analytics.com":      {},
	"analytics.google.com":              {},

	// Ads / measurement noise common on Android browsers & WebViews
	"googleads.g.doubleclick.net":   {},
	"ad.doubleclick.net":            {},
	"pagead2.googlesyndication.com": {},
	"www.googletagmanager.com":      {},
	"www.googletagservices.com":     {},
}

// androidTelemetrySuffixes matches any host under these DNS suffixes (leading
// dot required). Used for Crashlytics and App Measurement regional endpoints.
var androidTelemetrySuffixes = []string{
	".crashlytics.com",
	".app-measurement.com",
}

// telemetryHost normalises a Host header / flow host for telemetry matching:
// strip an optional :port and lowercase.
func telemetryHost(host string) string {
	if i := strings.LastIndexByte(host, ':'); i != -1 {
		host = host[:i]
	}
	return strings.ToLower(host)
}

// isBrowserTelemetry reports whether host is a known Chrome or Firefox
// background telemetry / update / crash-reporting endpoint.
func isBrowserTelemetry(host string) bool {
	_, ok := browserTelemetryHosts[telemetryHost(host)]
	return ok
}

// isAndroidTelemetry reports whether host is a known Android OS / GMS /
// Crashlytics / Analytics background telemetry endpoint.
func isAndroidTelemetry(host string) bool {
	h := telemetryHost(host)
	if _, ok := androidTelemetryHosts[h]; ok {
		return true
	}
	for _, suf := range androidTelemetrySuffixes {
		if h == suf[1:] || strings.HasSuffix(h, suf) {
			return true
		}
	}
	return false
}
