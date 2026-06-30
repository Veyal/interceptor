package store

import "regexp"

// soft404Re matches common "page not found" phrases in HTML/JSON error pages
// that return HTTP 2xx/3xx instead of an honest 404.
var soft404Re = regexp.MustCompile(`(?i)(` +
	`not\s+found|` +
	`page\s+does\s+not\s+exist|` +
	`doesn'?t\s+exist|` +
	`no\s+such|` +
	`couldn'?t\s+find|` +
	`could\s+not\s+find|` +
	`\b404\b|` +
	`no\s+results|` +
	`nothing\s+found|` +
	`resource\s+not\s+found|` +
	`invalid\s+url|` +
	`unknown\s+page` +
	`)`)

func isSoft404Content(body []byte) bool {
	return len(body) > 0 && soft404Re.Match(body)
}
