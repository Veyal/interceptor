package store

import (
	"sort"
	"strconv"
	"strings"
)

// Endpoint is a unique (host, method, path) surface aggregated from flows — the
// building block of the endpoint map. Repeated hits collapse into one row.
type Endpoint struct {
	Host       string `json:"host"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Scheme     string `json:"scheme"`
	LastStatus int    `json:"lastStatus"` // status of the most recent hit
	Statuses   []int  `json:"statuses"`   // every distinct status seen, sorted
	Hits       int    `json:"hits"`
	LastFlowID int64  `json:"lastFlowId"` // most recent flow, for click-through
}

// EndpointFilter narrows which flows are aggregated into endpoints.
type EndpointFilter struct {
	Host         string
	Search       string
	ExcludeFlags int64
}

// Endpoints returns the unique endpoints in history grouped by (host, method,
// path), ordered by host then path. The latest status/scheme/flow per group come
// from the most recent hit (SQLite fills bare columns from the MAX(id) row).
func (s *Store) Endpoints(f EndpointFilter) ([]Endpoint, error) {
	var where []string
	var args []any
	if f.ExcludeFlags != 0 {
		where = append(where, "(flags & ?) = 0")
		args = append(args, f.ExcludeFlags)
	}
	if f.Host != "" {
		where = append(where, "instr(lower(host), lower(?)) > 0")
		args = append(args, f.Host)
	}
	if f.Search != "" {
		where = append(where, "(instr(lower(path), lower(?)) > 0 OR instr(lower(host), lower(?)) > 0)")
		args = append(args, f.Search, f.Search)
	}
	q := `SELECT host, method, path, scheme, status, MAX(id) AS last_id, COUNT(*) AS hits,
	             GROUP_CONCAT(DISTINCT status) AS statuses
	      FROM flows`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " GROUP BY host, method, path ORDER BY host, path, method"

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Endpoint
	for rows.Next() {
		var e Endpoint
		var statusCSV string
		if err := rows.Scan(&e.Host, &e.Method, &e.Path, &e.Scheme, &e.LastStatus, &e.LastFlowID, &e.Hits, &statusCSV); err != nil {
			return nil, err
		}
		e.Statuses = parseStatusCSV(statusCSV)
		out = append(out, e)
	}
	return out, rows.Err()
}

// parseStatusCSV turns GROUP_CONCAT(DISTINCT status) ("200,404") into a sorted
// de-duplicated []int.
func parseStatusCSV(s string) []int {
	if s == "" {
		return nil
	}
	seen := map[int]bool{}
	var out []int
	for _, p := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.Ints(out)
	return out
}
