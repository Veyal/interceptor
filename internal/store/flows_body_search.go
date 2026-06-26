package store

import (
	"fmt"
	"strings"
)

const maxFlowBodyScanFlows = 8000

// FlowIDsBodySearch returns flow ids whose request or response body contains term
// (case-insensitive). Other FlowFilter fields apply; Search is the body term.
func (s *Store) FlowIDsBodySearch(f FlowFilter, maxScan int) ([]int64, string, error) {
	term := strings.ToLower(strings.TrimSpace(f.Search))
	if term == "" {
		return nil, "", nil
	}
	if maxScan <= 0 {
		maxScan = maxFlowBodyScanFlows
	}
	base := f
	base.Search = ""
	where, args := buildFlowFilterWhere(base)
	q := `SELECT id, req_body_hash, res_body_hash FROM flows`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY id DESC LIMIT ?"
	args = append(args, maxScan)

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()

	hashHit := map[string]bool{}
	var ids []int64
	scanned := 0
	for rows.Next() {
		scanned++
		var id int64
		var reqH, resH string
		if err := rows.Scan(&id, &reqH, &resH); err != nil {
			return nil, "", err
		}
		for _, hash := range []string{reqH, resH} {
			if hash == "" {
				continue
			}
			hit, ok := hashHit[hash]
			if !ok {
				var err error
				hit, err = s.bodyContainsTerm(hash, term, maxEndpointBodyReadBytes)
				if err != nil {
					hit = false
				}
				hashHit[hash] = hit
			}
			if hit {
				ids = append(ids, id)
				break
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	var note string
	if scanned >= maxScan {
		note = fmt.Sprintf("Body search scanned the latest %d flows. Narrow with host/method filters if results look incomplete.", maxScan)
	}
	return ids, note, nil
}
