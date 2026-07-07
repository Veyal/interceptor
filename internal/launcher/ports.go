package launcher

import (
	"fmt"
	"net"
	"strconv"
)

// FindFreePort returns the first TCP port in [start, start+span) that is not
// in used and can actually be bound on host right now, verified by a real
// listen-then-close probe — not just absence from used — so a port already
// held by an unrelated process is skipped too.
func FindFreePort(host string, start, span int, used map[int]bool) (int, error) {
	for p := start; p < start+span; p++ {
		if used[p] {
			continue
		}
		ln, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(p)))
		if err != nil {
			continue
		}
		_ = ln.Close()
		return p, nil
	}
	return 0, fmt.Errorf("no free TCP port found in [%d, %d) on %s", start, start+span, host)
}
