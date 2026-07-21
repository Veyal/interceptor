// Package annotator is the official example Interseptor extension
// (see docs/extensions.md and issue #25). It is intentionally small and
// dependency-light: a working demonstration of the Phase-1 in-process hook API
// that a third-party author can copy.
//
// What it does: when a flow is captured, if its host contains any of the
// configured substrings, it adds a tag to that flow — so an operator can, for
// example, auto-label every request that touches an internal admin host.
//
// It follows the two rules every hook must follow:
//   - never block the proxy hot path — the hook body just hands off to a
//     goroutine and returns immediately;
//   - never import proxy/control types — it talks to the host through the small
//     Store interface below, so it stays decoupled and unit-testable.
package annotator

import (
	"log"
	"strings"

	"github.com/Veyal/interseptor/internal/plugin"
	"github.com/Veyal/interseptor/internal/store"
)

// Store is the slice of the host the annotator needs. *store.Store satisfies it.
type Store interface {
	GetFlow(id int64) (*store.Flow, error)
	AddFlowTags(flowID int64, tags []string) ([]string, error)
}

// Config declares which flows to tag and with what.
type Config struct {
	// HostContains: a flow is annotated when its host contains any of these
	// (case-insensitive) substrings. Empty means "match nothing".
	HostContains []string
	// Tag applied to matching flows. Defaults to "annotated" when empty.
	Tag string
}

// Enable registers the annotator against the plugin registry. Call once at
// startup (see cmd/interseptor wiring). It is a no-op when st is nil or the
// config matches nothing, so an accidental enable can never tag every flow.
func Enable(st Store, cfg Config) {
	if st == nil || len(cfg.HostContains) == 0 {
		return
	}
	tag := cfg.Tag
	if tag == "" {
		tag = "annotated"
	}
	needles := make([]string, 0, len(cfg.HostContains))
	for _, n := range cfg.HostContains {
		if n = strings.ToLower(strings.TrimSpace(n)); n != "" {
			needles = append(needles, n)
		}
	}
	if len(needles) == 0 {
		return
	}

	plugin.OnFlowCaptured(func(flowID int64) {
		// Off the hot path: the proxy has already answered the client.
		go annotate(st, flowID, needles, tag)
	})
}

// annotate loads the flow and tags it when its host matches. Best-effort:
// failures are logged, never propagated (an extension must not disrupt capture).
func annotate(st Store, flowID int64, needles []string, tag string) {
	f, err := st.GetFlow(flowID)
	if err != nil || f == nil {
		return
	}
	host := strings.ToLower(f.Host)
	if !matchesAny(host, needles) {
		return
	}
	if _, err := st.AddFlowTags(flowID, []string{tag}); err != nil {
		log.Printf("annotator: tag flow %d: %v", flowID, err)
	}
}

func matchesAny(host string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(host, n) {
			return true
		}
	}
	return false
}
