// Package hello is a minimal, self-contained Interseptor extension example.
// It registers an OnFlowCaptured hook that logs one line per captured flow.
//
// See docs/extensions.md for the full guide. To ship a real extension, copy
// this into internal/plugin/<name>/ and wire Enable into cmd/interseptor.
package hello

import (
	"log"

	"github.com/Veyal/interseptor/internal/plugin"
)

// flowSource is the narrow slice of the host this extension needs. Declaring it
// here (instead of importing store) keeps the extension decoupled and testable;
// *store.Store satisfies a superset of it.
type flowSource interface {
	FlowSummary(id int64) (method, host, path string, ok bool)
}

// Enable registers the hello hook. No-op on a nil host so an accidental enable
// can never misfire. Call once at startup.
func Enable(src flowSource) {
	if src == nil {
		return
	}
	plugin.OnFlowCaptured(func(flowID int64) {
		// Off the hot path: the proxy has already answered the client.
		go func() {
			method, host, path, ok := src.FlowSummary(flowID)
			if !ok {
				return
			}
			log.Printf("hello: captured %s %s%s (flow %d)", method, host, path, flowID)
		}()
	})
}
