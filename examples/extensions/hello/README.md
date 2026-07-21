# hello — a minimal Interseptor extension

A copy-paste starting point for the Phase-1 in-process hook API. See
[`docs/extensions.md`](../../../docs/extensions.md) for the full guide and
[`internal/plugin/annotator`](../../../internal/plugin/annotator) for a
complete, tested example that ships with the binary.

`hello.go` registers an `OnFlowCaptured` hook that logs one line per captured
flow. It demonstrates the whole contract in ~30 lines:

- **narrow host interface** (`flowSource`) instead of importing `store`;
- **non-blocking** hook body — work happens in a goroutine;
- **opt-in `Enable`** that no-ops on a nil host, so it can never misfire.

## Turning it into a real extension

1. Copy this directory to `internal/plugin/<yourname>/` (Go can't build a hook
   into the binary from under `examples/`).
2. Widen the host interface to the calls you need (`AddFlowTags`, `GetFlow`,
   `CreateFinding`, …) — `*store.Store` will satisfy it.
3. Call your `Enable(...)` from `cmd/interseptor`, gated behind an env var or
   setting so default behavior is unchanged.
4. Add a `_test.go` that drives your logic against a fake host — no proxy
   required.
