# Interceptor — Slice #1: Core Intercepting Proxy (Design)

- **Date:** 2026-06-22
- **Status:** Approved (pending spec review)
- **Slice:** #1 of the Interceptor build (formerly "Conduit")

## Goal

Build **Interceptor**, a lightweight intercepting HTTP/HTTPS proxy, with performance as a
first-class constraint. The explicit benchmark is "much lighter than Burp Suite." Burp is heavy
because it (a) runs on the JVM (hundreds of MB of heap + GC before any traffic), (b) keeps full
HTTP history — including bodies — in memory, (c) runs passive analysis on every message, and (d)
carries a heavyweight Swing UI plus many threads. Interceptor deliberately inverts each: a compiled
native (Go) core, bodies streamed to disk with only a light index in RAM, analysis off the hot path,
and a virtualized web UI.

This document specifies **slice #1 only**: the core intercepting proxy. Later modules (repeater,
intruder, scanner, API/MCP) are separate design → plan → build cycles.

## Locked decisions

| Decision | Choice |
|---|---|
| Product name | **Interceptor** (rename from "Conduit" folded into this build) |
| Core stack | **Go**, compiled to a single static binary |
| UI | **React** (rebuilt from the existing design as a Vite app), served as static files by the core, opened in the default browser |
| Storage | **Persistent + lean**: SQLite metadata + on-disk content-addressed bodies, lazy-loaded; one rolling session that survives restarts |
| SQLite driver | `modernc.org/sqlite` (pure Go, **no cgo** → keeps the single static binary) |
| Go module path | `github.com/Veyal/interceptor` |

## Scope

### In scope (slice #1)
- MITM proxy for **HTTP and HTTPS**, with local-CA TLS interception.
- Live **capture** of flows (metadata + bodies) to persistent storage.
- **Proxy / History** view: list, filter, sort, and inspect real captured traffic (request + response, raw/pretty/headers).
- **Intercept workflow** for *requests*: hold / forward (with edits) / drop, plus **match & replace** rules.
- **Configurable proxy listener**: bind address *and* port changeable at runtime from Settings (default `127.0.0.1:8080`; may bind `0.0.0.0` for LAN/device interception).

### Out of scope (deferred to later slices)
- **Response interception** (pausing/editing responses). Responses are *captured* in v1 but not *held*.
- **WebSocket** capture/interception (the design has a WebSockets sub-tab; HTTP/HTTPS only in v1).
- Repeater, Intruder, Scanner, API keys / REST API / MCP modules.
- Named project files (save/open named sessions). v1 is one rolling session.
- Upstream/chained proxy, native webview window, fine-grained intercept scope rules.

## Architecture

One Go binary running three cooperating subsystems in-process, with **two localhost listeners**:

- **Proxy port** — default `127.0.0.1:8080`, **runtime-configurable** (addr + port). Carries the victim traffic being intercepted.
- **Control port** — fixed `127.0.0.1:9966`, **localhost-only**. Serves the React UI and the REST + WebSocket API.

Separating them ensures the UI is never itself proxied/captured and the control plane never listens on an external interface.

### Packages (one responsibility each, independently testable)

| Package | Responsibility | Depends on |
|---|---|---|
| `proxy` | Listener, `CONNECT` handling, TLS MITM, upstream forwarding, runtime rebind | `tlsca`, `capture`, `intercept` |
| `tlsca` | Load/generate local CA; mint + cache per-host leaf certs | — |
| `intercept` | Hold queue + match-&-replace engine; per-flow pause/modify decision | `store` |
| `capture` | Tee request/response into the body store; build flow records | `store` |
| `store` | SQLite (metadata, rules, settings) + content-addressed body files; query / lazy-load | — |
| `control` | REST + WS API, serves UI, bridges UI ↔ intercept/store, live event broadcast | `store`, `intercept` |
| `cmd/interceptor` | Config, wiring, lifecycle | all |

### Request lifecycle

1. Client points at the proxy (manual or system proxy). HTTP request, or `CONNECT` for HTTPS.
2. HTTPS → proxy answers `CONNECT`, mints a leaf cert for the host signed by the local CA, terminates TLS with the client, reads the plaintext request.
3. Proxy builds a **Flow** (id, request line/headers; body tee'd → body store).
4. **Intercept gate:** if intercept is ON, the flow is pushed to the hold queue and the proxy goroutine *blocks* awaiting a UI decision (forward [possibly edited] / drop). If OFF, it passes straight through.
5. **Match & replace:** enabled rules transform the (possibly edited) request before it leaves.
6. Proxy dials upstream, streams the response back to the client while tee'ing the response body to the store.
7. Flow finalized → SQLite row updated → `flow.updated` event broadcast on the control WebSocket → the UI history list updates live (no refetch).

## Data model & storage

SQLite database + body store under `~/.interceptor/` (`interceptor.db`, `bodies/`, `ca/`).

- **`flows`** — `id`, `ts`, `method`, `scheme`, `host`, `port`, `path`, `http_version`, `status`,
  `req_headers` (JSON), `res_headers` (JSON), `req_body_hash`, `res_body_hash`, `req_len`, `res_len`,
  `mime`, `duration_ms`, `client_addr`, `error`, `flags` (intercepted/edited/truncated).
  Indexed on `host`, `status`, `method`, `ts`.
- **`rules`** — `id`, `order`, `enabled`, `type` (req/res · header/body), `match` (regex), `replace`.
- **`settings`** — key/value: proxy bind addr, proxy port, intercept on/off, fallback-on-pin, etc.
- **Body store** — each unique body is a content-addressed file (`bodies/aa/bb/<sha256>`), **deduped**,
  optionally gzipped. Flow rows reference bodies by hash. **Bodies never enter SQLite** and are read
  only when a flow is opened.

## Performance mechanics

- Hot path holds only fixed-size buffers; bodies stream through a tee → async writer goroutine over a
  buffered channel, so disk I/O never blocks forwarding.
- In RAM: a bounded ring of recent flow *metadata* for the live list + SQLite's page cache. Everything
  else lives on disk and is queried on demand.
- Filtering and sorting are pushed down to SQL — never performed over a large array in the browser.
- **Backpressure:** if the writer lags, drop *body capture* (mark the flow `body_truncated`) — never
  drop forwarding.
- UI: a virtualized list (only visible rows mounted) fed by incremental WebSocket events plus paged
  scrollback queries.
- Target: tens of thousands of flows per session with flat RAM and sub-frame UI updates.

## Intercept & match-and-replace

- Intercept is a toggle. When ON, **every request is held** (Burp-style) until the user forwards or
  drops it; the held raw request is editable before forwarding. When OFF, traffic flows through.
- Match & replace rules (ordered, individually enabled) apply regex transforms to request headers or
  body before the request leaves. Response-side rules are defined in the schema but only request-side
  rules execute in v1 (responses are not modified yet).

## TLS / CA

- On first run, generate a local CA (key + cert) under `~/.interceptor/ca/`. The user installs/trusts
  it once (Settings surfaces the cert + install hint, matching the existing design).
- Per-host leaf certs are minted on demand, signed by the CA, and cached (in-memory + optionally on
  disk) keyed by host.

## Error handling

- **Upstream failure** (DNS/TLS/timeout) → synthesize an error response to the client *and* record the
  flow with an error status — failures are visible in history, not silent.
- **Cert pinning** (client rejects our leaf) → record `tls_intercept_failed`; configurable fallback to
  a blind tunnel (pass-through without interception).
- **Body-store write error** → mark the flow `capture_error`; forwarding still succeeds (capture must
  never break the proxy).
- **Proxy rebind** (new addr/port from Settings) → open the *new* listener first; if it fails (port in
  use, privileged port, bad address) keep the *old* one and return a structured error → UI toast. Swap
  only once the new listener is live, draining in-flight flows on the old one.
- **Control API** validation → structured JSON errors surfaced via the existing toast system.
- **Graceful shutdown** → stop accepting, drain in-flight flows, flush the body writer, checkpoint +
  close SQLite.

## Testing strategy

- **Unit, per package:** `tlsca` (leaf minting + chain to CA), `intercept` (regex match, forward/drop/
  edit decisions), `store` (CRUD, dedup, lazy load, filter SQL), `capture` (tee correctness,
  truncation under backpressure).
- **Integration:** boot the proxy on an ephemeral port; point a Go `http.Client` trusting our CA at a
  local test upstream; assert flows captured, intercept hold → forward/drop, match & replace applied,
  bodies stored + retrievable, and that a **failed rebind preserves the old listener**.
- **Performance smoke:** replay N-thousand requests; assert a RAM ceiling and a throughput floor.
- The Go core is fully testable headless — the control API is the seam; the UI is not required for tests.

## UI

The existing React/HTML design (currently the `Conduit.dc.html` Design Component + screenshots) is the
visual source of truth, rebuilt as a real Vite React app. Slice #1 wires up the **Proxy** tab
(HTTP history list, filters, request/response inspector) and the **Intercept** controls (hold queue,
forward/drop, match & replace), plus the **Settings** needed for the proxy listener (bind address +
port) and the CA. All "Conduit" naming is changed to "Interceptor" as part of this slice.

## Open questions

None blocking. Response interception, WebSocket capture, and the other modules are explicitly deferred
to their own slices.
