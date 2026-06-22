# Interceptor — Roadmap

*Owner: Product · Last updated: 2026-06-22 · Horizon: rolling. Now/Next/Later, not dates.*

Roadmap is organized around the strategy in [strategy.md](strategy.md). Two jobs: **(A) close the
table-stakes gaps** that lose a "Burp alternative" evaluation, and **(B) press our differentiators**
(lightweight, free/open, scriptable/agent-native).

## What exists today (v1 baseline)

Proxy + HTTP/HTTPS MITM, live history with inspector, intercept (hold/forward/drop) + request-side
match-&-replace, **Repeater**, **Intruder** (Sniper/Pitchfork), passive **Scanner**, **WebSocket
frame capture**, runtime listener rebind, CA management, and a **REST + SSE control API** with API
keys and an MCP descriptor. ~3.7k LOC of Go, no cgo, single static binary.

## Themes

1. **Trustworthy core** — be a tool pentesters stage real work on (scope, scale, correctness).
2. **Interop** — play well with the rest of the toolchain (HAR, upstream proxy, browsers).
3. **Differentiators** — lean into speed, free/open, and the API/MCP/agent story.
4. **Reach** — make adoption frictionless and the value provable (benchmarks, docs, packaging).

## Now (next slice) — close the highest-leverage gaps + quick wins

| Item | Theme | Why | Effort |
|---|---|---|---|
| **Target scope** (in/out-of-scope host/path patterns; filters history, focuses intercept & scanner) | Trustworthy core | #1 recurring table-stakes gap; reduces noise → reinforces our "quiet/precise" edge. **PRD:** [prd-0001-target-scope.md](prd-0001-target-scope.md) | M |
| **Performance benchmarks, published** (cold start, idle RSS, 10k-flow scroll vs Burp/ZAP) | Reach | Our core thesis is unproven until measured; this is marketing gold and a regression guard | S |
| **System-proxy toggle** (point the OS at the proxy from Settings; off by default, explicit) | Interop | Removes the #1 setup friction for new users | S |
| **HAR export** of selected flows / history | Interop | Near-universal interop ask; HTTP Toolkit gating it behind Pro annoys users — we give it free | S–M |

## Next — parity + differentiation

| Item | Theme | Why | Effort |
|---|---|---|---|
| **Response interception** (hold/edit/drop responses; response-side match-&-replace executes) | Trustworthy core | Burp-parity gap explicitly deferred in the v1 spec; builds directly on the existing intercept engine | M |
| **Full MCP server** (stdio + SSE MCP exposing the control API as agent tools, beyond today's descriptor) | Differentiator | Rides the hottest 2024–25 trend; a defensible angle the JVM incumbents lack natively | M |
| **Upstream / chained proxy** (route upstream through a corporate or another proxy) | Interop | Recurring enterprise/corp-network requirement | M |
| **History full-text search + saved filters** | Trustworthy core | Scales the core loop to large sessions; pairs with scope | M |
| **HAR / raw import** (replay external captures) | Interop | Completes the interop story; feeds Repeater/Scanner from other tools | S–M |

## Later — bigger bets & forward-looking

| Item | Theme | Why / caveat | Effort |
|---|---|---|---|
| **Projects** (named save/load; export/import a portable session file) | Trustworthy core | Burp Community's most-missed feature; our SQLite store already persists — this is multi-DB + export | M |
| **Session / auth handling** (login macros, token refresh, re-auth on 401) | Trustworthy core | High value, high complexity; a known pain point across *all* tools | L |
| **HTTP/2 support** | Trustworthy core | Increasingly expected; significant proxy work | L |
| **BYO-key AI assist** (explain request, suggest payloads, summarize findings) | Differentiator | Keeps pace with Burp AI without hosting our own model; optional & local-first | M–L |
| **Extension / plugin API** | Differentiator | Burp's real moat; only worth it once core is sticky | XL |
| **Remote tunnel** (expose the proxy to a remote device/LAN securely) | Interop | Niche; external dependency; lower priority for core users | M |
| **Collaboration / multi-user** | Reach | Team/commercial segment; far off | XL |
| **HTTP/3 / QUIC** | Trustworthy core | Immature even in mitmproxy; forward-looking differentiator, not table stakes | XL |

## Prioritization model

Lightweight RICE — **Reach × Impact × Confidence ÷ Effort**. Reach = share of target users
touched; Impact = 0.25/0.5/1/2/3; Confidence = 0.5/0.8/1.0; Effort in person-weeks (S≈1, M≈2–4,
L≈6–10, XL≈12+). Top current scores:

| Feature | Reach | Impact | Conf | Effort | ~Score | Bucket |
|---|---|---|---|---|---|---|
| Target scope | High | 1.0 | 1.0 | M | High | Now |
| Perf benchmarks | High | 0.5 | 1.0 | S | High | Now |
| System-proxy toggle | Med | 0.5 | 1.0 | S | High | Now |
| HAR export | High | 0.5 | 0.8 | S–M | High | Now |
| Response interception | Med | 1.0 | 0.8 | M | Med-High | Next |
| Full MCP server | Med | 1.0 | 0.8 | M | Med-High | Next |
| Upstream proxy | Med | 0.5 | 1.0 | M | Med | Next |
| Projects (save/load) | Med | 1.0 | 0.8 | M | Med | Later |
| Session/auth handling | Med | 2.0 | 0.5 | L | Med | Later |
| HTTP/2 | Med | 1.0 | 0.8 | L | Low-Med | Later |

*Scores are directional, revisited each planning cycle. "Now" is a small committed slice; "Next"
and "Later" are intentionally not dated.*

## How we work (lightweight product process)

1. A roadmap item graduates to a **PRD** ([prd-0001-target-scope.md](prd-0001-target-scope.md) is the
   template/exemplar) before build.
2. Each PRD → a TDD implementation plan under `docs/superpowers/plans/` (existing convention).
3. Every change lands with tests, a `CHANGELOG.md` entry, and updates to this roadmap.
4. We measure against [metrics.md](metrics.md) and let the data re-rank the backlog.
