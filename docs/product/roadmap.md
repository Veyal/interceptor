# Interceptor — Roadmap

*Owner: Product · Last updated: 2026-06-22 · Horizon: rolling. Now/Next/Later, not dates.*

Roadmap is organized around the strategy in [strategy.md](strategy.md). The product **intent** is a
proxy operated by **a penetration tester and their AI assistant together**, so the top priorities
are: **(A) make the AI a first-class operator** (a real MCP server + an AI-friendly API), **(B)
frictionless UX/onboarding** for the human, and only then **(C) close table-stakes gaps** and **(D)
press differentiators**. See [improvements.md](improvements.md) for the gap analysis driving this.

## What exists today (v1 baseline)

Proxy + HTTP/HTTPS MITM, live history with inspector, intercept (hold/forward/drop) + request-side
match-&-replace, **Repeater**, **Intruder** (Sniper/Pitchfork), passive **Scanner**, **WebSocket
frame capture**, runtime listener rebind, CA management, and a **REST + SSE control API** with API
keys and an MCP descriptor. ~3.7k LOC of Go, no cgo, single static binary.

## Themes

1. **AI-operable** — the AI can do everything the UI can: a real MCP server + an AI-friendly API.
2. **Frictionless UX** — instant onboarding (CA, proxy setup, MCP setup), low-noise, easy to drive.
3. **Trustworthy core** — be a tool pentesters stage real work on (scope, scale, correctness).
4. **Interop & reach** — HAR, upstream proxy, benchmarks, packaging.

## ✅ Shipped (cycle 1 — the AI-operable pivot)

The entire **Now + Next** slate of cycle 1 landed (each TDD'd, with a control API, UI, MCP tool, and
verified live). See [CHANGELOG.md](../../CHANGELOG.md).

| Shipped | Notes |
|---|---|
| **Real MCP server** (`interceptor mcp`) | stdio JSON-RPC, **18 tools**, bounded results |
| **MCP setup in the UI** + AI-friendly API | copy-paste client config; `/api/reference` self-documents |
| **Target scope** (PRD-0001) | include/exclude rules focus history + intercept + scanner |
| **Response interception** | response match-&-replace + hold/edit/drop |
| **HAR export & import** | HAR 1.2 round-trip; free interop |
| **System-proxy toggle** (macOS) | opt-in only |
| **Upstream / chained proxy** | race-safe, live + at startup |
| **History full-text search** | method/host/path |
| **Onboarding "get started" card** + **performance benchmarks** | see [benchmarks.md](../benchmarks.md): ~20 MB idle, ~1 s cold start |

## Now (cycle 2) — depth on the core loop

| Item | Theme | Why | Effort |
|---|---|---|---|
| **Projects** (named save/load; export/import a portable session: flows + rules + scope + settings) | Trustworthy core | Burp Community's most-missed feature; builds on HAR export + the SQLite store | M |
| **Comparative benchmarks** (idle RSS / cold start / 10k-flow scroll **vs Burp & ZAP**, reproducible script) + CI throughput guard | Interop & reach | Turns our measured numbers into a credible published comparison | S–M |
| **Saved filters / views** + scope-aware quick filters | Trustworthy core | Scales the core loop; pairs with scope and search | S–M |

## Next (cycle 2) — parity + agent depth

| Item | Theme | Why | Effort |
|---|---|---|---|
| **MCP: streamable-HTTP transport + `analyze_flow`** | AI-operable | Lets hosted agents connect without a subcommand; a decision-ready flow summary tool | M |
| **Session / auth handling** (login macros, token refresh, re-auth on 401) | Trustworthy core | High value; a pain point across all tools | L |
| **BYO-key AI assist** (explain request, suggest payloads, summarize findings) | Differentiator | Keeps pace with Burp AI without hosting a model; optional & local-first | M–L |
| **WebSocket through an upstream proxy** + WS message replay | Interop & reach | Completes upstream-proxy + WS coverage | M |

## Later (cycle 2) — bigger bets

| Item | Theme | Why / caveat | Effort |
|---|---|---|---|
| **HTTP/2 support** | Trustworthy core | Increasingly expected; significant proxy work | L |
| **Extension / plugin API** | Differentiator | Burp's real moat; worth it once core is sticky | XL |
| **Collaboration / multi-user** | Reach | Team/commercial segment | XL |
| **Remote tunnel** (expose the proxy to a remote device securely) | Interop | Niche; external dependency | M |
| **HTTP/3 / QUIC** | Trustworthy core | Immature even in mitmproxy; forward-looking | XL |

## Prioritization model

Lightweight RICE — **Reach × Impact × Confidence ÷ Effort**. Reach = share of target users
touched; Impact = 0.25/0.5/1/2/3; Confidence = 0.5/0.8/1.0; Effort in person-weeks (S≈1, M≈2–4,
L≈6–10, XL≈12+). Cycle-2 top scores:

| Feature | Reach | Impact | Conf | Effort | ~Score | Bucket |
|---|---|---|---|---|---|---|
| Projects (save/load) | Med | 1.0 | 0.8 | M | High | Now |
| Comparative benchmarks | High | 0.5 | 0.8 | S–M | High | Now |
| Saved filters/views | Med | 0.5 | 1.0 | S–M | Med-High | Now |
| MCP streamable-HTTP + analyze_flow | Med | 1.0 | 0.8 | M | Med-High | Next |
| Session/auth handling | Med | 2.0 | 0.5 | L | Med | Next |
| BYO-key AI assist | Med | 1.0 | 0.6 | M–L | Med | Next |
| HTTP/2 | Med | 1.0 | 0.8 | L | Low-Med | Later |

*Scores are directional, revisited each planning cycle. "Now" is a small committed slice; "Next"
and "Later" are intentionally not dated.*

## How we work (lightweight product process)

1. A roadmap item graduates to a **PRD** ([prd-0001-target-scope.md](prd-0001-target-scope.md) is the
   template/exemplar) before build.
2. Each PRD → a TDD implementation plan under `docs/superpowers/plans/` (existing convention).
3. Every change lands with tests, a `CHANGELOG.md` entry, and updates to this roadmap.
4. We measure against [metrics.md](metrics.md) and let the data re-rank the backlog.
