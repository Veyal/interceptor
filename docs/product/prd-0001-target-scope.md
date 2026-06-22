# PRD-0001 — Target Scope

*Owner: Product · Status: ✅ Shipped · Priority: Now (P0) · Last updated: 2026-06-22*
*Links: [strategy.md](strategy.md) · [roadmap.md](roadmap.md) · [metrics.md](metrics.md)*

> This PRD is also the **template** for future PRDs — keep the section structure.

## 1. Summary

Let users define which hosts/paths are **in scope** for an engagement, and have that scope
**focus the whole tool**: filter the history, optionally gate interception and the scanner to
in-scope traffic only. Scope is the single most-requested table-stakes feature we're missing, and
it directly reinforces our "quiet, low-noise" positioning against ZAP.

## 2. Problem & context

A real engagement touches dozens of third-party hosts (CDNs, analytics, fonts, telemetry) the
tester doesn't care about. Without scope:
- the history is **drowned in noise**, slowing the core loop;
- **intercept holds every request**, including irrelevant third-party traffic, making the
  hold-and-forward workflow unusable on real sites;
- the **scanner reports findings on out-of-scope hosts** the tester can't action and shouldn't
  report — inflating exactly the false-positive/triage burden we criticize ZAP for.

Burp, ZAP, mitmproxy, and Hetty all have scope. Our 2024–25 market scan flagged it as a recurring
expectation whose absence loses a "Burp alternative" evaluation. It is the highest-RICE item on the
roadmap.

## 3. Goals / Non-goals

**Goals**
- Define scope as ordered include/exclude rules over host (+ optional path, scheme, port).
- Apply scope to: history view, intercept gate, and the scanner.
- Make "is this in scope?" obvious in the UI and queryable via the API.
- Keep capture-everything the default (Burp-style): scope **filters/focuses**, it doesn't drop data
  unless the user explicitly opts in.

**Non-goals**
- Per-rule advanced conditions (headers, MIME, query-param matching) — later.
- Importing scope from Burp project files — later (tracked separately).
- Auto-suggesting scope from observed traffic — future enhancement.

## 4. Users & use cases

- **Pavan (pentester):** sets scope to the client's `*.acme.com` and excludes `analytics.acme.com`;
  works the whole engagement seeing only relevant flows; scanner findings are all reportable.
- **Bea (bug-bounty):** pastes the program's in-scope domains; intercept only holds those; less noise.
- **Devi (dev):** scopes to `localhost:3000` and her staging host; ignores third-party SDK chatter.
- **Auto (agent/CI):** sets scope via the API before a run so automated capture/scan stay focused.

## 5. Functional requirements

Priority: **P0** = required for launch, **P1** = strongly desired, **P2** = nice-to-have.

- **R1 (P0)** — A scope is an **ordered list of rules**; each rule has: `enabled`, `action`
  (`include` | `exclude`), `host` pattern, optional `path` pattern, optional `scheme`, optional
  `port`.
- **R2 (P0)** — **Matching semantics (Burp-aligned):** a flow is *in scope* if it matches at least
  one enabled `include` rule **and** no enabled `exclude` rule. **If there are no include rules,
  everything is in scope except matched excludes** (so "exclude-only" scope works).
- **R3 (P0)** — **Host pattern** supports a simple, documented syntax: exact (`api.acme.com`),
  leading-wildcard (`*.acme.com`), and "domain + subdomains" convenience. **Path pattern** is a
  prefix or glob. (Implementation may compile to regex internally; the *user-facing* syntax must be
  simple and documented — we are explicitly not exposing raw regex as the default.)
- **R4 (P0)** — **History:** a **"In-scope only"** toggle filters the flow list to in-scope flows.
  Each flow row shows an unobtrusive in/out-of-scope affordance.
- **R5 (P0)** — **Intercept gate:** a setting **"Intercept in-scope only"** (default on once scope
  exists) — when intercept is ON, out-of-scope requests pass straight through instead of being held.
- **R6 (P0)** — **Scanner:** the scanner only analyzes **in-scope** flows. (Today it already excludes
  Intruder traffic; add the scope predicate.)
- **R7 (P1)** — **Right-click a flow → "Add host to scope" / "Exclude host from scope"** (one-click
  scope building from observed traffic), consistent with the existing context menu.
- **R8 (P1)** — **Settings option "Don't capture out-of-scope"** (default **off**) — when on,
  out-of-scope flows are forwarded but **not** persisted, for users who want a lean DB.
- **R9 (P2)** — Scope is part of the (future) project export/import.

## 6. UX

- New **Settings → Scope** section: an ordered, editable rule table (enabled · action · host · path ·
  scheme · port · delete), mirroring the existing Match-&-Replace rules UI for consistency.
- **Proxy toolbar:** an **"In-scope only"** toggle next to the existing filters; active scope shows
  as a chip.
- **History rows:** out-of-scope rows are visually de-emphasized (dimmed) when the scope toggle is
  off, hidden when it's on.
- **Context menu:** add "Add host to scope" / "Exclude host" items (R7).
- Empty state: with no rules, copy explains "Everything is in scope. Add rules to focus."

## 7. API & data model

**Data:** new `scope_rules` table — `id, ord, enabled, action, host, path, scheme, port` — managed
exactly like the existing `rules` table (CRUD + recompiled on change). A small **`internal/scope`**
package compiles rules into a matcher and exposes `InScope(flow) bool`; `store.FlowFilter` gains an
`InScopeOnly bool` (host patterns pushed to SQL where trivial, otherwise filtered in the matcher).

**REST (mirrors `/api/rules`):**
- `GET /api/scope` → `{ rules: [...] }`
- `POST /api/scope` → create rule
- `PUT /api/scope/{id}` → update
- `DELETE /api/scope/{id}` → delete
- `GET /api/flows?inScope=1` → in-scope-only history
- Scope changes broadcast `scope.update` over SSE.

**Wiring:** the proxy consults the matcher in the intercept gate (R5); `control.scannerRun` filters
by `InScope` (R6). The matcher is the single source of truth used by history, intercept, and scanner.

## 8. Acceptance criteria (testable)

- Given include `*.acme.com` and exclude `analytics.acme.com`, then `app.acme.com/` is **in** scope
  and `analytics.acme.com/` and `cdn.other.com/` are **out**.
- Given **no include** rules and exclude `*.doubleclick.net`, then everything **except**
  `*.doubleclick.net` is in scope.
- With "In-scope only" on, `GET /api/flows?inScope=1` returns only in-scope flows.
- With intercept ON and "intercept in-scope only", an out-of-scope request is **forwarded without
  being held** (no entry in the hold queue) while an in-scope request **is** held.
- The scanner produces **no findings** whose target host is out of scope.
- Unit tests for the `scope` matcher cover include-only, exclude-only, include+exclude, wildcard,
  path, and default-everything cases. `go test -race ./...` and `go vet ./...` stay green.

## 9. Success metrics

- **Adoption:** % of sessions with ≥1 scope rule defined (target: a healthy majority of multi-flow
  sessions).
- **Noise reduction (leading indicator of value):** median in-scope/total flow ratio in sessions
  that use scope (expect well under 1.0 — proves it's focusing real traffic).
- **Quality:** scanner precision improves (fewer un-actionable, out-of-scope findings) — ties to the
  [metrics.md](metrics.md) scanner-precision KPI.

## 10. Rollout / phasing

1. **Phase 1 (P0):** `internal/scope` + `scope_rules` store + REST + history "in-scope only" +
   scanner focus. (Ships value immediately.)
2. **Phase 2 (P0/P1):** intercept gating (R5) + context-menu scope building (R7).
3. **Phase 3 (P1/P2):** "don't capture out-of-scope" (R8) + project export hook (R9).

Each phase: TDD plan under `docs/superpowers/plans/`, tests, `CHANGELOG.md` entry.

## 11. Risks & open questions

- **Pattern syntax:** keep it simple (wildcards, not raw regex) to avoid foot-guns, but power users
  may want regex — offer an explicit "regex" rule type later. *Decision needed before build.*
- **Performance:** scope matching must stay off the hot path — the proxy gate check must be O(rules)
  and cheap; large histories filter in SQL where possible.
- **Default behavior:** confirm capture-everything-by-default (only filter) is right vs. opt-in
  drop — leaning yes (matches Burp; avoids data loss surprises).

## 12. Out of scope / future

Header/MIME/param conditions; Burp scope import; auto-suggested scope; per-scope saved profiles
(tie to future Projects).
