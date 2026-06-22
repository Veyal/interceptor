# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

This is **not** a conventional application — it is a single self-contained **Design Component (`.dc.html`)** artifact that specifies the UI of **Conduit**, an intercepting HTTP proxy / security testing tool (a Burp-Suite-style "HTTP client UI" design spec). The entire product lives in **`Conduit.dc.html`**; everything else is generated runtime, preview assets, or reference screenshots.

- `Conduit.dc.html` — the design itself: an `<x-dc>` template plus an embedded `Component` logic class. **This is the only file you normally edit.**
- `support.js` — the Design Composer runtime (React + Babel renderer). **Generated — do not edit** (see header: "GENERATED from dc-runtime/src/*.ts … Rebuild with `cd dc-runtime && bun run build`"). That `dc-runtime` source project is not part of this repo.
- `screenshots/` — reference renders of each module (repeater-history, api-rest, intercept, settings). Treat these as the visual ground truth for how the design should look.
- `.thumbnail` — WebP preview image of the whole canvas.

## Building, running, testing

There is **no build system, test suite, linter, or package manifest in this repo** — do not look for `package.json`, `npm`, etc. The artifact is rendered by an external **Design Composer host**, not by this repo.

To preview/render `Conduit.dc.html`:
- `support.js` auto-boots on `DOMContentLoaded`. It **requires the host to provide `window.React` and `window.ReactDOM`** — it does *not* inject them. Opening the bare file in a plain browser throws `dc-runtime: window.React is not available yet`. Render it inside the Design Composer preview, or a harness that loads React + ReactDOM *before* `support.js`.
- The runtime pulls **Babel from `https://unpkg.com/@babel/standalone@7.26.4`** at runtime, and the template loads Google Fonts (JetBrains Mono). **Network access is required** for a faithful preview.
- The preview canvas is sized `1280×800` (declared in the `data-props` `$preview`).

To change the runtime behavior itself (the `<sc-for>`/`<sc-if>`/`{{ }}` engine), you must edit and rebuild the separate `dc-runtime` project — not possible from this repo alone. Regenerating `support.js` here by hand is wrong.

## Architecture of `Conduit.dc.html`

The file has two parts:

1. **Template** — the `<x-dc>` block (starts ~line 9). Plain HTML with inline styles plus a small templating DSL (below).
2. **Logic** — a `<script type="text/x-dc" data-dc-script>` block (~line 746) containing `class Component extends DCLogic`.

### The `renderVals()` pattern (most important thing to understand)

`Component` follows a strict render-derived-view-model pattern:

- **`state`** (~line 748) is one flat object holding *all* UI state — current `tab`, filters, sort keys, intercept queue, repeater/intruder inputs, theme, etc. `this.setState({...})` triggers a re-render (React under the hood).
- **Static mock datasets** are class fields: `traffic` (the 16 captured HTTP flows), `issues` (scanner findings by severity), `wsFrames` (WebSocket frames), `endpoints` (the REST API reference). Seeded `apiKeys` and `matchRules` live in `state`. To change what the UI displays, edit these.
- **Pure helpers** format/colorize: `methodColor`, `statusColor`, `statusText`, `mimeLabel`, `typeOf`, `fmtSize`, `fmtTime`, `prettyBody`, `hlJSON` (JSON syntax highlighter), `rawReq`/`rawRes`, `pre`.
- **`renderVals()`** (~line 990) is the heart: on every render it computes the **entire view-model** from `state` — theme tokens, nav colors, the filtered+sorted `rows`, sortable column headers, filter chips, the selected flow's request/response panels, and the repeater/intruder/intercept/websocket/api view-models. Crucially it also builds the **event-handler closures** (`onClick`, `onCtx`, send-to-Repeater/Intruder, forward/drop held requests, etc.). The names it returns are exactly the names the template binds to.

Data flow: `state → renderVals() → {{ }} bindings → DOM`; user events → closures from `renderVals()` → `setState` → re-render. All behavior is **simulated client-side** — e.g. `sendRepeater()` fakes a response with `setTimeout`; there is no real proxy or network.

### Template DSL (interpreted by `support.js`)

- `{{ expr }}` — interpolation; binds to `state` fields, helper results, and `renderVals()` outputs.
- `<sc-for list="{{ collection }}" as="r"> … {{ r.field }} … </sc-for>` — iteration.
- `<sc-if value="{{ cond }}"> … </sc-if>` — conditional rendering.
- `onClick="{{ handler }}"`, plus `onInput` / `onChange` / `onContextMenu` — event bindings to closures.
- `style="..."` with a paired `style-hover="..."` for hover states.
- Theming is via **CSS custom properties** (`--bg`, `--accent`, `--fg`, `--red`, `--sx-key` …) applied to the root element from the `DARK`/`LIGHT` token maps in `renderVals()`. Use these variables for any new color — never hardcode hex in the template.

## Product modules (the `tab` values)

`proxy` (HTTP History + WebSockets sub-tabs, with the intercept hold/forward/drop queue and match-&-replace rules) · `intruder` (Sniper/Pitchfork/etc. attack types, `§…§` fuzz markers, payload lists) · `repeater` (compose/send a request, response views, send history) · `scanner` (security issues grouped by severity) · `api` (API Keys / REST reference / MCP sub-tabs) · `settings` (port, bind address, SSL/CA cert, system proxy, remote tunnel).

When adding a module or feature: add its state to `state`, derive its view-model + handlers in `renderVals()`, and render it in the template with `<sc-for>`/`<sc-if>` gated on `state.tab`. Keep the mock-data-driven, fully-simulated approach consistent with the existing modules, and cross-check against `screenshots/` for the intended look.

## Changelog policy

Every change to this project is recorded in `CHANGELOG.md` ([Keep a Changelog](https://keepachangelog.com/) format). **Before finishing any turn in which you modified `Conduit.dc.html`, docs, or config**, add a bullet under `## [Unreleased]` describing *what* changed and *why*, grouped under `Added` / `Changed` / `Fixed` / `Removed`. When a batch of work is finalized, rename `[Unreleased]` to a dated section (`## [YYYY-MM-DD] — summary`) and start a fresh empty `[Unreleased]`.

A `Stop` hook (`.claude/hooks/changelog-reminder.sh`, configured in `.claude/settings.json`) enforces this: if project files changed without a matching `CHANGELOG.md` update, it reminds you before the turn ends. It is a non-destructive nudge — it only ever blocks the stop with a reminder, never fails the session. Note it activates only after Claude Code reloads its config (open `/hooks` once, or restart), because `.claude/` was created mid-session.
