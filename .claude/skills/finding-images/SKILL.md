# Finding image evidence

Findings support three body block types: `text`, `flow`, and `image`.

## Persist shape (in `findings.body`)

```json
{"type":"image","hash":"<64-char sha256>","mime":"image/png","caption":"..."}
```

Never store `data`, `path`, `url`, or `missing` in the body JSON.

## Upload

- REST: `POST /api/findings/{id}/images` with `{data, mime?, caption?, position?}`
- MCP: `add_finding_image` (same fields) — for real browser/device screenshots you already have
- Bytes go through `PutImageBytes` → content-addressed `bodiesDir` (same as flow bodies)
- Max 5 MiB; MIME allowlist via `SanitizeNotesImageMIME` (raster only)

## Flow PNG previews (tool-styled HTTP screenshots)

Prefer these for report evidence of captured traffic (History / Repeater / Intruder / PoC):

- REST: `GET /api/flows/{id}/preview.png?side=both|req|res&pretty=0|1&layout=vertical|horizontal&theme=dark|light`
- REST: `POST /api/findings/{id}/flow-preview` with `{flowId, side?, pretty?, layout?, theme?, caption?, position?}` — render + attach
- MCP: `render_flow_preview` with `flowId` + optional `findingId` / `pretty` / `layout` / `theme` (recommended: always pass `findingId`)

Defaults: `side=both`, `pretty=true`, `layout=horizontal` (request left / response right), `theme=light`.

Generated PNGs use Interseptor chrome + monospace req/res panes (pure Go, no browser).

## Serve

`GET /api/findings/images/{hash}` — `nosniff`, sanitized Content-Type, long cache.

HTML report export (`?format=html`) rewrites image URLs to `data:` URIs so offline/client reports show screenshots.

## GC

`GCBodies` unions flow body hashes **and** hashes from finding image blocks (`FindingImageHashes`). Without that, `POST /api/flows/gc` deletes screenshots.

## UI

Findings editor is point-first: Impact → Why → Target → **PoC timeline** (primary editor). **＋ Screenshot** / flow attach / flow-preview PNG defaults: pretty, horizontal (request left / response right), light theme.

Click any screenshot (or markdown `.md-img`) → full-viewport lightbox: scroll / ± / double-click to zoom, drag to pan, Fit or Esc to close.

Prefer `render_flow_preview` for HTTP evidence; `add_finding_image` for real UI/device shots. Each artifact caption should state what changed and why it proves Impact.
