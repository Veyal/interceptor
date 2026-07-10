---
name: finding-images
description: Attach screenshots to findings as content-addressed image blocks (not base64 in body JSON).
---

# Finding image evidence

Findings support three body block types: `text`, `flow`, and `image`.

## Persist shape (in `findings.body`)

```json
{"type":"image","hash":"<64-char sha256>","mime":"image/png","caption":"..."}
```

Never store `data`, `path`, `url`, or `missing` in the body JSON.

## Upload

- REST: `POST /api/findings/{id}/images` with `{data, mime?, caption?, position?}`
- MCP: `add_finding_image` (same fields)
- Bytes go through `PutImageBytes` → content-addressed `bodiesDir` (same as flow bodies)
- Max 5 MiB; MIME allowlist via `SanitizeNotesImageMIME` (raster only)

## Serve

`GET /api/findings/images/{hash}` — `nosniff`, sanitized Content-Type, long cache.

## GC

`GCBodies` unions flow body hashes **and** hashes from finding image blocks (`FindingImageHashes`). Without that, `POST /api/flows/gc` deletes screenshots.

## UI

Findings editor: **＋ Screenshot** → file picker → POST images → reload blocks. Caption edits persist via body PATCH (hash/mime/caption only).
