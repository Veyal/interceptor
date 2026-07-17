# PRD-0004 — Message codecs

**Status:** Shipped in 1.5.3 · **Owner:** veyal · **Issue:** [#28](https://github.com/Veyal/interseptor/issues/28)

## Problem

Engagements often wrap API JSON behind client-side crypto (prefix + AES-ECB, custom packing).
Operators had to export blobs to external scripts, breaking the inspect → edit → resend loop for
humans and agents.

## Solution

Project-scoped Starlark codecs under `<project>/codecs/*.star` with `match` / `decode` / optional
`encode`. Display-only by default; `apply_on_send` re-encodes Repeater plaintext. Never on the
proxy hot path. AES-ECB helpers in `internal/starx`. UI Decoded view + Codecs panel; REST + MCP.

## Non-goals (v1)

- Silent MITM mutation of live traffic
- Vendor codec library in core
- Rule-pack `codecs/` install (project-local first; packs can follow)

## Acceptance

See GitHub #28 checklist — runner, AES helpers, Decoded UI, apply_on_send, REST/MCP, example, docs.
