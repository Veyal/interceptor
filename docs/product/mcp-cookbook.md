# MCP Cookbook — three recipes for the AI-assisted pentester

*For Priya + Atlas: copy these prompts into your MCP client after connecting
`interceptor mcp` or `POST http://127.0.0.1:9966/mcp`.*

## Recipe 1 — Map an API from captured traffic

**Goal:** Triage what landed in History and pick endpoints worth attacking.

```
1. list_flows with search set to the target host
2. analyze_flow on the most interesting ids (POST/PUT, auth headers, 4xx/5xx)
3. get_flow for bodies you need to read
4. flow_as_curl on anything you want to replay manually
```

**Tip:** Add an include-scope rule (`add_scope_rule`) first so `list_flows` isn't noisy.

## Recipe 2 — Agent-driven content discovery

**Goal:** Find hidden paths without leaving Interceptor.

```
1. list_scope — confirm the target is in scope
2. suggest_discovery_paths for the host (merges history seeds + AI if a key is set)
3. start_discovery with baseUrl=https://target/ and wordlist from step 2
4. Poll discovery_state until running=false
5. send_request on interesting hits; run_scanner for passive follow-up
```

**Human takeover:** Watch the Discover tab and History (`?discovery=1` filter) live.

## Recipe 3 — Triage scanner findings and fuzz

**Goal:** Turn passive hits into confirmed bugs.

```
1. run_scanner
2. list_issues — read severity/title/evidence
3. scan_report for a Markdown summary to paste into notes (append_notes)
4. For a reflected-param finding: get_flow → start_intruder with § markers
5. set_session if sends need auth; run_login_macro after a 401
```

**Safety:** `active_scan` sends real payloads — pass `arm=true` once per session and only on authorized targets.
