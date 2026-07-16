# MCP Cookbook — recipes for the AI-assisted pentester

*For Priya + Atlas: copy these prompts into your MCP client after connecting
`interseptor mcp` or `POST http://127.0.0.1:9966/mcp`.*

## Recipe 1 — Map an API from captured traffic

**Goal:** Triage what landed in History and pick endpoints worth attacking.

```
1. list_flows with search set to the target host
2. analyze_flow on the most interesting ids (POST/PUT, auth headers, 4xx/5xx)
3. get_flow for bodies you need to read
4. flow_as_curl on anything you want to replay manually
```

**Tip:** Add an include-scope rule (`add_scope_rule`) first so `list_flows` isn't noisy.

## Recipe 2 — Content discovery through the proxy

**Goal:** Find hidden paths, with every hit landing in History for triage.

Interseptor has no built-in forced-browser (the old `start_discovery` /
`discovery_state` / `suggest_discovery_paths` tools were removed — see
CHANGELOG). Run a real tool instead, pointed **through** the Interseptor
proxy, so every request it fires is captured like any other traffic:

```
1. list_scope — confirm the target is in scope
2. Run a forced-browse tool through the proxy, e.g.:
   feroxbuster -u https://target/ --proxy http://127.0.0.1:8080 -k
   (or gobuster / ffuf configured with the same proxy)
3. list_flows with search set to the target host to see what landed
4. host_stats for a per-host summary of what was hit
5. send_request on interesting hits; run_scanner for passive follow-up
```

**Human takeover:** Watch Proxy History live — hits appear as normal
captured flows, no separate Discover tab.

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

## Recipe 4 — Close out findings (engagement end)

**Goal:** Leave a report-ready project, not a History pile.

```
1. list_findings — triage status / severity / ready flags
2. For each stub: update_finding with Impact / Why / Target pillars
3. get_flow + add_finding_poc for proof flows (and screenshots if needed)
4. Mark uncertain items needs_verification with concrete check steps
5. export_findings_report (or UI Export report) → Markdown/HTML for the client
6. Optional: export_full_project for a portable archive
```

**Human checklist:** [engagement-closeout.md](../engagement-closeout.md)

## Recipe 5 — Autopilot with trust review

**Goal:** Run Autopilot, then accept only what the Trust ledger justified.

```
1. list_scope — Autopilot refuses to start without include rules
2. check_readiness — fix blockers (OOB, auth, traffic)
3. autopwn_start with a tight budget (maxRequests / maxWallMs)
4. autopwn_state while it runs; watch Activity + History (glass box)
5. list_findings — review only newly filed items; delete/revise noise
6. autopwn_stop if budgets look wrong mid-run
```

**Tip:** In the UI, the Autopilot **Trust ledger** shows filed / rejected / skipped
with reasons — use that before you trust Critical/High.

## Recipe 6 — Custom checks and rule packs

**Goal:** Encode a finding as a reusable check, or install an official pack.

```
1. list_checks / list_active_checks — see what's loaded
2. Author offline: `interseptor check new` → validate → test
3. save_check / save_active_check when ready (or drop into Checks UI)
4. list_packs / pack_info — see installed packs (install is human-gated)
5. Human: Scanner → Checks → Install official pack, or
   `interseptor rules install pack.tar.gz`
```

## Recipe 7 — Intruder from AI payload lists

**Goal:** Fuzz one injection point with AI-suggested payloads, then file a finding.

```
1. get_flow on the target exchange
2. suggest_intruder_payloads with flowId (+ optional hint)
3. start_intruder using the returned positions/payloads (or UI ✨ Generate)
4. After the run: inspect flagged / interesting results in History
5. create_finding + add_finding_poc with the best attempt's flowId
```
