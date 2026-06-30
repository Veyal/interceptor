# One-off repair: align bounty-project findings with blocks + impact fields.
$base = 'http://127.0.0.1:9966/api/findings'

function Patch-Finding($id, $fields) {
    $json = $fields | ConvertTo-Json -Compress -Depth 10
    Invoke-RestMethod -Uri "$base/$id" -Method PATCH -ContentType 'application/json; charset=utf-8' -Body ([System.Text.Encoding]::UTF8.GetBytes($json))
    Write-Host "patched finding $id"
}

function Body-Json($blocks) {
    ($blocks | ConvertTo-Json -Compress -Depth 5)
}

$f1 = Invoke-RestMethod "$base/1"
Patch-Finding 1 @{
    target = '*.baliprov.dev (Laravel apps)'
    impact = 'Attackers can map the full software supply chain (framework versions, vendor paths, Sentry middleware) from production stack traces, enabling targeted CVE exploitation — including on inspektorat.baliprov.dev (anti-corruption platform).'
    body   = (Body-Json @(
        @{ type = 'text'; md = $f1.detail }
        @{ type = 'flow'; flowId = 271 }
        @{ type = 'flow'; flowId = 272 }
    ))
}

$f4 = Invoke-RestMethod "$base/4"
Patch-Finding 4 @{
    target = 'chatbot.baliprov.dev'
    impact = 'Any unauthenticated user can read and write chat messages in any session by guessing/enumerating predictable Chat-Session-Id values — cross-session data exposure and message injection.'
    body   = (Body-Json @(
        @{ type = 'text'; md = $f4.detail }
        @{ type = 'flow'; flowId = 278; note = 'Unauthenticated read of session chat-list' }
        @{ type = 'flow'; flowId = 279; note = 'Cross-session read (admin session)' }
    ))
}

$f5 = Invoke-RestMethod "$base/5"
Patch-Finding 5 @{
    impact = 'Anyone with the public DSN can read crash reports and captured PII from Sentry, and flood the project with fake events to burn quota and trigger false alerts.'
    body   = (Body-Json @(
        @{ type = 'text'; md = $f5.detail }
        @{ type = 'flow'; flowId = 284; note = 'Public JS chunk containing hardcoded Sentry DSN with sendDefaultPii:true' }
    ))
}

$ssoText = @'
## SSO Open Redirect via unvalidated redirect_url

The backend `GET /api/login-url` endpoint accepts an arbitrary `redirect_url` query parameter and embeds it in a JWT forwarded to `sso.baliprov.dev`. An attacker can set `redirect_url=https://evil.example.com` to harvest post-authentication tokens after the victim completes SSO login.

**Evidence:** The API returns HTTP 200 and the `login_url` contains the attacker-controlled domain embedded in the signed JWT.
'@

Patch-Finding 6 @{
    detail = $ssoText
    impact = 'An attacker can redirect victims through SSO and capture post-authentication tokens at an attacker-controlled URL, enabling account takeover across all SSO-integrated baliprov apps.'
    body   = (Body-Json @(
        @{ type = 'text'; md = $ssoText }
        @{ type = 'flow'; flowId = 285; note = 'GET /api/login-url?redirect_url=https://evil.example.com — evil URL embedded in JWT' }
    ))
}

$regText = @'
## Open Self-Registration on SIPADAS (kelolasampah.baliprov.dev)

The SIPADAS waste-management portal allows unauthenticated self-registration (`GET/POST /register`). New accounts are immediately assigned the **Surveyor** role without admin approval, exposing the government employee onboarding surface to anyone on the internet.

**Reproduction:**
1. `GET /register` — public registration form (HTTP 200)
2. `POST /register` with arbitrary credentials — account created and auto-assigned Surveyor role (HTTP 302)
'@

Patch-Finding 2 @{
    target = 'kelolasampah.baliprov.dev'
    detail = $regText
    impact = 'Unauthenticated attackers can create government portal accounts without approval, accessing the employee onboarding surface and surveyor-verification workflows.'
    body   = (Body-Json @(
        @{ type = 'text'; md = $regText }
        @{ type = 'flow'; flowId = 280; note = 'Public registration form' }
        @{ type = 'flow'; flowId = 283; note = 'Open registration creates Surveyor account (HTTP 302)' }
    ))
}

# Attach flows for finding 2 if missing
foreach ($fid in 280, 283) {
    try {
        Invoke-RestMethod -Uri "$base/2/flows" -Method POST -ContentType 'application/json' -Body (@{ flowId = $fid } | ConvertTo-Json)
    } catch { /* already attached */ }
}

$f3 = Invoke-RestMethod "$base/3"
Patch-Finding 3 @{
    cvss   = '9.8'
    impact = 'Unauthenticated attacker gains Admin on a government waste-management portal, accesses PII (NIK, addresses, WhatsApp) for 312+ surveyors, and downloads official government assignment letters (SK PDFs).'
}

Write-Host 'done — reload Findings tab'
