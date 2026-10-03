# AI-Augmented Bug-Bounty Recon — methodology & Argus mapping

Sanitized reference distilled from the "Kongsec Methodology for AI-Augmented Bug
Bounty Recon" training paper (b4kong, 2026) plus the accompanying dorking/automation
notes. This file is **methodology + how it maps to Argus modules** — not a copy of
the paper. All real tokens/webhooks/keys from the source notes are **redacted**;
never commit live credentials to this repo.

> **Scope discipline (non-negotiable).** Every technique here assumes an
> **authorised** target: a public VDP, a paid program, or a written engagement
> letter. Searching public Postman/GitHub/Wayback is passive and never touches the
> target. Finding and proving an exposure is in scope; **using a discovered
> third-party credential against its vendor's API is not** — that is unauthorised
> access. Argus's secret-recon modules find, redact, and report. They never validate.

## The three artefacts that leak first

Across real engagements, three public surfaces produce most initial footholds —
all free to enumerate, all legal to read:

| Surface | Why it leaks | Argus module |
|---|---|---|
| **Public Postman workspaces** | env vars / bearer tokens pasted and forgotten | `postman_dork` |
| **Public GitHub (code + history)** | hardcoded secrets, esp. in commit history | `github_dork`, `github_org` |
| **Frontend JS / source-maps** | keys shipped to the browser | `jsmap` |

Observed leak frequency (ordering matters more than the exact numbers): Postman ≈ highest,
**GitHub commit history > GitHub current tree**, then JS bundles, source-maps, Docker/registry
layers, NPM/PyPI packages, employee gists/forks. New hunters under-invest in commit history.

## The pipeline → Argus

The paper's three stages map onto Argus like this:

- **Stage 1 — Postman mining** → `argus run postman_dork <domain>`
  Searches public workspaces for the brand, pulls environment/globals JSON, scans with
  the 48-pattern catalog + triage. (Validation of a found token is deliberately NOT done.)
- **Stage 2 — GitHub source review** → `argus run github_dork <domain>` (current code) +
  `argus run github_org <domain>` (commit history, needs `git`). Both need `GITHUB_TOKEN`.
- **Stage 3 — Burp validation / exploitation** → **out of scope for Argus by design.**
  Argus "finds and proves, does not weaponize." Chaining a primitive to impact in Burp is
  the human analyst's job, in an authorised environment.

JS/source-map extraction is a cross-cutting passive source → `argus run jsmap <domain>`
(scans archived bundles via Wayback; a live-bundle scan belongs at the `--probe` tier).

All four are opt-in via `argus run` / `argus all` — they are **not** in the default passive
`pivot` discovery set (which stays rdap/dns/subdomains/wayback), so a normal pivot is not
slowed or made loud by them.

## Confirmed pattern library (primitive → reachability → impact)

The paper's 18 accepted chains, with how Argus covers each today:

| # | Chain | Argus coverage |
|---|---|---|
| P01 | exposed `.git` → source + secrets | `exposure_probe` + `exposed_secret` rule |
| P02 | Spring Boot `/actuator/env` → DB creds + API keys | partial — `admin_probe`/`exposure_probe`; actuator sig = gap |
| P03 | `/actuator/heapdump` → in-memory secrets | gap |
| P04 | JS bundle → hardcoded creds + RSA keys | `jsmap` (archived) |
| P05 | OpenAPI/Swagger exposed → endpoint map → IDOR | gap (endpoint map) |
| P06 | public dev environment → weak auth | `preprod_weakness` rule |
| P07 | S3 bucket listing → customer UUIDs → IDOR | gap |
| P08 | SVG upload → served as text/html → stored XSS | `reflected_xss` (related) |
| P09 | unauth API returns business errors (not 401) → missing auth gate | partial |
| P10 | `X-Organization-ID` as only auth → other org IDs → IDOR | gap (IDOR logic) |
| P11 | APISIX/Jenkins dashboard public → CI management | `jenkins_suspected`/`jenkins_confirmed` |
| P12 | Base64 `clientId:clientSecret` in JS → direct API auth | `jsmap` finds the secret; auth step out of scope |
| P13 | RSA private key in frontend → decrypt API responses | `jsmap` (private-key patterns) |
| P14 | eToken/magic link not invalidated + Referer leak | gap |
| P15 | CNAME → unclaimed cloud service → takeover | `takeover_service` + `subdomain_takeover` rule |
| P16 | unauth socket.io handshake → namespace enum | gap |
| P17 | public widget/embed config → overwrite customer config | gap |
| P18 | password-reset host-header injection → token to attacker | gap (host-header) |

"Gap" = a reportable class the paper documents that Argus does not yet claim — candidate
roadmap items, each to land the Argus way (evidence fn + self-gating signature + rule + test).

## Hypothesis ledger ↔ Argus investigation model

The paper's `notes.md` ledger (one row per candidate: **ID · Hypothesis · Evidence ·
Next test · Status**, statuses `open/blocked/rejected/confirmed`) is essentially what
Argus's `investigation.conclusions` already produces: each conclusion carries a
hypothesis, an evidence ledger, a confidence/score, and a severity. The discipline to
import: **every row needs an evidence location** (a request/response, a file+line, or a
commit) and **a distinct next test** — "try more payloads" is not a test. Argus enforces
the evidence half structurally (providers only observe; I-1 forbids silence-as-negative).

## Triage: smart false-positive filtering (the deterministic core)

Argus's `triage.py` implements the human-triager heuristics so modules don't spam:

- **FP list:** `test, demo, example, sample, dummy, password, 1234, admin, changeme,
  your_api_key, xxxxx, …`, plus `.env.example` placeholders, README/tutorial creds, mock
  keys, commit hashes, UUIDs, env-var names without a value, redacted/empty strings.
- **Entropy floor:** Shannon entropy per char; low-entropy generic catches dropped — but
  structured provider formats (`AKIA…`, `ghp_…`, `sk_live_…`, `AIza…`) are never
  entropy-gated, since the prefix already proves structure.
- **Self-gating:** a hit is only claimed when the secret is actually present in the fetched
  artefact (RAW file / workspace JSON / archived bundle / added history line).
- **Redaction:** output keeps first/last 4 chars only — Argus never stores a usable secret.

The LLM "analyst" layer (below) is optional, for messier scanner output than the
deterministic core handles.

## Prompt library (optional LLM layer)

Reference prompts from the paper, for a Codex/Claude layer on top of the modules. All keep
the same guardrails: evidence-grounded, no network unless permitted, **no PoCs, no
credential validation.**

- **Secret triage:** classify scanner output into TRUE POSITIVE / FALSE POSITIVE /
  UNCERTAIN; output only true positives with repo/RAW URL, commit, file, redacted value,
  why-TP, and FP checks. Generate only a `curl -sS '<RAW_URL>'` to re-read the file.
- **Recon triage:** group URLs by app cluster, name likely framework, list endpoints by
  kind (auth/admin/static/api), propose the three cheapest tests. Don't run them.
- **Same-flow-two-accounts:** given two HARs of the same flow, list request pairs that
  differ only in identity, whether the server authorises on each, and the test to break it.
- **Focused fuzz-plan:** for one endpoint, produce a 20-line fuzz plan where each line is a
  distinct hypothesis ("if I do X, I expect Y, disproved by Z"), cheapest first.
- **Adversarial critic:** read a candidate finding and give every reason it would be closed
  as informative/not-a-bug; if it survives, say so in one sentence. Run before every report.

## Reporting template + pre-submission checklist

Report structure (maps to Argus's report export): one-line title (primitive → reachability
→ impact), 2–3 sentence summary, numbered copy-pasteable steps (one request/action each),
PoC (exactly one request in curl form + one response redacted to the minimum), impact (who
can trigger / what they can read-change-destroy, in the program's terms), one-paragraph
remediation naming the file/endpoint/header, references (program URL + asset, CWE,
related CVE). Secret exposures map to **CWE-798** (hard-coded credentials) / **CWE-200**
(sensitive info exposure).

Pre-submission checklist (the step most hunters skip is the critic):
1. Every PoC request reproduced from a fresh session in the last 24h.
2. No real user data in the report — all identifiers are the reporter's own.
3. Asset confirmed in scope on the program page today.
4. Adversarial-critic prompt run and the finding survived.
5. Severity matches the program's rubric, not the reporter's.
6. Remediation names the file/endpoint/header.
7. Every screenshot redacted for tokens/emails/internal hostnames.
8. Hypothesis-ledger row marked `confirmed` with the request/evidence cited.
9. Submitted through the program's channel — not email/DM.
10. A note added for the next engagement.

## Tooling referenced (keep real tokens in untracked local config only)

gitGraber, gitleaks, trufflehog, github-dorks (GitHub secret scanning); subfinder, httpx,
gau, waybackurls, qsreplace, ffuf, nuclei (subdomain/JS/fuzzing pipeline); slackcat (alerting).
Config examples in the source notes used real `GITHUB_TOKENS`, `SLACK_WEBHOOK_URL`, a Stripe
`sk_live_` key and a Firebase token — all treated as **compromised and to be rotated**, and
replaced with `<REDACTED>` here.
