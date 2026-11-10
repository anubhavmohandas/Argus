# Advanced Bug-Bounty Methodology — sir's Advance Notes, mapped to Argus

Sanitized reference distilled from sir's "Bug Bounty Advance Notes" (Broken Access
Control, SSRF, API Reconnaissance & Third-Party Exploits, GitHub Recon Dorking,
Business Logic, MFA Bypass, Automation). This file is **methodology + how it maps to
Argus** — not a copy of the notes. All real tokens/keys/endpoints from the source are
**redacted**; never commit live credentials to this repo. Companion to
[kongsec-methodology.md](kongsec-methodology.md).

> **Scope discipline (non-negotiable).** Every technique assumes an **authorised**
> target (public VDP, paid program, or written engagement). Searching public
> GitHub/Postman/Wayback is passive and never touches the target. Finding and proving
> an exposure is in scope; **using a discovered third-party credential against its
> vendor's API, or exploiting SSRF/BAC beyond a harmless proof, is not.** Argus
> finds, redacts, and reports — it never validates a credential or weaponises a bug.

## What these notes added to Argus (code)

| Note | Argus change |
|---|---|
| GitHub Recon Dorking Guide | `github_recon._DORKS` grown 8 → 41 (secret keywords, credential file types, cloud/provider key formats, API-doc/endpoint, header tokens). Paced to GitHub's 10 req/min code-search limit (a full run ≈ 4.5 min). Still self-gated against the live RAW file; still redacts. |
| API Recon — provider key formats | New typed patterns in `modules._SECRET_PATTERNS`: Shopify `shp(at\|ca\|pa\|ss)_…`, New Relic `NRAK-…`, GitLab `glpat-…`, Discord webhook URLs. |
| (JSHarvester, from Kongsec) JS asset scoring | `js_recon._score_js/_prioritize` — the `jsmap` budget now reads sourcemaps + config/secret/auth bundles first. |
| (AegisDroid, from Kongsec) APK analysis | new `apk` module — static DEX/AXML parse, permissions, ATT&CK-Mobile behavior strings, packer markers, recon indicators, shared secret catalog. |

## Methodology classes — how far Argus goes, and why

Argus stays at evidence-based, scope-gated, SSRF-guarded detection. BAC is tested only
through researcher-controlled sessions; SSRF and business logic need out-of-band infra or
human judgement, so they remain hunter guidance (and, later, NYX reasoning):

- **Broken Access Control (BAC / IDOR)** — vertical (low-priv → `/admin`, `/teacher`,
  `/manager`) and horizontal (`/api/users/{id}`, `/orders/{id}` across accounts). Argus
  *does* test this class — but only with researcher-controlled sessions: the identity ×
  endpoint matrix (`matrix.py`) shows which identities have not been tried on an endpoint,
  and `differential.py` runs the one-mutation cross-account comparison through the
  orchestrator, each request gated by `EngagementPolicy.can_test`. The notes' vertical and
  horizontal patterns tell the hunter which endpoints and accounts to load in.
- **SSRF** — injection points `?url=`, `?image=`, `?profile_pic=`, webhook/convert endpoints,
  cloud metadata `169.254.169.254`. Argus's provider layer is deliberately built *not* to
  become an SSRF primitive (`_resolvable_and_global` guard), so it never fires SSRF payloads —
  it can only flag candidate URL-consuming params for the hunter's own OOB testing.
- **Business Logic / MFA Bypass** — coupon/price tampering, race conditions, OTP skip/brute,
  response-manipulation MFA bypass. Not pattern-detectable; stays methodology.

## Hunter workflow (how the pieces chain)
1. Argus recon → subdomains, archived JS (`jsmap`, high-value bundles first), API endpoints,
   admin interfaces, ID-bearing params.
2. `github_dork` → leaked creds/config/API-docs referencing the scope (proven, redacted).
3. Hunter picks BAC/SSRF/logic candidates from the surfaced params/endpoints and runs the
   manual methodology above (authenticated, OOB, multi-account).

> The private exploit reports in the notes are disclosed case studies. Their *detection
> signals* informed the above; their working payloads are **not** encoded into Argus —
> attack-execution stays out of the recon/triage engine.
