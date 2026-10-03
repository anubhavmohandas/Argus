# GitHub Secret-Recon — methodology & reference

Reference for Argus's `github_dork` module (`argus/github_recon.py`). This is the
**sanitized** write-up of the GitHub dorking + secret-triage workflow. Every real
token, webhook, and key from the source notes has been **redacted** — never commit
live credentials to this repo (Argus's own `secrets` module flags that).

> Scope: authorized bug-bounty / security research only. Searching public GitHub
> is passive (it never touches the program's target). **Finding and proving an
> exposure is in scope; using a discovered third-party credential against its
> vendor's API is not** — that crosses into unauthorized access and is an explicit
> Argus non-goal. Rotate/report, don't authenticate.

## 1. Native implementation

`argus run github_dork <domain>` (needs `GITHUB_TOKEN`) does the core loop:
dork-search public code → fetch the RAW file → run the 48-pattern secret catalog
(`modules.scan_text`) → triage out placeholders/test values (entropy + FP list) →
self-gate (the secret must still be present at HEAD of that commit) → emit a
finding with the repo, RAW URL, redacted value, and a `curl` that re-fetches the
RAW file for inspection.

```bash
export GITHUB_TOKEN=<your_pat_redacted>
argus run github_dork example.com --json
```

## 2. Dork patterns (manual reference)

Secret keywords paired with a scope domain (GitHub code search UI or API):

```
"example.com" api_key
"example.com" access_token
"example.com" aws_secret_access_key
"example.com" client_secret
"example.com" jwt_secret
"example.com" db_password
"example.com" secret_token
"example.com" smtp_password
```

File-type dorks:

```
"example.com" path:*.env
"example.com" path:*.json
"example.com" path:*.yml
"example.com" path:*.config
"example.com" path:*.pem
"example.com" path:id_rsa
"example.com" path:*.sql
```

Provider-prefix sweeps (high signal):

```
"AKIA" path:*.env          # AWS access key id
"AIza" path:*.json         # Google API key
"sk_live_" path:*.js       # Stripe live
"ghp_"                     # GitHub PAT
"xox" path:*.env           # Slack token
```

## 3. Automation tools

- **gitGraber** (`github.com/hisxo/gitGraber`) — keyword-driven GitHub scanner with
  Slack alerting. Config needs `GITHUB_TOKENS = [<redacted>, …]` and
  `SLACK_WEBHOOK_URL = '<SLACK_WEBHOOK_REDACTED>'`. Run: `python3 gitGraber.py -q example.com -s`.
- **gitleaks** (`github.com/gitleaks/gitleaks`) — `gitleaks detect -r <repo_url>`.
- **trufflehog** — `trufflehog git <repo_url>` (entropy + verified detectors).
- **github-dorks** (`github.com/techgaun/github-dorks`) —
  `python3 github-dorks.py -q example.com -t <GITHUB_TOKEN_REDACTED>`.

> Keep real tokens/webhooks in untracked local env/config only. The values in the
> original notes have been treated as compromised and must be rotated.

## 4. Fuzzing / subdomain pipeline (adjacent recon)

Not part of `github_dork`, kept here as reference. All Slack webhook URLs redacted.

```bash
# subdomains → live hosts
subfinder -d example.com | httpx -silent -mc 200,302 | tee valid.txt

# JS files → nuclei exposure templates → Slack
cat valid.txt | waybackurls | grep '\.js$' | tee js.txt
nuclei -l js.txt -t nuclei-templates/http/exposures/ | slackcat -1 -u '<SLACK_WEBHOOK_REDACTED>'

# vhost / content fuzzing
ffuf -w subdomain-wordlist.txt -u https://example.com -H "Host: FUZZ.example.com" -mc 200
```

High-signal content-discovery keywords (for 403/404 → dashboard/login hunting):

```
api  config  secret  env  /v1  id=  sql  xml  csv  eyJ  prod  stg  access
key=  configuration  .yml  .py  .sh  auth  token=  customer  dashboard
x-api-key  api-key
```

## 5. Smart triage prompt (LLM analyst)

Used to triage raw scanner output into high-confidence true positives. The
`github_dork` module implements the deterministic parts (FP list + entropy +
self-gating); this prompt is the optional LLM layer for messier input.

> **Role:** senior GitHub Secret Exposure Analyst. Classify each finding as TRUE
> POSITIVE (real credential, strong evidence), FALSE POSITIVE (example / placeholder
> / test / dummy / UUID / hash / public id), or UNCERTAIN. Output **only** TRUE
> POSITIVES.
>
> **FP filtering:** aggressively drop `test, demo, example, sample, dummy, password,
> 1234, admin, changeme, your_api_key, xxxxx, …`, plus `.env.example` placeholders,
> README/tutorial creds, mock keys, commit hashes, checksums, generic UUIDs, env-var
> names without a value, redacted/empty/low-entropy strings.
>
> **TP signals:** recognizable provider formats (AWS/GitHub/Slack/Stripe/SendGrid/
> Twilio/Google/Firebase/JWT/private keys/DB connection strings), assignment to
> `API_KEY / SECRET_KEY / ACCESS_TOKEN / CLIENT_SECRET / DB_PASSWORD / PRIVATE_KEY`,
> high entropy with realistic length/charset/placement, genuine (non-example) host.
> Historical commits still count.
>
> **Per true positive, report:** type, confidence (HIGH/VERY HIGH), repo URL, RAW URL,
> commit, date, author, file, org, detected variable, the exact value, why-TP, and
> the FP checks performed.
>
> **Safe verification only:** generate `curl -sS '<RAW_GITHUB_URL>'` (optionally
> `| grep -n -C3 '<VAR>'`) to re-read the exposed file. Never invent URLs/endpoints.
> **Never** auto-send discovered credentials to third-party APIs, authenticate, or
> perform any state-changing action. Validity is judged from static evidence unless
> the user has an explicitly authorized validation environment.

## 6. Static verify helper

`curl -sS '<RAW_GITHUB_URL>'` re-fetches the exposed file so you can read the
surrounding context and confirm the secret is still live at that commit. This is
the only "verification" the workflow performs — no credential is ever exercised
against its vendor.

## 7. Reporting

Once a true positive is confirmed, the report writes itself from the evidence:
title (e.g. "Live <provider> credential exposed in public GitHub repo"), the repo +
RAW URL, the redacted value + format, impact (what the key authorizes), and
remediation (rotate immediately, purge from history, enable push protection /
secret scanning). Map to **CWE-200** (exposure of sensitive information).
