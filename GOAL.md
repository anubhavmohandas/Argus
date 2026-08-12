# GOAL — ARGUS: the bug-hunter's correlation engine

**One seed in → a scored, evidence-backed dossier of real, reportable findings out.**

ARGUS is not another scanner. A scanner runs checks against a target you hand
it. ARGUS **discovers the targets itself** — seed a domain and it walks RDAP →
DNS → certificate transparency → resolves to IPs → pivots those back into more
domains, deduping the whole way into one entity graph. Then it reasons over that
graph and hands a bug hunter findings they can actually file: each one carrying
the evidence that proves it, a confidence score, and a written hypothesis.

The pivot loop is the moat. Individual lookups are a commodity; the engine that
chains them, correlates the results, and knows what it *doesn't* know is the hard
part — and the useful one.

## The prime directive

Every finding ARGUS surfaces must be **true, evidenced, and reportable** — the
kind you can paste into a bug-bounty submission without embarrassment. That means
no guesses dressed as facts, no scanner-noise low-signal spam, and no confident
claim without the request/response that backs it. A hunter's time is the scarce
resource; ARGUS's job is to spend it only on findings worth chasing.

## The invariants (why a hunter can trust it)

These are load-bearing. Nothing ships that violates them.

1. **Evidence, not assertion.** Providers only ever *observe* — they write to
   `Entity.evidence` and never touch the engine. The engine reasons; providers
   collect. The two never blur.
2. **Silence is never a negative (I-1).** An unreachable host or unset header
   establishes *nothing* — it is never recorded as a clean bill of health. A
   `False` only ever means "checked, and confirmed absent." This is the line
   between an honest tool and one that lulls you.
3. **Self-gating signatures.** A finding is only claimed when the response
   carries something a soft-404 / catch-all *cannot forge*: the real
   `/etc/passwd` body for traversal, a live `__schema` for GraphQL, our unique
   reflected origin for CORS. No control-request guessing games.
4. **Confidence is earned, not flat.** Verified outranks suspected; a
   discovery-only run is never overconfident; a fully-probed one has no phantom
   unknowns. Scores mean something.
5. **Engagement is consent-gated.** Passive by default (never touches the
   target). `--probe`, `--probe-paths`, `--scan` each escalate loudness and each
   demands the operator confirm authorization first. SSRF guard runs before every
   single outbound request — no probe ever touches a non-global target.

## What's built (the spine holds)

- **Pivot engine + entity graph** — RDAP/DNS/CT/IP correlation from one seed
  (domain, ip, username, phone, email), deduped into a scored graph.
- **The Provider Contract** — every evidence source `@declares` exactly the
  predicates it owns; `argus coverage` proves every engine predicate has at least
  one provider (a few, like `known_vulnerable_service`, have two — the static
  catalog and the live NVD lookup — and both are listed). Currently **full coverage.**
- **Providers live:** `http_probe` (internet-facing, tech, auth, missing
  headers, insecure cookie, clickjacking), `cors_probe`, `graphql_probe`,
  `admin_probe`, `exposure_probe`, `traversal_probe`, `port_scan`, `kev`,
  `cert_analysis`.
- **Rules → findings:** TOML rules turn evidence into scored conclusions with a
  severity, a recommendation, and a written hypothesis — the dossier.
- **Investigation memory** — runs are saved and diffed, so re-running a target
  surfaces *what changed* since last time.
- **11 green test suites** guarding the invariants, the public contract, and
  every provider.

## Roadmap — from "solid engine" to "complete bug-hunting repo"

Each item ships the ARGUS way: a pure evidence function + a self-gating
signature + a TOML rule + a test, honest about I-1. Ordered by hunter payoff.

### Near — more reportable classes, same discipline
- [x] **Subdomain takeover** — dangling CNAME → known fingerprint (S3/GitHub
      Pages/Heroku/etc.). Shipped: `takeover_service` fingerprints → `subdomain_takeover`.
- [x] **Open redirect** — reflected redirect to an attacker origin, self-gated on
      the `Location` actually pointing off-host. Shipped: `redirect_probe`.
- [x] **Secrets in exposed files** — extend `exposure_probe`: parse recovered
      `.env` / `.git` config for live-looking keys (already have the secret
      scanner in `test_argus`).
- [x] **Security.txt / disclosure policy** — surface where/how to report, per
      target. Turns a finding into a filed report faster.

### Mid — depth on what's already there
- [x] **CORS variants** — `Origin: null` reflection, pre-flight abuse (today only
      the credentialed reflected-specific-origin case is claimed).
- [ ] **GraphQL depth** — field suggestion / batching / mutation enumeration once
      introspection is confirmed.
- [ ] **Directory / vhost brute** on the active tier, budget-bounded like
      `admin_probe`.
- [ ] **Richer version→CVE** — KEV is the floor; add a real version-range match so
      more `known_exploited` fires with evidence.

### Far — the deliverable, not just the data
- [x] **Report export** — one command, one Markdown/HTML bounty-ready report per
      finding: title, severity, steps-to-reproduce from the captured request,
      impact, remediation. The dossier becomes a submission.
- [x] **Scope file** — an in/out-of-scope allowlist honored by every provider, so
      a program's rules are enforced by the tool, not the operator's memory.
- [x] **Rate-limit / politeness knob** — global request budget + backoff, so a
      full run stays inside a program's rules of engagement.

## Non-goals (Occam's fence)

- Not a fuzzer, not an exploit framework — ARGUS *finds and proves*, it does not
  weaponize.
- No new runtime dependency for anything stdlib can do; core stays drop-anywhere.
- No finding without its evidence. No speculative predicate without a probe that
  fills it and a rule that reads it.

## Acceptance (what "done" means, always)

`argus coverage` shows every predicate owned once, and **all `test_*.py` pass** —
the invariants above are executable, not aspirational. Every new class lands with
its own test or it doesn't land. Last verified green: 2026-08-09.
