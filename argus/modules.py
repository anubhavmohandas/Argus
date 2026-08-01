"""Built-in Argus recon modules — strengths harvested from the source tools.

  ip / phone / username  <- GhostTrack (reused, hardened)
  secrets                <- Claude-OSINT 48-pattern catalog (reused)
  dns / rdap / subdomains <- Shadowbroker recon toolkit + Claude-OSINT arsenal

Each is a @module-registered function: takes a validated target, yields Findings.
Add a new module here (or in a new file imported by __init__) — that's the seam
your MY OWN tools and the optional LLM layer plug into.
"""
from __future__ import annotations

import concurrent.futures
import re

from .core import (
    CRITICAL, HIGH, MEDIUM, LOW, INFO,
    Finding, module, http_get, http_json, q,
)


# ── ip ────────────────────────────────────────────────────────────────────
@module("ip", kind="ip", help="Geolocate + ASN/ISP/org for an IP (ipwho.is)")
def ip_intel(ip: str):
    data = http_json(f"http://ipwho.is/{q(ip)}")
    if not data or not data.get("success", True):
        yield Finding("ip", ip, "lookup failed", INFO, source="ipwho.is")
        return
    conn = data.get("connection", {}) or {}
    tz = data.get("timezone", {}) or {}
    yield Finding(
        "ip", ip, f"{data.get('city','?')}, {data.get('country','?')}", INFO,
        data={
            "type": data.get("type"), "city": data.get("city"),
            "region": data.get("region"), "country": data.get("country"),
            "lat": data.get("latitude"), "lon": data.get("longitude"),
            "asn": conn.get("asn"), "org": conn.get("org"), "isp": conn.get("isp"),
            "domain": conn.get("domain"), "timezone": tz.get("id"),
            "maps": f"https://www.google.com/maps/@{data.get('latitude')},{data.get('longitude')},8z",
        },
        source="ipwho.is",
    )


# ── phone ─────────────────────────────────────────────────────────────────
@module("phone", kind="phone", help="Carrier/region/timezone for a phone number (offline)")
def phone_intel(number: str):
    try:
        import phonenumbers
        from phonenumbers import carrier, geocoder, timezone
    except ImportError:
        yield Finding("phone", number, "phonenumbers not installed (pip install phonenumbers)", INFO)
        return
    try:
        parsed = phonenumbers.parse(number, None if number.startswith("+") else "US")
    except phonenumbers.NumberParseException as e:
        yield Finding("phone", number, f"parse error: {e}", INFO)
        return
    yield Finding(
        "phone", number,
        f"{geocoder.description_for_number(parsed, 'en') or 'unknown'} · {carrier.name_for_number(parsed, 'en') or 'unknown carrier'}",
        INFO,
        data={
            "valid": phonenumbers.is_valid_number(parsed),
            "possible": phonenumbers.is_possible_number(parsed),
            "country_code": parsed.country_code,
            "national": parsed.national_number,
            "region": phonenumbers.region_code_for_number(parsed),
            "carrier": carrier.name_for_number(parsed, "en"),
            "location": geocoder.description_for_number(parsed, "en"),
            "timezones": list(timezone.time_zones_for_number(parsed)),
            "e164": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
            "international": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        },
        source="libphonenumber",
    )


# ── username ──────────────────────────────────────────────────────────────
# Sites that return a real 404 for a missing profile (status is trustworthy).
# occam: status-code heuristic only. Soft-404 sites are reported as "unverified".
#        Upgrade path = vendor Sherlock/Maigret's per-site content checks.
_USER_SITES = {
    "GitHub": "https://github.com/{}",
    "GitLab": "https://gitlab.com/{}",
    "Reddit": "https://www.reddit.com/user/{}/about.json",
    "Instagram": "https://www.instagram.com/{}/",
    "TikTok": "https://www.tiktok.com/@{}",
    "Twitter/X": "https://x.com/{}",
    "Telegram": "https://t.me/{}",
    "Medium": "https://medium.com/@{}",
    "Pinterest": "https://www.pinterest.com/{}/",
    "SoundCloud": "https://soundcloud.com/{}",
    "Behance": "https://www.behance.net/{}",
    "Dribbble": "https://dribbble.com/{}",
    "ProductHunt": "https://www.producthunt.com/@{}",
    "Twitch": "https://www.twitch.tv/{}",
    "YouTube": "https://www.youtube.com/@{}",
}
# Reliable-404 hosts: a 200 here is a strong "exists" signal.
_HARD_404 = {"GitHub", "GitLab", "Reddit", "Twitch"}


def _check_site(name_url_user):
    name, tmpl, user = name_url_user
    url = tmpl.format(user)
    status, _ = http_get(url, timeout=8.0)
    return name, url, status


@module("username", kind="username", help="Enumerate a username across social platforms")
def username_enum(user: str):
    jobs = [(name, tmpl, user) for name, tmpl in _USER_SITES.items()]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        for name, url, status in ex.map(_check_site, jobs):
            if status == 200:
                sev = LOW if name in _HARD_404 else INFO
                verdict = "found" if name in _HARD_404 else "found (unverified — possible soft-404)"
                yield Finding("username", user, f"{name}: {verdict}", sev,
                              data={"url": url, "status": status}, source=name)
            elif status == 404:
                pass  # confirmed absent — no noise
            # other statuses (403/429/0) are inconclusive; skipped to keep signal clean


# ── secrets ───────────────────────────────────────────────────────────────
# 48-pattern catalog ported from Claude-OSINT offensive-osint (MIT). Most-specific
# patterns first so generic catches don't pre-empt typed ones.
_SECRET_PATTERNS = [
    ("AWS_ACCESS_KEY", CRITICAL, "aws", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("AWS_SECRET_TYPED", CRITICAL, "aws", r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key['\"\s:=]+([A-Za-z0-9/+=]{40})"),
    ("GCP_SERVICE_ACCOUNT", CRITICAL, "gcp", r'"type"\s*:\s*"service_account"'),
    ("GOOGLE_API_KEY", HIGH, "gcp", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("GH_PAT_CLASSIC", CRITICAL, "github", r"\bghp_[A-Za-z0-9]{36}\b"),
    ("GH_PAT_FINEGRAINED", CRITICAL, "github", r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
    ("GH_OAUTH", HIGH, "github", r"\bgho_[A-Za-z0-9]{36}\b"),
    ("STRIPE_LIVE", CRITICAL, "stripe", r"\bsk_live_[0-9A-Za-z]{24,}\b"),
    ("STRIPE_TEST", LOW, "stripe", r"\bsk_test_[0-9A-Za-z]{24,}\b"),
    ("SLACK_TOKEN", HIGH, "slack", r"\bxox[abpors]-[0-9A-Za-z\-]{10,48}\b"),
    ("SLACK_WEBHOOK", MEDIUM, "slack", r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    ("SENDGRID", HIGH, "email_svc", r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
    ("TWILIO_API", HIGH, "twilio", r"\bSK[0-9a-fA-F]{32}\b"),
    ("JWT", MEDIUM, "jwt", r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    ("BASIC_AUTH_URL", MEDIUM, "basic_auth", r"https?://[^/\s:@]+:[^/\s:@]+@[^/\s]+"),
    ("RSA_PRIVKEY", CRITICAL, "private_key", r"-----BEGIN RSA PRIVATE KEY-----"),
    ("OPENSSH_PRIVKEY", CRITICAL, "private_key", r"-----BEGIN OPENSSH PRIVATE KEY-----"),
    ("GENERIC_PRIVKEY", CRITICAL, "private_key", r"-----BEGIN (DSA |PGP |)PRIVATE KEY-----"),
    ("GENERIC_API_KEY", MEDIUM, "generic", r"(?i)(?:api[_\-]?key|apikey|api_secret|access_token|secret[_\-]?token)['\"\s:=]+[\"']([A-Za-z0-9+/=_\-]{24,})[\"']"),
    ("ANTHROPIC_API", CRITICAL, "ai_api", r"\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{93,}\b"),
    ("OPENAI_PROJECT", CRITICAL, "ai_api", r"\bsk-proj-[A-Za-z0-9_\-]{40,}T3BlbkFJ[A-Za-z0-9_\-]{40,}\b"),
    ("HUGGINGFACE", HIGH, "ai_api", r"\bhf_[A-Za-z0-9]{30,}\b"),
    ("DIGITALOCEAN", HIGH, "infra_api", r"\bdop_v1_[a-f0-9]{64}\b"),
    ("NPM_TOKEN", HIGH, "package_registry", r"\bnpm_[A-Za-z0-9]{36}\b"),
    ("PYPI_TOKEN", HIGH, "package_registry", r"\bpypi-AgENdGV[A-Za-z0-9_\-]+\b"),
    ("DOCKER_HUB_PAT", HIGH, "package_registry", r"\bdckr_pat_[A-Za-z0-9_\-]{27,}\b"),
    ("ATLASSIAN_TOKEN", HIGH, "saas_api", r"\bATATT3xFfGF0[A-Za-z0-9_\-]{180,}\b"),
    ("DATADOG_API", HIGH, "observability", r"(?i)dd[_\-]?api[_\-]?key['\"\s:=]+([a-f0-9]{32})"),
    ("SENTRY_DSN", LOW, "observability", r"https://[a-f0-9]+@o[0-9]+\.ingest\.sentry\.io/[0-9]+"),
    ("DISCORD_BOT", HIGH, "bot_token", r"\b[MN][A-Za-z\d]{23}\.[\w\-]{6}\.[\w\-]{27}\b"),
    ("TELEGRAM_BOT", HIGH, "bot_token", r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b"),
]
_SECRET_COMPILED = [(n, s, c, re.compile(p)) for (n, s, c, p) in _SECRET_PATTERNS]


def scan_text(text: str, source: str = "<text>"):
    """Yield a Finding per secret match. Reusable outside the module runner."""
    for lineno, line in enumerate(text.splitlines(), 1):
        for name, sev, cat, rx in _SECRET_COMPILED:
            for m in rx.finditer(line):
                yield Finding("secrets", source, f"{name} ({cat})", sev,
                              data={"match": m.group(0)[:80], "line": lineno, "category": cat},
                              source=source)


@module("secrets", kind="path", help="Scan a file or directory for leaked credentials (48 patterns)")
def secrets_scan(path: str):
    import os
    skip = (".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".cache")
    targets = []
    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            if any(p in root for p in skip):
                continue
            targets += [os.path.join(root, f) for f in files]
    else:
        targets = [path]
    for fp in targets:
        try:
            if os.path.getsize(fp) > 10 * 1024 * 1024:
                continue
            with open(fp, "r", errors="replace") as fh:
                yield from scan_text(fh.read(), source=fp)
        except (OSError, IOError):
            continue


# ── dns ───────────────────────────────────────────────────────────────────
@module("dns", kind="domain", help="Resolve A/AAAA/MX/NS/TXT via DNS-over-HTTPS")
def dns_records(domain: str):
    for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
        data = http_json(f"https://dns.google/resolve?name={q(domain)}&type={rtype}")
        answers = (data or {}).get("Answer", []) if data else []
        vals = [a.get("data") for a in answers if a.get("data")]
        if vals:
            yield Finding("dns", domain, f"{rtype}: {len(vals)} record(s)", INFO,
                          data={"type": rtype, "records": vals}, source="dns.google")


# ── rdap / whois ──────────────────────────────────────────────────────────
@module("rdap", kind="domain", help="Registrar, dates, nameservers via RDAP")
def rdap_lookup(domain: str):
    data = http_json(f"https://rdap.org/domain/{q(domain)}")
    if not data:
        yield Finding("rdap", domain, "no RDAP record", INFO, source="rdap.org")
        return
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
    registrar = next((e.get("vcardArray", [None, []])[1] for e in data.get("entities", [])
                      if "registrar" in (e.get("roles") or [])), None)
    yield Finding("rdap", domain, f"registered domain: {domain}", INFO,
                  data={
                      "handle": data.get("handle"),
                      "status": data.get("status"),
                      "registered": events.get("registration"),
                      "expires": events.get("expiration"),
                      "last_changed": events.get("last changed"),
                      "nameservers": [ns.get("ldhName") for ns in data.get("nameservers", [])],
                  },
                  source="rdap.org")


# ── subdomains ────────────────────────────────────────────────────────────
@module("subdomains", kind="domain", help="Passive subdomain discovery via certificate transparency (crt.sh)")
def subdomains(domain: str):
    data = http_json(f"https://crt.sh/?q=%25.{q(domain)}&output=json", timeout=25.0)
    if not data:
        yield Finding("subdomains", domain, "crt.sh returned nothing", INFO, source="crt.sh")
        return
    names = set()
    for row in data:
        for n in str(row.get("name_value", "")).splitlines():
            n = n.strip().lstrip("*.").lower()
            if n.endswith(domain) and "@" not in n:
                names.add(n)
    yield Finding("subdomains", domain, f"{len(names)} unique subdomain(s)", LOW if names else INFO,
                  data={"subdomains": sorted(names)}, source="crt.sh")
