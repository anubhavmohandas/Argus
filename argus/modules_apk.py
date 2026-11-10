"""Argus APK module — mobile static-analysis surface, harvested from Kongsec/AegisDroid TI.

A brand-new target kind for Argus: hand it a `.apk` path, get recon Findings. Pure
stdlib (zipfile + struct + hashlib + re), so it runs on any arch with no Android SDK,
no apktool, no native deps — the whole point of AegisDroid being "dependency-light".

What it does (static only — nothing is executed):
  * unzips the APK, parses DEX string tables and binary-XML (AXML) manifest strings
  * infers permissions + components, lists native libs + signing certs, flags entropy
  * harvests indicators from all strings: URLs, domains, IPs, emails, API paths,
    deep links, GraphQL, Firebase, S3/cloud, auth headers, crypto wallets
  * behavioral rules: sensitive-permission risk, suspicious API strings (with ATT&CK
    Mobile technique IDs), packer/protector markers, high-entropy/multi-DEX, native code
  * scans the string blob for leaked credentials with Argus's shared secret catalog + triage

Scope: this is DEFENSIVE static analysis / recon. It reads an APK; it builds nothing
and attacks nothing. AegisDroid's threat-feed (STIX) matching is not ported.
"""
from __future__ import annotations

import math
import re
import struct
import zipfile
from pathlib import Path

from .core import CRITICAL, HIGH, MEDIUM, LOW, INFO, Finding, module
from .modules import scan_text          # reuse Argus's shared secret catalog (no second copy)
from .triage import is_false_positive, redact

# ── budgets (keep a hostile APK from blowing memory/time) ───────────────────
MAX_DEX_STRINGS_PER_FILE = 30000
MAX_TOTAL_STRINGS = 160000
MAX_PRINTABLE_FILES = 420
MAX_PRINTABLE_BYTES = 2 * 1024 * 1024
MAX_ENTRY_BYTES = 64 * 1024 * 1024   # a single dex is ~10MB; bigger is a zip bomb
TEXTLIKE_SUFFIXES = (".json", ".xml", ".txt", ".html", ".js", ".properties",
                     ".cfg", ".conf", ".ini", ".pem", ".cer", ".crt", ".0")


# ── low-level stdlib helpers ────────────────────────────────────────────────
def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts if c)


def _printable_strings(data: bytes, min_len: int = 6) -> list[str]:
    out, buf = [], bytearray()
    for b in data:
        if 32 <= b <= 126:
            buf.append(b)
        else:
            if len(buf) >= min_len:
                out.append(buf.decode("utf-8", "ignore"))
            buf.clear()
    if len(buf) >= min_len:
        out.append(buf.decode("utf-8", "ignore"))
    return out


def _sha256(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


def _uleb128(data: bytes, offset: int) -> tuple[int, int]:
    result, shift, cursor = 0, 0, offset
    while cursor < len(data):
        byte = data[cursor]
        cursor += 1
        result |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            break
        shift += 7
    return result, cursor


def _extract_dex_strings(data: bytes, limit: int = 50000) -> list[str]:
    if len(data) < 112 or not data.startswith(b"dex\n"):
        return []
    try:
        string_ids_size = struct.unpack_from("<I", data, 56)[0]
        string_ids_off = struct.unpack_from("<I", data, 60)[0]
    except struct.error:
        return []
    strings = []
    for idx in range(min(string_ids_size, limit)):
        try:
            off = struct.unpack_from("<I", data, string_ids_off + idx * 4)[0]
            _, cursor = _uleb128(data, off)
            end = data.index(b"\x00", cursor)
            strings.append(data[cursor:end].decode("utf-8", "ignore"))
        except (ValueError, struct.error, IndexError):
            continue
    return strings


def _extract_axml_strings(data: bytes, limit: int = 20000) -> list[str]:
    strings, offset = [], 0
    while offset + 8 <= len(data) and len(strings) < limit:
        try:
            chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, offset)
        except struct.error:
            break
        if chunk_type == 0x0001 and chunk_size >= header_size >= 28:
            try:
                string_count, _, flags, strings_start, _ = struct.unpack_from("<IIIII", data, offset + 8)
                utf8 = bool(flags & 0x00000100)
                offsets_base = offset + header_size
                data_base = offset + strings_start
                for idx in range(min(string_count, limit - len(strings))):
                    so = struct.unpack_from("<I", data, offsets_base + idx * 4)[0]
                    cursor = data_base + so
                    if utf8:
                        _, cursor = _uleb128(data, cursor)
                        blen, cursor = _uleb128(data, cursor)
                        strings.append(data[cursor:cursor + blen].decode("utf-8", "ignore"))
                    else:
                        clen = struct.unpack_from("<H", data, cursor)[0]
                        cursor += 2
                        strings.append(data[cursor:cursor + clen * 2].decode("utf-16le", "ignore"))
            except (struct.error, IndexError):
                pass
        if chunk_size <= 0:
            break
        offset += chunk_size
    return [s for s in strings if s]


def _read_apk(path: Path) -> dict:
    dex_strings, manifest_strings, all_printable = [], [], []
    files, native_libs, certs = [], [], []
    total_uncompressed = 0
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            name = info.filename
            total_uncompressed += info.file_size
            lower = name.lower()
            row = {"name": name, "uncompressed": info.file_size}
            sample = b""
            should_read = info.file_size <= MAX_ENTRY_BYTES and (
                lower.endswith((".dex", ".xml", ".rsa", ".dsa", ".ec"))
                or (info.file_size <= MAX_PRINTABLE_BYTES and lower.endswith(TEXTLIKE_SUFFIXES)
                    and len(all_printable) < MAX_TOTAL_STRINGS))
            if should_read:
                try:
                    sample = zf.read(info)
                except (RuntimeError, zipfile.BadZipFile):
                    sample = b""
            if sample:
                row["sha256"] = _sha256(sample)
                row["entropy"] = round(_entropy(sample), 4)
                if lower.endswith(".dex"):
                    dex_strings.extend(_extract_dex_strings(sample, limit=MAX_DEX_STRINGS_PER_FILE))
                elif lower.endswith(".xml"):
                    manifest_strings.extend(_extract_axml_strings(sample))
                if lower.startswith("meta-inf/") and lower.endswith((".rsa", ".dsa", ".ec")):
                    certs.append({"name": name, "sha256": _sha256(sample)})
                if (len(all_printable) < MAX_TOTAL_STRINGS
                        and len(all_printable) // 1500 < MAX_PRINTABLE_FILES
                        and lower.endswith(TEXTLIKE_SUFFIXES)):
                    all_printable.extend(_printable_strings(sample, min_len=6)[:1500])
            if lower.startswith("lib/") and lower.endswith(".so"):
                native_libs.append(name)
            files.append(row)
    strings = sorted(set(dex_strings + manifest_strings + all_printable))[:MAX_TOTAL_STRINGS]
    permissions = sorted({s for s in manifest_strings + dex_strings if s.startswith("android.permission.")})
    components = sorted({s for s in manifest_strings
                         if any(x in s.lower() for x in ("activity", "service", "receiver", "provider"))})
    pkg = [s for s in manifest_strings if "." in s and "/" not in s and len(s) < 120]
    return {
        "zip": {"file_count": len(files), "total_uncompressed": total_uncompressed},
        "files": files, "native_libs": native_libs, "certificates": certs, "strings": strings,
        "manifest": {"permissions": permissions, "components": components[:100],
                     "package_candidates": sorted(set(pkg))[:25]},
    }


# ── indicator regexes (bytes) ───────────────────────────────────────────────
_URL_RE = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", re.I)
_API_PATH_RE = re.compile(rb"(?<![A-Za-z0-9_])/(?:api|v[0-9]+|graphql|rest|oauth|auth|login|signup|user|users|account|accounts|admin|internal|private|mobile|client|payment|wallet|order|orders|profile|device|devices|token|session|sessions|verify|otp|password|upload|download|debug|config|feature|flags|search|sync)(?:/[A-Za-z0-9._~:{}?&=%+-]+){0,8}", re.I)
_DEEP_LINK_RE = re.compile(rb"\b[a-z][a-z0-9+.-]{2,32}://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*", re.I)
_IPV4_RE = re.compile(rb"(?<![0-9])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![0-9])")
_EMAIL_RE = re.compile(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_DOMAIN_RE = re.compile(rb"(?<![@\w.-])(?:[A-Za-z0-9-]{1,63}\.)+(?:com|net|org|io|co|in|ru|cn|top|xyz|site|online|info|biz|app|dev|me|pw|cc|su|tv|cloud|store|live)(?![\w.-])", re.I)
_FIREBASE_RE = re.compile(rb"\bhttps?://[A-Za-z0-9-]+(?:-default-rtdb)?\.firebaseio\.com[^\s\"'<>]*|\b[A-Za-z0-9-]+\.firebaseapp\.com\b|\b[A-Za-z0-9-]+\.web\.app\b", re.I)
_S3_RE = re.compile(rb"\b(?:s3://[A-Za-z0-9._-]+|[A-Za-z0-9._-]+\.s3(?:[.-][A-Za-z0-9-]+)?\.amazonaws\.com|s3[.-][A-Za-z0-9-]+\.amazonaws\.com/[A-Za-z0-9._/-]+)\b", re.I)
_GRAPHQL_RE = re.compile(rb"(?i)(?:https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*graphql[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*|/graphql(?:/[A-Za-z0-9._~:{}?&=%+-]+)*)")
_HEADER_RE = re.compile(rb"(?i)\b(?:authorization|x-api-key|x-auth-token|x-access-token|x-csrf-token|x-device-id|x-client-id|x-session-id|cookie|set-cookie|bearer)\b")
_BTC_RE = re.compile(rb"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b")
_ETH_RE = re.compile(rb"\b0x[a-fA-F0-9]{40}\b")


def _unique(items, limit=None):
    seen, out = set(), []
    for it in items:
        c = it.strip().strip("'\"<>[](){}")
        if not c or c in seen:
            continue
        seen.add(c)
        out.append(c)
        if limit and len(out) >= limit:
            break
    return out


def _rx(pattern, blob, limit=5000):
    return _unique((m.group(0).decode("utf-8", "ignore") for m in pattern.finditer(blob)), limit=limit)


def _domain_from_url(url: str) -> str:
    host = url.split("://", 1)[-1].split("/", 1)[0].split("?", 1)[0].split("@")[-1]
    return host.split(":", 1)[0].lower().strip(".")


def _valid_domain(value: str) -> bool:
    d = value.strip(".").lower()
    if len(d) > 253 or "\\" in d or "_" in d or any(c in d for c in "(){}[]|*+?^$"):
        return False
    labels = d.split(".")
    if len(labels) < 2 or any((not lb or len(lb) > 63 or lb.startswith("-") or lb.endswith("-")) for lb in labels):
        return False
    return True


def _valid_api_path(value: str) -> bool:
    p = value.strip()
    if len(p) < 4 or len(p) > 240 or "\\" in p or any(x in p for x in ("${", "<", ">", " ")) or p.count("/") > 10:
        return False
    return not p.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ttf", ".otf", ".so"))


def _indicators(blob: bytes) -> dict:
    urls = [u for u in _rx(_URL_RE, blob) if len(u) <= 500 and "\\" not in u and not any(x in u for x in "(){}")]
    ips = [i for i in _rx(_IPV4_RE, blob) if not i.startswith(("0.", "10.", "127.", "169.254.", "192.168."))]
    domains = [d.lower() for d in _rx(_DOMAIN_RE, blob) if _valid_domain(d)]
    domains += [_domain_from_url(u) for u in urls]
    api_paths = [a for a in _rx(_API_PATH_RE, blob, limit=1500) if _valid_api_path(a)]
    deep = [d for d in _rx(_DEEP_LINK_RE, blob, limit=800)
            if not d.lower().startswith(("http://", "https://", "file://", "content://", "android.resource://"))]
    return {
        "urls": _unique(urls), "domains": _unique(d.lower() for d in domains), "ips": _unique(ips),
        "emails": _rx(_EMAIL_RE, blob), "api_paths": _unique(api_paths, limit=1200),
        "deep_links": _unique(deep, limit=400), "graphql": _rx(_GRAPHQL_RE, blob, limit=200),
        "firebase": _rx(_FIREBASE_RE, blob, limit=300), "cloud_assets": _rx(_S3_RE, blob, limit=300),
        "auth_headers": _unique((h.lower() for h in _rx(_HEADER_RE, blob, limit=500)), limit=80),
        "crypto_wallets": _unique(_rx(_BTC_RE, blob, limit=200) + _rx(_ETH_RE, blob, limit=200)),
    }


# ── behavioral rules (verbatim intent from AegisDroid rules.py) ─────────────
_PERMISSION_RISK = {
    "android.permission.SEND_SMS": (CRITICAL, "Sends SMS messages"),
    "android.permission.READ_SMS": (HIGH, "Reads SMS messages"),
    "android.permission.RECEIVE_SMS": (HIGH, "Receives SMS messages"),
    "android.permission.READ_CALL_LOG": (HIGH, "Reads call logs"),
    "android.permission.RECORD_AUDIO": (HIGH, "Records audio"),
    "android.permission.REQUEST_INSTALL_PACKAGES": (HIGH, "Can request package installs"),
    "android.permission.SYSTEM_ALERT_WINDOW": (HIGH, "Can draw overlay windows"),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": (CRITICAL, "Accessibility abuse potential"),
    "android.permission.CAMERA": (MEDIUM, "Accesses camera"),
    "android.permission.ACCESS_FINE_LOCATION": (MEDIUM, "Precise location access"),
    "android.permission.READ_CONTACTS": (MEDIUM, "Reads contacts"),
    "android.permission.QUERY_ALL_PACKAGES": (MEDIUM, "Enumerates installed apps"),
}
_SUSPICIOUS = {
    "DexClassLoader": (HIGH, "Dynamic DEX loading", ["T1407"]),
    "Runtime.getRuntime().exec": (HIGH, "Shell command execution", ["T1626"]),
    "AccessibilityService": (CRITICAL, "Accessibility service behavior", ["T1517"]),
    "DevicePolicyManager": (HIGH, "Device admin capability", ["T1401"]),
    "SmsManager": (CRITICAL, "SMS manager usage", ["T1448"]),
    "content://sms": (CRITICAL, "SMS content provider access", ["T1412"]),
    "getSubscriberId": (HIGH, "Subscriber identifier collection", ["T1426"]),
    "getDeviceId": (HIGH, "Device identifier collection", ["T1426"]),
    "addJavascriptInterface": (HIGH, "Risky WebView JavaScript bridge", ["T1438"]),
    "BOOT_COMPLETED": (MEDIUM, "Persistence on boot", ["T1398"]),
    "frida": (MEDIUM, "Frida/debug tooling reference", ["T1628"]),
    "xposed": (MEDIUM, "Xposed/root instrumentation reference", ["T1628"]),
}
_PACKERS = {"jiagu": "Qihoo 360 Jiagu", "bangcle": "Bangcle", "ijiami": "Ijiami",
            "upx": "UPX", "apkprotect": "APKProtect", "secneo": "SecNeo", "libshell": "Shell/protector lib"}


def _str_hits(strings, marker):
    ml = marker.lower()
    if ml in {"frida", "xposed"}:
        return [s for s in strings if re.search(rf"(?i)(^|[^a-z0-9]){re.escape(marker)}([^a-z0-9]|$)", s)][:8]
    return [s for s in strings if ml in s.lower()][:8]


# ── the Argus module ────────────────────────────────────────────────────────
@module("apk", kind="path", help="Static APK recon: strings, perms, ATT&CK behaviors, packers, secrets (offline)")
def apk_recon(path: str):
    p = Path(path)
    if not p.is_file() or not zipfile.is_zipfile(p):
        yield Finding("apk", path, "not a readable APK/ZIP file", INFO, source="argus")
        return
    name = p.name
    apk = _read_apk(p)
    strings = apk["strings"]
    blob = "\n".join(strings).encode("utf-8", "ignore")
    ind = _indicators(blob)

    # 1. sensitive permissions
    for perm in apk["manifest"]["permissions"]:
        if perm in _PERMISSION_RISK:
            sev, desc = _PERMISSION_RISK[perm]
            yield Finding("apk", name, f"sensitive permission: {perm.rsplit('.', 1)[-1]}", sev,
                          data={"permission": perm, "why": desc}, source="manifest")

    # 2. suspicious API / behavior strings (ATT&CK Mobile)
    for marker, (sev, desc, attack) in _SUSPICIOUS.items():
        hits = _str_hits(strings, marker)
        if hits:
            yield Finding("apk", name, desc, sev,
                          data={"marker": marker, "attack": attack, "evidence": hits}, source="dex")

    # 3. packer / protector markers
    joined = "\n".join(strings).lower()
    packers = [label for m, label in _PACKERS.items()
               if any(m in lib.lower() for lib in apk["native_libs"])
               or (m == "upx" and "upx!" in joined)
               or (m != "upx" and re.search(rf"(?i)(^|[^a-z0-9]){re.escape(m)}([^a-z0-9]|$)", joined))]
    if packers:
        yield Finding("apk", name, "protector/packer indicators", HIGH,
                      data={"packers": packers, "attack": ["T1406"]}, source="dex")

    # 4. high-entropy / multi-DEX / native code
    hi_dex = [f["name"] for f in apk["files"] if f["name"].lower().endswith(".dex") and f.get("entropy", 0) >= 7.4]
    if hi_dex:
        yield Finding("apk", name, "high-entropy DEX (encryption/obfuscation likely)", MEDIUM,
                      data={"files": hi_dex, "attack": ["T1406"]}, source="dex")
    dex_files = [f["name"] for f in apk["files"] if f["name"].lower().endswith(".dex")]
    if len(dex_files) > 2:
        yield Finding("apk", name, f"multiple DEX files ({len(dex_files)})", LOW,
                      data={"files": dex_files}, source="dex")
    if apk["native_libs"]:
        yield Finding("apk", name, "native code present (needs binary analysis)", LOW,
                      data={"native_libs": apk["native_libs"][:20], "attack": ["T1627"]}, source="zip")

    # 5. recon indicators worth a bug-hunter's attention
    for key, title, sev in (
        ("api_paths", "API paths exposed in client (authz/IDOR/SSRF surface)", MEDIUM),
        ("graphql", "GraphQL endpoint/route (check introspection + authz)", MEDIUM),
        ("firebase", "Firebase asset (check public read/write rules)", MEDIUM),
        ("cloud_assets", "Cloud storage asset (check public listing/write)", MEDIUM),
        ("deep_links", "deep links / custom schemes (auth-bypass surface)", LOW),
    ):
        if ind.get(key):
            yield Finding("apk", name, title, sev, data={key: ind[key][:12]}, source="indicators")

    # 6. secrets — reuse the shared secret catalog + triage (same as jsmap/github_dork)
    emitted = 0
    for hit in scan_text("\n".join(strings), source=f"apk:{name}"):
        value = str(hit.data.get("match", ""))
        if is_false_positive(value):
            continue
        yield Finding("apk", name, f"secret in APK strings: {hit.title}", hit.severity,
                      data={"match_redacted": redact(value),
                            "category": hit.data.get("category"),
                            "line": hit.data.get("line")},
                      source="apk-strings")
        emitted += 1
        if emitted >= 50:
            break

    # 7. summary
    yield Finding("apk", name,
                  f"APK recon complete — {apk['zip']['file_count']} entries, "
                  f"{len(apk['manifest']['permissions'])} perms, {len(ind['domains'])} domains, "
                  f"{len(ind['urls'])} URLs, {len(apk['native_libs'])} native libs",
                  INFO,
                  data={"package_candidates": apk["manifest"]["package_candidates"],
                        "certificates": apk["certificates"], "indicator_counts":
                        {k: len(v) for k, v in ind.items()}},
                  source="argus")
