"""Argus CLI. `pivot` is the headline command; `run`/`all` expose raw modules."""
from __future__ import annotations

import argparse
import itertools
import json
import os
import sys
import threading
from pathlib import Path

from . import core, feedback, policy, providers, scope as scope_mod, store
from .core import MODULES, run_module, run_all, sort_by_severity
from .pivot import pivot, dossier, report_markdown, Budget, classify
from .engine import investigate

_SEV_COLOR = {
    core.CRITICAL: "\033[1;31m", core.HIGH: "\033[31m", core.MEDIUM: "\033[33m",
    core.LOW: "\033[36m", core.INFO: "\033[90m",
}
_RESET = "\033[0m"


def _color_enabled() -> bool:
    """ANSI only when it'll render: a real terminal, NO_COLOR unset, and on
    Windows 10+ after enabling virtual-terminal processing. Keeps output clean
    when piped/redirected and on legacy consoles — same behavior every OS."""
    if os.environ.get("NO_COLOR") is not None or not sys.stdout.isatty():
        return False
    if sys.platform == "win32":
        try:
            import ctypes
            k = ctypes.windll.kernel32
            h = k.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = ctypes.c_uint32()
            if not k.GetConsoleMode(h, ctypes.byref(mode)):
                return False
            k.SetConsoleMode(h, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        except Exception:
            return False
    return True


_COLOR = _color_enabled()


# --- banner ---------------------------------------------------------------
# ANSI Shadow "ARGUS", coloured with a magenta->cyan vertical gradient using
# 24-bit truecolor. Hardcoded art keeps the tool dependency-free (no figlet).
# Everything degrades to plain text when colour is off (NO_COLOR / piped /
# legacy console), so the same code is safe in a script or a redirect.
_BANNER_ART = [
    " █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗",
    "██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝",
    "███████║██████╔╝██║  ███╗██║   ██║███████╗",
    "██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║",
    "██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║",
    "╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝",
]
_TAGLINE = "autonomous correlation recon engine"
_AUTHOR = "ANUBHAV MOHANDAS"
_GRAD_START, _GRAD_END = (255, 0, 153), (0, 224, 255)   # magenta -> cyan


def _mix(a, z, t):
    """Linear-interpolate two RGB tuples at position t (0..1)."""
    return tuple(round(x + (y - x) * t) for x, y in zip(a, z))


def _grad_text(text: str, start, end, bold: bool = True) -> str:
    """Paint each character along a horizontal start->end gradient (truecolor).
    Returns the text untouched when colour is off — same string, no escapes."""
    if not _COLOR or not text:
        return text
    n = max(len(text) - 1, 1)
    b = "1;" if bold else ""
    out = []
    for i, ch in enumerate(text):
        r, g, bl = _mix(start, end, i / n)
        out.append(f"\033[{b}38;2;{r};{g};{bl}m{ch}")
    return "".join(out) + _RESET


def banner() -> str:
    """The ARGUS wordmark + author credit — magenta→cyan throughout: the letters
    fade top-to-bottom, the rule and the name fade left-to-right. Plain when
    colour is off (NO_COLOR / piped / legacy console)."""
    art = _BANNER_ART
    w = len(art[0])
    rule_plain = "─" * w
    if not _COLOR:
        return (f"{chr(10).join(art)}\n\n{rule_plain}\n  {_TAGLINE}\n"
                f"  ✦ crafted by  {_AUTHOR}\n{rule_plain}")
    lines = []
    for i, line in enumerate(art):
        r, g, b = _mix(_GRAD_START, _GRAD_END, i / (len(art) - 1))
        lines.append(f"\033[1;38;2;{r};{g};{b}m{line}{_RESET}")
    rule = _grad_text(rule_plain, _GRAD_START, _GRAD_END, bold=False)
    tagline = f"\033[3;38;2;130;205;235m  {_TAGLINE}{_RESET}"          # soft cyan, italic
    author = (f"\033[2;38;2;150;150;150m  ✦ crafted by  {_RESET}"     # dim label
              + _grad_text(_AUTHOR, _GRAD_START, _GRAD_END))          # name in the gradient
    return "\n".join([*lines, rule, tagline, author, rule])


# --- interactive menu -----------------------------------------------------
# Menu choice -> the pivot flags for that engagement level. The heavy lifting
# is NOT reimplemented here: the menu builds an argv and re-enters main(), so
# there is exactly one pivot code path whether you use flags or the menu.
_MODES = {
    "1": ("Passive", "public sources only — never touches the target", []),
    "2": ("Active", "+ probe hosts + live NVD CVEs & write-ups", ["--probe", "--cve"]),
    "3": ("Active+", "+ request admin & sensitive paths (.git/.env)", ["--probe-paths", "--cve"]),
    "4": ("Full scan", "+ TCP port scan, service versions & live CVEs (loudest)", ["--scan", "--cve"]),
}
# green → red: the colour itself tells you how loud the level is (safe → loudest)
_MODE_COLOR = {"1": "38;2;80;220;120", "2": "38;2;230;200;60",
               "3": "38;5;208", "4": "38;2;235;70;70"}


def _confirm_active() -> bool:
    """Active modes connect to the target's own servers — a real authorization
    boundary, so it is an explicit, defaulted-to-no confirmation, never assumed."""
    warn = "\n  ⚠  ACTIVE mode connects to the target's OWN servers."
    print(f"\033[33m{warn}\033[0m" if _COLOR else warn)
    print("     Only run this on assets you own or are authorized to test.")
    return input("     Proceed? [y/N]: ").strip().lower() in ("y", "yes")


def _ask(prompt: str, default: str = "") -> str:
    """Prompt with an inline default shown in [brackets]; empty input keeps it."""
    hint = f" [{default}]" if default else ""
    return input(f"  {prompt}{hint}: ").strip() or default


def _yes(prompt: str, default: str = "n") -> bool:
    return _ask(prompt, default).lower() in ("y", "yes")


def _pivot_flow():
    """Interactive pivot: seed, engagement level, then every option (all defaulted).
    Builds the argv only — main() runs the one real pivot path. None = cancel."""
    seed = input("\n  Seed (domain / ip / email / username / phone): ").strip()
    if not seed:
        print("  no seed given.")
        return None
    print("\n  Engagement level:")
    for key, (label, desc, _) in _MODES.items():
        tag = "  (safe default)" if key == "1" else ""
        head = f"[{key}] {label:<9}"
        if _COLOR:
            head = f"\033[1;{_MODE_COLOR[key]}m{head}{_RESET}"
        print(f"   {head} {desc}{tag}")
    choice = _ask("Mode 1-4", "1")
    if choice not in _MODES:
        print("  not a valid choice — staying passive.")
        choice = "1"
    flags = list(_MODES[choice][2])
    argv = ["pivot", seed]
    if _yes("Customise options (depth/max/deep/ports/scope/rate/report/memory/json)?"):
        argv += ["--depth", _ask("Pivot depth", "2"),
                 "--max", _ask("Max entities", "40"),
                 "--deep", _ask("Re-pivot into N subdomains", "0")]
        if choice == "4":
            ports = _ask("Ports (blank = common service ports)")
            if ports:
                argv += ["--ports", ports]
        scope_file = _ask("Scope file (blank = none)")
        if scope_file:
            argv += ["--scope", scope_file]
        if flags:   # rate only bites the active tiers that actually send requests
            rate = _ask("Max HTTP requests/sec (blank = unlimited)")
            if rate:
                argv += ["--rate", rate]
        report = _ask("Write Markdown report to (blank = none)")
        if report:
            argv += ["--report", report]
        if not _yes("Save to investigation memory?", "y"):
            argv.append("--no-memory")
        if _yes("JSON output?"):
            argv.append("--json")
    if flags and not _confirm_active():
        print("  cancelled — nothing sent to the target.")
        return None
    return argv + flags


def _module_flow():
    """Interactive `run`: pick one module by number, give it a target."""
    names = sorted(MODULES)
    print("\n  Modules:")
    for i, name in enumerate(names, 1):
        print(f"   [{i:>2}] {name:<11} {MODULES[name].help}")
    pick = _ask("Module number", "1")
    if not pick.isdigit() or not 1 <= int(pick) <= len(names):
        print("  not a valid choice.")
        return None
    name = names[int(pick) - 1]
    target = input(f"  Target for {name}: ").strip()
    if not target:
        print("  no target given.")
        return None
    return ["run", name, target] + (["--json"] if _yes("JSON output?") else [])


def _all_flow():
    """Interactive `all`: one target, every module that fits it."""
    target = input("\n  Target (every fitting module runs): ").strip()
    if not target:
        print("  no target given.")
        return None
    return ["all", target] + (["--json"] if _yes("JSON output?") else [])


# Every CLI capability, reachable from the menu. Each flow returns an argv (or
# None to cancel); the menu re-enters main() with it, so there is exactly one
# code path whether Argus is driven by flags or by menu.
_ACTIONS = {
    "1": ("Pivot", "autonomous correlation from one seed (the headline)", _pivot_flow),
    "2": ("Run module", "one recon module against one target", _module_flow),
    "3": ("Run all", "every module that fits a target", _all_flow),
    "4": ("Modules", "list the available recon modules", lambda: ["modules"]),
    "5": ("Coverage", "which engine predicates have an evidence provider", lambda: ["coverage"]),
}


def interactive() -> int:
    """The 'main menu': banner + action picker exposing every capability. Bare
    `argus` on a terminal lands here; scripts (no TTY) get --help so nothing hangs."""
    if _COLOR:  # only when attached to a real terminal
        print("\033[2J\033[3J\033[H", end="")  # clear screen + scrollback, cursor home
    print(banner())
    try:
        print("\n  What do you want to do?")
        for key, (label, desc, _) in _ACTIONS.items():
            print(f"   [{key}] {label:<11} {desc}")
        action = _ask("Choose 1-5", "1")
        entry = _ACTIONS.get(action)
        if entry is None:
            print("  not a valid choice — bye.")
            return 0
        argv = entry[2]()
        if argv is None:
            print("  cancelled.")
            return 0
    except (EOFError, KeyboardInterrupt):
        print("\n  cancelled.")
        return 0
    print()
    return main(argv)


# What each module is doing + which ones are slow, so the pivot loop never looks
# frozen. Printed to stderr (like every other [argus] status line) so --json stays clean.
_STEP_LABEL = {
    "rdap": "registrar / RDAP", "dns": "DNS records (A/AAAA/MX/NS/TXT)",
    "subdomains": "subdomains via crt.sh — slow, up to ~25s", "ip": "IP geo / ASN",
    "username": "social-profile enumeration", "phone": "phone intel",
}


_SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"   # braille cycle — reads as motion without needing color


def _progress(mod_name: str, value: str):
    """Live per-module status during a pivot — kills the 'nothing is happening'
    feel while a slow crt.sh/RDAP fetch blocks (crt.sh alone can take ~25s).
    Returns a done() the engine calls when the module finishes, which stops the
    animation. Animates only on a real terminal; piped/JSON runs get one static
    stderr line so machine output stays clean."""
    label = _STEP_LABEL.get(mod_name, mod_name)
    msg = f"{mod_name:<10} {value}  · {label}"
    if not sys.stderr.isatty():
        print(f"  → {msg}", file=sys.stderr, flush=True)
        return lambda: None
    stop = threading.Event()
    dim, reset = ("\033[90m", _RESET) if _COLOR else ("", "")

    def spin():
        for frame in itertools.cycle(_SPIN):
            sys.stderr.write(f"\r{dim}  {frame} {msg}{reset}\033[K")
            sys.stderr.flush()
            if stop.wait(0.08):
                break
        sys.stderr.write("\r\033[K")   # erase the line so the dossier prints clean
        sys.stderr.flush()

    t = threading.Thread(target=spin, daemon=True)
    t.start()
    return lambda: (stop.set(), t.join())


def _print_findings(findings, as_json: bool):
    if as_json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
        return
    if not findings:
        print("  (no findings)")
        return
    for f in sort_by_severity(findings):
        c = _SEV_COLOR.get(f.severity, "") if _COLOR else ""
        r = _RESET if _COLOR else ""
        print(f"  {c}[{f.severity:<8}]{r} {f.module:<11} {f.title}")
        for k, v in (f.data or {}).items():
            if v:
                print(f"      {k}: {v}")


def main(argv=None):
    """Console entrypoint. Wraps the real dispatch so a Ctrl-C during a slow
    pivot prints one clean line instead of a socket-level traceback. interactive()
    re-enters through here, so the guard covers menu-driven runs too."""
    try:
        return _run(argv)
    except KeyboardInterrupt:
        print("\n  interrupted.", file=sys.stderr)
        return 130


def _run(argv=None):
    p = argparse.ArgumentParser(prog="argus", description="Autonomous correlation recon engine.")
    sub = p.add_subparsers(dest="cmd")

    pv = sub.add_parser("pivot", help="Autonomous multi-source correlation from one seed")
    pv.add_argument("seed", help="domain / ip / username / phone / email")
    pv.add_argument("--depth", type=int, default=2, help="max pivot depth (default 2)")
    pv.add_argument("--max", type=int, default=40, dest="max_entities", help="max entities (default 40)")
    pv.add_argument("--deep", type=int, default=0, help="re-pivot into N discovered subdomains (default 0)")
    pv.add_argument("--probe", action="store_true",
                    help="ACTIVE: connect to discovered hosts to establish evidence (off by default)")
    pv.add_argument("--probe-paths", action="store_true",
                    help="ACTIVE, louder: also request administrative + sensitive-file paths (~9 requests/host). Implies --probe")
    pv.add_argument("--scan", action="store_true",
                    help="ACTIVE, loudest: TCP-connect scan discovered hosts for open ports + service versions, then match a CVE catalog")
    pv.add_argument("--ports", default=None,
                    help="port spec for --scan, e.g. '1-1024' or '22,80,443' (default: common service ports)")
    pv.add_argument("--cve", action="store_true",
                    help="look up observed service versions against NVD live and attach the real CVEs + reference write-ups (needs --probe or --scan to have observed a version; set NVD_API_KEY to lift rate limits)")
    pv.add_argument("--policy", default=None, metavar="FILE",
                    help="compile a pasted bug-bounty program page into the engagement policy: scope + rate + "
                         "non-reportable exclusions + objectives (supersedes --scope/--rate)")
    pv.add_argument("--scope", default=None, metavar="FILE",
                    help="engagement-scope file (in/out-of-scope allowlist); no active probe touches a host outside it")
    pv.add_argument("--rate", type=float, default=None, metavar="N",
                    help="politeness: cap outbound HTTP probe requests to N per second (default: unlimited)")
    pv.add_argument("--max-requests", type=int, default=None, dest="max_requests", metavar="N",
                    help="politeness: hard cap on total outbound HTTP probe requests for the run")
    pv.add_argument("--report", default=None, metavar="PATH",
                    help="also write a bug-bounty-ready Markdown report to PATH")
    pv.add_argument("--no-memory", action="store_true", help="don't save this run or compare against past ones")
    pv.add_argument("--json", action="store_true")

    rn = sub.add_parser("run", help="Run one module against a target")
    rn.add_argument("module", choices=sorted(MODULES))
    rn.add_argument("target")
    rn.add_argument("--json", action="store_true")

    al = sub.add_parser("all", help="Run every module that fits the target")
    al.add_argument("target")
    al.add_argument("--json", action="store_true")

    fb = sub.add_parser("feedback", help="Record a researcher verdict on a past finding (append-only; nudges future ranking)")
    fb.add_argument("rule", help="rule id the finding came from, e.g. exposed_secret")
    fb.add_argument("target", help="the host/entity the finding was about")
    fb.add_argument("verdict", help=f"one of {', '.join(feedback.VERDICTS)} (or tp/fp/dup)")
    fb.add_argument("--program", default="", help="engagement key the verdict belongs to (use the pivot seed for now)")
    fb.add_argument("--note", default="", help="free-text note for the report trail")

    sub.add_parser("modules", help="List available modules")
    sub.add_parser("coverage", help="Which engine predicates have an evidence provider (the roadmap)")

    args = p.parse_args(argv)

    if args.cmd == "modules":
        for name, m in sorted(MODULES.items()):
            print(f"  {name:<12} [{m.kind:<9}] {m.help}")
        return 0

    if args.cmd == "coverage":
        for pred, prov in providers.coverage().items():
            print(f"  {pred:<28} {prov or '— NO PROVIDER'}")
        return 0

    if args.cmd == "pivot":
        print(f"[argus] seed {args.seed!r} classified as: {classify(args.seed)}", file=sys.stderr)
        # Engagement policy, set before any provider runs. Always reset both, so a
        # menu-driven second run never inherits the first run's scope/rate.
        pol = None
        if args.policy:
            try:
                pol = policy.compile(Path(args.policy).read_text())
            except OSError as e:
                print(f"error: cannot read policy file {args.policy!r}: {e}", file=sys.stderr)
                return 2
            pol.apply()   # scope + rate, from the compiled program
            print(f"[argus] engagement policy compiled from {args.policy!r}", file=sys.stderr)
            for ln in pol.summary().splitlines():
                print(f"        {ln}", file=sys.stderr)
        elif args.scope:
            try:
                providers.set_scope(scope_mod.load(args.scope))
            except ValueError as e:
                print(f"error: {e}", file=sys.stderr)
                return 2
            print(f"[argus] scope loaded from {args.scope!r} — active probes limited to in-scope hosts", file=sys.stderr)
        else:
            providers.set_scope(None)
        if not pol:
            providers.set_rate(args.rate, args.max_requests)
        past = [] if args.no_memory else store.history(args.seed)
        g = pivot(args.seed, Budget(max_depth=args.depth, max_entities=args.max_entities,
                                    expand_subdomains=args.deep), on_step=_progress)
        if args.probe or args.probe_paths:   # providers add evidence only — the engine is untouched by this
            n = providers.enrich(g)                 # HTTP probe -> evidence + version + clickjacking
            t = providers.enrich_tls(g)             # TLS probe -> observed cert fingerprint
            c = providers.enrich_cors(g)            # CORS probe -> cors_misconfig (one GET/host)
            k = providers.enrich_kev(g)             # analysis: version -> known_exploited
            r = providers.analyze_certificates(g)   # analysis: shared cert -> certificate_reused
            m = providers.enrich_email_spoof(g)     # analysis: DMARC over DoH -> email_spoofable (no target engagement)
            s = providers.enrich_security_txt(g)    # disclosure: where to report (observation only, one GET/host)
            line = f"probed {n} HTTP, {t} TLS, {c} CORS; {k} known-exploit, {r} cert-reuse, {m} email-spoofable, {s} security.txt"
            if args.probe_paths:   # its own flag: multiplies the requests against the target
                line += (f", {providers.enrich_admin(g)} admin-surface"
                         f", {providers.enrich_exposure(g)} exposed-file"
                         f", {providers.enrich_traversal(g)} path-traversal"
                         f", {providers.enrich_graphql(g)} graphql-introspection"
                         f", {providers.enrich_redirect(g)} open-redirect"
                         f", {providers.enrich_injection(g)} xss/ssti")
            print(f"[argus] {line} — evidence attached", file=sys.stderr)
        if args.scan:   # loudest tier: a TCP connect scan is unmistakable in the target's logs
            try:
                ports = providers.parse_ports(args.ports) if args.ports else None
            except ValueError as e:
                print(f"error: {e}", file=sys.stderr)
                return 2
            v = providers.enrich_scan(g, ports=ports)
            print(f"[argus] port-scanned hosts; {v} with a catalog CVE — evidence attached", file=sys.stderr)
        if getattr(args, "cve", False):   # live NVD lookup over versions the probe/scan observed
            v = providers.enrich_nvd(g)
            print(f"[argus] NVD live lookup; {v} host(s) with a live CVE + references — evidence attached", file=sys.stderr)
        result = investigate(g)   # discovery -> reasoning: the one result object
        if pol:   # program policy: suppress findings it declared non-reportable / out of scope
            result, suppressed = pol.filter(result)
            if suppressed:
                names = ", ".join(sorted({c.rule for c in suppressed}))
                print(f"[argus] policy suppressed {len(suppressed)} non-reportable finding(s): {names}",
                      file=sys.stderr)
        # historical feedback: nudge rank by past researcher verdicts (never confidence).
        # occam: program identity is the seed for now — a --program/policy.name key is the follow-up.
        result = feedback.annotate(result, program=args.seed)
        if past:  # investigation memory — "I've seen this before"
            print("[argus] seen before —", file=sys.stderr)
            for line in store.memory_block(past, g).splitlines():
                print(f"        {line}", file=sys.stderr)
        if not args.no_memory:
            store.save(args.seed, g)   # memory stores evidence; conclusions are re-derivable
        if args.report:
            try:
                Path(args.report).write_text(report_markdown(args.seed, g, result))
                print(f"[argus] report written to {args.report}", file=sys.stderr)
            except OSError as e:
                print(f"error: cannot write report {args.report!r}: {e}", file=sys.stderr)
                return 2
        if args.json:
            print(json.dumps({"graph": g.to_dict(), "investigation": result.to_dict()}, indent=2))
        else:
            print(dossier(g, result))
        return 0

    if args.cmd == "run":
        try:
            _print_findings(run_module(args.module, args.target), args.json)
        except (KeyError, ValueError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        return 0

    if args.cmd == "all":
        _print_findings(run_all(args.target), args.json)
        return 0

    if args.cmd == "feedback":
        try:
            p_out = feedback.record(args.rule, args.target, args.verdict,
                                    program=args.program, note=args.note)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        prog = f" [{args.program}]" if args.program else ""
        print(f"[argus] recorded {args.verdict} on {args.rule} @ {args.target}{prog} → {p_out}", file=sys.stderr)
        return 0

    # No subcommand: on a real terminal, open the interactive menu; piped or
    # scripted (no TTY), print help so nothing ever blocks on input().
    if args.cmd is None and sys.stdin.isatty() and sys.stdout.isatty():
        return interactive()
    p.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
