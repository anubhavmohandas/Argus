"""Argus CLI. `pivot` is the headline command; `run`/`all` expose raw modules."""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import core, providers, store
from .core import MODULES, run_module, run_all, sort_by_severity
from .pivot import pivot, dossier, Budget, classify
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
    p = argparse.ArgumentParser(prog="argus", description="Autonomous correlation recon engine.")
    sub = p.add_subparsers(dest="cmd")

    pv = sub.add_parser("pivot", help="Autonomous multi-source correlation from one seed")
    pv.add_argument("seed", help="domain / ip / username / phone / email")
    pv.add_argument("--depth", type=int, default=2, help="max pivot depth (default 2)")
    pv.add_argument("--max", type=int, default=40, dest="max_entities", help="max entities (default 40)")
    pv.add_argument("--deep", type=int, default=0, help="re-pivot into N discovered subdomains (default 0)")
    pv.add_argument("--probe", action="store_true",
                    help="ACTIVE: connect to discovered hosts to establish evidence (off by default)")
    pv.add_argument("--no-memory", action="store_true", help="don't save this run or compare against past ones")
    pv.add_argument("--json", action="store_true")

    rn = sub.add_parser("run", help="Run one module against a target")
    rn.add_argument("module", choices=sorted(MODULES))
    rn.add_argument("target")
    rn.add_argument("--json", action="store_true")

    al = sub.add_parser("all", help="Run every module that fits the target")
    al.add_argument("target")
    al.add_argument("--json", action="store_true")

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
        past = [] if args.no_memory else store.history(args.seed)
        g = pivot(args.seed, Budget(max_depth=args.depth, max_entities=args.max_entities,
                                    expand_subdomains=args.deep))
        if args.probe:   # providers add evidence only — the engine is untouched by this
            n = providers.enrich(g)                 # HTTP probe -> evidence + version
            t = providers.enrich_tls(g)             # TLS probe -> observed cert fingerprint
            k = providers.enrich_kev(g)             # analysis: version -> known_exploited
            r = providers.analyze_certificates(g)   # analysis: shared cert -> certificate_reused
            print(f"[argus] probed {n} HTTP, {t} TLS; {k} known-exploit, {r} cert-reuse — evidence attached",
                  file=sys.stderr)
        result = investigate(g)   # discovery -> reasoning: the one result object
        if past:  # investigation memory — "I've seen this before"
            prev = past[-1]
            print(f"[argus] seen before: {len(past)} prior investigation(s), "
                  f"last {prev.get('timestamp', '?')[:10]} — {store.compare_line(prev, g)}",
                  file=sys.stderr)
        if not args.no_memory:
            store.save(args.seed, g)   # memory stores evidence; conclusions are re-derivable
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

    p.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
