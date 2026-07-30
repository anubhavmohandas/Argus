"""Argus CLI. `pivot` is the headline command; `run`/`all` expose raw modules."""
from __future__ import annotations

import argparse
import json
import sys

from . import core
from .core import MODULES, run_module, run_all, sort_by_severity
from .pivot import pivot, dossier, Budget, classify

_SEV_COLOR = {
    core.CRITICAL: "\033[1;31m", core.HIGH: "\033[31m", core.MEDIUM: "\033[33m",
    core.LOW: "\033[36m", core.INFO: "\033[90m",
}
_RESET = "\033[0m"


def _print_findings(findings, as_json: bool):
    if as_json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
        return
    if not findings:
        print("  (no findings)")
        return
    for f in sort_by_severity(findings):
        c = _SEV_COLOR.get(f.severity, "")
        print(f"  {c}[{f.severity:<8}]{_RESET} {f.module:<11} {f.title}")
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
    pv.add_argument("--json", action="store_true")

    rn = sub.add_parser("run", help="Run one module against a target")
    rn.add_argument("module", choices=sorted(MODULES))
    rn.add_argument("target")
    rn.add_argument("--json", action="store_true")

    al = sub.add_parser("all", help="Run every module that fits the target")
    al.add_argument("target")
    al.add_argument("--json", action="store_true")

    sub.add_parser("modules", help="List available modules")

    args = p.parse_args(argv)

    if args.cmd == "modules":
        for name, m in sorted(MODULES.items()):
            print(f"  {name:<12} [{m.kind:<9}] {m.help}")
        return 0

    if args.cmd == "pivot":
        print(f"[argus] seed {args.seed!r} classified as: {classify(args.seed)}", file=sys.stderr)
        g = pivot(args.seed, Budget(max_depth=args.depth, max_entities=args.max_entities,
                                    expand_subdomains=args.deep))
        if args.json:
            print(json.dumps({
                "nodes": [{"type": e.type, "value": e.value, "depth": e.depth, "via": e.via}
                          for e in g.nodes.values()],
                "edges": [{"src": s, "rel": r, "dst": d} for (s, r, d) in g.edges],
                "findings": [f.to_dict() for f in g.findings],
            }, indent=2))
        else:
            print(dossier(g))
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
