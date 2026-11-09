from __future__ import annotations
import argparse, json
from pathlib import Path
from .scanner import scan_tree

def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    scan = sub.add_parser("scan")
    scan.add_argument("--path", type=Path, required=True)
    scan.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], default=None)
    args = p.parse_args(argv)
    result = scan_tree(args.path)
    print(json.dumps(result, indent=2))
    if args.fail_on:
        order = ["low", "medium", "high", "critical"]
        threshold = order.index(args.fail_on)
        bad = [f for f in result["findings"] if order.index(f["severity"]) >= threshold]
        return 2 if bad else 0
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
