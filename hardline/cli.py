"""`hardline scan router.rsc` — same engine as the web app, for scripts and CI."""
from __future__ import annotations

import argparse
import json
import sys

from .parser import parse, ParseError
from .scoring import build_report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="hardline", description="RouterOS security posture scan")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan a RouterOS /export file")
    s.add_argument("file", help="path to .rsc export, or - for stdin")
    s.add_argument("--json", action="store_true", help="emit JSON instead of text")
    s.add_argument("--ai", action="store_true", help="include the AI summary (needs ANTHROPIC_API_KEY)")
    s.add_argument("--fail-on", default="critical", choices=["critical", "high", "medium", "low", "never"],
                   help="exit 2 if a finding at or above this severity exists")
    args = ap.parse_args(argv)

    text = sys.stdin.read() if args.file == "-" else open(args.file, encoding="utf-8", errors="replace").read()
    try:
        cfg = parse(text)
    except ParseError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    report = build_report(cfg)
    if args.ai:
        from .ai import summarize
        report.ai_summary = summarize(report)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(f"Hardline — {report.identity or 'router'} — RouterOS {report.version or '?'} {report.model or ''}")
        print(f"Grade {report.grade}  score {report.score}/100  exposure {report.exposure_score}  evidence {report.evidence_score}")
        print(f"MikroTrick exposed: {'YES' if report.mikrotrick_exposed else 'no'}   "
              f"critical {report.counts['critical']}  high {report.counts['high']}  medium {report.counts['medium']}  low {report.counts['low']}")
        print()
        for f in report.findings:
            print(f"[{f.severity.upper():8}] {f.id} {f.title}")
            print(f"    {f.observed}")
            for line in f.fix:
                print(f"    > {line}")
            if f.caution:
                print(f"    ! {f.caution}")
            print()
        if report.ai_summary:
            print("── AI summary ──")
            print(report.ai_summary)

    order = ["critical", "high", "medium", "low"]
    if args.fail_on != "never":
        threshold = order.index(args.fail_on)
        if any(order.index(f.severity) <= threshold for f in report.findings if f.severity in order):
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
