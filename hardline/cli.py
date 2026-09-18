"""`hardline` opens the app locally. `hardline scan router.rsc` is the same engine for scripts and CI."""
from __future__ import annotations

import argparse
import json
import sys

from .parser import parse, ParseError
from .scoring import build_report


def serve(port: int = 8080, host: str = "127.0.0.1", open_browser: bool = True) -> int:
    """Run the web app locally. Nothing leaves this machine unless an Anthropic key is set."""
    import os
    import threading
    import webbrowser

    import uvicorn

    os.environ.setdefault("HARDLINE_LOCAL", "1")
    url = f"http://{host}:{port}/"
    print(f"Hardline running locally at {url}  (Ctrl+C to stop)", flush=True)
    if os.environ.get("HARDLINE_AI", "1") != "0" and not os.environ.get("ANTHROPIC_API_KEY"):
        print("AI summary: off (no ANTHROPIC_API_KEY). Everything else runs offline.", flush=True)
    if open_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    uvicorn.run("hardline.app:app", host=host, port=port, log_level="warning")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="hardline", description="RouterOS security posture scan")
    sub = ap.add_subparsers(dest="cmd")
    sv = sub.add_parser("serve", help="open the web app on this machine (default when no command is given)")
    sv.add_argument("--port", type=int, default=8080)
    sv.add_argument("--host", default="127.0.0.1", help="bind address; keep 127.0.0.1 unless you mean to share it")
    sv.add_argument("--no-browser", action="store_true", help="do not open a browser tab")
    s = sub.add_parser("scan", help="scan a RouterOS /export file")
    s.add_argument("file", help="path to .rsc export, or - for stdin")
    s.add_argument("--json", action="store_true", help="emit JSON instead of text")
    s.add_argument("--ai", action="store_true", help="include the AI summary (needs ANTHROPIC_API_KEY)")
    s.add_argument("--fail-on", default="critical", choices=["critical", "high", "medium", "low", "never"],
                   help="exit 2 if a finding at or above this severity exists")
    args = ap.parse_args(argv)
    if args.cmd in (None, "serve"):
        return serve(port=getattr(args, "port", 8080), host=getattr(args, "host", "127.0.0.1"),
                     open_browser=not getattr(args, "no_browser", False))

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
