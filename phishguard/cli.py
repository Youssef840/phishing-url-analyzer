"""Command-line interface.

Usage:
    python -m phishguard.cli https://example.com
    python -m phishguard.cli https://example.com --json
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .analyzer import AnalyzerSettings, InvalidURLError, analyze_url

COLORS = {"safe": "\033[92m", "suspicious": "\033[93m", "malicious": "\033[91m"}
RESET = "\033[0m"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="phishguard", description="Phishing URL Analyzer")
    parser.add_argument("url", help="URL to analyse")
    parser.add_argument("--json", action="store_true", help="print the full JSON report")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    settings = AnalyzerSettings(
        vt_api_key=os.getenv("VT_API_KEY") or None,
        gsb_api_key=os.getenv("GSB_API_KEY") or None,
        cache_ttl=0,
    )
    try:
        report = analyze_url(args.url, settings, use_cache=False)
    except InvalidURLError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        sys.stdout.reconfigure(encoding="utf-8")
        v = report["verdict"]
        print(f"\nURL     : {report['url']}")
        print(f"Domain  : {report['domain']}")
        print(f"Verdict : {COLORS[v]}{report['verdict_info']['en'].upper()}{RESET}  (score {report['score']}/100)\n")
        for ind in report["indicators"]:
            pts = f"+{ind['points']:>2}" if ind["points"] else "  ."
            print(f"  [{pts}] {ind['severity']:<6} {ind['title']}")
    # Exit code reflects the verdict: handy for scripts / CI pipelines.
    return {"safe": 0, "suspicious": 1, "malicious": 3}[report["verdict"]]


if __name__ == "__main__":
    raise SystemExit(main())
