"""threatscribe command-line demo."""

from __future__ import annotations

import argparse

from .samples import SAMPLE_REPORT
from .service import ThreatScribeService


def _report(result: dict) -> None:
    print(f"Summary [{result['summary_source']}]:")
    print(f"  {result['summary']}\n")
    print(f"IOCs ({result['ioc_count']}):")
    for kind, values in result["iocs"].items():
        for v in values:
            print(f"  {kind:8} {v}")
    print("\nATT&CK techniques:")
    for t in result["techniques"]:
        print(f'  {t["id"]:11} {t["name"]}  ("{t["evidence"]}")')


def demo() -> None:
    print("1) Analysing a sample threat report (LLM summary -> extractive fallback)\n")
    _report(ThreatScribeService().analyze(SAMPLE_REPORT))


def analyze_file(path: str) -> None:
    with open(path, encoding="utf-8") as fh:
        _report(ThreatScribeService().analyze(fh.read()))


def main() -> None:
    parser = argparse.ArgumentParser(description="threatscribe CLI")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("demo", help="analyse a built-in sample report")
    a = sub.add_parser("analyze", help="analyse a report text file")
    a.add_argument("path", help="path to a threat-report text file")
    args = parser.parse_args()
    if args.command == "demo":
        demo()
    elif args.command == "analyze":
        analyze_file(args.path)


if __name__ == "__main__":
    main()
