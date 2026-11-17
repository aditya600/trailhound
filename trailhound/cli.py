"""Command-line interface.

Exit codes (useful in CI pipelines):
  0  nothing to report
  1  alerts or findings were reported
  2  error (bad path, bad arguments, unreadable file)
"""

import argparse
import sys
from typing import List, Optional

from . import __version__
from .engine import run_detections
from .iam_audit import audit_path
from .loader import load_events
from .models import SEVERITY_ORDER, severity_rank
from .report import (
    alerts_to_json,
    alerts_to_markdown,
    alerts_to_text,
    findings_to_json,
    findings_to_markdown,
    findings_to_text,
    rules_to_text,
)
from .rules import RULES


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trailhound",
        description="Detect attacker behavior in AWS CloudTrail logs and audit IAM policies.",
    )
    parser.add_argument("--version", action="version", version=f"trailhound {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--format", choices=["text", "json", "markdown"], default="text",
                        help="report format (default: text)")
    common.add_argument("-o", "--output", help="write the report to this file instead of printing it")
    common.add_argument("--min-severity", choices=list(SEVERITY_ORDER), default="low",
                        help="hide anything below this severity (default: low)")

    detect = sub.add_parser("detect", parents=[common], help="run detection rules on CloudTrail logs")
    detect.add_argument("path", help="a CloudTrail file or a folder of files (.json, .jsonl, .gz)")
    detect.add_argument("--disable", nargs="*", default=[], metavar="RULE_ID",
                        help="rule IDs to skip, for example TH-002")

    audit = sub.add_parser("audit-iam", parents=[common], help="audit IAM policy JSON files")
    audit.add_argument("path", help="a policy file or a folder of policy files")

    sub.add_parser("rules", help="list the detection rules")
    return parser


def _emit(text: str, output: Optional[str]) -> None:
    if output:
        with open(output, "w", encoding="utf-8") as handle:
            handle.write(text)
        print(f"Report written to {output}", file=sys.stderr)
    else:
        sys.stdout.write(text)


def _run_detect(args: argparse.Namespace) -> int:
    known = {rule.rule_id for rule in RULES}
    unknown = [rule_id for rule_id in args.disable if rule_id not in known]
    if unknown:
        raise ValueError(f"unknown rule id(s): {', '.join(unknown)}")

    events = load_events(args.path)
    alerts = run_detections(events, min_severity=args.min_severity, disabled=args.disable)

    if args.format == "json":
        text = alerts_to_json(alerts) + "\n"
    elif args.format == "markdown":
        text = alerts_to_markdown(alerts, source=args.path)
    else:
        text = f"Scanned {len(events)} event(s) from {args.path}\n" + alerts_to_text(alerts)
    _emit(text, args.output)
    return 1 if alerts else 0


def _run_audit(args: argparse.Namespace) -> int:
    findings, skipped = audit_path(args.path)
    minimum = severity_rank(args.min_severity)
    findings = [f for f in findings if severity_rank(f.severity) >= minimum]
    for name in skipped:
        print(f"warning: skipped {name} (no IAM policy found)", file=sys.stderr)

    if args.format == "json":
        text = findings_to_json(findings) + "\n"
    elif args.format == "markdown":
        text = findings_to_markdown(findings, source=args.path)
    else:
        text = findings_to_text(findings)
    _emit(text, args.output)
    return 1 if findings else 0


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "rules":
            sys.stdout.write(rules_to_text())
            return 0
        if args.command == "detect":
            return _run_detect(args)
        return _run_audit(args)
    except (FileNotFoundError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
