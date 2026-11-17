"""Turn alerts and findings into text, JSON or Markdown."""

import json
from collections import Counter
from typing import List, Sequence

from .models import SEVERITY_ORDER, Alert, Finding
from .rules import RULES

SEVERITIES_HIGH_TO_LOW = sorted(SEVERITY_ORDER, key=SEVERITY_ORDER.get, reverse=True)


def _cell(value: object) -> str:
    """Make a value safe to put inside a Markdown table cell."""
    return str(value).replace("|", "\\|").replace("\n", " ")


def _detail_text(details: dict) -> str:
    return ", ".join(f"{key}={value}" for key, value in details.items())


def _summary_lines(items: Sequence, label: str) -> List[str]:
    counts = Counter(item.severity for item in items)
    parts = [f"{counts[s]} {s}" for s in SEVERITIES_HIGH_TO_LOW if counts[s]]
    return [f"{len(items)} {label}" + (f" ({', '.join(parts)})" if parts else "")]


# ---------------------------------------------------------------- alerts

def alerts_to_json(alerts: Sequence[Alert]) -> str:
    return json.dumps([a.to_dict() for a in alerts], indent=2)


def alerts_to_text(alerts: Sequence[Alert]) -> str:
    if not alerts:
        return "No alerts.\n"
    lines = _summary_lines(alerts, "alert(s)") + [""]
    for a in alerts:
        lines.append(f"[{a.severity.upper():8}] {a.time}  {a.rule_id}  {a.title}  ({a.mitre})")
        lines.append(f"           identity={a.identity}  ip={a.source_ip}  region={a.region}  event={a.event_name}")
        if a.details:
            lines.append(f"           {_detail_text(a.details)}")
    return "\n".join(lines) + "\n"


def alerts_to_markdown(alerts: Sequence[Alert], source: str = "") -> str:
    lines = ["# TrailHound detection report", ""]
    if source:
        lines += [f"Source: `{source}`", ""]
    if not alerts:
        return "\n".join(lines + ["No alerts."]) + "\n"

    lines += ["## Summary", "", "| Severity | Alerts |", "| --- | --- |"]
    counts = Counter(a.severity for a in alerts)
    for severity in SEVERITIES_HIGH_TO_LOW:
        if counts[severity]:
            lines.append(f"| {severity} | {counts[severity]} |")

    techniques = sorted({a.mitre for a in alerts})
    lines += ["", f"MITRE ATT&CK techniques seen: {', '.join(techniques)}", ""]

    lines += ["## Alerts", "", "| Time (UTC) | Severity | Rule | Identity | Source IP | Event |",
              "| --- | --- | --- | --- | --- | --- |"]
    for a in alerts:
        lines.append(
            f"| {_cell(a.time)} | {a.severity} | {a.rule_id} {_cell(a.title)} | "
            f"{_cell(a.identity)} | {_cell(a.source_ip)} | {_cell(a.event_name)} |"
        )

    lines += ["", "## Details", ""]
    for a in alerts:
        lines.append(f"### {a.rule_id}: {a.title} ({a.severity})")
        lines.append(f"- Time: {a.time}")
        lines.append(f"- ATT&CK: {a.mitre}")
        lines.append(f"- Why it matters: {a.description}")
        if a.details:
            lines.append(f"- Details: {_cell(_detail_text(a.details))}")
        lines.append(f"- Event IDs: {', '.join(a.event_ids) or 'n/a'}")
        lines.append("")
    return "\n".join(lines) + "\n"


# -------------------------------------------------------------- findings

def findings_to_json(findings: Sequence[Finding]) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=2)


def findings_to_text(findings: Sequence[Finding]) -> str:
    if not findings:
        return "No findings.\n"
    lines = _summary_lines(findings, "finding(s)") + [""]
    for f in findings:
        lines.append(f"[{f.severity.upper():8}] {f.check_id}  {f.title}")
        lines.append(f"           {f.file} (statement {f.statement})")
        lines.append(f"           {f.description}")
        lines.append(f"           Fix: {f.recommendation}")
    return "\n".join(lines) + "\n"


def findings_to_markdown(findings: Sequence[Finding], source: str = "") -> str:
    lines = ["# TrailHound IAM policy audit", ""]
    if source:
        lines += [f"Source: `{source}`", ""]
    if not findings:
        return "\n".join(lines + ["No findings."]) + "\n"

    lines += ["| Severity | Check | File | Statement | Issue |", "| --- | --- | --- | --- | --- |"]
    for f in findings:
        lines.append(
            f"| {f.severity} | {f.check_id} | {_cell(f.file)} | {f.statement} | {_cell(f.title)} |"
        )
    lines += ["", "## Details", ""]
    for f in findings:
        lines.append(f"### {f.check_id}: {f.title} ({f.severity})")
        lines.append(f"- File: {f.file}, statement {f.statement}")
        lines.append(f"- Problem: {f.description}")
        lines.append(f"- Fix: {f.recommendation}")
        lines.append("")
    return "\n".join(lines) + "\n"


# ----------------------------------------------------------------- rules

def rules_to_text() -> str:
    lines = [f"{'ID':7} {'Severity':9} {'ATT&CK':11} Title"]
    for rule in RULES:
        lines.append(f"{rule.rule_id:7} {rule.severity:9} {rule.mitre:11} {rule.title}")
    return "\n".join(lines) + "\n"
