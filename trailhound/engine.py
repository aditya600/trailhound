"""The detection engine: runs every rule over a list of events."""

from collections import deque
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .events import identity_name, parse_time
from .models import Alert, severity_rank
from .rules import RULES, Rule


def _build_alert(rule: Rule, severity: str, event: dict, details: dict, events: List[dict]) -> Alert:
    return Alert(
        rule_id=rule.rule_id,
        title=rule.title,
        severity=severity,
        mitre=rule.mitre,
        time=event.get("eventTime", ""),
        identity=identity_name(event),
        source_ip=event.get("sourceIPAddress", "unknown"),
        region=event.get("awsRegion", "unknown"),
        event_name=event.get("eventName", ""),
        description=rule.description,
        details=details,
        event_ids=[e["eventID"] for e in events if e.get("eventID")],
    )


def run_detections(
    events: Iterable[dict],
    rules: Optional[Sequence[Rule]] = None,
    min_severity: str = "low",
    disabled: Iterable[str] = (),
) -> List[Alert]:
    """Run rules over events and return alerts, oldest first."""
    rules = list(rules) if rules is not None else RULES
    disabled_ids = set(disabled)
    ordered = sorted(events, key=lambda e: e.get("eventTime", ""))

    alerts: List[Alert] = []
    # For threshold rules: (rule id, group key) -> recent matching events.
    windows: Dict[Tuple[str, str], deque] = {}

    for event in ordered:
        for rule in rules:
            if rule.rule_id in disabled_ids:
                continue
            details = rule.match(event)
            if details is None:
                continue

            details = dict(details)
            severity = details.pop("_severity", rule.severity)

            # Simple rule: one matching event is one alert.
            if rule.threshold is None:
                alerts.append(_build_alert(rule, severity, event, details, [event]))
                continue

            # Threshold rule: count matches inside a sliding time window.
            when = parse_time(event.get("eventTime"))
            if when is None:
                continue
            group = rule.group_by(event)
            window = windows.setdefault((rule.rule_id, group), deque())
            window.append((when, event))
            while window and (when - window[0][0]).total_seconds() > rule.window_seconds:
                window.popleft()
            if len(window) >= rule.threshold:
                matched = [item for _, item in window]
                details.update(
                    {"count": len(matched), "window_seconds": rule.window_seconds, "group": group}
                )
                alerts.append(_build_alert(rule, severity, event, details, matched))
                window.clear()  # start counting again so we do not alert on every event

    minimum = severity_rank(min_severity)
    return [a for a in alerts if severity_rank(a.severity) >= minimum]
