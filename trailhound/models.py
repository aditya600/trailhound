"""Shared data structures used by every part of TrailHound."""

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def severity_rank(severity: str) -> int:
    """Turn a severity name into a number so severities can be compared."""
    return SEVERITY_ORDER[severity.lower()]


@dataclass
class Alert:
    """One detection raised from CloudTrail events."""

    rule_id: str
    title: str
    severity: str
    mitre: str
    time: str
    identity: str
    source_ip: str
    region: str
    event_name: str
    description: str
    details: Dict[str, Any] = field(default_factory=dict)
    event_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """One risky statement found in an IAM policy document."""

    check_id: str
    title: str
    severity: str
    file: str
    statement: int
    description: str
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
