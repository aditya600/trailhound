"""Helpers for reading IAM policy documents."""

import fnmatch
import json
from typing import Any, List, Optional


def as_list(value: Any) -> list:
    """IAM lets many fields be a single value or a list. Always return a list."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def parse_policy(document: Any) -> Optional[dict]:
    """Accept a dict or a JSON string and return the policy as a dict."""
    if isinstance(document, str):
        try:
            document = json.loads(document)
        except json.JSONDecodeError:
            return None
    return document if isinstance(document, dict) else None


def statements(document: Any) -> List[dict]:
    """Return the list of statements in a policy (empty if it is not valid)."""
    policy = parse_policy(document)
    if not policy:
        return []
    return [s for s in as_list(policy.get("Statement")) if isinstance(s, dict)]


def action_matches(pattern: str, action: str) -> bool:
    """True if an IAM action pattern (like 'iam:*') covers a specific action."""
    return fnmatch.fnmatchcase(action.lower(), pattern.lower())


def grants_full_admin(statement: dict) -> bool:
    """True for the classic 'Allow everything on everything' statement."""
    if statement.get("Effect") != "Allow":
        return False
    actions = [a for a in as_list(statement.get("Action")) if isinstance(a, str)]
    resources = [r for r in as_list(statement.get("Resource")) if isinstance(r, str)]
    return "*" in actions and "*" in resources
