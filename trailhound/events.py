"""Small helpers for reading CloudTrail event fields safely."""

from datetime import datetime, timezone
from typing import Any, Optional

TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def parse_time(value: Any) -> Optional[datetime]:
    """Parse a CloudTrail eventTime string. Returns None if it is not valid."""
    if not isinstance(value, str):
        return None
    try:
        return datetime.strptime(value, TIME_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def get_path(data: Any, *keys: str, default: Any = None) -> Any:
    """Walk nested dictionaries without raising errors.

    get_path(event, "userIdentity", "type") is the safe version of
    event["userIdentity"]["type"].
    """
    current = data
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
        if current is None:
            return default
    return current


def identity_name(event: dict) -> str:
    """Return a readable name for whoever made the API call."""
    identity = event.get("userIdentity") or {}
    if identity.get("type") == "Root":
        return "root"
    return (
        identity.get("userName")
        or identity.get("arn")
        or identity.get("principalId")
        or identity.get("invokedBy")
        or "unknown"
    )
