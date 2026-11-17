"""Load CloudTrail events from files or folders.

Supported formats:
  * the standard CloudTrail file: {"Records": [ ... ]}
  * a plain JSON array of events
  * JSON Lines (one event per line)
  * any of the above compressed as .gz (what CloudTrail writes to S3)
"""

import gzip
import json
from pathlib import Path
from typing import List


def _read_text(path: Path) -> str:
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            return handle.read()
    return path.read_text(encoding="utf-8")


def _parse(text: str) -> list:
    text = text.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Not one JSON document, so try JSON Lines.
        events = []
        for number, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"line {number}: invalid JSON ({exc.msg})") from exc
        return events
    if isinstance(data, dict) and "Records" in data:
        return data["Records"]
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return [data]
    raise ValueError("unsupported JSON structure")


def _is_log_file(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith((".json", ".json.gz", ".jsonl", ".jsonl.gz"))


def load_events(path: str) -> List[dict]:
    """Load every CloudTrail event under a file or folder, sorted by time."""
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"path not found: {root}")
    if root.is_file():
        files = [root]
    else:
        files = sorted(p for p in root.rglob("*") if p.is_file() and _is_log_file(p))
    if not files:
        raise FileNotFoundError(f"no .json, .jsonl or .gz log files found in: {root}")

    events: List[dict] = []
    for file in files:
        try:
            parsed = _parse(_read_text(file))
        except (OSError, ValueError) as exc:
            raise ValueError(f"{file}: {exc}") from exc
        # Keep real events only (this skips CloudTrail digest files).
        events.extend(e for e in parsed if isinstance(e, dict) and "eventName" in e)

    events.sort(key=lambda e: e.get("eventTime", ""))
    return events
