from __future__ import annotations

import json
from pathlib import Path
from typing import Any


REQUIRED_FIELDS = {
    "timestamp_ms",
    "node_id",
    "layer",
    "event_id",
    "packet_seq",
    "src",
    "dst",
    "priority",
    "ttl",
    "action",
    "reason",
}


def parse_jsonl(path: str | Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line_no, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        record = json.loads(line)
        missing = REQUIRED_FIELDS - record.keys()
        if missing:
            raise ValueError(f"{path}:{line_no} missing fields: {sorted(missing)}")
        records.append(record)
    return records


def actions_for_event(records: list[dict[str, Any]], event_id: str) -> list[str]:
    return [record["action"] for record in records if record["event_id"] == event_id]
