from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass
class LogRecord:
    timestamp_ms: int
    node_id: str
    layer: str
    event_id: str
    packet_seq: int
    src: str
    dst: str
    priority: str
    ttl: int
    action: str
    reason: str
    rssi: int | None = None
    snr: int | None = None
    extra: dict[str, Any] | None = None


class JsonlLogSink:
    def __init__(self, scenario_name: str) -> None:
        self.base_dir = Path("logs") / scenario_name
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.base_dir / "scenario.log"
        self.path.write_text("", encoding="utf-8")

    def write(self, record: LogRecord) -> None:
        payload = asdict(record)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")
