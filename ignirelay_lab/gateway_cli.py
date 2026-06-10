from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from .logging_utils import JsonlLogSink, LogRecord
from .model import Packet


def default_gateway_dir() -> Path:
    return Path(os.environ.get(
        "IGNIRELAY_GATEWAY_DIR",
        Path(__file__).resolve().parents[2] / "ignirelay-gateway",
    ))


class GatewayCliSink:
    def __init__(
        self,
        scenario_name: str,
        log: JsonlLogSink,
        gateway_dir: Path | None = None,
        reset: bool = True,
    ) -> None:
        self.log = log
        self.gateway_dir = gateway_dir or default_gateway_dir()
        self.base_dir = Path("logs") / scenario_name
        self.packet_jsonl = self.base_dir / "gateway_packets.jsonl"
        self.db_path = self.base_dir / "gateway.sqlite"
        self.export_json = self.base_dir / "gateway_events.json"
        self.export_csv = self.base_dir / "gateway_events.csv"
        self.events: dict[str, dict[str, Any]] = {}
        self.routes: list[Packet] = []
        self.packet_jsonl.write_text("", encoding="utf-8")
        if reset:
            for path in (self.db_path, self.export_json, self.export_csv):
                if path.exists():
                    path.unlink()

    def receive(self, now_ms: int, packet: Packet) -> None:
        self.routes.append(packet)
        with self.packet_jsonl.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(packet.to_gateway_record(now_ms), sort_keys=True) + "\n")
        self.log.write(LogRecord(
            timestamp_ms=now_ms,
            node_id="GatewayCliSink",
            layer="GATEWAY_CLI",
            event_id=packet.event_id,
            packet_seq=packet.packet_seq,
            src=packet.src,
            dst="Gateway",
            priority=packet.priority.label,
            ttl=packet.ttl,
            action="queue_cli_ingest",
            reason="gateway_cli_integration",
        ))

    def finalize(self) -> None:
        if not self.packet_jsonl.exists() or self.packet_jsonl.stat().st_size == 0:
            return
        if not self.gateway_dir.exists():
            raise RuntimeError(f"Gateway repo not found: {self.gateway_dir}")

        self._run_gateway("ingest", "--input", str(self.packet_jsonl.resolve()))
        self._run_gateway(
            "export",
            "--json",
            str(self.export_json.resolve()),
            "--csv",
            str(self.export_csv.resolve()),
        )
        rows = json.loads(self.export_json.read_text(encoding="utf-8"))
        self.events = {row["event_id"]: row for row in rows}

    def _run_gateway(self, *args: str) -> None:
        command = [
            sys.executable,
            "-m",
            "ignirelay_gateway.cli",
            "--db",
            str(self.db_path.resolve()),
            *args,
        ]
        subprocess.run(
            command,
            cwd=self.gateway_dir,
            check=True,
            capture_output=True,
            text=True,
        )
