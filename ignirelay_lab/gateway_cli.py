from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from . import corpus_fixtures as fx
from .logging_utils import JsonlLogSink, LogRecord
from .model import GatewayInbound


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
        self.config_json = self.base_dir / "gateway_config.test.json"
        self.events: dict[str, dict[str, Any]] = {}
        self.routes: list[GatewayInbound] = []
        self.packet_jsonl.write_text("", encoding="utf-8")
        if reset:
            for path in (self.db_path, self.export_json, self.export_csv):
                if path.exists():
                    path.unlink()

    @staticmethod
    def _to_record(inbound: GatewayInbound, now_ms: int) -> dict[str, Any]:
        # B4 E2E: hand the gateway the byte-exact on-air LoRa frame so it
        # re-verifies (mac8/crc16/ttl) the real bytes itself. `local_est_ms` is
        # intentionally omitted (bootstrap/un-synced gateway → §8 skips the HLC
        # window; the frames are honest and within budget anyway).
        return {
            "frame_hex": inbound.raw_frame.hex(),
            "last_hop_node_id": inbound.last_hop_label,
            "observed_at_ms": now_ms,
        }

    def _write_test_config(self) -> Path:
        """Write a TEST-ONLY gateway config so the sibling gateway can verify the
        field HMAC. The secret is the corpus TEST-ONLY field_join_secret (same one
        the frames are signed with); the file lives under the gitignored logs/
        dir and is NOT a production credential."""
        secret_b64 = base64.b64encode(fx.test_field().secret).decode()
        self.config_json.write_text(json.dumps({
            "field_secrets_b64": [secret_b64],
            "admin_token": "TEST-ONLY-LAB-NOT-A-REAL-TOKEN",
            "db_path": str(self.db_path.resolve()),
        }, indent=2), encoding="utf-8")
        return self.config_json

    def receive(self, now_ms: int, inbound: GatewayInbound) -> None:
        self.routes.append(inbound)
        with self.packet_jsonl.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(self._to_record(inbound, now_ms), sort_keys=True) + "\n")
        self.log.write(LogRecord(
            timestamp_ms=now_ms,
            node_id="GatewayCliSink",
            layer="GATEWAY_CLI",
            event_id=inbound.event_id_hex,
            packet_seq=inbound.packet_seq,
            src=inbound.last_hop_label,
            dst="Gateway",
            priority=inbound.priority_label,
            ttl=inbound.ttl,
            action="queue_cli_ingest",
            reason="gateway-cli-integration",
        ))

    def finalize(self) -> None:
        if not self.packet_jsonl.exists() or self.packet_jsonl.stat().st_size == 0:
            return
        if not self.gateway_dir.exists():
            raise RuntimeError(f"Gateway repo not found: {self.gateway_dir}")

        config = self._write_test_config()
        self._run_gateway("ingest", "--input", str(self.packet_jsonl.resolve()),
                          config=config)
        self._run_gateway(
            "export",
            "--json",
            str(self.export_json.resolve()),
            "--csv",
            str(self.export_csv.resolve()),
        )
        rows = json.loads(self.export_json.read_text(encoding="utf-8"))
        self.events = {row["event_id"]: row for row in rows}

    def _run_gateway(self, *args: str, config: Path | None = None) -> None:
        command = [
            sys.executable,
            "-m",
            "ignirelay_gateway.cli",
            "--db",
            str(self.db_path.resolve()),
        ]
        if config is not None:
            command += ["--config", str(config.resolve())]
        command += list(args)
        subprocess.run(
            command,
            cwd=self.gateway_dir,
            check=True,
            capture_output=True,
            text=True,
        )
