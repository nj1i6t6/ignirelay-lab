"""B7 — simulated end-to-end on the REAL field-node executables.

Topology (MASTER §6 B7):

    FakePhone --BLE(UDP)--> NodeA(real C exe) --LoRa(UDP hub)--> NodeB(real C exe)
                                                                       |
                                                          FakeLoRaUdpHub taps every
                                                          on-air frame --> Gateway(B4)

Nothing in this module re-implements node logic: the two nodes are the B6
`zephyr.exe` (native/bsim) spawned as subprocesses. The phone signs real
EventEnvelopeV2 v3 bytes (corpus TEST-ONLY key) and injects them over a UDP side
channel that models the App->Node BLE first hop. The hub moves byte-exact
LORA-WIRE frames between node sockets and taps each frame to the B4 gateway,
which re-verifies and de-duplicates by canonical event_id.

Requires the Linux node executable path in IGNIRELAY_NODE_EXE (the bsim build's
zephyr.exe). When unset/missing the scenario is skipped so the pure-Python
scenarios still run on hosts without the build.
"""

from __future__ import annotations

import os
import socket
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import corpus_fixtures as fx
from .actors import FakePhone
from .gateway_cli import default_gateway_dir
from .logging_utils import JsonlLogSink, LogRecord
from .wire import lora_v1 as lora

HUB_HOST = "127.0.0.1"
HUB_PORT = 9300
# Deterministic per-node ports (so the hub can address a node before it speaks).
NODE_PORTS = {1: 9401, 2: 9402}
BLE_PORTS = {1: 9501, 2: 9502}


class NodeExeMissing(RuntimeError):
    pass


def count_node_receipt_emits(stdout_text: str) -> int:
    """Count NODE_RECEIPT emit records in a node's structured stdout.

    The node logs key=value fields with other fields between `layer=` and
    `action=` (event_id/packet_seq/src/dst/...), so we match per-line on both
    tokens rather than an adjacent substring.
    """
    n = 0
    for line in stdout_text.splitlines():
        if "layer=NODE_RECEIPT" in line and "action=emit" in line:
            n += 1
    return n


def node_exe_path() -> Path:
    """Resolve the B6 node executable (Linux native/bsim zephyr.exe)."""
    env = os.environ.get("IGNIRELAY_NODE_EXE")
    if env:
        p = Path(env)
        if p.is_file():
            return p
        raise NodeExeMissing(f"IGNIRELAY_NODE_EXE not a file: {p}")
    build = os.environ.get("IGNIRELAY_FIELD_NODE_BUILD")
    if build:
        hits = sorted(Path(build).glob("**/zephyr/zephyr.exe"))
        if hits:
            return hits[0]
    raise NodeExeMissing(
        "set IGNIRELAY_NODE_EXE to the field-node bsim zephyr.exe "
        "(or IGNIRELAY_FIELD_NODE_BUILD to its build dir)"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Node subprocess
# ─────────────────────────────────────────────────────────────────────────────
class NodeProcess:
    def __init__(self, exe: Path, node_id: int, secret_hex: str,
                 out_path: Path) -> None:
        self.exe = exe
        self.node_id = node_id
        self.secret_hex = secret_hex
        self.out_path = out_path
        self.proc: Optional[subprocess.Popen] = None
        self._out = None

    def start(self) -> None:
        self._out = self.out_path.open("ab")
        # nrf_bsim native runner registers options as single-dash `-opt=value`
        # (native_add_command_line_opts); GNU `--opt value` is rejected.
        args = [
            str(self.exe), "-nosim",
            f"-lora-hub={HUB_HOST}:{HUB_PORT}",
            f"-node-id={self.node_id}",
            f"-node-port={NODE_PORTS[self.node_id]}",
            f"-ble-port={BLE_PORTS[self.node_id]}",
            f"-field-secret={self.secret_hex}",
        ]
        self.proc = subprocess.Popen(args, stdout=self._out,
                                     stderr=subprocess.STDOUT)

    def wait_ready(self, timeout_s: float = 8.0) -> bool:
        deadline = time.time() + timeout_s
        token = f"node {self.node_id} ready on hub"
        while time.time() < deadline:
            if self.out_path.exists() and token in self.out_path.read_text(
                    encoding="utf-8", errors="replace"):
                return True
            if self.proc is not None and self.proc.poll() is not None:
                return False
            time.sleep(0.05)
        return False

    def stop(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=3)
        if self._out is not None:
            self._out.close()
            self._out = None

    def stdout_text(self) -> str:
        return self.out_path.read_text(encoding="utf-8", errors="replace")


# ─────────────────────────────────────────────────────────────────────────────
# FakeLoRaUdpHub — moves real frame bytes; taps every frame to the gateway feed
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class TappedFrame:
    frame_hex: str
    last_hop_node_id: str
    observed_at_ms: int
    src_port: int


class LoRaUdpHub:
    """Shared LoRa medium model: a frame from any node is fanned out to every
    other node and tapped to the gateway feed (flat broadcast — both nodes are in
    range of the gateway, so honest multi-hop duplicates reach the B4 dedupe)."""

    def __init__(self, log: JsonlLogSink) -> None:
        self.log = log
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((HUB_HOST, HUB_PORT))
        self.sock.setblocking(False)
        self.port_to_node = {NODE_PORTS[n]: n for n in NODE_PORTS}
        self.taps: list[TappedFrame] = []
        self._obs = 1000  # monotonic observed_at, strictly increasing per tap

    def _node_label(self, port: int) -> str:
        n = self.port_to_node.get(port)
        return f"Node{'A' if n == 1 else 'B' if n == 2 else '?'}" if n else "?"

    def _tap(self, frame: bytes, src_port: int) -> None:
        self._obs += 1
        self.taps.append(TappedFrame(frame.hex(), self._node_label(src_port),
                                     self._obs, src_port))

    def pump(self, duration_s: float, idle_quiesce_s: float = 0.4) -> None:
        """Route + tap frames until the medium is idle for idle_quiesce_s."""
        end = time.time() + duration_s
        last_activity = time.time()
        while time.time() < end:
            try:
                frame, addr = self.sock.recvfrom(4096)
            except BlockingIOError:
                if time.time() - last_activity > idle_quiesce_s:
                    return
                time.sleep(0.01)
                continue
            src_port = addr[1]
            self._tap(frame, src_port)
            # Fan out to every OTHER known node port (shared medium).
            for port in NODE_PORTS.values():
                if port != src_port:
                    self.sock.sendto(frame, (HUB_HOST, port))
            self._log(self._node_label(src_port), frame, "route", "fan-out")
            last_activity = time.time()

    def replay_to_node(self, frame_hex: str, node_id: int) -> None:
        """Re-deliver a captured frame to one node (assertion 5: NodeB restart)."""
        self.sock.sendto(bytes.fromhex(frame_hex), (HUB_HOST, NODE_PORTS[node_id]))

    def gateway_feed(self) -> list[dict]:
        return [{"frame_hex": t.frame_hex, "last_hop_node_id": t.last_hop_node_id,
                 "observed_at_ms": t.observed_at_ms} for t in self.taps]

    def close(self) -> None:
        self.sock.close()

    def _log(self, src: str, frame: bytes, action: str, reason: str) -> None:
        self.log.write(LogRecord(
            timestamp_ms=0, node_id="LoRaUdpHub", layer="HUB",
            event_id="", packet_seq=0, src=src, dst="medium",
            priority="-", ttl=0, action=action, reason=reason,
        ))


# ─────────────────────────────────────────────────────────────────────────────
# Phone BLE injection (App -> NodeA side channel)
# ─────────────────────────────────────────────────────────────────────────────
def _ble_batch(entries: list[tuple[bytes, bytes]]) -> bytes:
    """Pack [anon8(8) | len u16 LE | envelope]* into one datagram."""
    out = bytearray()
    for anon8, env in entries:
        out += anon8[:8].ljust(8, b"\x00")
        out += bytes([len(env) & 0xFF, (len(env) >> 8) & 0xFF])
        out += env
    return bytes(out)


def inject_ble(node_id: int, entries: list[tuple[bytes, bytes]]) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(_ble_batch(entries), (HUB_HOST, BLE_PORTS[node_id]))
    finally:
        sock.close()


# ─────────────────────────────────────────────────────────────────────────────
# Gateway (B4) ingest of the tapped feed
# ─────────────────────────────────────────────────────────────────────────────
def _run_gateway(gateway_dir: Path, db_path: Path, config_path: Path,
                 *args: str) -> None:
    import sys
    cmd = [sys.executable, "-m", "ignirelay_gateway.cli",
           "--db", str(db_path.resolve()),
           "--config", str(config_path.resolve()), *args]
    subprocess.run(cmd, cwd=gateway_dir, check=True, capture_output=True,
                   text=True)


def ingest_feed(base_dir: Path, feed: list[dict]) -> dict[str, dict]:
    """Append the feed to the gateway packet jsonl, run B4 ingest+export, return
    the canonical events keyed by event_id. DB persists across calls (assertion
    5 reuses it to prove no duplicate canonical after NodeB restart)."""
    import base64
    import json
    gateway_dir = default_gateway_dir()
    if not gateway_dir.exists():
        raise RuntimeError(f"gateway repo not found: {gateway_dir}")
    feed_path = base_dir / "gateway_feed.jsonl"
    db_path = base_dir / "gateway.sqlite"
    cfg_path = base_dir / "gateway_config.test.json"
    export_json = base_dir / "gateway_events.json"

    with feed_path.open("a", encoding="utf-8") as fh:
        for rec in feed:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")
    cfg_path.write_text(json.dumps({
        "field_secrets_b64": [base64.b64encode(fx.test_field().secret).decode()],
        "admin_token": "TEST-ONLY-LAB-NOT-A-REAL-TOKEN",
        "db_path": str(db_path.resolve()),
    }, indent=2), encoding="utf-8")

    # Re-ingest only the new feed slice each call: write a slice file.
    slice_path = base_dir / "gateway_feed_slice.jsonl"
    slice_path.write_text(
        "".join(json.dumps(r, sort_keys=True) + "\n" for r in feed),
        encoding="utf-8")
    _run_gateway(gateway_dir, db_path, cfg_path, "ingest", "--input",
                 str(slice_path.resolve()))
    _run_gateway(gateway_dir, db_path, cfg_path, "export", "--json",
                 str(export_json.resolve()), "--csv",
                 str((base_dir / "gateway_events.csv").resolve()))
    rows = json.loads(export_json.read_text(encoding="utf-8"))
    return {row["event_id"]: row for row in rows}


# ─────────────────────────────────────────────────────────────────────────────
# Orchestration
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class E2EResult:
    name: str
    log_path: str
    presence_event_id: str
    sos_event_id: str
    gateway_events: dict[str, dict]
    gateway_events_after_restart: dict[str, dict]
    feed_event_order: list[str]          # event_id first-seen order in gateway feed
    feed_frame_counts: dict[str, int]    # event_id -> EVENT frames tapped (pre-dedupe)
    nodeA_node_receipts: int
    nodeA_out_path: str
    sos_frame_hex: str
    skipped: Optional[str] = None
    # convenience for the cli GATE-SCEN adapter
    delivered_event_ids: list[str] = field(default_factory=list)
    accepted_event_ids: list[str] = field(default_factory=list)


def _feed_order_and_counts(feed: list[dict],
                           lora_mac_key: bytes) -> tuple[list[str], dict[str, int]]:
    """First-seen order + per-event frame count across the tapped EVENT frames
    (the order/multiplicity in which they reached the gateway, pre-dedupe)."""
    order: list[str] = []
    counts: dict[str, int] = {}
    for rec in feed:
        res = lora.verify_lora_frame(bytes.fromhex(rec["frame_hex"]),
                                     lora_mac_key=lora_mac_key, local_est_ms=None,
                                     seen_event_ids=None)
        if res.reason is not None or res.parsed is None:
            continue
        if res.parsed.ptype != lora.PTYPE_EVENT:
            continue
        eid = res.parsed.event_id.hex()
        counts[eid] = counts.get(eid, 0) + 1
        if eid not in order:
            order.append(eid)
    return order, counts


def run_e2e_real_stack(name: str = "e2e_real_stack",
                       seed: int = 7) -> E2EResult:
    log = JsonlLogSink(name)
    base_dir = Path("logs") / name
    field_mat = fx.test_field()
    secret_hex = field_mat.secret.hex()

    try:
        exe = node_exe_path()
    except NodeExeMissing as exc:
        return E2EResult(name, str(log.path), "", "", {}, {}, [], {}, 0, "", "",
                         skipped=str(exc))

    # Fresh gateway DB / feed for this run.
    for f in ("gateway.sqlite", "gateway_feed.jsonl", "gateway_feed_slice.jsonl"):
        p = base_dir / f
        if p.exists():
            p.unlink()

    phone = FakePhone()
    anon8 = phone.anon_user_id[:8]
    presence = phone.presence(0)
    sos = phone.sos(1)            # SOS_RED, priority 1
    nodeA_out = base_dir / "nodeA.out"
    nodeB_out = base_dir / "nodeB.out"
    for p in (nodeA_out, nodeB_out):
        p.write_text("", encoding="utf-8")

    hub = LoRaUdpHub(log)
    node_a = NodeProcess(exe, 1, secret_hex, nodeA_out)
    node_b = NodeProcess(exe, 2, secret_hex, nodeB_out)
    sos_frame_hex = ""
    try:
        node_a.start()
        node_b.start()
        if not (node_a.wait_ready() and node_b.wait_ready()):
            raise RuntimeError("node(s) failed to reach ready state")

        # Inject PRESENCE then SOS in one batch — NodeA's priority queue must emit
        # SOS (prio 1) before PRESENCE (prio 3) despite the injection order.
        inject_ble(1, [(anon8, presence.envelope_bytes),
                       (anon8, sos.envelope_bytes)])
        hub.pump(duration_s=6.0)

        feed = hub.gateway_feed()
        sos_frame_hex = next(
            (t.frame_hex for t in hub.taps
             if _frame_event_id(t.frame_hex, field_mat.lora_mac_key)
             == sos.event_id_hex and t.last_hop_node_id == "NodeA"), "")
        events = ingest_feed(base_dir, feed)
        feed_order, feed_counts = _feed_order_and_counts(feed,
                                                         field_mat.lora_mac_key)
        receipts = count_node_receipt_emits(node_a.stdout_text())

        # ── assertion 5: kill NodeB, restart fresh, replay NodeA's SOS frame ──
        node_b.stop()
        node_b2 = NodeProcess(exe, 2, secret_hex, nodeB_out)
        node_b2.start()
        if not node_b2.wait_ready():
            raise RuntimeError("NodeB failed to restart")
        before = len(hub.taps)
        if sos_frame_hex:
            hub.replay_to_node(sos_frame_hex, 2)
        hub.pump(duration_s=4.0)
        new_feed = hub.gateway_feed()[before:]
        events_after = ingest_feed(base_dir, new_feed) if new_feed else events
        node_b2.stop()
    finally:
        node_a.stop()
        node_b.stop()
        hub.close()

    return E2EResult(
        name=name, log_path=str(log.path),
        presence_event_id=presence.event_id_hex,
        sos_event_id=sos.event_id_hex,
        gateway_events=events, gateway_events_after_restart=events_after,
        feed_event_order=feed_order, feed_frame_counts=feed_counts,
        nodeA_node_receipts=receipts,
        nodeA_out_path=str(nodeA_out), sos_frame_hex=sos_frame_hex,
        delivered_event_ids=sorted(events.keys()),
        accepted_event_ids=sorted(events.keys()),
    )


def _frame_event_id(frame_hex: str, lora_mac_key: bytes) -> str:
    res = lora.verify_lora_frame(bytes.fromhex(frame_hex),
                                 lora_mac_key=lora_mac_key, local_est_ms=None,
                                 seen_event_ids=None)
    if res.reason is not None or res.parsed is None:
        return ""
    return res.parsed.event_id.hex()
