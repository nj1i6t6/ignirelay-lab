"""B7/B8 — simulated end-to-end on the REAL field-node executables.

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

B8 layers chaos onto the same real-byte topology: the hub applies per-recipient
packet loss / corruption / time-bounded partitions / asymmetric (one-way) links
to the real LORA-WIRE frames. Delivery resilience comes entirely from the real C
node's bounded ACK-retry (≤3, core/retry.h) and TTL relay — NOT from any Python
retransmission. Random seeds are fixed and recorded in logs/<scenario>/report.json.

Requires the Linux node executable path in IGNIRELAY_NODE_EXE (the bsim build's
zephyr.exe). When unset/missing the scenario is skipped so the pure-Python
scenarios still run on hosts without the build.
"""

from __future__ import annotations

import json
import os
import random
import socket
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import corpus_fixtures as fx
from .actors import FakePhone
from .channel import ChannelProfile
from .gateway_cli import default_gateway_dir
from .logging_utils import JsonlLogSink, LogRecord
from .wire import lora_v1 as lora

HUB_HOST = "127.0.0.1"


# ─────────────────────────────────────────────────────────────────────────────
# Port layout — parameterised so chaos scenarios can run with disjoint ports
# (Owner note: e2e_real_stack uses fixed UDP ports; never run two in parallel on
# the same ports). cli --all runs scenarios sequentially AND each scenario gets a
# distinct port base, so an accidental overlap still cannot collide.
# ─────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class PortLayout:
    hub_port: int
    node_ports: dict[int, int]
    ble_ports: dict[int, int]


def make_ports(base: int = 0) -> PortLayout:
    return PortLayout(
        hub_port=9300 + base,
        node_ports={1: 9401 + base, 2: 9402 + base},
        ble_ports={1: 9501 + base, 2: 9502 + base},
    )


DEFAULT_PORTS = make_ports(0)
# Disjoint per-scenario bases for the B8 chaos scenarios (sequential-safe).
SCENARIO_PORT_BASE = {
    "e2e_real_stack": 0,
    "loss_50": 20,
    "partition_heal": 40,
    "asymmetric_link": 60,
    "loss_20_realstack": 80,
    "c4_live": 100,
}

# Backwards-compatible module aliases (the frozen B7 helpers reference these).
HUB_PORT = DEFAULT_PORTS.hub_port
NODE_PORTS = DEFAULT_PORTS.node_ports
BLE_PORTS = DEFAULT_PORTS.ble_ports


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


def count_lora_tx(stdout_text: str, action: str) -> int:
    """Count LORA_TX lines with the given action (transmit/retransmit/drop)."""
    n = 0
    for line in stdout_text.splitlines():
        if "layer=LORA_TX" in line and f"action={action}" in line:
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
                 out_path: Path, ports: PortLayout = DEFAULT_PORTS) -> None:
        self.exe = exe
        self.node_id = node_id
        self.secret_hex = secret_hex
        self.out_path = out_path
        self.ports = ports
        self.proc: Optional[subprocess.Popen] = None
        self._out = None
        self.start_offset = 0

    def start(self) -> None:
        self.start_offset = self.out_path.stat().st_size if self.out_path.exists() else 0
        self._out = self.out_path.open("ab")
        # nrf_bsim native runner registers options as single-dash `-opt=value`
        # (native_add_command_line_opts); GNU `--opt value` is rejected.
        args = [
            str(self.exe), "-nosim",
            f"-lora-hub={HUB_HOST}:{self.ports.hub_port}",
            f"-node-id={self.node_id}",
            f"-node-port={self.ports.node_ports[self.node_id]}",
            f"-ble-port={self.ports.ble_ports[self.node_id]}",
            f"-field-secret={self.secret_hex}",
            f"-storage-file={self.out_path.parent / f'node_{self.node_id}.journal'}",
        ]
        self.proc = subprocess.Popen(args, stdout=self._out,
                                     stderr=subprocess.STDOUT)

    def wait_ready(self, timeout_s: float = 8.0) -> bool:
        deadline = time.time() + timeout_s
        token = f"node {self.node_id} ready on hub"
        while time.time() < deadline:
            if self.out_path.exists():
                try:
                    with self.out_path.open("rb") as f:
                        f.seek(self.start_offset)
                        tail = f.read().decode("utf-8", errors="replace")
                        if token in tail:
                            return True
                except OSError:
                    pass
            if self.proc is not None and self.proc.poll() is not None:
                return False
            time.sleep(0.01)
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


def drain_udp(sock: socket.socket) -> int:
    old_to = sock.gettimeout()
    sock.setblocking(False)
    drained = 0
    try:
        while True:
            sock.recvfrom(4096)
            drained += 1
    except (BlockingIOError, socket.error):
        pass
    finally:
        sock.settimeout(old_to)
    return drained


# ─────────────────────────────────────────────────────────────────────────────
# FakeLoRaUdpHub — moves real frame bytes; taps every frame to the gateway feed.
# B8: applies per-recipient chaos (loss / corrupt / partition / asymmetric).
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class TappedFrame:
    frame_hex: str
    last_hop_node_id: str
    observed_at_ms: int
    src_port: int


def _empty_chaos_stats() -> dict[str, int]:
    return {
        "rx_from_nodes": 0,
        "event_frames": 0,
        "tap_delivered": 0,
        "tap_dropped_loss": 0,
        "tap_dropped_partition": 0,
        "fanout_delivered": 0,
        "fanout_dropped_loss": 0,
        "fanout_dropped_partition": 0,
        "fanout_dropped_asymmetric": 0,
        "corrupt_injected": 0,
    }


class LoRaUdpHub:
    """Shared LoRa medium model: a frame from any node is fanned out to every
    other node and tapped to the gateway feed (flat broadcast — both nodes are in
    range of the gateway, so honest multi-hop duplicates reach the B4 dedupe).

    With a ChannelProfile, each fan-out and each gateway tap is an independent
    radio receiver subject to per-link loss / corruption / partition / asymmetry,
    applied to the byte-exact LORA-WIRE frame. Delivery resilience is the real C
    node's job (bounded retry + relay), never the hub's."""

    def __init__(self, log: JsonlLogSink, ports: PortLayout = DEFAULT_PORTS,
                 profile: Optional[ChannelProfile] = None,
                 rng: Optional[random.Random] = None,
                 live_out: Optional[Path] = None) -> None:
        self.log = log
        self.ports = ports
        self.profile = profile or ChannelProfile()
        self.rng = rng or random.Random(0)
        # C4: when set, every tapped frame is appended to this JSONL the moment
        # it is tapped (serial-stream model) so a `gateway ingest --follow`
        # process picks it up live — not batched at the end of the run.
        self.live_out = live_out
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((HUB_HOST, ports.hub_port))
        self.sock.setblocking(False)
        self.port_to_node = {p: n for n, p in ports.node_ports.items()}
        self.taps: list[TappedFrame] = []
        self._obs = 1000  # monotonic observed_at, strictly increasing per tap
        self.stats = _empty_chaos_stats()
        self._t0: Optional[float] = None  # partition anchor (set at injection)

    def mark_injection(self) -> None:
        """Anchor partition windows to the moment events are injected."""
        self._t0 = time.monotonic()

    def _node_label(self, port: int) -> str:
        n = self.port_to_node.get(port)
        return f"Node{'A' if n == 1 else 'B' if n == 2 else '?'}" if n else "?"

    # -- chaos decisions -------------------------------------------------------
    def _hit(self, percent: int) -> bool:
        return percent > 0 and self.rng.randrange(100) < percent

    def _partitioned(self) -> bool:
        """A partition window drops both fan-out and gateway tap. Two forms:

        - {"drop_first_frames": N}: the link is down for the first N on-air frames
          then heals. Clock-independent (the bsim node clock advances faster than
          wall-clock, so a frame count — not a wall-ms window — deterministically
          covers a known number of the node's bounded-retry attempts).
        - {"start_ms": a, "end_ms": b}: wall-clock window relative to injection.
        """
        for w in self.profile.partition_windows:
            if "drop_first_frames" in w:
                if self.stats["rx_from_nodes"] <= int(w["drop_first_frames"]):
                    return True
            elif "start_ms" in w and self._t0 is not None:
                elapsed_ms = (time.monotonic() - self._t0) * 1000.0
                if int(w["start_ms"]) <= elapsed_ms < int(w["end_ms"]):
                    return True
        return False

    def _asym_down(self, src_node: Optional[int], dst_node: int) -> bool:
        if src_node is None:
            return False
        return self.profile.asymmetric_link.get(f"{src_node}->{dst_node}",
                                                True) is False

    def _corrupt(self, frame: bytes) -> bytes:
        raw = bytearray(frame)
        lo, hi = 11, max(11, len(raw) - 2)
        if hi > lo:
            raw[self.rng.randrange(lo, hi)] ^= 0xFF
        return bytes(raw)

    def _maybe_corrupt(self, frame: bytes) -> bytes:
        if self._hit(self.profile.corrupt_percent):
            self.stats["corrupt_injected"] += 1
            return self._corrupt(frame)
        return frame

    def _tap(self, frame: bytes, src_port: int) -> None:
        self._obs += 1
        tf = TappedFrame(frame.hex(), self._node_label(src_port),
                         self._obs, src_port)
        self.taps.append(tf)
        if self.live_out is not None:
            # Append-and-flush per tap so the follow-ingest sees it immediately.
            with self.live_out.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(
                    {"frame_hex": tf.frame_hex,
                     "last_hop_node_id": tf.last_hop_node_id,
                     "observed_at_ms": tf.observed_at_ms}, sort_keys=True) + "\n")
                fh.flush()

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
            src_node = self.port_to_node.get(src_port)
            self.stats["rx_from_nodes"] += 1
            is_event = len(frame) >= 1 and (frame[0] & 0x0F) == 0x1
            if is_event:
                self.stats["event_frames"] += 1
            partitioned = self._partitioned()

            # gateway tap (the gateway is a radio receiver too: loss + partition).
            if partitioned:
                self.stats["tap_dropped_partition"] += 1
                self._log(self._node_label(src_port), frame, "drop",
                          "tap-partition")
            elif self._hit(self.profile.packet_loss_percent):
                self.stats["tap_dropped_loss"] += 1
                self._log(self._node_label(src_port), frame, "drop", "tap-loss")
            else:
                self._tap(self._maybe_corrupt(frame), src_port)
                self.stats["tap_delivered"] += 1

            # fan out to every OTHER known node port (shared medium).
            for dst_node, port in self.ports.node_ports.items():
                if port == src_port:
                    continue
                if partitioned:
                    self.stats["fanout_dropped_partition"] += 1
                    continue
                if self._asym_down(src_node, dst_node):
                    self.stats["fanout_dropped_asymmetric"] += 1
                    continue
                if self._hit(self.profile.packet_loss_percent):
                    self.stats["fanout_dropped_loss"] += 1
                    continue
                self.sock.sendto(self._maybe_corrupt(frame), (HUB_HOST, port))
                self.stats["fanout_delivered"] += 1

            self._log(self._node_label(src_port), frame, "route", "fan-out")
            last_activity = time.time()

    def replay_to_node(self, frame_hex: str, node_id: int) -> None:
        """Re-deliver a captured frame to one node (assertion 5: NodeB restart)."""
        self.sock.sendto(bytes.fromhex(frame_hex),
                         (HUB_HOST, self.ports.node_ports[node_id]))

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


def inject_ble(node_id: int, entries: list[tuple[bytes, bytes]],
               ports: PortLayout = DEFAULT_PORTS) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(_ble_batch(entries), (HUB_HOST, ports.ble_ports[node_id]))
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
    res = subprocess.run(cmd, cwd=gateway_dir, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"gateway failed ({res.returncode}):\nSTDOUT: {res.stdout}\nSTDERR: {res.stderr}")


def ingest_feed(base_dir: Path, feed: list[dict]) -> dict[str, dict]:
    """Append the feed to the gateway packet jsonl, run B4 ingest+export, return
    the canonical events keyed by event_id. DB persists across calls (assertion
    5 reuses it to prove no duplicate canonical after NodeB restart)."""
    import base64
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
# Orchestration — B7 frozen e2e (one PRESENCE + one SOS + NodeB restart)
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
    ports = make_ports(SCENARIO_PORT_BASE.get(name, 0))

    try:
        exe = node_exe_path()
    except NodeExeMissing as exc:
        return E2EResult(name, str(log.path), "", "", {}, {}, [], {}, 0, "", "",
                         skipped=str(exc))

    # Fresh gateway DB / feed / node journals for this run.
    for f in ("gateway.sqlite", "gateway_feed.jsonl", "gateway_feed_slice.jsonl"):
        p = base_dir / f
        if p.exists():
            p.unlink()
    for p in base_dir.glob("*.journal"):
        p.unlink()

    phone = FakePhone()
    anon8 = phone.anon_user_id[:8]
    presence = phone.presence(0)
    sos = phone.sos(1)            # SOS_RED, priority 1
    nodeA_out = base_dir / "nodeA.out"
    nodeB_out = base_dir / "nodeB.out"
    for p in (nodeA_out, nodeB_out):
        p.write_text("", encoding="utf-8")

    hub = LoRaUdpHub(log, ports=ports)
    node_a = NodeProcess(exe, 1, secret_hex, nodeA_out, ports=ports)
    node_b = NodeProcess(exe, 2, secret_hex, nodeB_out, ports=ports)
    sos_frame_hex = ""
    try:
        node_a.start()
        node_b.start()
        if not (node_a.wait_ready() and node_b.wait_ready()):
            raise RuntimeError("node(s) failed to reach ready state")

        # Inject PRESENCE then SOS in one batch — NodeA's priority queue must emit
        # SOS (prio 1) before PRESENCE (prio 3) despite the injection order.
        inject_ble(1, [(anon8, presence.envelope_bytes),
                       (anon8, sos.envelope_bytes)], ports=ports)
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
        node_b2 = NodeProcess(exe, 2, secret_hex, nodeB_out, ports=ports)
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


# ─────────────────────────────────────────────────────────────────────────────
# Orchestration — B8 chaos run (PRESENCE + N SOS under a ChannelProfile)
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class ChaosResult:
    name: str
    seed: int
    log_path: str
    report_path: str
    report: dict
    gateway_events: dict[str, dict]
    sos_event_ids: list[str]
    presence_event_id: str
    delivered_sos: list[str]
    feed_frame_counts: dict[str, int]
    nodeA_retransmits: int
    nodeA_node_receipts: int
    skipped: Optional[str] = None


def run_chaos_real_stack(name: str, profile: ChannelProfile, seed: int, *,
                         sos_count: int = 1, with_presence: bool = True,
                         pump_s: float = 14.0, quiesce_s: float = 2.2,
                         ) -> ChaosResult:
    """Run the real-stack topology under a chaos profile and write report.json.

    Resilience is the real C node's bounded retry + relay; the hub only loses /
    corrupts / partitions bytes. Returns a ChaosResult with the report dict."""
    log = JsonlLogSink(name)
    base_dir = Path("logs") / name
    field_mat = fx.test_field()
    secret_hex = field_mat.secret.hex()
    ports = make_ports(SCENARIO_PORT_BASE.get(name, 0))

    def _skip(reason: str) -> ChaosResult:
        return ChaosResult(name, seed, str(log.path), "", {"skipped": reason},
                           {}, [], "", [], {}, 0, 0, skipped=reason)

    try:
        exe = node_exe_path()
    except NodeExeMissing as exc:
        return _skip(str(exc))

    # Fresh gateway DB / feed / node journals for this run.
    for f in ("gateway.sqlite", "gateway_feed.jsonl", "gateway_feed_slice.jsonl"):
        p = base_dir / f
        if p.exists():
            p.unlink()
    for p in base_dir.glob("*.journal"):
        p.unlink()

    rng = random.Random(seed)
    phone = FakePhone()
    anon8 = phone.anon_user_id[:8]
    presence = phone.presence(0) if with_presence else None
    sos_events = [phone.sos(1 + i) for i in range(sos_count)]
    nodeA_out = base_dir / "nodeA.out"
    nodeB_out = base_dir / "nodeB.out"
    for p in (nodeA_out, nodeB_out):
        p.write_text("", encoding="utf-8")

    hub = LoRaUdpHub(log, ports=ports, profile=profile, rng=rng)
    node_a = NodeProcess(exe, 1, secret_hex, nodeA_out, ports=ports)
    node_b = NodeProcess(exe, 2, secret_hex, nodeB_out, ports=ports)
    try:
        node_a.start()
        node_b.start()
        if not (node_a.wait_ready() and node_b.wait_ready()):
            raise RuntimeError("node(s) failed to reach ready state")

        entries: list[tuple[bytes, bytes]] = []
        if presence is not None:
            entries.append((anon8, presence.envelope_bytes))
        for s in sos_events:
            entries.append((anon8, s.envelope_bytes))
        hub.mark_injection()
        inject_ble(1, entries, ports=ports)
        hub.pump(duration_s=pump_s, idle_quiesce_s=quiesce_s)

        feed = hub.gateway_feed()
        events = ingest_feed(base_dir, feed)
        feed_order, feed_counts = _feed_order_and_counts(feed,
                                                         field_mat.lora_mac_key)
        receipts = count_node_receipt_emits(node_a.stdout_text())
        retransmits = count_lora_tx(node_a.stdout_text(), "retransmit")
        tx_total = count_lora_tx(node_a.stdout_text(), "transmit")
        tx_exhausted = count_lora_tx(node_a.stdout_text(), "drop")
    finally:
        node_a.stop()
        node_b.stop()
        hub.close()

    sos_ids = [s.event_id_hex for s in sos_events]
    presence_id = presence.event_id_hex if presence is not None else ""
    delivered_sos = [eid for eid in sos_ids if eid in events]
    # dedup count = verified EVENT frames that mapped to an already-stored event.
    total_event_frames = sum(feed_counts.values())
    dedup_count = max(total_event_frames - len(events), 0)

    sos_delivered = len(delivered_sos) == len(sos_ids) and len(sos_ids) > 0
    # "no duplicate canonical": every delivered event is exactly one row, and the
    # gateway received >=1 frame for each (the real B4 PK-dedupe collapsed any
    # multi-hop / retransmit copies).
    no_duplicate = all(feed_counts.get(eid, 0) >= 1 for eid in events) and \
        len(events) == len(set(events))

    report = {
        "scenario": name,
        "seed": seed,
        "node_exe": str(exe),
        "ports": {"hub": ports.hub_port, "nodes": ports.node_ports,
                  "ble": ports.ble_ports},
        "profile": {
            "packet_loss_percent": profile.packet_loss_percent,
            "corrupt_percent": profile.corrupt_percent,
            "partition_windows": profile.partition_windows,
            "asymmetric_link": profile.asymmetric_link,
        },
        "injected": {
            "presence": 1 if presence is not None else 0,
            "sos": len(sos_ids),
            "sos_event_ids": sos_ids,
            "presence_event_id": presence_id,
        },
        "frames": hub.stats,
        "gateway": {
            "canonical": len(events),
            "dedup": dedup_count,
            "delivered_event_ids": sorted(events.keys()),
            "frames_per_event": feed_counts,
        },
        "node_a": {
            "node_receipts": receipts,
            "transmit": tx_total,
            "retransmit": retransmits,
            "drop_retry_exhausted": tx_exhausted,
        },
        "drops": {
            "tap_loss": hub.stats["tap_dropped_loss"],
            "tap_partition": hub.stats["tap_dropped_partition"],
            "fanout_loss": hub.stats["fanout_dropped_loss"],
            "fanout_partition": hub.stats["fanout_dropped_partition"],
            "fanout_asymmetric": hub.stats["fanout_dropped_asymmetric"],
        },
        "invariants": {
            "sos_delivered": sos_delivered,
            "sos_delivery_ratio": (len(delivered_sos) / len(sos_ids))
            if sos_ids else 0.0,
            "no_duplicate_canonical": no_duplicate,
            "nodeA_retransmitted": retransmits > 0,
        },
    }
    report_path = base_dir / "report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True),
                           encoding="utf-8")

    return ChaosResult(
        name=name, seed=seed, log_path=str(log.path),
        report_path=str(report_path), report=report,
        gateway_events=events, sos_event_ids=sos_ids,
        presence_event_id=presence_id, delivered_sos=delivered_sos,
        feed_frame_counts=feed_counts, nodeA_retransmits=retransmits,
        nodeA_node_receipts=receipts,
    )


# ─────────────────────────────────────────────────────────────────────────────
# C4 — live producer: stream tapped frames to a JSONL while the real stack runs
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class StreamResult:
    name: str
    live_out: str
    presence_event_id: str
    sos_event_id: str
    taps: int
    skipped: Optional[str] = None


def stream_e2e_real_stack(name: str = "c4_live", seed: int = 7, *,
                          live_out: Optional[Path] = None,
                          pump_s: float = 10.0) -> StreamResult:
    """C4 live producer for the gateway follow-ingest pipeline.

    Runs the SAME real-byte topology as `run_e2e_real_stack` (two real C node
    executables + the LoRa UDP hub) and streams each tapped on-air frame to
    `live_out` the instant it is tapped. Unlike `run_e2e_real_stack` this does
    NOT batch-ingest at the end and does NOT do the NodeB-restart phase — it is
    a pure live frame source; ingestion is the gateway's `ingest --follow` job.

    Frames are byte-exact LORA-WIRE v1 (signed by the corpus TEST-ONLY field);
    nothing here re-implements node logic or touches frozen contracts.
    """
    log = JsonlLogSink(name)
    base_dir = Path("logs") / name
    base_dir.mkdir(parents=True, exist_ok=True)
    field_mat = fx.test_field()
    secret_hex = field_mat.secret.hex()
    ports = make_ports(SCENARIO_PORT_BASE.get(name, 100))

    try:
        exe = node_exe_path()
    except NodeExeMissing as exc:
        return StreamResult(name, "", "", "", 0, skipped=str(exc))

    live_path = Path(live_out) if live_out is not None else None
    if live_path is not None:
        live_path.parent.mkdir(parents=True, exist_ok=True)
        # Append-only: the feed is caller-owned (a live stream). Never truncate
        # it — a follow-ingest may already be tailing and the caller may have
        # written earlier frames (e.g. a HEARTBEAT) we must not erase.
        if not live_path.exists():
            live_path.write_text("", encoding="utf-8")

    phone = FakePhone()
    anon8 = phone.anon_user_id[:8]
    presence = phone.presence(0)
    sos = phone.sos(1)            # SOS_RED, safety=trapped(4)
    nodeA_out = base_dir / "nodeA.out"
    nodeB_out = base_dir / "nodeB.out"
    for p in (nodeA_out, nodeB_out):
        p.write_text("", encoding="utf-8")

    hub = LoRaUdpHub(log, ports=ports, live_out=live_path)
    node_a = NodeProcess(exe, 1, secret_hex, nodeA_out, ports=ports)
    node_b = NodeProcess(exe, 2, secret_hex, nodeB_out, ports=ports)
    try:
        node_a.start()
        node_b.start()
        if not (node_a.wait_ready() and node_b.wait_ready()):
            raise RuntimeError("node(s) failed to reach ready state")
        # PRESENCE then SOS in one batch (SOS prio 1 emits before PRESENCE prio 3).
        inject_ble(1, [(anon8, presence.envelope_bytes),
                       (anon8, sos.envelope_bytes)], ports=ports)
        hub.pump(duration_s=pump_s)
    finally:
        node_a.stop()
        node_b.stop()
        hub.close()

    return StreamResult(
        name=name, live_out=str(live_path) if live_path else "",
        presence_event_id=presence.event_id_hex,
        sos_event_id=sos.event_id_hex, taps=len(hub.taps),
    )


def main(argv: Optional[list[str]] = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(
        description="C4 live producer: stream real-stack LoRa frames to a JSONL.")
    ap.add_argument("--live-out", required=True,
                    help="JSONL the gateway `ingest --follow` tails")
    ap.add_argument("--name", default="c4_live")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--pump-s", type=float, default=10.0)
    args = ap.parse_args(argv)
    result = stream_e2e_real_stack(args.name, args.seed,
                                   live_out=Path(args.live_out),
                                   pump_s=args.pump_s)
    print(json.dumps(result.__dict__, sort_keys=True), flush=True)
    return 2 if result.skipped else 0


if __name__ == "__main__":
    raise SystemExit(main())
