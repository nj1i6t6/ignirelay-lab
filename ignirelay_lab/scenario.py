"""Lab scenarios (B3) — every scenario runs on REAL EventEnvelope + LORA-WIRE bytes.

The phone signs real v3 envelopes (corpus TEST-ONLY key); the node verifies
signature + field_mac at BLE ingest, translates to a §5 compact LoRa payload,
and emits real LORA-WIRE frames on the FakeLoRaChannel; the receiving node runs
the full §8 pipeline before the Gateway sink stores a single canonical row.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field, replace

from . import corpus_fixtures as fx
from .actors import (
    RECEIPT_ACCEPTED,
    FakeBleLink,
    FakeGatewaySink,
    FakePhone,
    GatewaySink,
    SimNode,
)
from .channel import ChannelProfile, FakeLoRaChannel
from .gateway_cli import GatewayCliSink
from .logging_utils import JsonlLogSink
from .model import LoraFrame, WirePriority
from .wire import lora_v1 as lora

MAIN_SOS_SCENARIOS = {"normal", "loss_20", "busy_sos", "gateway_cli"}


@dataclass
class ScenarioResult:
    name: str
    delivered_event_ids: list[str]
    log_path: str
    gateway_mode: str = "fake"
    sos_event_id: str | None = None
    accepted_event_ids: list[str] = field(default_factory=list)
    # e2e_real_stack (B7) extras — JSON-scalar so the cli can dump the result.
    presence_event_id: str | None = None
    e2e_sos_before_presence: bool | None = None
    e2e_no_dup_after_restart: bool | None = None
    e2e_nodeA_receipts: int | None = None
    e2e_skipped: str | None = None
    # chaos (B8) extras — real-stack run under a ChannelProfile.
    chaos_report_path: str | None = None
    chaos_sos_delivered: bool | None = None
    chaos_no_dup: bool | None = None
    chaos_retransmitted: bool | None = None
    chaos_sos_ratio: float | None = None
    chaos_skipped: str | None = None


CHAOS_SCENARIOS = {"loss_50", "partition_heal", "asymmetric_link"}


def _node_rng(seed: int, node_num: int) -> random.Random:
    return random.Random(seed * 1000 + node_num)


def run_scenario(
    name: str,
    profile: ChannelProfile,
    seed: int = 7,
    gateway_mode: str = "fake",
) -> ScenarioResult:
    log = JsonlLogSink(name)
    rng = random.Random(seed)
    field_mat = fx.test_field()
    channel = FakeLoRaChannel(profile, log, rng)
    phone = FakePhone()
    ble = FakeBleLink()
    node_a = SimNode("NodeA", log, node_num=1, field=field_mat,
                     rng=_node_rng(seed, 1))
    node_b = SimNode("NodeB", log, node_num=2, field=field_mat,
                     rng=_node_rng(seed, 2))
    gateway = _make_gateway(name, log, gateway_mode)

    if name == "e2e_real_stack":
        return _run_e2e_real_stack(name, seed)
    if name in CHAOS_SCENARIOS:
        return _run_chaos(name, profile, seed)
    if name == "node_reboot":
        return _run_node_reboot(name, log, phone, ble, node_a, node_b, gateway)
    if name == "gateway_reboot":
        return _run_gateway_reboot(name, log, phone, ble, node_a, node_b)
    if name == "duplicate_storm_10_nodes":
        return _run_duplicate_storm(name, log, phone, ble, node_a, node_b,
                                    gateway, field_mat)
    if name == "replayed_valid_packet":
        return _run_replayed_valid(name, log, phone, ble, node_a, node_b, gateway)
    if name == "expired_event":
        return _run_expired_event(name, log, phone, ble, node_a, gateway)

    # ── main store-and-forward flow: phone → NodeA (BLE) → LoRa → NodeB → GW ──
    events = [phone.presence(0)]
    if name in MAIN_SOS_SCENARIOS:
        events.append(phone.sos(1))
    sos_id = next((e.event_id_hex for e in events
                   if e.priority == WirePriority.SOS_RED), None)

    accepted: list[str] = []
    for e in events:
        receipt = ble.send_envelope(node_a, 1, e.envelope_bytes)
        if receipt.status == RECEIPT_ACCEPTED:
            accepted.append(e.event_id_hex)

    for step in range(160):
        now_ms = step * 100
        node_a.transmit_next(now_ms, channel, "NodeB")
        for frame in channel.drain_ready(now_ms):
            inbound = node_b.receive_lora(now_ms, frame, hlc_now_ms=now_ms)
            if inbound is not None:
                gateway.receive(now_ms, inbound)
        if len(gateway.events) >= len(accepted):
            break

    gateway.finalize()
    return _result(name, log, gateway, gateway_mode, sos_id, accepted)


def _make_gateway(name: str, log: JsonlLogSink, gateway_mode: str) -> GatewaySink:
    if gateway_mode == "cli":
        return GatewayCliSink(name, log)
    if gateway_mode == "fake":
        return FakeGatewaySink(log)
    raise ValueError(f"unknown gateway mode: {gateway_mode}")


def _ingest_one_sos(phone: FakePhone, ble: FakeBleLink, node: SimNode,
                    now_ms: int = 0):
    sos = phone.sos(now_ms)
    ble.send_envelope(node, now_ms, sos.envelope_bytes)
    event = node.queue[0]
    node.packet_seq += 1
    frame = node.build_frame(event, "NodeB")
    return sos, frame


def _run_node_reboot(name, log, phone, ble, node_a, node_b, gateway):
    sos, frame = _ingest_one_sos(phone, ble, node_a)
    inbound = node_b.receive_lora(100, frame, hlc_now_ms=100)
    if inbound is not None:
        gateway.receive(100, inbound)
    # Reboot retaining the dedupe ring → the replayed duplicate is still rejected.
    node_b.reboot(150, preserve_seen=True)
    node_b.receive_lora(200, frame, hlc_now_ms=200)  # → replay-duplicate
    gateway.finalize()
    return _result(name, log, gateway, "fake", sos.event_id_hex,
                   [sos.event_id_hex])


def _run_gateway_reboot(name, log, phone, ble, node_a, node_b):
    sos, frame = _ingest_one_sos(phone, ble, node_a)
    inbound = node_b.receive_lora(100, frame, hlc_now_ms=100)

    gw1 = GatewayCliSink(name, log)
    gw1.receive(100, inbound)
    gw1.finalize()

    # New sink, same scenario DB path: process restart while SQLite keeps the
    # event_id dedupe state. Same event_id via a different last hop → dedupe.
    gw2 = GatewayCliSink(name, log, reset=False)
    gw2.receive(200, replace(inbound, last_hop_label="NodeC",
                             packet_seq=inbound.packet_seq + 1))
    gw2.finalize()
    return _result(name, log, gw2, "cli", sos.event_id_hex, [sos.event_id_hex])


def _run_duplicate_storm(name, log, phone, ble, node_a, node_b, gateway,
                         field_mat):
    sos = phone.sos(0)
    ble.send_envelope(node_a, 0, sos.envelope_bytes)
    event = node_a.queue[0]
    # 10 relays put the SAME event_id on air (different src_node). NodeB's dedupe
    # ring accepts the first and rejects the other nine (replay-duplicate).
    for i in range(10):
        raw = lora.encode_event_frame(
            lora_mac_key=field_mat.lora_mac_key,
            flags=lora.FLAG_HLC_SYNCED,
            field_tag=field_mat.field_tag,
            src_node=10 + i,
            packet_seq=i + 1,
            ttl=5,
            event_id=event.envelope_id,
            event_type=event.event_type,
            priority=int(event.priority),
            hlc_ms=event.created_ms,
            hlc_counter=event.created_counter,
            payload=event.compact_payload,
        )
        frame = LoraFrame(raw=raw, src=f"Node{10 + i}", dst="NodeB",
                          event_id_hex=event.event_id_hex,
                          event_type=event.event_type,
                          priority_label=event.priority.label, ttl=5,
                          packet_seq=i + 1)
        inbound = node_b.receive_lora(100 + i, frame, hlc_now_ms=100 + i)
        if inbound is not None:
            gateway.receive(100 + i, inbound)
    gateway.finalize()
    return _result(name, log, gateway, "fake", sos.event_id_hex,
                   [sos.event_id_hex])


def _run_replayed_valid(name, log, phone, ble, node_a, node_b, gateway):
    sos, frame = _ingest_one_sos(phone, ble, node_a)
    inbound = node_b.receive_lora(100, frame, hlc_now_ms=100)
    if inbound is not None:
        gateway.receive(100, inbound)
    # Same valid frame replayed later → rejected by the dedupe ring.
    node_b.receive_lora(300, frame, hlc_now_ms=300)
    gateway.finalize()
    return _result(name, log, gateway, "fake", sos.event_id_hex,
                   [sos.event_id_hex])


def _run_expired_event(name, log, phone, ble, node_a, gateway):
    exp = phone.expired_sos(100)
    ble.send_envelope(node_a, 100, exp.envelope_bytes)  # → REJECTED envelope-expired
    # Rejected at BLE ingest: never queued, never on air, never reaches gateway.
    gateway.finalize()
    return _result(name, log, gateway, "fake", exp.event_id_hex, [])


def _run_e2e_real_stack(name: str, seed: int) -> ScenarioResult:
    """B7: drive the real B6 node executables; adapt the rich E2EResult to a
    ScenarioResult so GATE-SCEN can evaluate it like any other scenario."""
    from .e2e_real_stack import run_e2e_real_stack

    r = run_e2e_real_stack(name, seed=seed)
    if r.skipped:
        return ScenarioResult(name=name, delivered_event_ids=[],
                              log_path=r.log_path, gateway_mode="cli",
                              sos_event_id=r.sos_event_id or None,
                              e2e_skipped=r.skipped)
    order = r.feed_event_order
    big = 10 ** 9
    sos_before = (order.index(r.sos_event_id) if r.sos_event_id in order else big) \
        < (order.index(r.presence_event_id) if r.presence_event_id in order else big)
    no_dup = (set(r.gateway_events_after_restart) == set(r.gateway_events)
              and len(r.gateway_events_after_restart) == len(r.gateway_events))
    return ScenarioResult(
        name=name, delivered_event_ids=sorted(r.gateway_events.keys()),
        log_path=r.log_path, gateway_mode="cli", sos_event_id=r.sos_event_id,
        accepted_event_ids=sorted(r.gateway_events.keys()),
        presence_event_id=r.presence_event_id,
        e2e_sos_before_presence=sos_before,
        e2e_no_dup_after_restart=no_dup,
        e2e_nodeA_receipts=r.nodeA_node_receipts,
    )


def _run_chaos(name: str, profile: ChannelProfile, seed: int) -> ScenarioResult:
    """B8: drive the real B6 node executables under a chaos profile and adapt the
    rich ChaosResult to a ScenarioResult. Delivery resilience is the real C node's
    bounded retry + relay; the hub only loses/corrupts/partitions bytes."""
    from .e2e_real_stack import run_chaos_real_stack

    r = run_chaos_real_stack(name, profile, seed, sos_count=1)
    if r.skipped:
        return ScenarioResult(name=name, delivered_event_ids=[],
                              log_path=r.log_path, gateway_mode="cli",
                              chaos_report_path=r.report_path or None,
                              chaos_skipped=r.skipped)
    inv = r.report["invariants"]
    return ScenarioResult(
        name=name, delivered_event_ids=sorted(r.gateway_events.keys()),
        log_path=r.log_path, gateway_mode="cli",
        sos_event_id=(r.sos_event_ids[0] if r.sos_event_ids else None),
        accepted_event_ids=sorted(r.gateway_events.keys()),
        chaos_report_path=r.report_path,
        chaos_sos_delivered=inv["sos_delivered"],
        chaos_no_dup=inv["no_duplicate_canonical"],
        chaos_retransmitted=inv["nodeA_retransmitted"],
        chaos_sos_ratio=inv["sos_delivery_ratio"],
    )


def _result(name, log, gateway, gateway_mode, sos_id, accepted):
    return ScenarioResult(
        name=name,
        delivered_event_ids=sorted(gateway.events),
        log_path=str(log.path),
        gateway_mode=gateway_mode,
        sos_event_id=sos_id,
        accepted_event_ids=accepted,
    )
