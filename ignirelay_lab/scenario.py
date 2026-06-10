from __future__ import annotations

import random
from dataclasses import dataclass

from .actors import FakeGatewaySink, FakePhone, GatewaySink, SimNode
from .channel import ChannelProfile, FakeLoRaChannel
from .gateway_cli import GatewayCliSink
from .logging_utils import JsonlLogSink
from .model import Packet, Priority


@dataclass
class ScenarioResult:
    name: str
    delivered_event_ids: list[str]
    log_path: str
    gateway_mode: str = "fake"


def run_scenario(
    name: str,
    profile: ChannelProfile,
    seed: int = 7,
    gateway_mode: str = "fake",
) -> ScenarioResult:
    log = JsonlLogSink(name)
    rng = random.Random(seed)
    channel = FakeLoRaChannel(profile, log, rng)
    phone = FakePhone()
    node_a = SimNode("NodeA", log)
    node_b = SimNode("NodeB", log)
    gateway = _make_gateway(name, log, gateway_mode)

    if name == "node_reboot":
        return _run_node_reboot(name, log, channel, node_a, node_b, gateway)
    if name == "gateway_reboot":
        return _run_gateway_reboot(name, log)
    if name == "duplicate_storm_10_nodes":
        return _run_duplicate_storm(name, log, gateway)
    if name == "replayed_valid_packet":
        return _run_replayed_valid(name, log, gateway)
    if name == "expired_event":
        return _run_expired_event(name, log, channel, node_b, gateway)

    now_ms = 0
    events = [phone.presence(now_ms, "NodeA")]
    if name in {"normal", "loss_20", "busy_sos", "gateway_cli"}:
        events.append(phone.sos(now_ms + 1, "NodeA"))

    for event in events:
        node_a.ingest_phone_event(event.created_ms, event)

    for step in range(80):
        now_ms = step * 100
        node_a.transmit_next(now_ms, channel, "NodeB")
        for packet in channel.drain_ready(now_ms):
            forwarded = node_b.receive_lora(now_ms, packet)
            if forwarded is not None:
                gateway.receive(now_ms, forwarded)
        if len(gateway.events) == len(events):
            break

    gateway.finalize()
    return _result(name, log, gateway, gateway_mode)


def _make_gateway(name: str, log: JsonlLogSink, gateway_mode: str) -> GatewaySink:
    if gateway_mode == "cli":
        return GatewayCliSink(name, log)
    if gateway_mode == "fake":
        return FakeGatewaySink(log)
    raise ValueError(f"unknown gateway mode: {gateway_mode}")


def _run_node_reboot(
    name: str,
    log: JsonlLogSink,
    channel: FakeLoRaChannel,
    node_a: SimNode,
    node_b: SimNode,
    gateway: GatewaySink,
) -> ScenarioResult:
    packet = Packet(
        event_id="node-reboot-event",
        event_type="SOS",
        priority=Priority.P0,
        ttl=4,
        packet_seq=1,
        src="NodeA",
        dst="NodeB",
        payload={"contract": "TODO_APP_NODE_PLACEHOLDER", "source_node_id": "NodeA"},
    )
    channel.transmit(0, packet)
    for delivered in channel.drain_ready(100):
        forwarded = node_b.receive_lora(100, delivered)
        if forwarded:
            gateway.receive(100, forwarded)
    node_b.reboot(150, preserve_seen=True)
    duplicate = Packet(**{**packet.__dict__, "packet_seq": 2})
    forwarded = node_b.receive_lora(200, duplicate)
    if forwarded:
        gateway.receive(200, forwarded)
    gateway.finalize()
    return _result(name, log, gateway)


def _run_gateway_reboot(name: str, log: JsonlLogSink) -> ScenarioResult:
    gateway = GatewayCliSink(name, log)
    packet = Packet(
        event_id="gateway-reboot-event",
        event_type="SOS",
        priority=Priority.P0,
        ttl=4,
        packet_seq=1,
        src="NodeB",
        dst="Gateway",
        payload={"contract": "TODO_APP_NODE_PLACEHOLDER", "source_node_id": "NodeA"},
    )
    gateway.receive(100, packet)
    gateway.finalize()

    # New sink instance, same scenario DB path: simulates process restart while
    # SQLite keeps event_id dedupe state.
    restarted = GatewayCliSink(name, log, reset=False)
    duplicate = Packet(**{**packet.__dict__, "packet_seq": 2, "src": "NodeC"})
    restarted.receive(200, duplicate)
    restarted.finalize()
    return _result(name, log, restarted, "cli")


def _run_duplicate_storm(name: str, log: JsonlLogSink, gateway: GatewaySink) -> ScenarioResult:
    for index in range(10):
        packet = Packet(
            event_id="storm-event-1",
            event_type="SOS",
            priority=Priority.P0,
            ttl=4,
            packet_seq=index + 1,
            src=f"Node{index}",
            dst="Gateway",
            payload={"contract": "TODO_APP_NODE_PLACEHOLDER", "source_node_id": "NodeA"},
        )
        gateway.receive(100 + index, packet)
    gateway.finalize()
    return _result(name, log, gateway)


def _run_replayed_valid(name: str, log: JsonlLogSink, gateway: GatewaySink) -> ScenarioResult:
    packet = Packet(
        event_id="replay-event-1",
        event_type="SOS",
        priority=Priority.P0,
        ttl=4,
        packet_seq=1,
        src="NodeB",
        dst="Gateway",
        payload={"contract": "TODO_APP_NODE_PLACEHOLDER", "source_node_id": "NodeA"},
        replay_epoch="LAB_EPOCH_PLACEHOLDER",
    )
    gateway.receive(100, packet)
    gateway.receive(200, Packet(**{**packet.__dict__, "packet_seq": 2}))
    gateway.finalize()
    return _result(name, log, gateway)


def _run_expired_event(
    name: str,
    log: JsonlLogSink,
    channel: FakeLoRaChannel,
    node_b: SimNode,
    gateway: GatewaySink,
) -> ScenarioResult:
    packet = Packet(
        event_id="expired-event-1",
        event_type="PRESENCE",
        priority=Priority.P3,
        ttl=0,
        packet_seq=1,
        src="NodeA",
        dst="NodeB",
        payload={"contract": "TODO_APP_NODE_PLACEHOLDER", "source_node_id": "NodeA"},
        expires_at_ms=50,
    )
    channel.transmit(100, packet)
    forwarded = node_b.receive_lora(150, packet)
    if forwarded:
        gateway.receive(150, forwarded)
    gateway.finalize()
    return _result(name, log, gateway)


def _result(
    name: str,
    log: JsonlLogSink,
    gateway: GatewaySink,
    gateway_mode: str = "fake",
) -> ScenarioResult:
    return ScenarioResult(
        name=name,
        delivered_event_ids=sorted(gateway.events),
        log_path=str(log.path),
        gateway_mode=gateway_mode,
    )
