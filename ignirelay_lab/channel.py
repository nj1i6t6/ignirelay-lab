from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from pathlib import Path

from .logging_utils import JsonlLogSink, LogRecord
from .model import Packet


@dataclass
class ChannelProfile:
    packet_loss_percent: int = 0
    delay_ms_min: int = 10
    delay_ms_max: int = 50
    duplicate_percent: int = 0
    reorder_percent: int = 0
    corrupt_percent: int = 0
    channel_busy_percent: int = 0
    partition_windows: list[dict[str, int | str]] = field(default_factory=list)
    asymmetric_link: dict[str, bool] = field(default_factory=dict)
    simultaneous_tx_collision: bool = False
    hidden_node_case: bool = False
    broadcast_storm_nodes: int = 0

    @classmethod
    def from_file(cls, path: str | Path) -> "ChannelProfile":
        return cls(**json.loads(Path(path).read_text(encoding="utf-8")))


@dataclass
class Delivery:
    due_ms: int
    packet: Packet


class FakeLoRaChannel:
    def __init__(
        self,
        profile: ChannelProfile,
        log: JsonlLogSink,
        rng: random.Random,
    ) -> None:
        self.profile = profile
        self.log = log
        self.rng = rng
        self.pending: list[Delivery] = []

    def _hit(self, percent: int) -> bool:
        return self.rng.randrange(100) < percent

    def transmit(self, now_ms: int, packet: Packet) -> bool:
        if packet.ttl <= 0:
            self._log(now_ms, packet, "LORA_TX", "drop", "ttl_expired")
            return False
        if self._hit(self.profile.channel_busy_percent):
            self._log(now_ms, packet, "LORA_TX", "busy", "channel_busy")
            return False
        if self._hit(self.profile.packet_loss_percent):
            self._log(now_ms, packet, "LORA_TX", "drop", "packet_loss")
            return False

        outgoing = Packet(**{**packet.__dict__})
        if self._hit(self.profile.corrupt_percent):
            outgoing.corrupted = True
            self._log(now_ms, outgoing, "LORA_TX", "tx_corrupt", "corrupt_percent")
        else:
            self._log(now_ms, outgoing, "LORA_TX", "tx", "queued_for_air")

        delay = self.rng.randint(
            self.profile.delay_ms_min,
            self.profile.delay_ms_max,
        )
        self.pending.append(Delivery(now_ms + delay, outgoing))

        if self._hit(self.profile.duplicate_percent):
            duplicate = Packet(**{**outgoing.__dict__})
            duplicate.packet_seq = outgoing.packet_seq
            self.pending.append(Delivery(now_ms + delay + 1, duplicate))
            self._log(now_ms, duplicate, "LORA_TX", "duplicate", "duplicate_percent")

        if self._hit(self.profile.reorder_percent):
            self.pending.sort(key=lambda item: self.rng.random())
        else:
            self.pending.sort(key=lambda item: item.due_ms)
        return True

    def drain_ready(self, now_ms: int) -> list[Packet]:
        ready = [item.packet for item in self.pending if item.due_ms <= now_ms]
        self.pending = [item for item in self.pending if item.due_ms > now_ms]
        return ready

    def _log(self, now_ms: int, packet: Packet, layer: str, action: str, reason: str) -> None:
        self.log.write(LogRecord(
            timestamp_ms=now_ms,
            node_id="FakeLoRaChannel",
            layer=layer,
            event_id=packet.event_id,
            packet_seq=packet.packet_seq,
            src=packet.src,
            dst=packet.dst,
            priority=packet.priority.label,
            ttl=packet.ttl,
            action=action,
            reason=reason,
        ))
