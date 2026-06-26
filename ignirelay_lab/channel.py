"""FakeLoRaChannel (B3) — transports REAL LORA-WIRE v1 frame bytes.

Chaos (loss / busy / corruption / duplication / reorder / delay) is applied to
the byte-exact `LoraFrame.raw`. A corrupted frame still reaches the receiver but
with a flipped body byte, so the receiver MUST reject it via CRC/MAC (§8). Three
transmit outcomes are distinguished so the node can model radio honestly:

    SENT  — frame put on air intact.
    BUSY  — channel busy; CSMA deferral (NOT a delivery failure → no retry budget).
    LOST  — frame did not reach air intact (packet loss, or corrupted-in-flight);
            the sender retransmits (bounded ACK-retry).
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path

from .logging_utils import JsonlLogSink, LogRecord
from .model import LoraFrame


class TransmitOutcome(Enum):
    SENT = "sent"
    BUSY = "busy"
    LOST = "lost"


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
    frame: LoraFrame


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

    def _corrupt(self, frame: LoraFrame) -> LoraFrame:
        raw = bytearray(frame.raw)
        # Flip a byte in the body/payload region [11, len-2) so the CRC (and then
        # MAC) is the check that rejects it; never touch ver_ptype byte 0.
        lo, hi = 11, max(11, len(raw) - 2)
        idx = self.rng.randrange(lo, hi) if hi > lo else 0
        raw[idx] ^= 0xFF
        return replace(frame, raw=bytes(raw), corrupted=True)

    def transmit(self, now_ms: int, frame: LoraFrame) -> TransmitOutcome:
        if frame.ttl <= 0:
            self._log(now_ms, frame, "LORA_TX", "drop", "ttl-expired")
            return TransmitOutcome.LOST
        if self._hit(self.profile.channel_busy_percent):
            self._log(now_ms, frame, "LORA_TX", "busy", "channel-busy")
            return TransmitOutcome.BUSY
        if self._hit(self.profile.packet_loss_percent):
            self._log(now_ms, frame, "LORA_TX", "drop", "packet-loss")
            return TransmitOutcome.LOST

        delay = self.rng.randint(self.profile.delay_ms_min,
                                 self.profile.delay_ms_max)

        if self._hit(self.profile.corrupt_percent):
            corrupted = self._corrupt(frame)
            self.pending.append(Delivery(now_ms + delay, corrupted))
            self._log(now_ms, corrupted, "LORA_TX", "tx_corrupt", "corrupt-percent")
            self._reorder()
            # On air but garbled → receiver drops via CRC; sender retransmits.
            return TransmitOutcome.LOST

        self.pending.append(Delivery(now_ms + delay, frame))
        self._log(now_ms, frame, "LORA_TX", "tx", "queued-for-air")

        if self._hit(self.profile.duplicate_percent):
            self.pending.append(Delivery(now_ms + delay + 1, frame))
            self._log(now_ms, frame, "LORA_TX", "duplicate", "duplicate-percent")

        self._reorder()
        return TransmitOutcome.SENT

    def _reorder(self) -> None:
        if self._hit(self.profile.reorder_percent):
            self.pending.sort(key=lambda item: self.rng.random())
        else:
            self.pending.sort(key=lambda item: item.due_ms)

    def drain_ready(self, now_ms: int) -> list[LoraFrame]:
        ready = [item.frame for item in self.pending if item.due_ms <= now_ms]
        self.pending = [item for item in self.pending if item.due_ms > now_ms]
        return ready

    def _log(self, now_ms: int, frame: LoraFrame, layer: str, action: str,
             reason: str) -> None:
        self.log.write(LogRecord(
            timestamp_ms=now_ms,
            node_id="FakeLoRaChannel",
            layer=layer,
            event_id=frame.event_id_hex,
            packet_seq=frame.packet_seq,
            src=frame.src,
            dst=frame.dst,
            priority=frame.priority_label,
            ttl=frame.ttl,
            action=action,
            reason=reason,
        ))
