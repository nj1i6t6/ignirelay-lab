from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class Priority(IntEnum):
    P0 = 0
    P1 = 1
    P3 = 3
    P4 = 4

    @property
    def label(self) -> str:
        return self.name


@dataclass(order=True)
class QueuedEvent:
    sort_key: tuple[int, int] = field(init=False, repr=False)
    created_ms: int
    event_id: str
    event_type: str
    priority: Priority
    ttl: int
    source_node_id: str
    payload: dict[str, Any]

    def __post_init__(self) -> None:
        self.sort_key = (int(self.priority), self.created_ms)


@dataclass
class Packet:
    event_id: str
    event_type: str
    priority: Priority
    ttl: int
    packet_seq: int
    src: str
    dst: str
    payload: dict[str, Any]
    corrupted: bool = False
    requires_ack: bool = True
    expires_at_ms: int | None = None
    replay_epoch: str | None = None
    security_placeholder: str = "TODO_CONTRACT_PLACEHOLDER"

    def to_gateway_record(self, now_ms: int) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "priority": self.priority.label,
            "source_node_id": self.payload.get("source_node_id", self.src),
            "last_hop_node_id": self.src,
            "packet_seq": self.packet_seq,
            "src": self.src,
            "dst": self.dst,
            "ttl": self.ttl,
            "observed_at_ms": now_ms,
            "expires_at_ms": self.expires_at_ms,
            "replay_epoch": self.replay_epoch,
            "security_placeholder": self.security_placeholder,
            "payload_json": self.payload,
        }
