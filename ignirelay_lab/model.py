"""Lab simulator data models (B3 — real EventEnvelope / LORA-WIRE bytes).

No fake-contract placeholders: every event is a real signed EventEnvelopeV2 at
BLE ingest and a real LORA-WIRE v1 frame on air. Scheduling priority uses the
wire `PriorityV2` enum directly (lower number = more severe).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class WirePriority(IntEnum):
    """`PriorityV2` (event_envelope_v2.dart) — lower number = more severe.

    The envelope `priority` field MUST be non-zero (0 = UNSPECIFIED is rejected
    by §3.4 required-field validation), so the lab uses the 1..6 wire values, not
    a separate P0..P4 namespace.
    """

    SOS_RED = 1
    SOS_YELLOW = 2
    ALERT = 3
    STATUS = 4
    RESOURCE = 5
    NORMAL = 6

    @property
    def label(self) -> str:
        return self.name


@dataclass(order=True)
class QueuedEvent:
    """A verified event awaiting LoRa transmission (post BLE-ingest translation).

    Heap order = (priority, created_ms): SOS_RED(1) is dequeued before NORMAL(6),
    ties broken by HLC creation time (oldest first).
    """

    sort_key: tuple[int, int] = field(init=False, repr=False)
    created_ms: int
    created_counter: int
    envelope_id: bytes
    event_id_hex: str
    event_type: int          # EventTypeV2
    priority: WirePriority
    ttl: int
    author_key: bytes
    compact_payload: bytes   # LORA-WIRE §5 compact payload bytes

    def __post_init__(self) -> None:
        self.sort_key = (int(self.priority), self.created_ms)


@dataclass
class LoraFrame:
    """A LORA-WIRE v1 frame on the fake channel — carries REAL frame bytes.

    `raw` is the byte-exact §3 frame (hdr‖body‖mac8‖crc16). Routing fields
    (src/dst) name the simulated nodes; the logging fields are a pre-parsed view
    so the channel can log without re-verifying. `corrupted` marks a frame the
    channel flipped a bit in — the receiver MUST reject it via CRC/MAC.
    """

    raw: bytes
    src: str
    dst: str
    event_id_hex: str
    event_type: int
    priority_label: str
    ttl: int
    packet_seq: int
    corrupted: bool = False


@dataclass
class GatewayInbound:
    """A LoRa-verified event handed to the Gateway sink (Gateway = a storing node).

    Built only AFTER the receiving node passed the full §8 LoRa pipeline
    (crc/mac/ttl/replay/hlc-window). `decoded_payload` is the structured §5
    compact decode (real data, not a placeholder). `raw_frame` is the byte-exact
    on-air LORA-WIRE frame the node verified — the B4 gateway re-verifies these
    exact bytes independently (E2E), so it must travel with the inbound.
    """

    event_id_hex: str
    event_type: int
    event_type_label: str
    priority: int
    priority_label: str
    src_node: int
    last_hop_label: str
    ttl: int
    packet_seq: int
    hlc_ms: int
    hlc_counter: int
    compact_payload: bytes
    decoded_payload: dict[str, Any]
    raw_frame: bytes = b""


# EventTypeV2 → human label (logging / gateway records only).
EVENT_TYPE_LABELS = {
    1: "SOS",
    3: "PRESENCE",
    4: "CHECKPOINT",
    50: "HAZARD",
    82: "ADMIN_BROADCAST",
    102: "HEARTBEAT",
    105: "NODE_RECEIPT",
}


def event_type_label(event_type: int) -> str:
    return EVENT_TYPE_LABELS.get(event_type, f"TYPE_{event_type}")
