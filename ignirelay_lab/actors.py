"""Lab actors running REAL bytes (B3).

- FakePhone   : builds real signed EventEnvelopeV2 v3 bytes (PRESENCE/SOS/
                CHECKPOINT) with a corpus TEST-ONLY key, hands them over a fake
                BLE link to a SimNode.
- SimNode     : BLE ingest = full envelope verify (Ed25519 + field_mac + expiry +
                dedupe) → translate to a LORA-WIRE §5 compact payload → priority
                queue → real LORA-WIRE frame on the FakeLoRaChannel; LoRa receive
                = full §8 pipeline (crc/mac/ttl/replay/hlc-window) → Gateway sink;
                returns a real NODE_RECEIPT (accepted/duplicate/rejected) to the
                phone.
- NODE_RECEIPT: app_node_gatt_v1.md §5 — segment 1 (PHONE_TO_NODE_ACCEPTED) only;
                MUST NOT be read as HOP_ACKED or GATEWAY_CONFIRMED.
"""

from __future__ import annotations

import hashlib
import heapq
from dataclasses import dataclass
from typing import Any, Optional, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import corpus_fixtures as fx
from .channel import FakeLoRaChannel, TransmitOutcome
from .logging_utils import JsonlLogSink, LogRecord
from .model import (
    GatewayInbound,
    LoraFrame,
    QueuedEvent,
    WirePriority,
    event_type_label,
)
from .wire import compact
from .wire import envelope_v3 as ev
from .wire import lora_v1 as lora

# NODE_RECEIPT status (app_node_gatt_v1.md §5.2).
RECEIPT_ACCEPTED = 0
RECEIPT_DUPLICATE = 1
RECEIPT_REJECTED = 2

# Bounded ACK-retry budgets (loss-driven retransmissions). Channel-busy is CSMA
# deferral and does NOT consume the budget (§ realistic radio: busy ≠ failure).
LOSS_BUDGET_CRITICAL = 6   # SOS_RED — critical traffic retries harder, still bounded
LOSS_BUDGET_DEFAULT = 3

# Retry/defer backoff (ms) with jitter.
RETRY_BACKOFF_MS = 100
RETRY_JITTER_MS = 80

# 24h validity window for phone-built envelopes (ms).
_DEFAULT_VALIDITY_MS = 24 * 60 * 60 * 1000

# TEST-ONLY location used by the simulated phone (same anchor as the corpus /
# LoRa generator). Synthetic simulator data — not a production GPS path.
_LAT_E7 = 250339805
_LNG_E7 = 1215654177


class GatewaySink(Protocol):
    events: dict[str, dict[str, Any]]
    routes: list[GatewayInbound]

    def receive(self, now_ms: int, inbound: GatewayInbound) -> None:
        ...

    def finalize(self) -> None:
        ...


# ─────────────────────────────────────────────────────────────────────────────
# FakePhone — real signed envelopes
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class PhoneEvent:
    envelope_bytes: bytes
    envelope_id: bytes
    event_type: int
    priority: WirePriority

    @property
    def event_id_hex(self) -> str:
        return self.envelope_id.hex()


class FakePhone:
    def __init__(self, phone_id: str = "phone-lab-1") -> None:
        self.phone_id = phone_id
        self.field = fx.test_field()
        self._seed = fx.author_seed()
        self._sk = Ed25519PrivateKey.from_private_bytes(self._seed)
        self.author_key = self._sk.public_key().public_bytes_raw()
        self.anon_user_id = fx.anon_user_id(phone_id)
        self._counter = 0

    # -- envelope assembly -----------------------------------------------------
    def _next_envelope_id(self, event_type: int) -> bytes:
        self._counter += 1
        seed = f"{self.phone_id}:{event_type}:{self._counter}".encode()
        return hashlib.sha256(seed).digest()[:16]

    def _build(
        self,
        *,
        now_ms: int,
        event_type: int,
        priority: WirePriority,
        payload: bytes,
        validity_ms: int = _DEFAULT_VALIDITY_MS,
    ) -> PhoneEvent:
        envelope_id = self._next_envelope_id(event_type)
        created = ev.HlcTimestamp(ms=now_ms, counter=self._counter)
        expires = ev.HlcTimestamp(ms=now_ms + validity_ms, counter=0)
        canonical = ev.canonical_sig_input_v3(
            protocol_version=ev.PROTOCOL_VERSION_V3,
            envelope_id=envelope_id,
            field_id=self.field.field_id,
            event_type=event_type,
            priority=int(priority),
            created_ms=created.ms,
            created_counter=created.counter,
            expires_ms=expires.ms,
            expires_counter=expires.counter,
            max_hops=0,
            author_key=self.author_key,
            sig_algo=ev.SIG_ALGO_ED25519,
            payload_sha256=ev.payload_hash(payload),
        )
        signature = self._sk.sign(canonical)
        field_mac = ev.keys.compute_field_mac(self.field.field_mac_key, canonical)
        envelope = ev.EventEnvelopeV2(
            protocol_version=ev.PROTOCOL_VERSION_V3,
            envelope_id=envelope_id,
            event_type=event_type,
            priority=int(priority),
            created_at_hlc=created,
            expires_at_hlc=expires,
            author_key=self.author_key,
            sig_algo=ev.SIG_ALGO_ED25519,
            signature=signature,
            payload=payload,
            max_hops=0,
            field_id=self.field.field_id,
            field_mac=field_mac,
        )
        return PhoneEvent(
            envelope_bytes=envelope.encode(),
            envelope_id=envelope_id,
            event_type=event_type,
            priority=priority,
        )

    def _location(self, now_ms: int, *, src: int, lat_e7: int, lng_e7: int,
                  acc_m: int) -> ev.LocationEvidence:
        return ev.LocationEvidence(
            source=src,
            lat_e7=lat_e7,
            lng_e7=lng_e7,
            accuracy_m=acc_m,
            observed_at=ev.HlcTimestamp(ms=now_ms, counter=0),
        )

    # -- event builders --------------------------------------------------------
    def presence(self, now_ms: int) -> PhoneEvent:
        payload = ev.PresenceData(
            anon_user_id=self.anon_user_id,
            location=self._location(now_ms, src=1, lat_e7=_LAT_E7,
                                    lng_e7=_LNG_E7, acc_m=18),
            battery_hint=87,
        ).encode()
        return self._build(now_ms=now_ms, event_type=ev_type_presence(),
                           priority=WirePriority.ALERT, payload=payload)

    def sos(self, now_ms: int, *, safety: int = 4) -> PhoneEvent:
        payload = ev.StatusUpdateData(
            safety_state=safety,
            location=self._location(now_ms, src=1, lat_e7=_LAT_E7,
                                    lng_e7=_LNG_E7, acc_m=12),
        ).encode()
        return self._build(now_ms=now_ms, event_type=ev_type_sos(),
                           priority=WirePriority.SOS_RED, payload=payload)

    def checkpoint(self, now_ms: int) -> PhoneEvent:
        payload = ev.CheckpointData(
            anon_user_id=self.anon_user_id,
            checkpoint_id="cp-lab",
            location=self._location(now_ms, src=2, lat_e7=_LAT_E7,
                                    lng_e7=_LNG_E7, acc_m=30),
        ).encode()
        return self._build(now_ms=now_ms, event_type=ev_type_checkpoint(),
                           priority=WirePriority.STATUS, payload=payload)

    def expired_sos(self, now_ms: int) -> PhoneEvent:
        """An SOS whose validity window has already closed (expires < now)."""
        payload = ev.StatusUpdateData(
            safety_state=4,
            location=self._location(now_ms, src=1, lat_e7=_LAT_E7,
                                    lng_e7=_LNG_E7, acc_m=12),
        ).encode()
        # validity 0 → expires == created == now; one ms in the past => expired.
        return self._build(now_ms=now_ms - 1, event_type=ev_type_sos(),
                           priority=WirePriority.SOS_RED, payload=payload,
                           validity_ms=0)

    def read_node_receipt(self, payload: bytes) -> "NodeReceipt":
        data = ev.NodeReceiptData.decode(payload)
        return NodeReceipt(
            ref_envelope_id=data.ref_envelope_id,
            status=data.status,
            queue_depth=data.queue_depth,
        )


def ev_type_presence() -> int:
    return ev_event_types()["presence"]


def ev_type_sos() -> int:
    return ev_event_types()["sos"]


def ev_type_checkpoint() -> int:
    return ev_event_types()["checkpoint"]


def ev_event_types() -> dict[str, int]:
    # EventTypeV2 (event_envelope_v2.dart): statusUpdate=1, presence=3, checkpoint=4.
    return {"sos": 1, "presence": 3, "checkpoint": 4}


# ─────────────────────────────────────────────────────────────────────────────
# NODE_RECEIPT (app_node_gatt_v1.md §5) — segment 1 only
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class NodeReceipt:
    ref_envelope_id: bytes
    status: int
    queue_depth: int
    # Segment label: this receipt ONLY attests PHONE_TO_NODE_ACCEPTED. It MUST
    # NOT be read as HOP_ACKED (LoRa ACK) or GATEWAY_CONFIRMED (§6).
    segment: str = "PHONE_TO_NODE_ACCEPTED"

    def to_payload(self) -> bytes:
        return ev.NodeReceiptData(
            ref_envelope_id=self.ref_envelope_id,
            status=self.status,
            queue_depth=self.queue_depth,
        ).encode()


# ─────────────────────────────────────────────────────────────────────────────
# Fake BLE link (function injection; real BLE in field-node bsim later)
# ─────────────────────────────────────────────────────────────────────────────


class FakeBleLink:
    """The App↔Node first hop, simulated as a direct call carrying real bytes."""

    def send_envelope(self, node: "SimNode", now_ms: int,
                      envelope_bytes: bytes) -> NodeReceipt:
        return node.ble_ingest(now_ms, envelope_bytes)


# ─────────────────────────────────────────────────────────────────────────────
# SimNode
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class RetryState:
    loss_attempts: int = 0
    next_attempt_ms: int = 0


class SimNode:
    def __init__(
        self,
        node_id: str,
        log: JsonlLogSink,
        *,
        node_num: int,
        field: Optional[fx.TestField] = None,
        rng=None,
        max_queue_size: int = 8,
    ) -> None:
        self.node_id = node_id
        self.node_num = node_num & 0xFFFF
        self.log = log
        self.field = field or fx.test_field()
        self._rng = rng
        self.max_queue_size = max_queue_size
        self.queue: list[QueuedEvent] = []
        self.seen_ble: set[bytes] = set()          # envelope_id dedupe (BLE)
        self.seen_lora: set[str] = set()           # event_id hex replay ring (LoRa)
        self.retry: dict[str, RetryState] = {}
        self.packet_seq = 0
        self.dropped_events: list[QueuedEvent] = []
        self.anon_by_author: dict[str, bytes] = {}

    # -- BLE ingest (App → Node) ----------------------------------------------
    def ble_ingest(self, now_ms: int, envelope_bytes: bytes) -> NodeReceipt:
        try:
            env = ev.EventEnvelopeV2.decode(envelope_bytes)
        except ev.ProtoDecodeError:
            return self._reject(now_ms, b"", "malformed-envelope")

        ref = env.envelope_id
        if env.protocol_version != ev.PROTOCOL_VERSION_V3:
            return self._reject(now_ms, ref, "unknown-protocol-version")
        if env.sig_algo != ev.SIG_ALGO_ED25519:
            return self._reject(now_ms, ref, "unknown-sig-algo")

        canonical = self._canonical(env)
        if not ev.ed25519_verify(env.author_key, canonical, env.signature):
            return self._reject(now_ms, ref, "signature-invalid")
        if not ev.keys.verify_field_mac(self.field.field_mac_key, canonical,
                                        env.field_mac):
            return self._reject(now_ms, ref, "field-mac-invalid")
        if env.expires_at_hlc.ms < now_ms:
            return self._reject(now_ms, ref, "envelope-expired")

        if ref in self.seen_ble:
            self._receipt_log(now_ms, ref, "duplicate", "envelope-id-seen")
            return NodeReceipt(ref, RECEIPT_DUPLICATE, len(self.queue))

        priority = WirePriority(env.priority)
        if len(self.queue) >= self.max_queue_size:
            # Queue full: shed the least-severe queued event if the newcomer is
            # more severe; otherwise reject the newcomer (it may be retried once
            # the queue drains — not added to the dedupe ring).
            worst_idx = max(range(len(self.queue)),
                            key=lambda i: self.queue[i].priority)
            worst = self.queue[worst_idx]
            if worst.priority > priority:  # higher value = less severe
                self.queue.pop(worst_idx)
                heapq.heapify(self.queue)
                self.dropped_events.append(worst)
                self._log(now_ms, worst.event_id_hex, 0, self.node_id,
                          self.node_id, worst.priority.label, worst.ttl,
                          "QUEUE", "drop", "queue-full-evict-lower-priority")
            else:
                return self._reject(now_ms, ref, "queue-full")

        compact_payload = self._translate(now_ms, env)
        self.seen_ble.add(ref)
        heapq.heappush(self.queue, QueuedEvent(
            created_ms=env.created_at_hlc.ms,
            created_counter=env.created_at_hlc.counter,
            envelope_id=ref,
            event_id_hex=ref.hex(),
            event_type=env.event_type,
            priority=priority,
            ttl=env.max_hops if env.max_hops > 0 else 6,
            author_key=env.author_key,
            compact_payload=compact_payload,
        ))
        self._receipt_log(now_ms, ref, "accepted",
                          event_type_label(env.event_type).lower())
        return NodeReceipt(ref, RECEIPT_ACCEPTED, len(self.queue))

    def _reject(self, now_ms: int, ref: bytes, reason: str) -> NodeReceipt:
        self._receipt_log(now_ms, ref, "rejected", reason)
        return NodeReceipt(ref, RECEIPT_REJECTED, len(self.queue))

    def _canonical(self, env: ev.EventEnvelopeV2) -> bytes:
        return ev.canonical_sig_input_v3(
            protocol_version=env.protocol_version,
            envelope_id=env.envelope_id,
            field_id=env.field_id,
            event_type=env.event_type,
            priority=env.priority,
            created_ms=env.created_at_hlc.ms,
            created_counter=env.created_at_hlc.counter,
            expires_ms=env.expires_at_hlc.ms,
            expires_counter=env.expires_at_hlc.counter,
            max_hops=env.max_hops,
            author_key=env.author_key,
            sig_algo=env.sig_algo,
            payload_sha256=ev.payload_hash(env.payload),
        )

    def _translate(self, now_ms: int, env: ev.EventEnvelopeV2) -> bytes:
        """§5 envelope typed payload → LoRa compact payload (post-verify)."""
        author_hex = env.author_key.hex()
        if env.event_type == 3:  # presence
            p = ev.PresenceData.decode(env.payload)
            self.anon_by_author[author_hex] = compact._anon8(p.anon_user_id)
            return compact.presence_from_typed(p, now_ms=now_ms)
        if env.event_type == 4:  # checkpoint
            c = ev.CheckpointData.decode(env.payload)
            self.anon_by_author[author_hex] = compact._anon8(c.anon_user_id)
            return compact.checkpoint_from_typed(
                c, checkpoint_node=self.node_num, now_ms=now_ms)
        if env.event_type == 1:  # status_update / SOS — anon8 from author's PRESENCE
            s = ev.StatusUpdateData.decode(env.payload)
            anon8 = self.anon_by_author.get(author_hex, b"\x00" * 8)
            return compact.sos_from_typed(s, anon8=anon8, now_ms=now_ms)
        raise ValueError(f"no §5 compact translation for event_type {env.event_type}")

    # -- LoRa transmit (Node → air) -------------------------------------------
    def _budget(self, priority: WirePriority) -> int:
        return LOSS_BUDGET_CRITICAL if priority == WirePriority.SOS_RED \
            else LOSS_BUDGET_DEFAULT

    def _backoff(self, now_ms: int) -> int:
        jitter = self._rng.randint(0, RETRY_JITTER_MS) if self._rng else 0
        return now_ms + RETRY_BACKOFF_MS + jitter

    def build_frame(self, event: QueuedEvent, dst: str) -> LoraFrame:
        raw = lora.encode_event_frame(
            lora_mac_key=self.field.lora_mac_key,
            flags=lora.FLAG_HLC_SYNCED,
            field_tag=self.field.field_tag,
            src_node=self.node_num,
            packet_seq=self.packet_seq,
            ttl=event.ttl,
            event_id=event.envelope_id,
            event_type=event.event_type,
            priority=int(event.priority),
            hlc_ms=event.created_ms,
            hlc_counter=event.created_counter,
            payload=event.compact_payload,
        )
        return LoraFrame(
            raw=raw, src=self.node_id, dst=dst,
            event_id_hex=event.event_id_hex, event_type=event.event_type,
            priority_label=event.priority.label, ttl=event.ttl,
            packet_seq=self.packet_seq,
        )

    def transmit_next(self, now_ms: int, channel: FakeLoRaChannel,
                      dst: str) -> Optional[TransmitOutcome]:
        if not self.queue:
            return None
        # Respect the highest-priority event's backoff: do not send lower-priority
        # traffic ahead of a critical event that is still backing off.
        best = self.queue[0]
        rs = self.retry.setdefault(best.event_id_hex, RetryState())
        if now_ms < rs.next_attempt_ms:
            return None

        event = heapq.heappop(self.queue)
        rs = self.retry.setdefault(event.event_id_hex, RetryState())
        if rs.loss_attempts >= self._budget(event.priority):
            self.dropped_events.append(event)
            self._log(now_ms, event.event_id_hex, 0, self.node_id, dst,
                      event.priority.label, event.ttl, "LORA_TX", "drop",
                      "retry-exhausted")
            return None

        self.packet_seq += 1
        frame = self.build_frame(event, dst)
        outcome = channel.transmit(now_ms, frame)

        if outcome is TransmitOutcome.SENT:
            self._log(now_ms, event.event_id_hex, self.packet_seq, self.node_id,
                      dst, event.priority.label, event.ttl, "LORA_TX",
                      "await_ack", "bounded-retry")
        elif outcome is TransmitOutcome.BUSY:
            rs.next_attempt_ms = self._backoff(now_ms)
            heapq.heappush(self.queue, event)
            self._log(now_ms, event.event_id_hex, self.packet_seq, self.node_id,
                      dst, event.priority.label, event.ttl, "LORA_TX",
                      "defer", "channel-busy")
        else:  # LOST (includes a corrupted-in-flight frame the receiver drops)
            rs.loss_attempts += 1
            rs.next_attempt_ms = self._backoff(now_ms)
            heapq.heappush(self.queue, event)
            self._log(now_ms, event.event_id_hex, self.packet_seq, self.node_id,
                      dst, event.priority.label, event.ttl, "LORA_TX",
                      "retry", "packet-loss")
        return outcome

    # -- LoRa receive (air → Node / Gateway) ----------------------------------
    def receive_lora(self, now_ms: int, frame: LoraFrame, *,
                     hlc_now_ms: Optional[int] = None) -> Optional[GatewayInbound]:
        if frame.dst != self.node_id:
            return None
        res = lora.verify_lora_frame(
            frame.raw,
            lora_mac_key=self.field.lora_mac_key,
            local_est_ms=hlc_now_ms,
            seen_event_ids=self.seen_lora,
        )
        if res.reason is not None:
            self._log(now_ms, frame.event_id_hex, frame.packet_seq, frame.src,
                      self.node_id, frame.priority_label, frame.ttl, "LORA_RX",
                      "drop", res.reason)
            return None

        parsed = res.parsed
        self._log(now_ms, frame.event_id_hex, parsed.packet_seq, frame.src,
                  self.node_id, WirePriority(parsed.priority).label, parsed.ttl,
                  "LORA_RX", "rx", "frame-verified")
        return self._to_gateway(now_ms, parsed, frame.raw)

    def _to_gateway(self, now_ms: int, parsed: lora.LoraParsedFrame,
                    raw_frame: bytes) -> GatewayInbound:
        decoded = _decode_compact(parsed.event_type, parsed.payload)
        return GatewayInbound(
            event_id_hex=parsed.event_id.hex(),
            event_type=parsed.event_type,
            event_type_label=event_type_label(parsed.event_type),
            priority=parsed.priority,
            priority_label=WirePriority(parsed.priority).label,
            src_node=parsed.src_node,
            last_hop_label=self.node_id,
            ttl=max(parsed.ttl - 1, 0),  # relay decrements before forwarding
            packet_seq=parsed.packet_seq,
            hlc_ms=parsed.hlc_ms,
            hlc_counter=parsed.hlc_counter,
            compact_payload=parsed.payload,
            decoded_payload=decoded,
            raw_frame=raw_frame,
        )

    def reboot(self, now_ms: int, preserve_seen: bool = True) -> None:
        self.queue.clear()
        self.retry.clear()
        if not preserve_seen:
            self.seen_ble.clear()
            self.seen_lora.clear()
        self._log(now_ms, "", 0, self.node_id, self.node_id,
                  WirePriority.NORMAL.label, 0, "NODE", "reboot",
                  "persistent-dedupe-retained" if preserve_seen
                  else "volatile-dedupe-cleared")

    # -- logging ---------------------------------------------------------------
    def _receipt_log(self, now_ms: int, ref: bytes, action: str,
                     reason: str) -> None:
        self.log.write(LogRecord(
            timestamp_ms=now_ms, node_id=self.node_id, layer="BLE_INGEST",
            event_id=ref.hex(), packet_seq=0, src="FakePhone", dst=self.node_id,
            priority="-", ttl=0, action=action, reason=reason,
            extra={"receipt_segment": "PHONE_TO_NODE_ACCEPTED",
                   "queue_depth": len(self.queue)},
        ))

    def _log(self, now_ms: int, event_id: str, packet_seq: int, src: str,
             dst: str, priority: str, ttl: int, layer: str, action: str,
             reason: str) -> None:
        self.log.write(LogRecord(
            timestamp_ms=now_ms, node_id=self.node_id, layer=layer,
            event_id=event_id, packet_seq=packet_seq, src=src, dst=dst,
            priority=priority, ttl=ttl, action=action, reason=reason,
        ))


def _decode_compact(event_type: int, payload: bytes) -> dict[str, Any]:
    try:
        if event_type == 1:
            return compact.decode_sos(payload)
        if event_type == 3:
            return compact.decode_presence(payload)
        if event_type == 4:
            return compact.decode_checkpoint(payload)
    except ValueError:
        pass
    return {"payload_hex": payload.hex()}


# ─────────────────────────────────────────────────────────────────────────────
# Gateway sink (Gateway = a storing node; real verification is B4)
# ─────────────────────────────────────────────────────────────────────────────


class FakeGatewaySink:
    def __init__(self, log: JsonlLogSink) -> None:
        self.log = log
        self.events: dict[str, dict[str, Any]] = {}
        self.routes: list[GatewayInbound] = []

    def receive(self, now_ms: int, inbound: GatewayInbound) -> None:
        self.routes.append(inbound)
        action = "dedupe" if inbound.event_id_hex in self.events else "store"
        reason = "event-id-seen" if action == "dedupe" else "canonical-event"
        self.events.setdefault(inbound.event_id_hex, {
            "event_id": inbound.event_id_hex,
            "event_type": inbound.event_type_label,
            "priority": inbound.priority_label,
            "source_node_id": f"node-{inbound.src_node}",
            "payload": inbound.decoded_payload,
        })
        self._log(now_ms, inbound, action, reason)

    def finalize(self) -> None:
        return None

    def _log(self, now_ms: int, inbound: GatewayInbound, action: str,
             reason: str) -> None:
        self.log.write(LogRecord(
            timestamp_ms=now_ms, node_id="Gateway", layer="GATEWAY_RX",
            event_id=inbound.event_id_hex, packet_seq=inbound.packet_seq,
            src=inbound.last_hop_label, dst="Gateway",
            priority=inbound.priority_label, ttl=inbound.ttl, action=action,
            reason=reason,
        ))
