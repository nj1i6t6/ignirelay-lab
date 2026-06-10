from __future__ import annotations

import heapq
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Protocol

from .channel import FakeLoRaChannel
from .logging_utils import JsonlLogSink, LogRecord
from .model import Packet, Priority, QueuedEvent


class GatewaySink(Protocol):
    events: dict[str, dict[str, Any]]
    routes: list[Packet]

    def receive(self, now_ms: int, packet: Packet) -> None:
        ...

    def finalize(self) -> None:
        ...


class FakePhone:
    def __init__(self, phone_id: str = "phone-lab-1") -> None:
        self.phone_id = phone_id

    def presence(self, now_ms: int, node_id: str) -> QueuedEvent:
        return QueuedEvent(
            created_ms=now_ms,
            event_id=f"presence-{now_ms}-{self.phone_id}",
            event_type="PRESENCE",
            priority=Priority.P3,
            ttl=4,
            source_node_id=node_id,
            payload={
                "contract": "TODO_APP_NODE_PLACEHOLDER",
                "phone_id": self.phone_id,
                "source_node_id": node_id,
            },
        )

    def sos(self, now_ms: int, node_id: str) -> QueuedEvent:
        return QueuedEvent(
            created_ms=now_ms,
            event_id=f"sos-{now_ms}-{self.phone_id}",
            event_type="SOS",
            priority=Priority.P0,
            ttl=6,
            source_node_id=node_id,
            payload={
                "contract": "TODO_APP_NODE_PLACEHOLDER",
                "phone_id": self.phone_id,
                "source_node_id": node_id,
            },
        )

    def heartbeat(self, now_ms: int, node_id: str, index: int = 0) -> QueuedEvent:
        return QueuedEvent(
            created_ms=now_ms,
            event_id=f"heartbeat-{index}-{node_id}",
            event_type="NODE_HEARTBEAT",
            priority=Priority.P4,
            ttl=2,
            source_node_id=node_id,
            payload={
                "contract": "TODO_APP_NODE_PLACEHOLDER",
                "source_node_id": node_id,
            },
        )


@dataclass
class RetryState:
    attempts: int = 0
    max_attempts: int = 3


class SimNode:
    def __init__(self, node_id: str, log: JsonlLogSink, max_queue_size: int = 8) -> None:
        self.node_id = node_id
        self.log = log
        self.max_queue_size = max_queue_size
        self.queue: list[QueuedEvent] = []
        self.seen: set[str] = set()
        self.retry: dict[str, RetryState] = defaultdict(RetryState)
        self.packet_seq = 0
        self.dropped_events: list[QueuedEvent] = []

    def ingest_phone_event(self, now_ms: int, event: QueuedEvent) -> bool:
        if event.event_id in self.seen:
            self._log(
                now_ms,
                event.event_id,
                0,
                self.node_id,
                self.node_id,
                event.priority,
                event.ttl,
                "PHONE_RX",
                "dedupe",
                "event_id_seen",
            )
            return False

        if len(self.queue) >= self.max_queue_size:
            worst_index = max(range(len(self.queue)), key=lambda idx: self.queue[idx].sort_key)
            worst = self.queue[worst_index]
            if worst.priority > event.priority:
                dropped = self.queue.pop(worst_index)
                heapq.heapify(self.queue)
                self.dropped_events.append(dropped)
                self._log(
                    now_ms,
                    dropped.event_id,
                    0,
                    self.node_id,
                    self.node_id,
                    dropped.priority,
                    dropped.ttl,
                    "QUEUE",
                    "drop",
                    "queue_full_drop_lowest_priority",
                )
            else:
                self.dropped_events.append(event)
                self._log(
                    now_ms,
                    event.event_id,
                    0,
                    self.node_id,
                    self.node_id,
                    event.priority,
                    event.ttl,
                    "QUEUE",
                    "drop",
                    "queue_full_drop_incoming",
                )
                return False

        self.seen.add(event.event_id)
        heapq.heappush(self.queue, event)
        self._log(
            now_ms,
            event.event_id,
            0,
            "FakePhone",
            self.node_id,
            event.priority,
            event.ttl,
            "PHONE_RX",
            "enqueue",
            event.event_type.lower(),
        )
        return True

    def transmit_next(self, now_ms: int, channel: FakeLoRaChannel, dst: str) -> None:
        if not self.queue:
            return
        event = heapq.heappop(self.queue)
        retry = self.retry[event.event_id]
        if retry.attempts >= retry.max_attempts:
            self._log(
                now_ms,
                event.event_id,
                self.packet_seq,
                self.node_id,
                dst,
                event.priority,
                event.ttl,
                "ACK_RETRY",
                "drop",
                "retry_exhausted",
            )
            return

        self.packet_seq += 1
        retry.attempts += 1
        packet = Packet(
            event_id=event.event_id,
            event_type=event.event_type,
            priority=event.priority,
            ttl=event.ttl,
            packet_seq=self.packet_seq,
            src=self.node_id,
            dst=dst,
            payload=event.payload,
        )
        sent = channel.transmit(now_ms, packet)
        if sent:
            self._log(
                now_ms,
                event.event_id,
                packet.packet_seq,
                self.node_id,
                dst,
                event.priority,
                event.ttl,
                "ACK_RETRY",
                "await_ack",
                "bounded_retry",
            )
        else:
            heapq.heappush(self.queue, event)
            self._log(
                now_ms,
                event.event_id,
                packet.packet_seq,
                self.node_id,
                dst,
                event.priority,
                event.ttl,
                "ACK_RETRY",
                "retry",
                "tx_not_accepted",
            )

    def receive_lora(self, now_ms: int, packet: Packet) -> Packet | None:
        if packet.dst != self.node_id:
            return None
        if packet.corrupted:
            self._packet_log(now_ms, packet, "LORA_RX", "drop", "corrupt_packet")
            return None
        if packet.ttl <= 0:
            self._packet_log(now_ms, packet, "LORA_RX", "drop", "ttl_expired")
            return None
        if packet.event_id in self.seen:
            self._packet_log(now_ms, packet, "LORA_RX", "ack", "duplicate_event_id")
            return None

        self.seen.add(packet.event_id)
        self._packet_log(now_ms, packet, "LORA_RX", "rx", "new_event")
        return Packet(
            event_id=packet.event_id,
            event_type=packet.event_type,
            priority=packet.priority,
            ttl=packet.ttl - 1,
            packet_seq=packet.packet_seq,
            src=self.node_id,
            dst="Gateway",
            payload=packet.payload,
            expires_at_ms=packet.expires_at_ms,
            replay_epoch=packet.replay_epoch,
            security_placeholder=packet.security_placeholder,
        )

    def reboot(self, now_ms: int, preserve_seen: bool = True) -> None:
        if not preserve_seen:
            self.seen.clear()
        self.queue.clear()
        self.retry.clear()
        self._log(
            now_ms,
            "",
            0,
            self.node_id,
            self.node_id,
            Priority.P4,
            0,
            "NODE",
            "reboot",
            "persistent_seen_placeholder" if preserve_seen else "volatile_seen_cleared",
        )

    def _packet_log(self, now_ms: int, packet: Packet, layer: str, action: str, reason: str) -> None:
        self._log(
            now_ms,
            packet.event_id,
            packet.packet_seq,
            packet.src,
            packet.dst,
            packet.priority,
            packet.ttl,
            layer,
            action,
            reason,
        )

    def _log(
        self,
        now_ms: int,
        event_id: str,
        packet_seq: int,
        src: str,
        dst: str,
        priority: Priority,
        ttl: int,
        layer: str,
        action: str,
        reason: str,
    ) -> None:
        self.log.write(
            LogRecord(
                timestamp_ms=now_ms,
                node_id=self.node_id,
                layer=layer,
                event_id=event_id,
                packet_seq=packet_seq,
                src=src,
                dst=dst,
                priority=priority.label,
                ttl=ttl,
                action=action,
                reason=reason,
            )
        )


class FakeGatewaySink:
    def __init__(self, log: JsonlLogSink) -> None:
        self.log = log
        self.events: dict[str, dict[str, Any]] = {}
        self.routes: list[Packet] = []

    def receive(self, now_ms: int, packet: Packet) -> None:
        self.routes.append(packet)
        if packet.ttl <= 0:
            self._log(now_ms, packet, "drop_expired", "ttl_expired_placeholder")
            return

        action = "dedupe" if packet.event_id in self.events else "store"
        reason = "event_id_seen" if action == "dedupe" else "canonical_event"
        self.events.setdefault(
            packet.event_id,
            {
                "event_id": packet.event_id,
                "event_type": packet.event_type,
                "priority": packet.priority.label,
                "source_node_id": packet.payload.get("source_node_id", packet.src),
                "payload": packet.payload,
            },
        )
        self._log(now_ms, packet, action, reason)

    def finalize(self) -> None:
        return None

    def _log(self, now_ms: int, packet: Packet, action: str, reason: str) -> None:
        self.log.write(
            LogRecord(
                timestamp_ms=now_ms,
                node_id="Gateway",
                layer="GATEWAY_RX",
                event_id=packet.event_id,
                packet_seq=packet.packet_seq,
                src=packet.src,
                dst="Gateway",
                priority=packet.priority.label,
                ttl=packet.ttl,
                action=action,
                reason=reason,
            )
        )
