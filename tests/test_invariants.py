"""B3 invariant tests (PHASE3 §6.1 — each invariant has one named test).

These exercise the REAL verification/scheduling paths: a tampered envelope is
rejected by the actual Ed25519 / field_mac checks, a corrupted LoRa frame by the
actual CRC, etc. No stub stands in for the unit under test (G4).
"""

import random
import unittest

from ignirelay_lab import corpus_fixtures as fx
from ignirelay_lab.actors import (
    LOSS_BUDGET_CRITICAL,
    RECEIPT_ACCEPTED,
    RECEIPT_DUPLICATE,
    RECEIPT_REJECTED,
    FakeBleLink,
    FakePhone,
    SimNode,
)
from ignirelay_lab.channel import ChannelProfile, FakeLoRaChannel, TransmitOutcome
from ignirelay_lab.logging_utils import JsonlLogSink
from ignirelay_lab.model import WirePriority
from ignirelay_lab.wire import keys
from ignirelay_lab.wire import lora_v1 as lora


def _node(name="NodeA", num=1, max_queue_size=8, seed=1):
    return SimNode(name, JsonlLogSink(f"test_{name}_{num}"), node_num=num,
                   rng=random.Random(seed), max_queue_size=max_queue_size)


class PriorityInvariants(unittest.TestCase):
    def test_p0_sos_preempts_lower_priority(self) -> None:
        """P0/SOS preempt: SOS_RED is at the head ahead of a queued PRESENCE."""
        phone, ble, node = FakePhone(), FakeBleLink(), _node()
        ble.send_envelope(node, 0, phone.presence(0).envelope_bytes)
        ble.send_envelope(node, 1, phone.sos(1).envelope_bytes)
        self.assertEqual(node.queue[0].priority, WirePriority.SOS_RED)
        self.assertEqual(node.queue[0].event_type, 1)

    def test_lowest_priority_shed_first_under_queue_pressure(self) -> None:
        """Under queue pressure the least-severe queued event is evicted; the
        critical SOS is retained (heartbeat=NORMAL would be shed even sooner)."""
        phone, ble, node = FakePhone(), FakeBleLink(), _node(max_queue_size=2)
        ble.send_envelope(node, 0, phone.checkpoint(0).envelope_bytes)  # STATUS(4)
        ble.send_envelope(node, 1, phone.presence(1).envelope_bytes)    # ALERT(3)
        r = ble.send_envelope(node, 2, phone.sos(2).envelope_bytes)     # SOS_RED(1)
        self.assertEqual(r.status, RECEIPT_ACCEPTED)
        self.assertEqual(len(node.queue), 2)
        self.assertTrue(any(e.priority == WirePriority.SOS_RED for e in node.queue))
        self.assertTrue(any(e.priority == WirePriority.STATUS
                            for e in node.dropped_events))

    def test_sos_preempts_under_busy_channel(self) -> None:
        """SOS under a busy channel still goes out before the lower-priority
        PRESENCE (its await_ack precedes presence's in the structured log)."""
        import json
        phone, ble = FakePhone(), FakeBleLink()
        log = JsonlLogSink("test_sos_preempt_busy")
        node = SimNode("NodeA", log, node_num=1, rng=random.Random(3))
        channel = FakeLoRaChannel(
            ChannelProfile(channel_busy_percent=70, delay_ms_min=10,
                           delay_ms_max=20), log, random.Random(3))
        presence = phone.presence(0)
        sos = phone.sos(1)
        ble.send_envelope(node, 0, presence.envelope_bytes)
        ble.send_envelope(node, 1, sos.envelope_bytes)
        for step in range(80):
            node.transmit_next(step * 100, channel, "NodeB")
        lines = log.path.read_text(encoding="utf-8").splitlines()
        sent = [json.loads(l) for l in lines if '"await_ack"' in l]
        order = [r["event_id"] for r in sent]
        self.assertIn(sos.event_id_hex, order)
        self.assertIn(presence.event_id_hex, order)
        self.assertLess(order.index(sos.event_id_hex),
                        order.index(presence.event_id_hex))


class RetryInvariants(unittest.TestCase):
    def test_bounded_loss_retry_then_drop(self) -> None:
        """Bounded retry: under 100% loss, an SOS is retried up to the budget
        then dropped (retry-exhausted) — the node does not spin forever."""
        phone, ble = FakePhone(), FakeBleLink()
        log = JsonlLogSink("test_bounded_retry")
        node = SimNode("NodeA", log, node_num=1, rng=random.Random(5))
        channel = FakeLoRaChannel(ChannelProfile(packet_loss_percent=100), log,
                                  random.Random(5))
        sos = phone.sos(0)
        ble.send_envelope(node, 0, sos.envelope_bytes)
        for step in range(40):
            node.transmit_next(step * 1000, channel, "NodeB")
        self.assertEqual(node.retry[sos.event_id_hex].loss_attempts,
                         LOSS_BUDGET_CRITICAL)
        self.assertEqual(node.queue, [])
        self.assertTrue(any(e.event_id_hex == sos.event_id_hex
                            for e in node.dropped_events))

    def test_retry_uses_jitter(self) -> None:
        """Retry backoff carries jitter (within [base, base+jitter], not fixed)."""
        from ignirelay_lab.actors import RETRY_BACKOFF_MS, RETRY_JITTER_MS
        phone, ble = FakePhone(), FakeBleLink()
        log = JsonlLogSink("test_jitter")
        node = SimNode("NodeA", log, node_num=1, rng=random.Random(11))
        channel = FakeLoRaChannel(ChannelProfile(packet_loss_percent=100), log,
                                  random.Random(11))
        sos = phone.sos(0)
        ble.send_envelope(node, 0, sos.envelope_bytes)
        offsets = []
        for i in range(LOSS_BUDGET_CRITICAL):
            now = i * 1000
            node.transmit_next(now, channel, "NodeB")
            offsets.append(node.retry[sos.event_id_hex].next_attempt_ms - now)
        for off in offsets:
            self.assertGreaterEqual(off, RETRY_BACKOFF_MS)
            self.assertLessEqual(off, RETRY_BACKOFF_MS + RETRY_JITTER_MS)
        self.assertGreater(len(set(offsets)), 1)  # jitter actually varies


class AckIdempotency(unittest.TestCase):
    def test_node_receipt_idempotent_on_duplicate_envelope(self) -> None:
        """Re-ingesting the same envelope → DUPLICATE; queue depth unchanged."""
        phone, ble, node = FakePhone(), FakeBleLink(), _node()
        sos = phone.sos(0)
        r1 = ble.send_envelope(node, 0, sos.envelope_bytes)
        depth = len(node.queue)
        r2 = ble.send_envelope(node, 1, sos.envelope_bytes)
        self.assertEqual(r1.status, RECEIPT_ACCEPTED)
        self.assertEqual(r2.status, RECEIPT_DUPLICATE)
        self.assertEqual(len(node.queue), depth)
        self.assertEqual(r2.ref_envelope_id, sos.envelope_id)

    def test_lora_ack_is_idempotent(self) -> None:
        """A LoRa ACK frame verifies identically however many times it is seen
        (ACKs never enter the dedupe ring — §3.3 / §7)."""
        tf = fx.test_field()
        ack = lora.encode_ack_frame(
            lora_mac_key=tf.lora_mac_key, flags=0, field_tag=tf.field_tag,
            src_node=9, packet_seq=1, ttl=3, ack_seq=42,
            event_id_prefix=b"\x01" * 8, status=0)
        seen: set[str] = set()
        r1 = lora.verify_lora_frame(ack, lora_mac_key=tf.lora_mac_key,
                                    seen_event_ids=seen)
        r2 = lora.verify_lora_frame(ack, lora_mac_key=tf.lora_mac_key,
                                    seen_event_ids=seen)
        self.assertIsNone(r1.reason)
        self.assertIsNone(r2.reason)
        self.assertEqual(r1.parsed.status, r2.parsed.status)
        self.assertEqual(seen, set())  # ACKs do not populate the replay ring


class IngestVerification(unittest.TestCase):
    """The node really verifies — tampering is rejected by the actual checks."""

    def setUp(self) -> None:
        self.phone, self.ble, self.node = FakePhone(), FakeBleLink(), _node()

    def test_valid_envelope_accepted(self) -> None:
        r = self.ble.send_envelope(self.node, 0,
                                   self.phone.sos(0).envelope_bytes)
        self.assertEqual(r.status, RECEIPT_ACCEPTED)

    def test_tampered_signature_rejected(self) -> None:
        env = bytearray(self.phone.sos(0).envelope_bytes)
        env[-1] ^= 0xFF  # flip a field_mac byte → field_mac fails first
        r = self.ble.send_envelope(self.node, 0, bytes(env))
        self.assertEqual(r.status, RECEIPT_REJECTED)

    def test_wrong_field_mac_rejected(self) -> None:
        # Re-sign a valid canonical but stamp a field_mac from a different key.
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        from ignirelay_lab.wire import envelope_v3 as ev
        sos = self.phone.sos(0)
        env = ev.EventEnvelopeV2.decode(sos.envelope_bytes)
        canonical = self.node._canonical(env)
        bad_key = keys.derive_lora_mac_key(b"not-the-field-secret")  # wrong key
        env.field_mac = keys.compute_field_mac(bad_key, canonical)
        r = self.node.ble_ingest(0, env.encode())
        self.assertEqual(r.status, RECEIPT_REJECTED)

    def test_expired_envelope_rejected(self) -> None:
        r = self.ble.send_envelope(self.node, 1000,
                                   self.phone.expired_sos(1000).envelope_bytes)
        self.assertEqual(r.status, RECEIPT_REJECTED)


class LoraIntegrity(unittest.TestCase):
    def _valid_frame(self):
        phone, ble, node = FakePhone(), FakeBleLink(), _node()
        ble.send_envelope(node, 0, phone.sos(0).envelope_bytes)
        node.packet_seq += 1
        return node, node.build_frame(node.queue[0], "NodeB")

    def test_corrupted_frame_rejected_by_crc(self) -> None:
        node, frame = self._valid_frame()
        raw = bytearray(frame.raw)
        raw[11] ^= 0xFF  # flip a body byte, leave CRC stale
        from ignirelay_lab.model import LoraFrame
        bad = LoraFrame(raw=bytes(raw), src="X", dst="NodeB",
                        event_id_hex=frame.event_id_hex,
                        event_type=frame.event_type,
                        priority_label=frame.priority_label, ttl=frame.ttl,
                        packet_seq=frame.packet_seq)
        peer = _node("NodeB", 2)
        self.assertIsNone(peer.receive_lora(0, bad))

    def test_forged_mac_rejected(self) -> None:
        node, frame = self._valid_frame()
        raw = bytearray(frame.raw)
        mac_off = len(raw) - lora.MAC8_BYTES - lora.CRC16_BYTES
        raw[mac_off] ^= 0xFF  # forge MAC...
        crc = lora.crc16_ccitt(bytes(raw[:-2]))  # ...and restamp CRC so MAC is the gate
        raw[-2], raw[-1] = crc & 0xFF, (crc >> 8) & 0xFF
        tf = fx.test_field()
        res = lora.verify_lora_frame(bytes(raw), lora_mac_key=tf.lora_mac_key,
                                     seen_event_ids=set())
        self.assertEqual(res.reason, "mac-mismatch")


if __name__ == "__main__":
    unittest.main()
