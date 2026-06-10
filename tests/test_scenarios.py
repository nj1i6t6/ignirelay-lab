import random
import unittest

from ignirelay_lab.actors import FakePhone, SimNode
from ignirelay_lab.channel import ChannelProfile, FakeLoRaChannel
from ignirelay_lab.logging_utils import JsonlLogSink
from ignirelay_lab.model import Priority
from ignirelay_lab.scenario import run_scenario


class ScenarioSmokeTests(unittest.TestCase):
    def test_normal_delivers_presence_and_sos(self) -> None:
        result = run_scenario("normal", ChannelProfile(), seed=1)
        self.assertEqual(len(result.delivered_event_ids), 2)

    def test_loss_20_has_at_least_one_delivery(self) -> None:
        profile = ChannelProfile(packet_loss_percent=20, duplicate_percent=5)
        result = run_scenario("loss_20", profile, seed=7)
        self.assertGreaterEqual(len(result.delivered_event_ids), 1)

    def test_busy_sos_delivers_sos_under_channel_pressure(self) -> None:
        profile = ChannelProfile(
            packet_loss_percent=5,
            duplicate_percent=10,
            reorder_percent=10,
            corrupt_percent=1,
            channel_busy_percent=80,
        )
        result = run_scenario("busy_sos", profile, seed=1)
        self.assertIn("sos-1-phone-lab-1", result.delivered_event_ids)

    def test_gateway_cli_integration_delivers_events(self) -> None:
        result = run_scenario("gateway_cli", ChannelProfile(), seed=1, gateway_mode="cli")
        self.assertEqual(result.gateway_mode, "cli")
        self.assertEqual(len(result.delivered_event_ids), 2)

    def test_node_reboot_keeps_duplicate_from_user_visible_event(self) -> None:
        result = run_scenario("node_reboot", ChannelProfile(), seed=1)
        self.assertEqual(result.delivered_event_ids, ["node-reboot-event"])

    def test_gateway_reboot_keeps_sqlite_dedupe_state(self) -> None:
        result = run_scenario("gateway_reboot", ChannelProfile(), seed=1)
        self.assertEqual(result.delivered_event_ids, ["gateway-reboot-event"])

    def test_duplicate_storm_has_one_user_visible_event(self) -> None:
        result = run_scenario("duplicate_storm_10_nodes", ChannelProfile(), seed=1)
        self.assertEqual(result.delivered_event_ids, ["storm-event-1"])

    def test_replayed_valid_packet_is_deduped(self) -> None:
        result = run_scenario("replayed_valid_packet", ChannelProfile(), seed=1)
        self.assertEqual(result.delivered_event_ids, ["replay-event-1"])

    def test_expired_event_skeleton_does_not_deliver(self) -> None:
        result = run_scenario("expired_event", ChannelProfile(), seed=1)
        self.assertEqual(result.delivered_event_ids, [])


class InvariantTests(unittest.TestCase):
    def test_p0_sos_is_dequeued_before_p3_presence(self) -> None:
        log = JsonlLogSink("test_p0_priority")
        phone = FakePhone()
        node = SimNode("NodeA", log)
        node.ingest_phone_event(0, phone.presence(0, "NodeA"))
        node.ingest_phone_event(1, phone.sos(1, "NodeA"))

        first = node.queue[0]
        self.assertEqual(first.priority, Priority.P0)
        self.assertEqual(first.event_type, "SOS")

    def test_p4_is_dropped_before_p0_under_queue_pressure(self) -> None:
        log = JsonlLogSink("test_p4_drop")
        phone = FakePhone()
        node = SimNode("NodeA", log, max_queue_size=2)
        node.ingest_phone_event(0, phone.heartbeat(0, "NodeA", index=1))
        node.ingest_phone_event(1, phone.heartbeat(1, "NodeA", index=2))
        node.ingest_phone_event(2, phone.sos(2, "NodeA"))

        self.assertEqual(len(node.queue), 2)
        self.assertTrue(any(event.priority == Priority.P0 for event in node.queue))
        self.assertTrue(any(event.priority == Priority.P4 for event in node.dropped_events))

    def test_retry_is_bounded(self) -> None:
        log = JsonlLogSink("test_retry_bounded")
        phone = FakePhone()
        node = SimNode("NodeA", log)
        channel = FakeLoRaChannel(
            ChannelProfile(channel_busy_percent=100),
            log,
            random.Random(1),
        )
        event = phone.sos(1, "NodeA")
        node.ingest_phone_event(1, event)
        for step in range(8):
            node.transmit_next(step * 100, channel, "NodeB")

        self.assertEqual(node.retry[event.event_id].attempts, 3)
        self.assertEqual(node.queue, [])


if __name__ == "__main__":
    unittest.main()
