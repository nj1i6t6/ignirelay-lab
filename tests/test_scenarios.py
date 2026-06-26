"""B3 scenario tests — every scenario runs on real EventEnvelope + LoRa bytes.

Mirrors GATE-SCEN: each scenario is evaluated by the same genuine invariant the
CLI uses (no hard-coded expected event ids).
"""

import unittest

from ignirelay_lab.channel import ChannelProfile
from ignirelay_lab.cli import DEFAULT_SEEDS, evaluate
from ignirelay_lab.scenario import run_scenario


def _run(name: str, profile: ChannelProfile, seed: int | None = None):
    return run_scenario(name, profile, seed=seed if seed is not None
                        else DEFAULT_SEEDS[name],
                        gateway_mode="cli" if name in
                        {"gateway_cli", "gateway_reboot"} else "fake")


class ScenarioTests(unittest.TestCase):
    def test_normal_delivers_presence_and_sos(self) -> None:
        r = _run("normal", ChannelProfile.from_file("profiles/normal.json"))
        self.assertEqual(len(r.delivered_event_ids), 2)
        self.assertIn(r.sos_event_id, r.delivered_event_ids)
        self.assertTrue(evaluate(r)[0])

    def test_loss_20_sos_always_delivered(self) -> None:
        prof = ChannelProfile.from_file("profiles/loss_20.json")
        # DoD D4: 20% loss → SOS delivery 100% (proved across many seeds), no dup.
        for seed in range(40):
            r = run_scenario("loss_20", prof, seed=seed)
            self.assertIn(r.sos_event_id, r.delivered_event_ids,
                          f"SOS lost at seed {seed}")
            self.assertEqual(len(r.delivered_event_ids),
                             len(set(r.delivered_event_ids)))

    def test_busy_sos_delivers_under_channel_pressure(self) -> None:
        r = _run("busy_sos",
                 ChannelProfile.from_file("profiles/channel_busy_80.json"))
        self.assertIn(r.sos_event_id, r.delivered_event_ids)
        self.assertTrue(evaluate(r)[0])

    def test_gateway_cli_integration_delivers_two(self) -> None:
        r = _run("gateway_cli", ChannelProfile.from_file("profiles/normal.json"))
        self.assertEqual(r.gateway_mode, "cli")
        self.assertEqual(len(r.delivered_event_ids), 2)
        self.assertTrue(evaluate(r)[0])

    def test_node_reboot_keeps_single_canonical(self) -> None:
        r = _run("node_reboot", ChannelProfile.from_file("profiles/normal.json"))
        self.assertEqual(r.delivered_event_ids, [r.sos_event_id])
        self.assertTrue(evaluate(r)[0])

    def test_gateway_reboot_keeps_sqlite_dedupe(self) -> None:
        r = _run("gateway_reboot",
                 ChannelProfile.from_file("profiles/normal.json"))
        self.assertEqual(len(r.delivered_event_ids), 1)
        self.assertTrue(evaluate(r)[0])

    def test_duplicate_storm_single_canonical(self) -> None:
        r = _run("duplicate_storm_10_nodes",
                 ChannelProfile.from_file("profiles/duplicate_storm_10_nodes.json"))
        self.assertEqual(r.delivered_event_ids, [r.sos_event_id])
        self.assertTrue(evaluate(r)[0])

    def test_replayed_valid_packet_deduped(self) -> None:
        r = _run("replayed_valid_packet",
                 ChannelProfile.from_file("profiles/normal.json"))
        self.assertEqual(r.delivered_event_ids, [r.sos_event_id])
        self.assertTrue(evaluate(r)[0])

    def test_expired_event_not_delivered(self) -> None:
        r = _run("expired_event", ChannelProfile.from_file("profiles/normal.json"))
        self.assertEqual(r.delivered_event_ids, [])
        self.assertTrue(evaluate(r)[0])


if __name__ == "__main__":
    unittest.main()
