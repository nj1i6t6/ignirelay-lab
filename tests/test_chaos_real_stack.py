"""B8 — chaos all-green acceptance assertions (MASTER §6 B8 DoD).

Runs the B7 e2e_real_stack topology (real B6 node executables + real LORA-WIRE
frames + real B4 gateway verification) under chaos profiles and asserts:

  1. loss_50         : SOS eventually delivered, no duplicate canonical.
  2. 20% loss        : SOS delivery 100% (a burst within the node TX buffer).
  3. partition_heal  : SOS delivered after the link heals (via bounded retry).
  4. asymmetric_link : SOS delivered despite a one-way (no reverse ACK) link.
  5. retry bound     : the real node never transmits an event more than 3 times
                       (lora_wire ACK/retry ≤3 — the B8 red line).

Random seeds are fixed (recorded in each logs/<scenario>/report.json). Resilience
comes from the real C node's bounded retry + TTL relay; the hub only loses /
corrupts / partitions bytes — it never retransmits on the node's behalf.

Skipped (not failed) when IGNIRELAY_NODE_EXE is unset/missing so the pure-Python
scenarios still run on hosts without the Linux node build.
"""

from __future__ import annotations

import os
import re
import unittest

from ignirelay_lab.channel import ChannelProfile
from ignirelay_lab import e2e_real_stack as e2e

SEED = 7
_TX_RE = re.compile(r"layer=LORA_TX .*?event_id=([0-9a-f]+).*?action=(transmit|retransmit)")


def _exe_available() -> bool:
    try:
        e2e.node_exe_path()
        return True
    except e2e.NodeExeMissing:
        return False


def _max_tx_attempts_per_event(stdout: str) -> int:
    counts: dict[str, int] = {}
    for line in stdout.splitlines():
        m = _TX_RE.search(line)
        if m:
            counts[m.group(1)] = counts.get(m.group(1), 0) + 1
    return max(counts.values(), default=0)


@unittest.skipUnless(_exe_available(),
                     "set IGNIRELAY_NODE_EXE to the field-node bsim zephyr.exe")
class ChaosRealStackTests(unittest.TestCase):
    loss50: e2e.ChaosResult
    loss20: e2e.ChaosResult
    partition: e2e.ChaosResult
    asymmetric: e2e.ChaosResult

    @classmethod
    def setUpClass(cls) -> None:
        prof = ChannelProfile.from_file
        cls.loss50 = e2e.run_chaos_real_stack(
            "loss_50", prof("profiles/loss_50.json"), SEED, sos_count=1)
        # 20% loss, 100% delivery: a burst of distinct SOS within the node's
        # bounded TX buffer (IR_RT_TX_CAP=8); each must reach the gateway.
        cls.loss20 = e2e.run_chaos_real_stack(
            "loss_20_realstack", prof("profiles/loss_20.json"), SEED,
            sos_count=6, with_presence=False)
        cls.partition = e2e.run_chaos_real_stack(
            "partition_heal", prof("profiles/partition_heal.json"), SEED,
            sos_count=1)
        cls.asymmetric = e2e.run_chaos_real_stack(
            "asymmetric_link", prof("profiles/asymmetric_link.json"), SEED,
            sos_count=1)
        for r in (cls.loss50, cls.loss20, cls.partition, cls.asymmetric):
            if r.skipped:
                raise unittest.SkipTest(r.skipped)

    # 1 ──────────────────────────────────────────────────────────────────────
    def test_loss_50_sos_eventually_delivered_no_duplicate(self) -> None:
        inv = self.loss50.report["invariants"]
        self.assertTrue(inv["sos_delivered"],
                        "50% loss: SOS must eventually be delivered")
        self.assertTrue(inv["no_duplicate_canonical"],
                        "50% loss: no duplicate canonical")
        # honest chaos really dropped frames on air
        self.assertGreater(self.loss50.report["frames"]["tap_dropped_loss"] +
                           self.loss50.report["frames"]["fanout_dropped_loss"], 0,
                           "50% profile must actually drop frames")

    # 2 ──────────────────────────────────────────────────────────────────────
    def test_loss_20_sos_delivery_100_percent(self) -> None:
        inv = self.loss20.report["invariants"]
        self.assertEqual(inv["sos_delivery_ratio"], 1.0,
                         "20% loss: SOS delivery must be 100%")
        self.assertEqual(len(self.loss20.delivered_sos),
                         len(self.loss20.sos_event_ids))
        self.assertTrue(inv["no_duplicate_canonical"])

    # 3 ──────────────────────────────────────────────────────────────────────
    def test_partition_heal_sos_delivered_after_heal(self) -> None:
        inv = self.partition.report["invariants"]
        self.assertTrue(inv["sos_delivered"],
                        "partition_heal: SOS must be delivered after the heal")
        self.assertTrue(inv["no_duplicate_canonical"])
        self.assertTrue(inv["nodeA_retransmitted"],
                        "partition_heal: delivery must come from a retry, not the "
                        "first (partitioned) attempt")
        self.assertGreater(self.partition.report["frames"]["fanout_dropped_partition"],
                           0, "partition window must actually drop frames")

    # 4 ──────────────────────────────────────────────────────────────────────
    def test_asymmetric_link_sos_delivered_one_way(self) -> None:
        inv = self.asymmetric.report["invariants"]
        self.assertTrue(inv["sos_delivered"],
                        "asymmetric_link: SOS must be delivered over the working "
                        "direction")
        self.assertTrue(inv["no_duplicate_canonical"])
        self.assertTrue(inv["nodeA_retransmitted"],
                        "asymmetric_link: no reverse ACK echo -> the node retries")
        self.assertGreater(
            self.asymmetric.report["frames"]["fanout_dropped_asymmetric"], 0,
            "asymmetric profile must drop the reverse-direction link")

    # 5 ──────────────────────────────────────────────────────────────────────
    def test_retry_never_exceeds_spec_bound(self) -> None:
        """The real node must never transmit an event more than 3 times
        (lora_wire ACK/retry ≤3 — B8 red line)."""
        for r in (self.loss50, self.loss20, self.partition, self.asymmetric):
            out_path = os.path.join("logs", r.name, "nodeA.out")
            with open(out_path, encoding="utf-8", errors="replace") as fh:
                stdout = fh.read()
            self.assertLessEqual(
                _max_tx_attempts_per_event(stdout), 3,
                f"{r.name}: an event was transmitted more than 3 times")


if __name__ == "__main__":
    unittest.main()
