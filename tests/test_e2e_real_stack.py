"""B7 — e2e_real_stack acceptance assertions (MASTER §6 B7 DoD D2).

Runs the simulated end-to-end ONCE against the real B6 node executables and
asserts the five required invariants, one per test (file:line reported by the
runner on failure):

  1. PRESENCE reaches the Gateway SQLite as exactly one canonical row.
  2. SOS(RED) reaches the Gateway SQLite as exactly one canonical row.
  3. Within the same window SOS arrives at the gateway before the P3 PRESENCE.
  4. NodeA's log carries a NODE_RECEIPT emit record.
  5. Killing + restarting NodeB and replaying yields no duplicate canonical.

Skipped (not failed) when IGNIRELAY_NODE_EXE is unset/missing so the pure-Python
scenarios still run on hosts without the Linux node build. The official gate
runs this in WSL with the bsim zephyr.exe present.
"""

from __future__ import annotations

import os
import unittest

from ignirelay_lab import e2e_real_stack as e2e


def _exe_available() -> bool:
    try:
        e2e.node_exe_path()
        return True
    except e2e.NodeExeMissing:
        return False


@unittest.skipUnless(_exe_available(),
                     "set IGNIRELAY_NODE_EXE to the field-node bsim zephyr.exe")
class E2ERealStackTests(unittest.TestCase):
    result: e2e.E2EResult

    @classmethod
    def setUpClass(cls) -> None:
        cls.result = e2e.run_e2e_real_stack("e2e_real_stack", seed=7)
        if cls.result.skipped:
            raise unittest.SkipTest(cls.result.skipped)

    # 1 ──────────────────────────────────────────────────────────────────────
    def test_presence_exactly_one_canonical(self) -> None:
        r = self.result
        rows = [e for e in r.gateway_events if e == r.presence_event_id]
        self.assertEqual(len(rows), 1, "PRESENCE must be exactly one canonical")
        self.assertGreaterEqual(
            r.feed_frame_counts.get(r.presence_event_id, 0), 1,
            "PRESENCE must have reached the gateway on air")
        self.assertEqual(r.gateway_events[r.presence_event_id]["event_type"],
                         "PRESENCE")

    # 2 ──────────────────────────────────────────────────────────────────────
    def test_sos_exactly_one_canonical(self) -> None:
        r = self.result
        rows = [e for e in r.gateway_events if e == r.sos_event_id]
        self.assertEqual(len(rows), 1, "SOS must be exactly one canonical")
        self.assertEqual(r.gateway_events[r.sos_event_id]["event_type"], "SOS")
        self.assertEqual(r.gateway_events[r.sos_event_id]["priority"], "SOS_RED")
        # Multi-hop sent >1 copy on air; the gateway deduped them to one row.
        self.assertGreaterEqual(r.feed_frame_counts.get(r.sos_event_id, 0), 2,
                                "expected duplicate SOS frames (multi-hop) to dedupe")

    # 3 ──────────────────────────────────────────────────────────────────────
    def test_sos_arrives_before_presence(self) -> None:
        r = self.result
        order = r.feed_event_order
        self.assertIn(r.sos_event_id, order)
        self.assertIn(r.presence_event_id, order)
        self.assertLess(order.index(r.sos_event_id),
                        order.index(r.presence_event_id),
                        "SOS (prio 1) must reach the gateway before PRESENCE (prio 3)")

    # 4 ──────────────────────────────────────────────────────────────────────
    def test_nodeA_emits_node_receipt(self) -> None:
        r = self.result
        self.assertGreaterEqual(r.nodeA_node_receipts, 1,
                                "NodeA must emit at least one NODE_RECEIPT")
        with open(r.nodeA_out_path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        emit_lines = [ln for ln in text.splitlines()
                      if "layer=NODE_RECEIPT" in ln and "action=emit" in ln]
        self.assertTrue(emit_lines,
                        "NodeA stdout must carry a NODE_RECEIPT emit line")

    # 5 ──────────────────────────────────────────────────────────────────────
    def test_nodeB_restart_no_duplicate_canonical(self) -> None:
        r = self.result
        self.assertEqual(set(r.gateway_events_after_restart),
                         set(r.gateway_events),
                         "NodeB restart+replay must not add a canonical event")
        self.assertEqual(len(r.gateway_events_after_restart),
                         len(r.gateway_events),
                         "no duplicate canonical after NodeB restart")
        self.assertIn(r.sos_event_id, r.gateway_events_after_restart)


if __name__ == "__main__":
    unittest.main()
