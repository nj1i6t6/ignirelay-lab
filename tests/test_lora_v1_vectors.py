"""B2 conformance: lab Python lora_v1 vs the App's frozen LoRa vectors.

Reads `IgniRelay/docs/specs/lora_wire_v1_vectors.json` (override the App repo
location with env var IGNIRELAY_APP_DIR) and verifies, for EVERY vector
(no sampling, no skipping — MASTER §6 B2):
  - CRC-16/CCITT-FALSE standard check value "123456789" -> 0x29B1,
  - lora_mac_key reproduced from the corpus TEST-ONLY secret,
  - every POSITIVE frame: verify accepts, committed mac8/crc16 match a live
    recompute, decode -> re-encode is bit-identical,
  - every NEGATIVE frame: rejected with exactly its declared reason.

Total vector count (positive + negative) is printed and asserted >= 50.
"""

from __future__ import annotations

import json
import os
import unittest
from pathlib import Path

from ignirelay_lab.wire import keys
from ignirelay_lab.wire import lora_v1 as lora


def _app_dir() -> Path:
    override = os.environ.get("IGNIRELAY_APP_DIR")
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[2] / "IgniRelay"


def _vectors_path() -> Path:
    return _app_dir() / "docs" / "specs" / "lora_wire_v1_vectors.json"


def _load_vectors() -> dict:
    return json.loads(_vectors_path().read_text(encoding="utf-8"))


class LoraV1VectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.vectors = _load_vectors()
        tf = cls.vectors["test_field"]
        cls.secret = bytes.fromhex(tf["field_join_secret_hex"])
        cls.lora_mac_key = keys.derive_lora_mac_key(cls.secret)
        assert cls.lora_mac_key.hex() == tf["lora_mac_key_hex"]

    def test_vectors_path_exists(self) -> None:
        self.assertTrue(
            _vectors_path().exists(),
            f"vectors not found at {_vectors_path()} "
            f"(set IGNIRELAY_APP_DIR to the App repo root)",
        )

    def test_crc16_ccitt_false_standard_check_value(self) -> None:
        self.assertEqual(lora.crc16_ccitt(b"123456789"), 0x29B1)
        self_test = self.vectors["meta"]["crc16_self_test"]
        self.assertEqual(self_test["expected_hex"], "29b1")
        self.assertEqual(self_test["actual_hex"], "29b1")

    def test_lora_mac_key_reproduced_and_domain_separated(self) -> None:
        tf = self.vectors["test_field"]
        self.assertEqual(self.lora_mac_key.hex(), tf["lora_mac_key_hex"])
        # Domain separation: LoRa key != BLE field-mac key from the same secret.
        self.assertNotEqual(
            self.lora_mac_key, keys.derive_field_mac_key(self.secret)
        )
        # field_tag = first 4 bytes of field_id.
        self.assertEqual(
            tf["field_tag_hex"], keys.derive_field_id(self.secret)[:4].hex()
        )

    def test_every_positive_frame_verifies_and_roundtrips(self) -> None:
        frames = self.vectors["frames"]
        events = acks = 0
        for s in frames:
            name = s["name"]
            frame = bytes.fromhex(s["frame_hex"])

            res = lora.verify_lora_frame(
                frame,
                lora_mac_key=self.lora_mac_key,
                local_est_ms=s.get("hlc_ms"),
                seen_event_ids=set(),
            )
            self.assertIsNone(res.reason, f"positive '{name}' rejected: {res.reason}")
            self.assertIsNotNone(res.parsed)

            # committed mac8 / crc16 trailers match a live recompute
            mac_off = len(frame) - lora.MAC8_BYTES - lora.CRC16_BYTES
            self.assertEqual(
                s["mac8_hex"], frame[mac_off:mac_off + lora.MAC8_BYTES].hex(),
                f"{name}: mac8 trailer",
            )
            self.assertEqual(
                s["crc16_hex"], frame[-lora.CRC16_BYTES:].hex(),
                f"{name}: crc16 trailer",
            )

            # decode -> re-encode bit-identical
            self.assertEqual(
                lora.reencode_frame(res.parsed, self.lora_mac_key), frame,
                f"{name}: re-encode drift",
            )

            if s["ptype"] == lora.PTYPE_EVENT:
                events += 1
            else:
                acks += 1

        print(f"\n[B2] lora positive frames: {len(frames)} "
              f"(event={events}, ack={acks})")
        self.assertGreaterEqual(events, 40)
        self.assertGreaterEqual(acks, 3)

    def test_every_negative_frame_rejected_with_declared_reason(self) -> None:
        negatives = self.vectors["negative"]
        reasons = set()
        for n in negatives:
            name = n["name"]
            frame = bytes.fromhex(n["frame_hex"])
            seen = set()
            if n.get("precondition_seen_event_id_hex"):
                seen.add(n["precondition_seen_event_id_hex"].lower())
            res = lora.verify_lora_frame(
                frame,
                lora_mac_key=self.lora_mac_key,
                local_est_ms=n.get("local_est_ms"),
                seen_event_ids=seen,
            )
            self.assertEqual(
                res.reason, n["expect_reason"], f"negative '{name}'"
            )
            reasons.add(n["expect_reason"])
        print(f"[B2] lora negative frames: {len(negatives)}")
        # The B1 step-3 mandated negative classes are all present.
        self.assertTrue(
            {"mac-mismatch", "crc-mismatch", "ttl-expired", "replay-duplicate",
             "replay-window", "truncated", "unknown-ptype", "unknown-version"}
            <= reasons,
            f"missing required negative classes: {reasons}",
        )

    def test_total_vector_count_at_least_50(self) -> None:
        total = len(self.vectors["frames"]) + len(self.vectors["negative"])
        print(f"[B2] lora total vectors: {total}")
        self.assertGreaterEqual(total, 50)


if __name__ == "__main__":
    unittest.main()
