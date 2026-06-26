"""B2 conformance: lab Python envelope_v3 vs the App's frozen corpus.

Reads `IgniRelay/docs/specs/wire_conformance_v1.json` (override the App repo
location with env var IGNIRELAY_APP_DIR) and verifies, for EVERY envelope sample
(no sampling, no skipping — MASTER §6 B2):
  - payload reconstruction (payload_hex or LCG generator) -> SHA-256 matches,
  - the 141-byte canonical signature input is byte-identical to the corpus,
  - field_mac = HMAC-SHA256(field_mac_key, canonical)[0..15] matches (control
    frames carry an all-zero field_id and no field_mac),
  - the Ed25519 signature verifies for every signed sample.
Plus: typed payload struct decode + round-trip for the typed samples, a full
EventEnvelopeV2 proto encode->decode round-trip, and every negative_case is
rejected with its spec drop_reason.

The sample count is printed and asserted >= 104.
"""

from __future__ import annotations

import json
import os
import unittest
from pathlib import Path

from ignirelay_lab.wire import envelope_v3 as ev
from ignirelay_lab.wire import keys


def _app_dir() -> Path:
    override = os.environ.get("IGNIRELAY_APP_DIR")
    if override:
        return Path(override)
    # Default: sibling of the lab repo, IDE/IgniRelay.
    return Path(__file__).resolve().parents[2] / "IgniRelay"


def _corpus_path() -> Path:
    return _app_dir() / "docs" / "specs" / "wire_conformance_v1.json"


def _load_corpus() -> dict:
    return json.loads(_corpus_path().read_text(encoding="utf-8"))


def _payload_bytes(struct: dict) -> bytes:
    if "payload_hex" in struct:
        return bytes.fromhex(struct["payload_hex"])
    gen = struct["payload_generator"]
    assert gen["algorithm"] == "lcg_byte_pattern_v1", gen
    return ev.lcg_payload(gen["seed"], gen["size"])


def _build_canonical(struct: dict, payload: bytes) -> bytes:
    created = struct["created_at_hlc"]
    expires = struct["expires_at_hlc"]
    return ev.canonical_sig_input_v3(
        protocol_version=struct["protocol_version"],
        envelope_id=bytes.fromhex(struct["envelope_id_hex"]),
        field_id=bytes.fromhex(struct["field_id_hex"]),
        event_type=struct["event_type"],
        priority=struct["priority"],
        created_ms=created["ms_since_epoch"],
        created_counter=created["counter"],
        expires_ms=expires["ms_since_epoch"],
        expires_counter=expires["counter"],
        max_hops=struct["max_hops"],
        author_key=bytes.fromhex(struct["author_key_hex"]),
        sig_algo=struct["sig_algo"],
        payload_sha256=ev.payload_hash(payload),
    )


class EnvelopeV3ConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.corpus = _load_corpus()
        tf = cls.corpus["test_field"]
        cls.secret = bytes.fromhex(tf["field_join_secret_hex"])
        cls.field_mac_key = keys.derive_field_mac_key(cls.secret)
        # Sanity: derived keys reproduce the corpus test_field exactly.
        assert keys.derive_field_id(cls.secret).hex() == tf["field_id_hex"]
        assert cls.field_mac_key.hex() == tf["field_mac_key_hex"]

    def test_corpus_path_exists(self) -> None:
        self.assertTrue(
            _corpus_path().exists(),
            f"corpus not found at {_corpus_path()} "
            f"(set IGNIRELAY_APP_DIR to the App repo root)",
        )

    def test_every_envelope_sample_canonical_signature_field_mac(self) -> None:
        samples = self.corpus["envelope_samples"]
        signed = 0
        control = 0
        for s in samples:
            name = s["name"]
            struct = s["envelope_struct"]
            payload = _payload_bytes(struct)

            # payload hash
            self.assertEqual(
                ev.payload_hash(payload).hex(), s["payload_sha256_hex"],
                f"{name}: payload sha256 mismatch",
            )

            # 141-byte canonical signature input
            sig_input = _build_canonical(struct, payload)
            self.assertEqual(
                len(sig_input), s["expected_canonical_sig_input_bytes"],
                f"{name}: canonical length",
            )
            self.assertEqual(len(sig_input), ev.CANONICAL_SIG_INPUT_BYTES)
            self.assertEqual(
                sig_input.hex(), s["expected_canonical_sig_input_hex"],
                f"{name}: canonical bytes mismatch",
            )

            # field_mac (control frames: zero field_id, no field_mac)
            field_mac_hex = struct["field_mac_hex"]
            if field_mac_hex == "":
                self.assertEqual(
                    struct["field_id_hex"], "00" * 16,
                    f"{name}: empty field_mac requires zero field_id (control)",
                )
                control += 1
            else:
                self.assertEqual(
                    keys.compute_field_mac(self.field_mac_key, sig_input).hex(),
                    field_mac_hex, f"{name}: field_mac mismatch",
                )

            # signature
            if s.get("expected_signature_hex"):
                self.assertEqual(
                    struct["author_key_hex"], s["derived_author_key_hex"],
                    f"{name}: author key mismatch",
                )
                self.assertTrue(
                    ev.ed25519_verify(
                        bytes.fromhex(struct["author_key_hex"]),
                        sig_input,
                        bytes.fromhex(s["expected_signature_hex"]),
                    ),
                    f"{name}: Ed25519 signature did not verify",
                )
                signed += 1

        print(
            f"\n[B2] envelope_samples verified: {len(samples)} "
            f"(signed={signed}, control={control})"
        )
        self.assertGreaterEqual(
            len(samples), 104, "corpus must carry >= 104 envelope samples"
        )

    def test_typed_payload_structs_decode_and_roundtrip(self) -> None:
        by_name = {s["name"]: s for s in self.corpus["envelope_samples"]}

        # StatusUpdateData TRAPPED + 2 needs + full location, bearing absent.
        s = by_name["status_trapped_loc_bearing_absent"]
        payload = _payload_bytes(s["envelope_struct"])
        status = ev.StatusUpdateData.decode(payload)
        self.assertEqual(status.safety_state, 4)  # trapped
        self.assertEqual(len(status.needs), 2)
        self.assertIsNotNone(status.location)
        self.assertEqual(status.location.lat_e7, 250339805)
        self.assertEqual(status.location.lng_e7, 1215654177)
        self.assertIsNone(status.location.bearing_deg)
        self.assertEqual(status.encode(), payload, "StatusUpdate re-encode drift")

        # bearing = 0 (due north) must survive as 0, distinct from absent.
        s = by_name["status_trapped_loc_bearing_north0"]
        payload = _payload_bytes(s["envelope_struct"])
        status = ev.StatusUpdateData.decode(payload)
        self.assertEqual(status.location.bearing_deg, 0)
        self.assertEqual(status.encode(), payload)

        # HazardMarkerData FLOOD + location + description.
        s = by_name["hazard_typed_flood"]
        payload = _payload_bytes(s["envelope_struct"])
        haz = ev.HazardMarkerData.decode(payload)
        self.assertEqual(haz.hazard_type, 2)  # flood
        self.assertEqual(haz.severity, 3)
        self.assertEqual(haz.description, "flood rising")
        self.assertEqual(haz.encode(), payload, "Hazard re-encode drift")

        # NodeReceiptData (A12 control frame, status=DUPLICATE, queue_depth=3).
        s = by_name["node_receipt_duplicate"]
        payload = _payload_bytes(s["envelope_struct"])
        rec = ev.NodeReceiptData.decode(payload)
        self.assertEqual(rec.status, 1)  # duplicate
        self.assertEqual(rec.queue_depth, 3)
        self.assertEqual(len(rec.ref_envelope_id), 16)
        self.assertEqual(rec.encode(), payload, "NodeReceipt re-encode drift")

    def test_event_envelope_proto_roundtrip(self) -> None:
        # Exercise the top-level EventEnvelopeV2 proto reader/writer on real
        # field values from every signed sample (signed => has a 64-byte sig).
        signed = [
            s for s in self.corpus["envelope_samples"]
            if s.get("expected_signature_hex")
        ]
        self.assertGreater(len(signed), 0)
        for s in signed:
            struct = s["envelope_struct"]
            payload = _payload_bytes(struct)
            env = ev.EventEnvelopeV2(
                protocol_version=struct["protocol_version"],
                envelope_id=bytes.fromhex(struct["envelope_id_hex"]),
                event_type=struct["event_type"],
                priority=struct["priority"],
                created_at_hlc=ev.HlcTimestamp(
                    struct["created_at_hlc"]["ms_since_epoch"],
                    struct["created_at_hlc"]["counter"],
                ),
                expires_at_hlc=ev.HlcTimestamp(
                    struct["expires_at_hlc"]["ms_since_epoch"],
                    struct["expires_at_hlc"]["counter"],
                ),
                max_hops=struct["max_hops"],
                author_key=bytes.fromhex(struct["author_key_hex"]),
                sig_algo=struct["sig_algo"],
                signature=bytes.fromhex(s["expected_signature_hex"]),
                payload=payload,
                is_experimental=struct.get("is_experimental", False),
                field_id=bytes.fromhex(struct["field_id_hex"]),
                field_mac=bytes.fromhex(struct["field_mac_hex"])
                if struct["field_mac_hex"] else b"",
            )
            decoded = ev.EventEnvelopeV2.decode(env.encode())
            self.assertEqual(decoded, env, f"{s['name']}: envelope roundtrip drift")

    def test_every_negative_case_rejected_with_spec_reason(self) -> None:
        negatives = self.corpus["negative_cases"]
        for case in negatives:
            reason = ev.classify_corpus_negative(case)
            self.assertEqual(
                reason, case["expected_drop_reason"],
                f"negative '{case['kind']}': expected "
                f"{case['expected_drop_reason']!r}, got {reason!r}",
            )
        print(f"[B2] negative_cases rejected: {len(negatives)}")
        self.assertGreaterEqual(len(negatives), 10)


if __name__ == "__main__":
    unittest.main()
