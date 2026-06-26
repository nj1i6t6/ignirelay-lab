"""B3 compact-payload conformance — lab compact.py vs the frozen LoRa vectors.

The §5 compact payloads my SimNode emits MUST be byte-identical to the frozen
generator's. This reproduces the committed `lora_wire_v1_vectors.json` PRESENCE /
SOS / CHECKPOINT payloads from the same inputs (no invented layout), and proves
the typed-envelope → compact translators produce them too.
"""

import json
import os
import unittest
from pathlib import Path

from ignirelay_lab.wire import compact
from ignirelay_lab.wire import envelope_v3 as ev


def _app_dir() -> Path:
    override = os.environ.get("IGNIRELAY_APP_DIR")
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[2] / "IgniRelay"


def _vectors() -> dict:
    path = _app_dir() / "docs" / "specs" / "lora_wire_v1_vectors.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _anon8(seed: int) -> bytes:
    # Reproduces the generator's _anon8: byte i = (seed + i*17) & 0xFF.
    return bytes((seed + i * 17) & 0xFF for i in range(8))


class CompactCodecConformance(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        frames = _vectors()["frames"]
        cls.by_prefix = {}
        for f in frames:
            for pfx in ("presence_", "sos_trapped_fix_", "sos_safe_nofix_",
                        "sos_injured_south_", "checkpoint_"):
                if f["name"].startswith(pfx) and pfx not in cls.by_prefix:
                    cls.by_prefix[pfx] = f

    def _expect(self, prefix: str) -> bytes:
        return bytes.fromhex(self.by_prefix[prefix]["payload_hex"])

    def test_presence_matches_vector(self) -> None:
        got = compact.encode_presence(anon8=_anon8(0x11), battery=87, evid_src=1)
        self.assertEqual(got, self._expect("presence_"))
        self.assertEqual(compact.decode_presence(got)["battery"], 87)

    def test_sos_trapped_fix_matches_vector(self) -> None:
        got = compact.encode_sos(anon8=_anon8(0x22), safety=4, loc_src=1,
                                 lat_e7=250339805, lng_e7=1215654177, acc_m=12,
                                 age_s=30)
        self.assertEqual(got, self._expect("sos_trapped_fix_"))
        d = compact.decode_sos(got)
        self.assertEqual((d["safety"], d["lat_e7"], d["lng_e7"]),
                         (4, 250339805, 1215654177))

    def test_sos_injured_south_signed_i32(self) -> None:
        got = compact.encode_sos(anon8=_anon8(0x24), safety=3, loc_src=2,
                                 lat_e7=-250339805, lng_e7=-1215654177,
                                 acc_m=65535, age_s=65535)
        self.assertEqual(got, self._expect("sos_injured_south_"))
        d = compact.decode_sos(got)
        self.assertEqual((d["lat_e7"], d["lng_e7"]), (-250339805, -1215654177))

    def test_sos_safe_nofix_matches_vector(self) -> None:
        got = compact.encode_sos(anon8=_anon8(0x23), safety=1, loc_src=0,
                                 lat_e7=0, lng_e7=0, acc_m=0, age_s=0)
        self.assertEqual(got, self._expect("sos_safe_nofix_"))

    def test_checkpoint_matches_vector(self) -> None:
        got = compact.encode_checkpoint(anon8=_anon8(0x33), checkpoint_node=7)
        self.assertEqual(got, self._expect("checkpoint_"))
        self.assertEqual(compact.decode_checkpoint(got)["checkpoint_node"], 7)

    def test_translators_reproduce_vectors_from_typed_payloads(self) -> None:
        # PRESENCE: anon_user_id[0:8] = _anon8(0x11), battery 87, gps source.
        p = ev.PresenceData(
            anon_user_id=_anon8(0x11) + b"\x00" * 8,
            location=ev.LocationEvidence(source=1),
            battery_hint=87,
        )
        self.assertEqual(compact.presence_from_typed(p, now_ms=0),
                         self._expect("presence_"))

        # SOS: anon8 supplied by the node; age_s = (now - observed)/1000 = 30.
        s = ev.StatusUpdateData(
            safety_state=4,
            location=ev.LocationEvidence(
                source=1, lat_e7=250339805, lng_e7=1215654177, accuracy_m=12,
                observed_at=ev.HlcTimestamp(ms=0)),
        )
        self.assertEqual(
            compact.sos_from_typed(s, anon8=_anon8(0x22), now_ms=30000),
            self._expect("sos_trapped_fix_"))

        # CHECKPOINT: anon_user_id[0:8] = _anon8(0x33), checkpoint_node = 7.
        c = ev.CheckpointData(anon_user_id=_anon8(0x33) + b"\x00" * 8,
                              checkpoint_id="cp")
        self.assertEqual(
            compact.checkpoint_from_typed(c, checkpoint_node=7, now_ms=0),
            self._expect("checkpoint_"))

    def test_loc13_roundtrip(self) -> None:
        b = compact.encode_loc13(src=1, lat_e7=-12345678, lng_e7=98765432,
                                 acc_m=42, age_s=600)
        d = compact.decode_loc13(b)
        self.assertEqual(
            (d["src"], d["lat_e7"], d["lng_e7"], d["acc_m"], d["age_s"]),
            (1, -12345678, 98765432, 42, 600))


if __name__ == "__main__":
    unittest.main()
