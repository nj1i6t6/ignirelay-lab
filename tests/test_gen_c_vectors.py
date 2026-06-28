"""B6 support: the C-vector generator stays faithful to the frozen App contracts.

`tools/gen_c_vectors.py` turns the App's frozen JSON vectors/corpus into C `.inc`
artifacts the field-node firmware compiles into its ztests. This test proves:
  - the committed `.inc` files in ignirelay-field-node are in sync with what the
    generator produces from the current App contracts (no stale/hand-edited
    artifacts) — same guarantee as `--check`,
  - the generator extracts exactly the corpus's own counts (no fabrication): all
    51 positive + 11 negative LoRa frames, the full §8.1 drop_reason vocabulary,
    and the whole event_type∈{1,50} envelope subset (33 canonical, the signed
    subset for full ingest, and only genuinely-typed payloads for translation).

It mirrors nothing and invents nothing; the App `docs/specs/` are the authority.
Set IGNIRELAY_APP_DIR / IGNIRELAY_FIELD_NODE_DIR to relocate the repos.
"""

from __future__ import annotations

import io
import json
import os
import unittest
from pathlib import Path

from tools import gen_c_vectors as gen


def _app_dir() -> Path:
    override = os.environ.get("IGNIRELAY_APP_DIR")
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[2] / "IgniRelay"


def _load(name: str) -> dict:
    path = _app_dir() / "docs" / "specs" / name
    return json.load(io.open(path, encoding="utf-8"))


# The closed §8.1 LORA-WIRE drop_reason vocabulary (lora_wire_v1.md §8.1).
DROP_REASONS = {
    "truncated", "unknown-version", "unknown-ptype", "length-mismatch",
    "payload-too-long", "crc-mismatch", "mac-mismatch", "ttl-expired",
    "replay-window", "replay-duplicate",
}


class GenCVectorsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.lora = _load("lora_wire_v1_vectors.json")
        cls.corpus = _load("wire_conformance_v1.json")

    def test_committed_inc_artifacts_are_in_sync(self) -> None:
        """The .inc checked into ignirelay-field-node must equal a fresh gen."""
        out_dir = gen._field_node_dir() / "tests" / "wire"
        expect = {
            out_dir / "lora_vectors.inc": gen.build_lora_inc(self.lora),
            out_dir / "envelope_vectors.inc": gen.build_envelope_inc(self.corpus),
        }
        for path, content in expect.items():
            self.assertTrue(path.is_file(), f"missing generated artifact: {path}")
            self.assertEqual(
                path.read_text(encoding="utf-8"),
                content,
                f"{path.name} is stale — rerun `python -m tools.gen_c_vectors`",
            )

    def test_lora_inc_covers_every_frame_and_reason(self) -> None:
        inc = gen.build_lora_inc(self.lora)
        self.assertEqual(len(self.lora["frames"]), 51)
        self.assertEqual(len(self.lora["negative"]), 11)
        # Every positive frame is represented by name in the artifact.
        for f in self.lora["frames"]:
            self.assertIn(f'.name="{f["name"]}"', inc)
        # The full §8.1 drop_reason vocabulary is represented in the negatives.
        reasons = {n["expect_reason"] for n in self.lora["negative"]}
        self.assertEqual(reasons, DROP_REASONS)
        for r in DROP_REASONS:
            self.assertIn(f'.expect_reason="{r}"', inc)
        # CRC standard self-test value is carried through.
        self.assertIn("0x29b1", inc)
        print(f"[B6] gen lora: positive=51 negative=11 reasons={len(reasons)}")

    def test_envelope_subset_counts_match_corpus(self) -> None:
        sub = [
            s for s in self.corpus["envelope_samples"]
            if s["envelope_struct"]["event_type"] in gen.INGEST_EVENT_TYPES
        ]
        signed = [s for s in sub if "expected_signature_hex" in s]
        self.assertEqual(len(sub), 33)
        self.assertEqual(len(signed), 10)
        inc = gen.build_envelope_inc(self.corpus)
        self.assertIn("#define IR_GEN_ENV_TYPED_COUNT 3", inc)
        # No PRESENCE(3)/CHECKPOINT(4) envelope samples exist in the corpus; the
        # generator must not fabricate them.
        self.assertEqual(
            [s for s in self.corpus["envelope_samples"]
             if s["envelope_struct"]["event_type"] in (3, 4)],
            [],
        )
        print(f"[B6] gen envelope subset: canonical={len(sub)} signed={len(signed)} typed=3")

    def test_generator_is_deterministic(self) -> None:
        self.assertEqual(
            gen.build_lora_inc(self.lora), gen.build_lora_inc(self.lora)
        )
        self.assertEqual(
            gen.build_envelope_inc(self.corpus), gen.build_envelope_inc(self.corpus)
        )


if __name__ == "__main__":
    unittest.main()
