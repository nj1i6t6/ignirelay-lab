"""W0: lab Python interpretation of the App-repo shared contract JSON."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path


def _app_dir() -> Path:
    override = os.environ.get("IGNIRELAY_APP_DIR")
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[2] / "IgniRelay"


sys.path.insert(0, str(_app_dir() / "tool"))
import w0_shared_contract as W  # noqa: E402


class W0LabContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.c = json.loads(
            (_app_dir() / "docs" / "specs" / "w0_shared_contract_v1.json").read_text(
                encoding="utf-8"
            )
        )

    def test_revision(self) -> None:
        self.assertEqual(self.c["contract_revision"], W.REVISION)

    def test_core_tables(self) -> None:
        for case in self.c["lww_cases"]:
            self.assertEqual(W.lww_compare(case["a"], case["b"]), case["expected"], case["name"])
        for case in self.c["capability_cases"]:
            ok, reason = W.negotiate_and_can_send(
                hello_valid=case["hello_valid"], local_max_rx=case["local_max_rx"],
                local_chunking=case["local_chunking"], peer_max_rx=case["peer_max_rx"],
                peer_chunking=case["peer_chunking"], mtu=case["mtu"],
                envelope_bytes=case["envelope_bytes"], is_control=case["is_control"],
            )
            self.assertEqual((ok, reason), (case["expected_ok"], case["expected_reason"]), case["name"])
        for case in self.c["checkpoint_id_cases"]:
            self.assertEqual(W.parse_checkpoint_id(case["id"]), case["expected"], case["id"])
        for case in self.c["hop_ack_cases"]:
            self.assertEqual(W.hop_ack_result(case), case["expected"], case["name"])
        for case in self.c["clock_policy_cases"]:
            self.assertEqual(
                W.clock_policy(case),
                (case["expected_admit"], case["expected_tx"], case["expected_receipt"]),
                case["name"],
            )

    def test_ed25519_join_golden(self) -> None:
        v = self.c["join_proof_vector"]
        pub = bytes.fromhex(v["author_pubkey_hex"])
        proof = W.join_proof_input(
            bytes.fromhex(v["field_id_hex"]), bytes.fromhex(v["anon8_hex"]),
            pub, bytes.fromhex(v["nonce_hex"]), v["ts_ms"], v["action"],
        )
        self.assertEqual(proof.hex(), v["proof_input_hex"])
        self.assertTrue(W.verify_ed25519(pub, proof, bytes.fromhex(v["possession_sig_hex"])))

    def test_c_inc_not_stale(self) -> None:
        gen = _app_dir() / "tool" / "generate_w0_c_inc.py"
        r = subprocess.run(
            [sys.executable, str(gen), "--check"],
            cwd=str(_app_dir()),
            capture_output=True,
            text=True,
        )
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_c_headers_match_frozen_numbers(self) -> None:
        node_root = Path(__file__).resolve().parents[2] / "ignirelay-field-node"
        w0_h = (node_root / "src" / "core" / "w0_contract.h").read_text(encoding="utf-8")
        self.assertIn("#define IR_W0_RECEIPT_BUSY 3", w0_h)
        self.assertIn("#define IR_W0_PENDING_TX_HOLD_MS 21600000u", w0_h)


if __name__ == "__main__":
    unittest.main()
