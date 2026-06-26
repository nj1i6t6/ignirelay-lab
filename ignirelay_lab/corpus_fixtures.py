"""TEST-ONLY key/identity material for the lab simulator (B3).

Single source of truth = the App's frozen conformance corpus
`docs/specs/wire_conformance_v1.json#test_field` (override its repo location with
the env var IGNIRELAY_APP_DIR). The lab NEVER hard-codes secrets: it reads the
same TEST-ONLY `field_join_secret` the envelope corpus and LoRa vectors share,
derives the field / field_mac / lora_mac keys via the B2 `keys` module, and uses
a TEST-ONLY Ed25519 author seed that is itself a corpus value
(`envelope_samples[*].test_only_private_key_hex` — the all-zero seed).

These are TEST-ONLY materials for the simulator. They are NOT production keys.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from .wire import keys

# The corpus all-zero Ed25519 seed (a committed `test_only_private_key_hex`
# value) → public key 3b6a27bc...da29. TEST-ONLY author identity for the phone.
_ALL_ZERO_SEED_HEX = "00" * 32


def app_dir() -> Path:
    override = os.environ.get("IGNIRELAY_APP_DIR")
    if override:
        return Path(override)
    # Default: sibling of the lab repo, IDE/IgniRelay.
    return Path(__file__).resolve().parents[1].parent / "IgniRelay"


def _corpus_path() -> Path:
    return app_dir() / "docs" / "specs" / "wire_conformance_v1.json"


@lru_cache(maxsize=1)
def _load_corpus() -> dict:
    path = _corpus_path()
    if not path.exists():
        raise FileNotFoundError(
            f"App conformance corpus not found at {path}. The lab reuses its "
            f"TEST-ONLY field_join_secret; set IGNIRELAY_APP_DIR to the App repo "
            f"root."
        )
    return json.loads(path.read_text(encoding="utf-8"))


@dataclass(frozen=True)
class TestField:
    """Derived TEST-ONLY field material (reproduces corpus #test_field)."""

    secret: bytes
    field_id: bytes
    field_mac_key: bytes
    lora_mac_key: bytes

    @property
    def field_tag(self) -> bytes:
        return self.field_id[:4]


@lru_cache(maxsize=1)
def test_field() -> TestField:
    corpus = _load_corpus()
    tf = corpus["test_field"]
    secret = bytes.fromhex(tf["field_join_secret_hex"])
    field_id = keys.derive_field_id(secret)
    field_mac_key = keys.derive_field_mac_key(secret)
    lora_mac_key = keys.derive_lora_mac_key(secret)
    # Defensive: prove the derivation still reproduces the frozen corpus keys.
    assert field_id.hex() == tf["field_id_hex"], "field_id drift vs corpus"
    assert field_mac_key.hex() == tf["field_mac_key_hex"], "field_mac_key drift"
    return TestField(
        secret=secret,
        field_id=field_id,
        field_mac_key=field_mac_key,
        lora_mac_key=lora_mac_key,
    )


def author_seed() -> bytes:
    """TEST-ONLY Ed25519 author seed — the corpus all-zero `test_only_private_key`.

    Asserts the seed is genuinely present in the corpus so this stays sourced
    from the frozen corpus rather than invented.
    """
    corpus = _load_corpus()
    seeds = {
        s.get("test_only_private_key_hex") for s in corpus["envelope_samples"]
    }
    if _ALL_ZERO_SEED_HEX not in seeds:
        raise AssertionError(
            "corpus no longer carries the all-zero TEST-ONLY author seed"
        )
    return bytes.fromhex(_ALL_ZERO_SEED_HEX)


def anon_user_id(label: str) -> bytes:
    """Deterministic TEST-ONLY 16-byte anon_user_id for a simulated phone.

    A pseudonymous app-level id (NOT the author pubkey, §OD-7). Stable per label
    so PRESENCE/SOS/CHECKPOINT from one phone share an anon8.
    """
    return hashlib.sha256(f"ignirelay-lab/anon/{label}".encode()).digest()[:16]
