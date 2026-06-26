"""Key derivation for the IgniRelay wire contracts (lab Python reference, B2).

Mirrors the App repo's `lib/app/crypto/field_auth_v2.dart` exactly:

    field_id      = SHA-256(field_join_secret)[0..15]
    field_mac_key = HKDF-SHA256(ikm=secret, salt=empty, info="ignirelay/field-mac/v3", L=32)
    lora_mac_key  = HKDF-SHA256(ikm=secret, salt=empty, info="ignirelay/lora-mac/v1",  L=32)

The two MAC keys are domain-separated by their HKDF `info` label
(`envelope_v2_spec` §21.3 / `lora_wire_v1.md` §6). The `info` byte strings MUST
match the App spec verbatim or the derived keys diverge.

This module INVENTS nothing — every constant comes from a frozen App spec; the
conformance tests prove these derivations reproduce the committed corpus keys.
"""

from __future__ import annotations

import hashlib
import hmac

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# HKDF domain-separation labels — MUST equal the App `FieldAuthV2` constants.
FIELD_MAC_HKDF_INFO = b"ignirelay/field-mac/v3"
LORA_MAC_HKDF_INFO = b"ignirelay/lora-mac/v1"

FIELD_ID_BYTES = 16
FIELD_MAC_BYTES = 16
LORA_MAC8_BYTES = 8


def derive_field_id(field_join_secret: bytes) -> bytes:
    """field_id = SHA-256(secret)[0..15]. One-way, public scope label."""
    return hashlib.sha256(field_join_secret).digest()[:FIELD_ID_BYTES]


def _hkdf_sha256_32(field_join_secret: bytes, info: bytes) -> bytes:
    # salt=b"" matches Dart's empty salt: RFC 5869 substitutes HashLen zero
    # bytes, and HMAC zero-pads a short/empty key to the block size, so an empty
    # salt and a 32-zero-byte salt produce the identical PRK. The conformance
    # tests pin this against the committed corpus keys.
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=info)
    return hkdf.derive(field_join_secret)


def derive_field_mac_key(field_join_secret: bytes) -> bytes:
    """field_mac_key = HKDF-SHA256(secret, info="ignirelay/field-mac/v3")."""
    return _hkdf_sha256_32(field_join_secret, FIELD_MAC_HKDF_INFO)


def derive_lora_mac_key(field_join_secret: bytes) -> bytes:
    """lora_mac_key = HKDF-SHA256(secret, info="ignirelay/lora-mac/v1")."""
    return _hkdf_sha256_32(field_join_secret, LORA_MAC_HKDF_INFO)


def compute_field_mac(field_mac_key: bytes, canonical_sig_input: bytes) -> bytes:
    """field_mac = HMAC-SHA256(field_mac_key, canonical_sig_input)[0..15]."""
    return hmac.new(field_mac_key, canonical_sig_input, hashlib.sha256).digest()[
        :FIELD_MAC_BYTES
    ]


def verify_field_mac(
    field_mac_key: bytes, canonical_sig_input: bytes, field_mac: bytes
) -> bool:
    if len(field_mac) != FIELD_MAC_BYTES:
        return False
    expected = compute_field_mac(field_mac_key, canonical_sig_input)
    return hmac.compare_digest(expected, field_mac)


def lora_mac8(lora_mac_key: bytes, hdr_body: bytes) -> bytes:
    """mac8 = HMAC-SHA256(lora_mac_key, hdr||body)[0..7] (lora_wire_v1.md §6)."""
    return hmac.new(lora_mac_key, hdr_body, hashlib.sha256).digest()[:LORA_MAC8_BYTES]
