"""LORA-WIRE v1 compact payload codec (lab Python, B3).

Mirrors the §5 "緊湊 payload 翻譯表" of the frozen App contract
`docs/specs/lora_wire_v1.md` byte-for-byte. A Node, after verifying an
`EventEnvelopeV2` at BLE ingest (Ed25519 signature + field_mac), **translates**
the typed envelope payload into one of these compact LoRa payloads before it
ever touches the LoRa air (OD-2: the 64-byte Ed25519 signature never rides LoRa).

INVENTS NO contract. The byte layout is taken verbatim from
`tool/generate_lora_wire_vectors.dart` (`_presencePayload` / `_loc13` /
`_sosPayload` / `_checkpointPayload`); the B3 compact-codec test reproduces the
committed `lora_wire_v1_vectors.json` payloads for presence/sos/checkpoint to
prove this matches the frozen generator.

§5 layouts (all multi-byte little-endian; lat/lng signed i32 = two's complement):

    loc13 (13 B) = src u8 | lat_e7 i32 | lng_e7 i32 | acc_m u16 | age_s u16
    PRESENCE  (3)  10 B = anon8(8) | battery u8 | evid_src u8
    SOS       (1)  22 B = anon8(8) | safety u8 | loc13(13)
    CHECKPOINT(4)  10 B = anon8(8) | checkpoint_node u16
"""

from __future__ import annotations

from typing import Optional

from .envelope_v3 import (
    CheckpointData,
    LocationEvidence,
    PresenceData,
    StatusUpdateData,
)

# ── §5 enum values (normative text of lora_wire_v1.md §5) ─────────────────────
# SafetyState: 0 unspecified / 1 safe / 2 unsafe / 3 injured / 4 trapped.
# LocationSource: 0 unknown / 1 gps / 2 field_node / 3 ble_rssi / 4 pdr / 5 manual.
LOC_SRC_UNKNOWN = 0

PRESENCE_BYTES = 10
SOS_BYTES = 22
CHECKPOINT_BYTES = 10
LOC13_BYTES = 13
ANON8_BYTES = 8

_U16_MAX = 0xFFFF


# ── LE helpers ────────────────────────────────────────────────────────────────
def _u16le(v: int) -> bytes:
    return bytes([v & 0xFF, (v >> 8) & 0xFF])


def _i32le(v: int) -> bytes:
    u = v & 0xFFFFFFFF  # two's complement
    return bytes([u & 0xFF, (u >> 8) & 0xFF, (u >> 16) & 0xFF, (u >> 24) & 0xFF])


def _rd_u16le(b: bytes, off: int) -> int:
    return b[off] | (b[off + 1] << 8)


def _rd_i32le(b: bytes, off: int) -> int:
    u = b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)
    return u - 0x100000000 if u & 0x80000000 else u


def _sat_u16(v: int) -> int:
    if v < 0:
        return 0
    return v if v <= _U16_MAX else _U16_MAX


def _anon8(anon_user_id: bytes) -> bytes:
    """anon8 = anon_user_id[0..7], zero-padded if the id is shorter (§OD-7)."""
    return (anon_user_id[:ANON8_BYTES]).ljust(ANON8_BYTES, b"\x00")


def age_seconds(observed_ms: int, now_ms: int) -> int:
    """age_s = (now - observed) in seconds, saturated to u16 (§5 loc13)."""
    return _sat_u16((now_ms - observed_ms) // 1000)


# ── loc13 ─────────────────────────────────────────────────────────────────────
def encode_loc13(*, src: int, lat_e7: int, lng_e7: int, acc_m: int,
                 age_s: int) -> bytes:
    return (
        bytes([src & 0xFF])
        + _i32le(lat_e7)
        + _i32le(lng_e7)
        + _u16le(_sat_u16(acc_m))
        + _u16le(_sat_u16(age_s))
    )


def decode_loc13(b: bytes, off: int = 0) -> dict:
    return {
        "src": b[off],
        "lat_e7": _rd_i32le(b, off + 1),
        "lng_e7": _rd_i32le(b, off + 5),
        "acc_m": _rd_u16le(b, off + 9),
        "age_s": _rd_u16le(b, off + 11),
    }


# ── PRESENCE (event_type 3) ───────────────────────────────────────────────────
def encode_presence(*, anon8: bytes, battery: int, evid_src: int) -> bytes:
    if len(anon8) != ANON8_BYTES:
        raise ValueError("anon8 must be 8 bytes")
    return anon8 + bytes([battery & 0xFF, evid_src & 0xFF])


def decode_presence(payload: bytes) -> dict:
    if len(payload) != PRESENCE_BYTES:
        raise ValueError(f"PRESENCE payload must be {PRESENCE_BYTES} bytes")
    return {
        "anon8_hex": payload[:ANON8_BYTES].hex(),
        "battery": payload[8],
        "evid_src": payload[9],
    }


# ── SOS / STATUS_UPDATE (event_type 1) ────────────────────────────────────────
def encode_sos(*, anon8: bytes, safety: int, loc_src: int, lat_e7: int,
               lng_e7: int, acc_m: int, age_s: int) -> bytes:
    if len(anon8) != ANON8_BYTES:
        raise ValueError("anon8 must be 8 bytes")
    return (
        anon8
        + bytes([safety & 0xFF])
        + encode_loc13(src=loc_src, lat_e7=lat_e7, lng_e7=lng_e7,
                       acc_m=acc_m, age_s=age_s)
    )


def decode_sos(payload: bytes) -> dict:
    if len(payload) != SOS_BYTES:
        raise ValueError(f"SOS payload must be {SOS_BYTES} bytes")
    out = {
        "anon8_hex": payload[:ANON8_BYTES].hex(),
        "safety": payload[8],
    }
    out.update(decode_loc13(payload, 9))
    return out


# ── CHECKPOINT (event_type 4) ─────────────────────────────────────────────────
def encode_checkpoint(*, anon8: bytes, checkpoint_node: int) -> bytes:
    if len(anon8) != ANON8_BYTES:
        raise ValueError("anon8 must be 8 bytes")
    return anon8 + _u16le(checkpoint_node)


def decode_checkpoint(payload: bytes) -> dict:
    if len(payload) != CHECKPOINT_BYTES:
        raise ValueError(f"CHECKPOINT payload must be {CHECKPOINT_BYTES} bytes")
    return {
        "anon8_hex": payload[:ANON8_BYTES].hex(),
        "checkpoint_node": _rd_u16le(payload, 8),
    }


# ── Typed-envelope → compact translators (BLE ingest → LoRa, §5) ──────────────
def _loc13_from_evidence(loc: Optional[LocationEvidence], now_ms: int) -> bytes:
    if loc is None:
        return encode_loc13(src=LOC_SRC_UNKNOWN, lat_e7=0, lng_e7=0, acc_m=0,
                            age_s=0)
    return encode_loc13(
        src=loc.source,
        lat_e7=loc.lat_e7,
        lng_e7=loc.lng_e7,
        acc_m=loc.accuracy_m,
        age_s=age_seconds(loc.observed_at.ms, now_ms),
    )


def presence_from_typed(p: PresenceData, *, now_ms: int) -> bytes:
    """Translate a verified PresenceData envelope payload to PRESENCE compact."""
    return encode_presence(
        anon8=_anon8(p.anon_user_id),
        battery=p.battery_hint,
        evid_src=p.location.source,
    )


def sos_from_typed(s: StatusUpdateData, *, anon8: bytes, now_ms: int) -> bytes:
    """Translate a verified StatusUpdateData (SOS) envelope payload to SOS compact.

    StatusUpdateData carries no anon_user_id (App struct); per §OD-7 the SOS
    compact anon8 is the author's anon_user_id (NOT the author pubkey). The Node
    supplies it from what the author advertised via PRESENCE/CHECKPOINT — exactly
    how the frozen generator treats anon8 as a translator-supplied value.
    """
    loc = s.location
    return (
        _anon8(anon8)
        + bytes([s.safety_state & 0xFF])
        + _loc13_from_evidence(loc, now_ms)
    )


def checkpoint_from_typed(c: CheckpointData, *, checkpoint_node: int,
                          now_ms: int) -> bytes:
    """Translate a verified CheckpointData envelope payload to CHECKPOINT compact."""
    return encode_checkpoint(
        anon8=_anon8(c.anon_user_id),
        checkpoint_node=checkpoint_node,
    )
