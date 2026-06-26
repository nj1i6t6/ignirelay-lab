"""LORA-WIRE v1 reference codec (lab Python, B2).

Mirrors the frozen App contract `docs/specs/lora_wire_v1.md` and reproduces
`docs/specs/lora_wire_v1_vectors.json` byte-for-byte:

    frame = hdr(11) || body || mac8(8) || crc16(2)        (§3)
    mac8  = HMAC-SHA256(lora_mac_key, hdr||body)[0..7]     (§6)
    crc16 = CRC-16/CCITT-FALSE(hdr||body||mac8), LE        (§6)

The receive pipeline order (§8) is fixed; each negative vector triggers exactly
one drop_reason from the closed §8.1 vocabulary. INVENTS NO contract — the B2
vector test pins this against the committed vectors (positive + negative).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Set

from . import keys

# ── Constants (lora_wire_v1.md §2/§3) ────────────────────────────────────────
WIRE_VERSION = 0x1
PTYPE_EVENT = 0x1
PTYPE_ACK = 0x2
HDR_BYTES = 11
MAC8_BYTES = 8
CRC16_BYTES = 2
EVENT_ID_BYTES = 16
ACK_FRAME_BYTES = 32                      # hdr 11 + body 11 + mac8 8 + crc16 2
MAX_PAYLOAD_BYTES = 64
EVENT_PREFIX_BYTES = EVENT_ID_BYTES + 1 + 1 + 8 + 1   # 27 (incl payload_len byte)
EVENT_MIN_FRAME_BYTES = HDR_BYTES + EVENT_PREFIX_BYTES + MAC8_BYTES + CRC16_BYTES  # 48

FLAG_HLC_SYNCED = 0x01
FLAG_RETRANSMISSION = 0x02
FLAG_MULE_ORIGIN = 0x04

HLC_REPLAY_WINDOW_MS = 48 * 60 * 60 * 1000  # 172800000

CRC_CHECK_INPUT = b"123456789"
CRC_CHECK_EXPECTED = 0x29B1


# ── CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF, no reflection, xorout 0) ────
def crc16_ccitt(data: bytes) -> int:
    crc = 0xFFFF
    for raw in data:
        crc ^= (raw & 0xFF) << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc & 0xFFFF


# ── LE helpers ───────────────────────────────────────────────────────────────
def _u16le(v: int) -> bytes:
    return bytes([v & 0xFF, (v >> 8) & 0xFF])


def _u48le(v: int) -> bytes:
    return bytes([(v >> (8 * i)) & 0xFF for i in range(6)])


def _rd_u16le(b: bytes, off: int) -> int:
    return b[off] | (b[off + 1] << 8)


def _rd_u48le(b: bytes, off: int) -> int:
    v = 0
    for i in range(6):
        v |= b[off + i] << (8 * i)
    return v


# ── Parsed frame model ───────────────────────────────────────────────────────
@dataclass
class LoraParsedFrame:
    version: int
    ptype: int
    flags: int
    field_tag: bytes
    src_node: int
    packet_seq: int
    ttl: int
    # EVENT only
    event_id: Optional[bytes] = None
    event_type: Optional[int] = None
    priority: Optional[int] = None
    hlc_ms: Optional[int] = None
    hlc_counter: Optional[int] = None
    payload: Optional[bytes] = None
    # ACK only
    ack_seq: Optional[int] = None
    event_id_prefix: Optional[bytes] = None
    status: Optional[int] = None


@dataclass
class LoraVerifyResult:
    reason: Optional[str]
    parsed: Optional[LoraParsedFrame]


def _hdr(ptype: int, flags: int, field_tag: bytes, src_node: int, packet_seq: int,
         ttl: int) -> bytes:
    if len(field_tag) != 4:
        raise ValueError("field_tag must be 4 bytes")
    return bytes([(WIRE_VERSION << 4) | (ptype & 0x0F), flags & 0xFF]) + \
        field_tag + _u16le(src_node) + _u16le(packet_seq) + bytes([ttl & 0xFF])


def _seal(hdr_body: bytes, lora_mac_key: bytes) -> bytes:
    mac8 = keys.lora_mac8(lora_mac_key, hdr_body)
    body = hdr_body + mac8
    return body + _u16le(crc16_ccitt(body))


def encode_event_frame(*, lora_mac_key: bytes, flags: int, field_tag: bytes,
                       src_node: int, packet_seq: int, ttl: int, event_id: bytes,
                       event_type: int, priority: int, hlc_ms: int,
                       hlc_counter: int, payload: bytes,
                       allow_oversize_payload: bool = False) -> bytes:
    if len(event_id) != EVENT_ID_BYTES:
        raise ValueError("event_id must be 16 bytes")
    if not allow_oversize_payload and len(payload) > MAX_PAYLOAD_BYTES:
        raise ValueError("payload too long")
    body = (
        _hdr(PTYPE_EVENT, flags, field_tag, src_node, packet_seq, ttl)
        + event_id
        + bytes([event_type & 0xFF, priority & 0xFF])
        + _u48le(hlc_ms)
        + _u16le(hlc_counter)
        + bytes([len(payload) & 0xFF])
        + payload
    )
    return _seal(body, lora_mac_key)


def encode_ack_frame(*, lora_mac_key: bytes, flags: int, field_tag: bytes,
                     src_node: int, packet_seq: int, ttl: int, ack_seq: int,
                     event_id_prefix: bytes, status: int) -> bytes:
    if len(event_id_prefix) != 8:
        raise ValueError("event_id_prefix must be 8 bytes")
    body = (
        _hdr(PTYPE_ACK, flags, field_tag, src_node, packet_seq, ttl)
        + _u16le(ack_seq)
        + event_id_prefix
        + bytes([status & 0xFF])
    )
    return _seal(body, lora_mac_key)


def reencode_frame(f: LoraParsedFrame, lora_mac_key: bytes) -> bytes:
    if f.ptype == PTYPE_EVENT:
        return encode_event_frame(
            lora_mac_key=lora_mac_key, flags=f.flags, field_tag=f.field_tag,
            src_node=f.src_node, packet_seq=f.packet_seq, ttl=f.ttl,
            event_id=f.event_id, event_type=f.event_type, priority=f.priority,
            hlc_ms=f.hlc_ms, hlc_counter=f.hlc_counter, payload=f.payload,
        )
    return encode_ack_frame(
        lora_mac_key=lora_mac_key, flags=f.flags, field_tag=f.field_tag,
        src_node=f.src_node, packet_seq=f.packet_seq, ttl=f.ttl,
        ack_seq=f.ack_seq, event_id_prefix=f.event_id_prefix, status=f.status,
    )


def verify_lora_frame(frame: bytes, *, lora_mac_key: bytes,
                      local_est_ms: Optional[int] = None,
                      seen_event_ids: Optional[Set[str]] = None,
                      hlc_replay_window_ms: int = HLC_REPLAY_WINDOW_MS
                      ) -> LoraVerifyResult:
    """Full §8 receive pipeline. reason==None => accepted; mutates seen set."""
    # 1) structural minimum header
    if len(frame) < HDR_BYTES:
        return LoraVerifyResult("truncated", None)
    ver_ptype = frame[0]
    version = (ver_ptype >> 4) & 0x0F
    ptype = ver_ptype & 0x0F
    # 2) version
    if version != WIRE_VERSION:
        return LoraVerifyResult("unknown-version", None)
    # 3) ptype
    if ptype not in (PTYPE_EVENT, PTYPE_ACK):
        return LoraVerifyResult("unknown-ptype", None)
    flags = frame[1]
    field_tag = frame[2:6]
    src_node = _rd_u16le(frame, 6)
    packet_seq = _rd_u16le(frame, 8)
    ttl = frame[10]

    # 4) length determination
    payload_len: Optional[int] = None
    if ptype == PTYPE_ACK:
        if len(frame) < ACK_FRAME_BYTES:
            return LoraVerifyResult("truncated", None)
        if len(frame) != ACK_FRAME_BYTES:
            return LoraVerifyResult("length-mismatch", None)
    else:
        if len(frame) < EVENT_MIN_FRAME_BYTES:
            return LoraVerifyResult("truncated", None)
        payload_len = frame[HDR_BYTES + EVENT_PREFIX_BYTES - 1]
        if payload_len > MAX_PAYLOAD_BYTES:
            return LoraVerifyResult("payload-too-long", None)
        expected = EVENT_MIN_FRAME_BYTES + payload_len
        if len(frame) < expected:
            return LoraVerifyResult("truncated", None)
        if len(frame) != expected:
            return LoraVerifyResult("length-mismatch", None)

    # 5) CRC16 over hdr||body||mac8
    crc_got = _rd_u16le(frame, len(frame) - CRC16_BYTES)
    crc_want = crc16_ccitt(frame[: len(frame) - CRC16_BYTES])
    if crc_got != crc_want:
        return LoraVerifyResult("crc-mismatch", None)

    # 6) MAC8 over hdr||body
    mac_off = len(frame) - MAC8_BYTES - CRC16_BYTES
    mac_got = frame[mac_off : mac_off + MAC8_BYTES]
    mac_want = keys.lora_mac8(lora_mac_key, frame[:mac_off])
    if mac_got != mac_want:
        return LoraVerifyResult("mac-mismatch", None)

    # 7) TTL
    if ttl == 0:
        return LoraVerifyResult("ttl-expired", None)

    if ptype == PTYPE_ACK:
        ack_seq = _rd_u16le(frame, HDR_BYTES)
        prefix = frame[HDR_BYTES + 2 : HDR_BYTES + 10]
        status = frame[HDR_BYTES + 10]
        return LoraVerifyResult(None, LoraParsedFrame(
            version=version, ptype=ptype, flags=flags, field_tag=field_tag,
            src_node=src_node, packet_seq=packet_seq, ttl=ttl,
            ack_seq=ack_seq, event_id_prefix=prefix, status=status,
        ))

    event_id = frame[HDR_BYTES : HDR_BYTES + 16]
    event_type = frame[HDR_BYTES + 16]
    priority = frame[HDR_BYTES + 17]
    hlc_ms = _rd_u48le(frame, HDR_BYTES + 18)
    hlc_counter = _rd_u16le(frame, HDR_BYTES + 24)
    payload = frame[HDR_BYTES + EVENT_PREFIX_BYTES :
                    HDR_BYTES + EVENT_PREFIX_BYTES + payload_len]

    # 8) HLC replay window (synced EVENT only)
    if (flags & FLAG_HLC_SYNCED) != 0 and local_est_ms is not None:
        if abs(hlc_ms - local_est_ms) > hlc_replay_window_ms:
            return LoraVerifyResult("replay-window", None)

    # 9) event_id dedupe
    id_hex = event_id.hex()
    if seen_event_ids is not None and id_hex in seen_event_ids:
        return LoraVerifyResult("replay-duplicate", None)
    if seen_event_ids is not None:
        seen_event_ids.add(id_hex)

    return LoraVerifyResult(None, LoraParsedFrame(
        version=version, ptype=ptype, flags=flags, field_tag=field_tag,
        src_node=src_node, packet_seq=packet_seq, ttl=ttl,
        event_id=event_id, event_type=event_type, priority=priority,
        hlc_ms=hlc_ms, hlc_counter=hlc_counter, payload=payload,
    ))
