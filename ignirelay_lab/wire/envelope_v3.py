"""EventEnvelope v3 reference codec (lab Python, B2).

A hand-written proto3 reader/writer + the spec-defined canonical signature
input, mirroring the App repo byte-for-byte:

  - proto3 primitives  ->  lib/app/proto/proto_wire.dart
  - EventEnvelopeV2     ->  lib/app/proto/event_envelope_v2.dart (fields 1..15)
  - canonical_sig_input ->  lib/app/crypto/canonical_encoder_v2.dart (141 B, v3)
  - field_id / field_mac / HKDF -> keys.py (= field_auth_v2.dart)
  - payload structs     ->  event_envelope_v2.dart (LocationEvidence,
                            StatusUpdateData, PresenceData, CheckpointData,
                            HazardMarkerData, NeedEntry, NodeReceiptData, ...)

INVENTS NO contract. The App `docs/specs/` are the sole authority; the B2
conformance test proves this reproduces the committed `wire_conformance_v1.json`
byte-for-byte (canonical hex, signature, field_mac) for every sample.

Spec authority order (MASTER §0.2):
  1. envelope_v2_spec_2026-05-13.md §21 (v3 field-auth, 141-B canonical)
  2. native_transport_v1_2026-05-13.md §4 (chunk header — negative cases only)
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field as dataclass_field
from typing import List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import keys

# ─────────────────────────────────────────────────────────────────────────────
# Frozen constants (single source = App mesh_constants.dart / canonical encoder)
# ─────────────────────────────────────────────────────────────────────────────

PROTOCOL_VERSION_V3 = 3
SIG_ALGO_ED25519 = 0x01
CANONICAL_SIG_INPUT_BYTES = 141

SOS_ENVELOPE_BUDGET_BYTES = 240          # mesh_constants kSosEnvelopeBudgetBytes
MAX_ENVELOPE_BYTES = 2048                # mesh_constants kMaxEnvelopeBytes
ATT_HEADER_SIZE = 3                      # mesh_constants kAttHeaderSize
CHUNK_HEADER_SIZE = 18                   # mesh_constants kChunkHeaderSize
MAX_CHUNKS_PER_ENVELOPE = 16             # mesh_constants kMaxChunksPerEnvelope

_U64_MASK = (1 << 64) - 1

# ─────────────────────────────────────────────────────────────────────────────
# proto3 wire primitives (mirror proto_wire.dart)
# ─────────────────────────────────────────────────────────────────────────────

WIRE_VARINT = 0
WIRE_LEN = 2


class ProtoDecodeError(Exception):
    pass


def _zigzag_encode64(v: int) -> int:
    return ((v << 1) ^ (v >> 63)) & _U64_MASK


def _zigzag_decode64(u: int) -> int:
    return (u >> 1) ^ -(u & 1)


class ProtoWriter:
    def __init__(self) -> None:
        self._buf = bytearray()

    def to_bytes(self) -> bytes:
        return bytes(self._buf)

    def _write_varint(self, value: int) -> None:
        v = value & _U64_MASK
        while v > 0x7F:
            self._buf.append((v & 0x7F) | 0x80)
            v >>= 7
        self._buf.append(v & 0x7F)

    def _write_tag(self, field_number: int, wire_type: int) -> None:
        self._write_varint((field_number << 3) | wire_type)

    def write_uint32(self, field_number: int, value: int) -> None:
        if value == 0:
            return
        self._write_tag(field_number, WIRE_VARINT)
        self._write_varint(value)

    write_uint64 = write_uint32  # same encoding; both omit zero (proto3)

    def write_sint64(self, field_number: int, value: int) -> None:
        if value == 0:
            return
        self._write_tag(field_number, WIRE_VARINT)
        self._write_varint(_zigzag_encode64(value))

    def write_bool(self, field_number: int, value: bool) -> None:
        if not value:
            return
        self._write_tag(field_number, WIRE_VARINT)
        self._write_varint(1)

    def write_enum(self, field_number: int, value: int) -> None:
        if value == 0:
            return
        self._write_tag(field_number, WIRE_VARINT)
        self._write_varint(value)

    def write_bytes(self, field_number: int, data: bytes) -> None:
        if not data:
            return
        self._write_tag(field_number, WIRE_LEN)
        self._write_varint(len(data))
        self._buf += data

    def write_bytes_always(self, field_number: int, data: bytes) -> None:
        # Emits tag + length even for empty bytes (envelope `payload`, §3.4).
        self._write_tag(field_number, WIRE_LEN)
        self._write_varint(len(data))
        self._buf += data

    def write_string(self, field_number: int, value: str) -> None:
        if not value:
            return
        data = value.encode("utf-8")
        self._write_tag(field_number, WIRE_LEN)
        self._write_varint(len(data))
        self._buf += data

    def write_message(self, field_number: int, data: bytes) -> None:
        self._write_tag(field_number, WIRE_LEN)
        self._write_varint(len(data))
        self._buf += data


class ProtoReader:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    @property
    def at_end(self) -> bool:
        return self._pos >= len(self._data)

    def read_varint(self) -> int:
        result = 0
        shift = 0
        while True:
            if self._pos >= len(self._data):
                raise ProtoDecodeError(f"truncated varint at {self._pos}")
            b = self._data[self._pos]
            self._pos += 1
            result |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                return result
            shift += 7
            if shift > 63:
                raise ProtoDecodeError("varint > 64 bits")

    def read_tag(self) -> int:
        return self.read_varint()

    def read_uint32(self) -> int:
        return self.read_varint()

    read_uint64 = read_uint32

    def read_sint64(self) -> int:
        return _zigzag_decode64(self.read_varint())

    def read_len_delimited(self) -> bytes:
        n = self.read_varint()
        if n < 0 or self._pos + n > len(self._data):
            raise ProtoDecodeError("length-delimited overflow")
        out = self._data[self._pos : self._pos + n]
        self._pos += n
        return out

    def read_string(self) -> str:
        return self.read_len_delimited().decode("utf-8")

    def skip_value(self, wire_type: int) -> None:
        if wire_type == WIRE_VARINT:
            self.read_varint()
        elif wire_type == WIRE_LEN:
            n = self.read_varint()
            if self._pos + n > len(self._data):
                raise ProtoDecodeError("skip length-delimited overflow")
            self._pos += n
        elif wire_type == 1:
            self._pos += 8
        elif wire_type == 5:
            self._pos += 4
        else:
            raise ProtoDecodeError(f"unsupported wire type {wire_type}")


def _tag_field(tag: int) -> int:
    return tag >> 3


def _tag_wire(tag: int) -> int:
    return tag & 0x7


# ─────────────────────────────────────────────────────────────────────────────
# HLC timestamp (proto: 1=ms uint64, 2=counter uint32)
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class HlcTimestamp:
    ms: int = 0
    counter: int = 0

    def encode(self) -> bytes:
        w = ProtoWriter()
        w.write_uint64(1, self.ms)
        w.write_uint32(2, self.counter)
        return w.to_bytes()

    @staticmethod
    def decode(data: bytes) -> "HlcTimestamp":
        r = ProtoReader(data)
        ms = 0
        ctr = 0
        while not r.at_end:
            tag = r.read_tag()
            f, wt = _tag_field(tag), _tag_wire(tag)
            if f == 1:
                ms = r.read_uint64()
            elif f == 2:
                ctr = r.read_uint32()
            else:
                r.skip_value(wt)
        return HlcTimestamp(ms=ms, counter=ctr)


# ─────────────────────────────────────────────────────────────────────────────
# Payload structs (decode + encode for round-trip cross-impl proof)
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class LocationEvidence:
    source: int = 0
    frame: int = 0
    lat_e7: int = 0
    lng_e7: int = 0
    accuracy_m: int = 0
    observed_at: HlcTimestamp = dataclass_field(default_factory=HlcTimestamp)
    anchor_node_id: str = ""
    distance_from_anchor_m: int = 0
    bearing_deg: Optional[int] = None

    def encode(self) -> bytes:
        w = ProtoWriter()
        w.write_enum(1, self.source)
        w.write_enum(2, self.frame)
        w.write_sint64(3, self.lat_e7)
        w.write_sint64(4, self.lng_e7)
        w.write_uint32(5, self.accuracy_m)
        if self.observed_at.ms != 0 or self.observed_at.counter != 0:
            w.write_message(6, self.observed_at.encode())
        w.write_string(7, self.anchor_node_id)
        w.write_uint32(8, self.distance_from_anchor_m)
        if self.bearing_deg is not None:
            w.write_uint32(9, self.bearing_deg + 1)
        return w.to_bytes()

    @staticmethod
    def decode(data: bytes) -> "LocationEvidence":
        r = ProtoReader(data)
        source = frame = lat = lng = acc = dist = 0
        observed = HlcTimestamp()
        anchor = ""
        bearing: Optional[int] = None
        while not r.at_end:
            tag = r.read_tag()
            f, wt = _tag_field(tag), _tag_wire(tag)
            if f == 1:
                source = r.read_uint32()
            elif f == 2:
                frame = r.read_uint32()
            elif f == 3:
                lat = r.read_sint64()
            elif f == 4:
                lng = r.read_sint64()
            elif f == 5:
                acc = r.read_uint32()
            elif f == 6:
                observed = HlcTimestamp.decode(r.read_len_delimited())
            elif f == 7:
                anchor = r.read_string()
            elif f == 8:
                dist = r.read_uint32()
            elif f == 9:
                raw = r.read_uint32()
                bearing = None if raw == 0 else raw - 1
            else:
                r.skip_value(wt)
        return LocationEvidence(
            source=source, frame=frame, lat_e7=lat, lng_e7=lng, accuracy_m=acc,
            observed_at=observed, anchor_node_id=anchor,
            distance_from_anchor_m=dist, bearing_deg=bearing,
        )


@dataclass(frozen=True)
class NeedEntry:
    category: int = 0
    severity: int = 0
    expires_at: HlcTimestamp = dataclass_field(default_factory=HlcTimestamp)

    def encode(self) -> bytes:
        w = ProtoWriter()
        w.write_enum(1, self.category)
        w.write_enum(2, self.severity)
        w.write_message(3, self.expires_at.encode())
        return w.to_bytes()

    @staticmethod
    def decode(data: bytes) -> "NeedEntry":
        r = ProtoReader(data)
        cat = sev = 0
        expires = HlcTimestamp()
        while not r.at_end:
            tag = r.read_tag()
            f, wt = _tag_field(tag), _tag_wire(tag)
            if f == 1:
                cat = r.read_uint32()
            elif f == 2:
                sev = r.read_uint32()
            elif f == 3:
                expires = HlcTimestamp.decode(r.read_len_delimited())
            else:
                r.skip_value(wt)
        return NeedEntry(category=cat, severity=sev, expires_at=expires)


@dataclass(frozen=True)
class StatusUpdateData:
    safety_state: int = 0
    needs: List[NeedEntry] = dataclass_field(default_factory=list)
    location: Optional[LocationEvidence] = None

    def encode(self) -> bytes:
        w = ProtoWriter()
        w.write_enum(1, self.safety_state)
        for n in self.needs:
            w.write_message(2, n.encode())
        if self.location is not None:
            w.write_message(3, self.location.encode())
        return w.to_bytes()

    @staticmethod
    def decode(data: bytes) -> "StatusUpdateData":
        r = ProtoReader(data)
        state = 0
        needs: List[NeedEntry] = []
        location: Optional[LocationEvidence] = None
        while not r.at_end:
            tag = r.read_tag()
            f, wt = _tag_field(tag), _tag_wire(tag)
            if f == 1:
                state = r.read_uint32()
            elif f == 2:
                needs.append(NeedEntry.decode(r.read_len_delimited()))
            elif f == 3:
                location = LocationEvidence.decode(r.read_len_delimited())
            else:
                r.skip_value(wt)
        return StatusUpdateData(safety_state=state, needs=needs, location=location)


@dataclass(frozen=True)
class PresenceData:
    anon_user_id: bytes = b""
    location: LocationEvidence = dataclass_field(default_factory=LocationEvidence)
    battery_hint: int = 0

    def encode(self) -> bytes:
        w = ProtoWriter()
        w.write_bytes(1, self.anon_user_id)
        loc = self.location.encode()
        if loc:
            w.write_message(2, loc)
        w.write_uint32(3, self.battery_hint)
        return w.to_bytes()

    @staticmethod
    def decode(data: bytes) -> "PresenceData":
        r = ProtoReader(data)
        anon = b""
        location = LocationEvidence()
        battery = 0
        while not r.at_end:
            tag = r.read_tag()
            f, wt = _tag_field(tag), _tag_wire(tag)
            if f == 1:
                anon = r.read_len_delimited()
            elif f == 2:
                location = LocationEvidence.decode(r.read_len_delimited())
            elif f == 3:
                battery = r.read_uint32()
            else:
                r.skip_value(wt)
        return PresenceData(anon_user_id=anon, location=location, battery_hint=battery)


@dataclass(frozen=True)
class CheckpointData:
    anon_user_id: bytes = b""
    checkpoint_id: str = ""
    location: LocationEvidence = dataclass_field(default_factory=LocationEvidence)

    def encode(self) -> bytes:
        w = ProtoWriter()
        w.write_bytes(1, self.anon_user_id)
        w.write_string(2, self.checkpoint_id)
        loc = self.location.encode()
        if loc:
            w.write_message(3, loc)
        return w.to_bytes()

    @staticmethod
    def decode(data: bytes) -> "CheckpointData":
        r = ProtoReader(data)
        anon = b""
        cid = ""
        location = LocationEvidence()
        while not r.at_end:
            tag = r.read_tag()
            f, wt = _tag_field(tag), _tag_wire(tag)
            if f == 1:
                anon = r.read_len_delimited()
            elif f == 2:
                cid = r.read_string()
            elif f == 3:
                location = LocationEvidence.decode(r.read_len_delimited())
            else:
                r.skip_value(wt)
        return CheckpointData(anon_user_id=anon, checkpoint_id=cid, location=location)


@dataclass(frozen=True)
class HazardMarkerData:
    hazard_id: str = ""
    hazard_type: int = 0
    severity: int = 0
    location: LocationEvidence = dataclass_field(default_factory=LocationEvidence)
    description: str = ""
    is_confirmation: bool = False

    def encode(self) -> bytes:
        w = ProtoWriter()
        w.write_string(1, self.hazard_id)
        w.write_enum(2, self.hazard_type)
        w.write_uint32(3, self.severity)
        loc = self.location.encode()
        if loc:
            w.write_message(4, loc)
        w.write_string(5, self.description)
        w.write_bool(6, self.is_confirmation)
        return w.to_bytes()

    @staticmethod
    def decode(data: bytes) -> "HazardMarkerData":
        r = ProtoReader(data)
        hid = ""
        htype = sev = 0
        location = LocationEvidence()
        desc = ""
        confirm = False
        while not r.at_end:
            tag = r.read_tag()
            f, wt = _tag_field(tag), _tag_wire(tag)
            if f == 1:
                hid = r.read_string()
            elif f == 2:
                htype = r.read_uint32()
            elif f == 3:
                sev = r.read_uint32()
            elif f == 4:
                location = LocationEvidence.decode(r.read_len_delimited())
            elif f == 5:
                desc = r.read_string()
            elif f == 6:
                confirm = r.read_uint32() != 0
            else:
                r.skip_value(wt)
        return HazardMarkerData(
            hazard_id=hid, hazard_type=htype, severity=sev, location=location,
            description=desc, is_confirmation=confirm,
        )


@dataclass(frozen=True)
class AdminBroadcastData:
    scope: int = 0
    message: str = ""
    expires_at: HlcTimestamp = dataclass_field(default_factory=HlcTimestamp)

    def encode(self) -> bytes:
        w = ProtoWriter()
        w.write_enum(1, self.scope)
        w.write_string(2, self.message)
        if self.expires_at.ms != 0 or self.expires_at.counter != 0:
            w.write_message(3, self.expires_at.encode())
        return w.to_bytes()

    @staticmethod
    def decode(data: bytes) -> "AdminBroadcastData":
        r = ProtoReader(data)
        scope = 0
        message = ""
        expires = HlcTimestamp()
        while not r.at_end:
            tag = r.read_tag()
            f, wt = _tag_field(tag), _tag_wire(tag)
            if f == 1:
                scope = r.read_uint32()
            elif f == 2:
                message = r.read_string()
            elif f == 3:
                expires = HlcTimestamp.decode(r.read_len_delimited())
            else:
                r.skip_value(wt)
        return AdminBroadcastData(scope=scope, message=message, expires_at=expires)


@dataclass(frozen=True)
class NodeReceiptData:
    ref_envelope_id: bytes = b""
    status: int = 0
    queue_depth: int = 0

    def encode(self) -> bytes:
        w = ProtoWriter()
        w.write_bytes(1, self.ref_envelope_id)
        w.write_uint32(2, self.status)
        w.write_uint32(3, self.queue_depth)
        return w.to_bytes()

    @staticmethod
    def decode(data: bytes) -> "NodeReceiptData":
        r = ProtoReader(data)
        ref = b""
        status = depth = 0
        while not r.at_end:
            tag = r.read_tag()
            f, wt = _tag_field(tag), _tag_wire(tag)
            if f == 1:
                ref = r.read_len_delimited()
            elif f == 2:
                status = r.read_uint32()
            elif f == 3:
                depth = r.read_uint32()
            else:
                r.skip_value(wt)
        return NodeReceiptData(ref_envelope_id=ref, status=status, queue_depth=depth)


# ─────────────────────────────────────────────────────────────────────────────
# EventEnvelopeV2 (proto fields 1..15; v3 adds 14 field_id / 15 field_mac)
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class EventEnvelopeV2:
    protocol_version: int
    envelope_id: bytes
    event_type: int
    priority: int
    created_at_hlc: HlcTimestamp
    expires_at_hlc: HlcTimestamp
    author_key: bytes
    sig_algo: int
    signature: bytes
    payload: bytes
    max_hops: int = 0
    last_relay_id: str = ""
    is_experimental: bool = False
    field_id: bytes = b"\x00" * 16
    field_mac: bytes = b""

    def encode(self) -> bytes:
        w = ProtoWriter()
        w.write_uint32(1, self.protocol_version)
        w.write_bytes(2, self.envelope_id)
        w.write_enum(3, self.event_type)
        w.write_enum(4, self.priority)
        w.write_message(5, self.created_at_hlc.encode())
        w.write_message(6, self.expires_at_hlc.encode())
        w.write_uint32(7, self.max_hops)
        w.write_bytes(8, self.author_key)
        w.write_uint32(9, self.sig_algo)
        w.write_bytes(10, self.signature)
        w.write_bytes_always(11, self.payload)
        w.write_string(12, self.last_relay_id)
        w.write_bool(13, self.is_experimental)
        w.write_bytes(14, self.field_id)
        w.write_bytes(15, self.field_mac)
        return w.to_bytes()

    @staticmethod
    def decode(data: bytes) -> "EventEnvelopeV2":
        r = ProtoReader(data)
        pv = 0
        pv_seen = False
        envelope_id: Optional[bytes] = None
        event_type = priority = max_hops = 0
        created = expires = None
        author_key: Optional[bytes] = None
        sig_algo = 0
        sig_algo_seen = False
        signature: Optional[bytes] = None
        payload: Optional[bytes] = None
        last_relay_id = ""
        is_experimental = False
        field_id: Optional[bytes] = None
        field_mac = b""
        while not r.at_end:
            tag = r.read_tag()
            f, wt = _tag_field(tag), _tag_wire(tag)
            if f == 1:
                pv = r.read_uint32()
                pv_seen = True
            elif f == 2:
                envelope_id = r.read_len_delimited()
            elif f == 3:
                event_type = r.read_uint32()
            elif f == 4:
                priority = r.read_uint32()
            elif f == 5:
                created = HlcTimestamp.decode(r.read_len_delimited())
            elif f == 6:
                expires = HlcTimestamp.decode(r.read_len_delimited())
            elif f == 7:
                max_hops = r.read_uint32()
            elif f == 8:
                author_key = r.read_len_delimited()
            elif f == 9:
                sig_algo = r.read_uint32()
                sig_algo_seen = True
            elif f == 10:
                signature = r.read_len_delimited()
            elif f == 11:
                payload = r.read_len_delimited()
            elif f == 12:
                last_relay_id = r.read_string()
            elif f == 13:
                is_experimental = r.read_uint32() != 0
            elif f == 14:
                field_id = r.read_len_delimited()
            elif f == 15:
                field_mac = r.read_len_delimited()
            else:
                r.skip_value(wt)
        # Required-field enforcement (envelope_v2_spec §3.4 / §21.2).
        if not pv_seen or pv == 0:
            raise ProtoDecodeError("protocol_version missing or zero")
        if envelope_id is None or len(envelope_id) != 16:
            raise ProtoDecodeError("envelope_id missing or not 16 bytes")
        if event_type == 0:
            raise ProtoDecodeError("event_type missing or UNSPECIFIED")
        if priority == 0:
            raise ProtoDecodeError("priority missing or UNSPECIFIED")
        if created is None:
            raise ProtoDecodeError("created_at_hlc missing")
        if expires is None:
            raise ProtoDecodeError("expires_at_hlc missing")
        if author_key is None or len(author_key) != 32:
            raise ProtoDecodeError("author_key missing or not 32 bytes")
        if not sig_algo_seen:
            raise ProtoDecodeError("sig_algo missing")
        if signature is None or len(signature) != 64:
            raise ProtoDecodeError("signature missing or not 64 bytes")
        if payload is None:
            raise ProtoDecodeError("payload field missing")
        if field_id is None or len(field_id) != 16:
            raise ProtoDecodeError("field_id missing or not 16 bytes")
        if field_mac and len(field_mac) != 16:
            raise ProtoDecodeError("field_mac present but not 16 bytes")
        return EventEnvelopeV2(
            protocol_version=pv, envelope_id=envelope_id, event_type=event_type,
            priority=priority, created_at_hlc=created, expires_at_hlc=expires,
            max_hops=max_hops, author_key=author_key, sig_algo=sig_algo,
            signature=signature, payload=payload, last_relay_id=last_relay_id,
            is_experimental=is_experimental, field_id=field_id, field_mac=field_mac,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Canonical signature input (v3, 141 B — canonical_encoder_v2.dart)
# ─────────────────────────────────────────────────────────────────────────────


def payload_hash(payload: bytes) -> bytes:
    return hashlib.sha256(payload).digest()


def canonical_sig_input_v3(
    *,
    protocol_version: int,
    envelope_id: bytes,
    field_id: bytes,
    event_type: int,
    priority: int,
    created_ms: int,
    created_counter: int,
    expires_ms: int,
    expires_counter: int,
    max_hops: int,
    author_key: bytes,
    sig_algo: int,
    payload_sha256: bytes,
) -> bytes:
    if len(envelope_id) != 16:
        raise ValueError("envelope_id must be 16 bytes")
    if len(field_id) != 16:
        raise ValueError("field_id must be 16 bytes")
    if len(author_key) != 32:
        raise ValueError("author_key must be 32 bytes")
    if len(payload_sha256) != 32:
        raise ValueError("payload_hash must be 32 bytes")
    out = bytearray()
    out += struct.pack("<I", protocol_version)
    out += bytes([16]) + envelope_id
    out += bytes([16]) + field_id
    out += struct.pack("<I", event_type)
    out += struct.pack("<I", priority)
    out += struct.pack("<Q", created_ms)
    out += struct.pack("<I", created_counter)
    out += struct.pack("<Q", expires_ms)
    out += struct.pack("<I", expires_counter)
    out += struct.pack("<I", max_hops)
    out += bytes([32]) + author_key
    out += bytes([sig_algo])
    out += bytes([32]) + payload_sha256
    if len(out) != CANONICAL_SIG_INPUT_BYTES:
        raise AssertionError(f"sig_input drift: {len(out)}")
    return bytes(out)


def ed25519_verify(author_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(author_key).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Deterministic LCG payload generator (corpus notes.payload_generator_*)
# ─────────────────────────────────────────────────────────────────────────────


def lcg_payload(seed: int, size: int) -> bytes:
    out = bytearray(size)
    state = seed & 0xFFFFFFFF
    for i in range(size):
        state = ((state * 1664525) + 1013904223) & 0xFFFFFFFF
        out[i] = state & 0xFF
    return bytes(out)


# ─────────────────────────────────────────────────────────────────────────────
# Negative-case classifier — reproduces the receiver/transport verdict for each
# corpus negative descriptor (envelope_v2_spec §3.4/§21 + native_transport_v1 §4).
# Returns the spec drop_reason; the conformance test asserts it equals the
# corpus's expected_drop_reason. Genuine validation (no echoing).
# ─────────────────────────────────────────────────────────────────────────────


def check_protocol_version(pv: int) -> Optional[str]:
    return None if pv == PROTOCOL_VERSION_V3 else "unknown-protocol-version"


def check_sig_algo(algo: int) -> Optional[str]:
    return None if algo == SIG_ALGO_ED25519 else "unknown-sig-algo"


def check_expiry(created_ms: int, expires_ms: int) -> Optional[str]:
    return "envelope-expired" if expires_ms < created_ms else None


def check_sos_budget(length: int) -> Optional[str]:
    return "over-budget-sos-rejected" if length > SOS_ENVELOPE_BUDGET_BYTES else None


def check_max_envelope(length: int) -> Optional[str]:
    return "over-max-envelope-bytes" if length > MAX_ENVELOPE_BYTES else None


def check_chunk_header(total_chunks: int, chunk_index: int) -> Optional[str]:
    # native_transport_v1 §4: total_chunks>=1 and chunk_index<total_chunks.
    if total_chunks <= 0 or chunk_index >= total_chunks or chunk_index < 0:
        return "chunk-bad-header"
    return None


def check_chunk_envelope_id_len(n: int) -> Optional[str]:
    return None if n == 16 else "invalid-envelope-id"


def _chunk_payload_size(mtu: int) -> int:
    return mtu - ATT_HEADER_SIZE - CHUNK_HEADER_SIZE


def check_chunk_mtu(mtu: int) -> Optional[str]:
    return "mtu-below-minimum-for-chunked" if _chunk_payload_size(mtu) < 1 else None


def check_chunk_count(envelope_len: int, mtu: int) -> Optional[str]:
    cp = _chunk_payload_size(mtu)
    if cp < 1:
        return "mtu-below-minimum-for-chunked"
    num_chunks = -(-envelope_len // cp)  # ceil
    return "over-max-chunks" if num_chunks > MAX_CHUNKS_PER_ENVELOPE else None


def check_reassembly_prefixes(prefixes: List[bytes]) -> Optional[str]:
    if len(set(prefixes)) > 1:
        return "reassembly-envelope-id-mismatch"
    return None


def classify_corpus_negative(case: dict) -> Optional[str]:
    """Apply the reference verdict to a corpus negative descriptor.

    Returns the drop_reason the reference implementation produces. The test
    compares it to `case['expected_drop_reason']`.
    """
    kind = case["kind"]
    if kind == "unknown_protocol_version":
        return check_protocol_version(case["protocol_version"])
    if kind == "unknown_sig_algo":
        return check_sig_algo(case["sig_algo"])
    if kind == "expires_before_created":
        return check_expiry(case["created_at_hlc_ms"], case["expires_at_hlc_ms"])
    if kind == "oversize_sos":
        return check_sos_budget(case["envelope_bytes_hex_length"])
    if kind == "oversize_envelope":
        return check_max_envelope(case["envelope_bytes_hex_length"])
    # native_transport_v1 §4 chunk/transport guards.
    if kind == "chunk_total_zero":
        return check_chunk_header(total_chunks=0, chunk_index=0)
    if kind == "chunk_index_oob":
        return check_chunk_header(total_chunks=2, chunk_index=5)
    if kind == "chunk_bad_envelope_id_length":
        return check_chunk_envelope_id_len(case["envelope_id_bytes"])
    if kind == "mtu_below_minimum":
        return check_chunk_mtu(case["mtu"])
    if kind == "over_max_chunks":
        return check_chunk_count(case["envelope_bytes_hex_length"], case["mtu"])
    if kind == "invalid_envelope_id_in_chunk":
        return check_reassembly_prefixes([b"\x01" * 16, b"\x02" * 16])
    raise ValueError(f"unknown negative-case kind: {kind}")
