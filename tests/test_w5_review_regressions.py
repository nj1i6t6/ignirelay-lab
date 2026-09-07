"""W5 review regression tests.

Verifies:
1. Relay forward responsibility durability across reboot (unacked relay must survive restart).
2. Relay queue-full admission (must reject when queue is full, without poisoning dedupe).
3. 513th expired record survives runtime recovery and sticky rejection (dedupe / journal alignment).
4. LoRa ingest path rejects known-expired frames (no success ACK, no echo, no forwarding).
5. TTL=1 frames do not occupy metadata queue and do not leak capacity.
"""

from __future__ import annotations

import socket
import struct
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from ignirelay_lab import e2e_real_stack as e2e
from ignirelay_lab.actors import FakePhone
from ignirelay_lab.wire import lora_v1 as lora


def _exe_available() -> bool:
    try:
        e2e.node_exe_path()
        return True
    except e2e.NodeExeMissing:
        return False


@unittest.skipUnless(_exe_available(),
                     "set IGNIRELAY_NODE_EXE to the field-node bsim zephyr.exe")
class W5ReviewRegressionTests(unittest.TestCase):
    def test_relay_ack_responsibility_survives_restart(self) -> None:
        """Receiver that ACKs a relay frame must persist it; unacked relay survives restart."""
        phone = FakePhone("r6-relay")
        ports = e2e.make_ports(3300)
        eid = b"\x99" * 16

        with tempfile.TemporaryDirectory() as d:
            n = e2e.NodeProcess(e2e.node_exe_path(), 2, phone.field.secret.hex(),
                                Path(d) / "before", ports)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind((e2e.HUB_HOST, ports.hub_port))
            s.settimeout(0.1)
            try:
                n.start()
                self.assertTrue(n.wait_ready())
                b = lora.encode_event_frame(
                    lora_mac_key=phone.field.lora_mac_key,
                    flags=0,
                    field_tag=phone.field.field_id[:4],
                    src_node=1,
                    packet_seq=11,
                    ttl=4,
                    event_id=eid,
                    event_type=1,
                    priority=0,
                    hlc_ms=1000,
                    hlc_counter=0,
                    payload=b"\x00" * 22,
                )
                s.sendto(b, (e2e.HUB_HOST, ports.node_ports[2]))
                acks = []
                forward = False
                deadline = time.monotonic() + 0.5
                while time.monotonic() < deadline:
                    try:
                        raw, _ = s.recvfrom(2048)
                    except socket.timeout:
                        continue
                    f = lora.verify_lora_frame(raw, lora_mac_key=phone.field.lora_mac_key).parsed
                    if f and f.ptype == 2:
                        acks.append(f.status)
                    if f and f.ptype == 1:
                        forward = True
                        break
                self.assertIn(0, acks, "Node must return ACK accepted (0)")
                self.assertTrue(forward, "Node must forward the event")
                n.stop()

                e2e.drain_udp(s)
                s.settimeout(0.1)

                journal_file = Path(d) / "node_2.journal"
                self.assertTrue(journal_file.exists(), "Journal file must exist")
                self.assertGreater(journal_file.stat().st_size, 0, "Journal must persist unacked relay")

                # Restart node and verify it recovers the pending relay and resumes transmission
                n2 = e2e.NodeProcess(e2e.node_exe_path(), 2, phone.field.secret.hex(),
                                     Path(d) / "after", ports)
                n2.start()
                self.assertTrue(n2.wait_ready())
                deadline = time.monotonic() + 1.0
                auto = False
                while time.monotonic() < deadline:
                    if eid.hex() in n2.stdout_text():
                        auto = True
                        break
                    time.sleep(0.01)
                self.assertTrue(auto, "Receiver ACKed and undertook forwarding; unacked relay must survive restart")
            finally:
                n.stop()
                if "n2" in locals():
                    n2.stop()
                s.close()

    def test_relay_full_must_not_accept_and_poison_dedupe(self) -> None:
        """When TX queue is full, relay must reject without poisoning dedupe so resend can succeed."""
        phone = FakePhone("r6-full")
        ports = e2e.make_ports(3340)

        with tempfile.TemporaryDirectory() as d:
            n = e2e.NodeProcess(e2e.node_exe_path(), 2, phone.field.secret.hex(),
                                Path(d) / "n", ports)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind((e2e.HUB_HOST, ports.hub_port))
            s.settimeout(0.05)
            try:
                n.start()
                self.assertTrue(n.wait_ready())
                raws = []
                for i in range(9):
                    raws.append(lora.encode_event_frame(
                        lora_mac_key=phone.field.lora_mac_key,
                        flags=0,
                        field_tag=phone.field.field_id[:4],
                        src_node=1,
                        packet_seq=100 + i,
                        ttl=4,
                        event_id=bytes([i + 1]) * 16,
                        event_type=1,
                        priority=0,
                        hlc_ms=1000 + i,
                        hlc_counter=0,
                        payload=b"\x00" * 22,
                    ))

                # Send all 9 frames
                for b in raws:
                    s.sendto(b, (e2e.HUB_HOST, ports.node_ports[2]))

                deadline = time.monotonic() + 0.5
                acks = []
                got = set()
                while time.monotonic() < deadline:
                    try:
                        raw, _ = s.recvfrom(2048)
                    except socket.timeout:
                        continue
                    f = lora.verify_lora_frame(raw, lora_mac_key=phone.field.lora_mac_key).parsed
                    if f and f.ptype == 2 and f.ack_seq == 108:
                        acks.append(f.status)
                    if f and f.ptype == 1:
                        got.add(f.event_id[0])

                # Resend the 9th frame
                s.sendto(raws[-1], (e2e.HUB_HOST, ports.node_ports[2]))
                time.sleep(0.05)

                deadline = time.monotonic() + 0.15
                while time.monotonic() < deadline:
                    try:
                        raw, _ = s.recvfrom(2048)
                    except socket.timeout:
                        continue
                    f = lora.verify_lora_frame(raw, lora_mac_key=phone.field.lora_mac_key).parsed
                    if f and f.ptype == 2 and f.ack_seq == 108:
                        acks.append(f.status)
                    if f and f.ptype == 1:
                        got.add(f.event_id[0])

                # Invariant: 9th packet when queue was full must NOT have been ACK accepted (0) while dropped
                self.assertFalse(0 in acks and 9 not in got,
                                 "ACK accepted cannot silently lose admission and dedupe retries")
            finally:
                n.stop()
                s.close()

    def test_513th_expired_survives_runtime_recovery(self) -> None:
        """513th expired record survives restart and sticky rejection."""
        phone = FakePhone("r7-expired")
        ports = e2e.make_ports(3420)
        target = phone.sos(1000)

        with tempfile.TemporaryDirectory() as d:
            ids = [i.to_bytes(16, "little") for i in range(512)] + [target.envelope_id]
            b = bytearray()
            for eid in ids:
                body = struct.pack("<IBBH", 0x49474E49, 1, 4, 28) + eid
                b.extend(body + struct.pack("<HH", lora.crc16_ccitt(body), 0x55AA))
            (Path(d) / "node_1.journal").write_bytes(b)

            n = e2e.NodeProcess(e2e.node_exe_path(), 1, phone.field.secret.hex(),
                                Path(d) / "n", ports)
            try:
                n.start()
                self.assertTrue(n.wait_ready())
                e2e.inject_ble(1, [(phone.anon_user_id[:8], target.envelope_bytes)], ports)
                time.sleep(0.08)
                trace = [x for x in n.stdout_text().splitlines() if target.event_id_hex in x]
                self.assertTrue(any("envelope-expired" in x for x in trace),
                                "Persisted expired ID #513 must not become accepted after reboot")
            finally:
                n.stop()

    def test_lora_honors_known_expired(self) -> None:
        """LoRa RX path rejects known-expired events without ACK accepted and without forwarding."""
        phone = FakePhone("r7-expired-lora")
        ports = e2e.make_ports(3500)
        eid = b"\x66" * 16

        with tempfile.TemporaryDirectory() as d:
            body = struct.pack("<IBBH", 0x49474E49, 1, 4, 28) + eid
            (Path(d) / "node_2.journal").write_bytes(body + struct.pack("<HH", lora.crc16_ccitt(body), 0x55AA))

            n = e2e.NodeProcess(e2e.node_exe_path(), 2, phone.field.secret.hex(),
                                Path(d) / "n", ports)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind((e2e.HUB_HOST, ports.hub_port))
            s.settimeout(0.05)
            try:
                n.start()
                self.assertTrue(n.wait_ready())
                raw = lora.encode_event_frame(
                    lora_mac_key=phone.field.lora_mac_key,
                    flags=0,
                    field_tag=phone.field.field_id[:4],
                    src_node=1,
                    packet_seq=11,
                    ttl=4,
                    event_id=eid,
                    event_type=1,
                    priority=1,
                    hlc_ms=1000,
                    hlc_counter=0,
                    payload=b"\x00" * 22,
                )
                s.sendto(raw, (e2e.HUB_HOST, ports.node_ports[2]))
                acks = []
                forward = False
                deadline = time.monotonic() + 0.2
                while time.monotonic() < deadline:
                    try:
                        b, _ = s.recvfrom(2048)
                    except socket.timeout:
                        continue
                    f = lora.verify_lora_frame(b, lora_mac_key=phone.field.lora_mac_key).parsed
                    if f and f.ptype == 2:
                        acks.append(f.status)
                    if f and f.ptype == 1 and f.event_id == eid:
                        forward = True
                self.assertNotIn(0, acks, "Known-expired frame must not receive ACK 0")
                self.assertFalse(forward, "Known-expired frame must not be forwarded")
            finally:
                n.stop()
                s.close()

    def test_ttl_one_does_not_leak_metadata_queue(self) -> None:
        """TTL=1 frames must not occupy metadata queue or block fresh SOS."""
        phone = FakePhone("r7-ttl")
        ports = e2e.make_ports(3460)

        with tempfile.TemporaryDirectory() as d:
            n = e2e.NodeProcess(e2e.node_exe_path(), 2, phone.field.secret.hex(),
                                Path(d) / "n", ports)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind((e2e.HUB_HOST, ports.hub_port))
            s.settimeout(0.2)
            try:
                n.start()
                self.assertTrue(n.wait_ready())
                acks = []
                for i in range(16):
                    raw = lora.encode_event_frame(
                        lora_mac_key=phone.field.lora_mac_key,
                        flags=0,
                        field_tag=phone.field.field_id[:4],
                        src_node=1,
                        packet_seq=100 + i,
                        ttl=1,
                        event_id=bytes([i + 1]) * 16,
                        event_type=1,
                        priority=1,
                        hlc_ms=1000 + i,
                        hlc_counter=0,
                        payload=b"\x00" * 22,
                    )
                    s.sendto(raw, (e2e.HUB_HOST, ports.node_ports[2]))
                    b, _ = s.recvfrom(2048)
                    f = lora.verify_lora_frame(b, lora_mac_key=phone.field.lora_mac_key).parsed
                    acks.append(f.status)

                target = phone.sos(2000)
                e2e.inject_ble(2, [(phone.anon_user_id[:8], target.envelope_bytes)], ports)
                time.sleep(0.08)
                lines = [x for x in n.stdout_text().splitlines() if target.event_id_hex in x]
                self.assertTrue(
                    any("NODE_RECEIPT" in x and "accepted" in x for x in lines),
                    "No pending TX remains, so TTL1 must not consume metadata capacity forever",
                )
            finally:
                n.stop()
                s.close()

    def test_eviction_and_failed_replacement_are_atomic(self) -> None:
        """Failed priority replacement due to storage full must preserve previously accepted pending events."""
        p = FakePhone("r8-evict")
        ports = e2e.make_ports(3540)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "node_1.journal"
            n = e2e.NodeProcess(e2e.node_exe_path(), 1, p.field.secret.hex(), Path(d) / "n", ports)
            try:
                n.start()
                self.assertTrue(n.wait_ready())
                events = [p.presence(1000 + i) for i in range(8)]
                sos = p.sos(2000)
                e2e.inject_ble(1, [(p.anon_user_id[:8], x.envelope_bytes) for x in events], ports)
                time.sleep(0.15)
                # Inject real storage write failure before injecting SOS
                subprocess.run(["chattr", "+i", str(path)], check=True)
                try:
                    e2e.inject_ble(1, [(p.anon_user_id[:8], sos.envelope_bytes)], ports)
                    time.sleep(0.15)
                finally:
                    subprocess.run(["chattr", "-i", str(path)], check=True)
                n.stop()
                trace = n.stdout_text()
                accepted = sum(any(x.event_id_hex in line and "NODE_RECEIPT" in line and "accepted" in line
                                   for line in trace.splitlines()) for x in events)
                pending = set()
                data = path.read_bytes()
                off = 0
                while off + 12 <= len(data):
                    length = int.from_bytes(data[off + 6:off + 8], "little")
                    kind = data[off + 5]
                    eid = data[off + 8:off + 24]
                    if kind == 1:
                        pending.add(eid)
                    elif kind in (3, 4):
                        pending.discard(eid)
                    if not length:
                        break
                    off += length
                remaining = sum(x.envelope_id in pending for x in events)
                self.assertEqual(accepted, 8, "precondition: all old events accepted")
                self.assertEqual(remaining, 8, "Failed replacement must preserve previously accepted pending")
            finally:
                n.stop()

    def test_ack_storage_full_does_not_restart_retry_budget(self) -> None:
        """When journal ACK append fails, refill must never restart retry budget for acknowledged events."""
        p = FakePhone("r8-ack-full")
        ports = e2e.make_ports(3580)
        with tempfile.TemporaryDirectory() as d:
            b = bytearray()
            for i in range(1165):
                body = struct.pack("<IBBH", 0x49474E49, 1, 2, 28) + i.to_bytes(16, "little")
                b.extend(body + struct.pack("<HH", lora.crc16_ccitt(body), 0x55AA))
            (Path(d) / "node_1.journal").write_bytes(b)
            n = e2e.NodeProcess(e2e.node_exe_path(), 1, p.field.secret.hex(), Path(d) / "n", ports)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind((e2e.HUB_HOST, ports.hub_port))
            s.settimeout(0.1)
            try:
                n.start()
                self.assertTrue(n.wait_ready())
                target = p.sos(1000)
                e2e.inject_ble(1, [(p.anon_user_id[:8], target.envelope_bytes)], ports)
                sent = 0
                deadline = time.monotonic() + 1.0
                while time.monotonic() < deadline and sent < 6:
                    try:
                        raw, _ = s.recvfrom(2048)
                    except socket.timeout:
                        continue
                    f = lora.verify_lora_frame(raw, lora_mac_key=p.field.lora_mac_key).parsed
                    if f and f.ptype == 1 and f.event_id == target.envelope_id:
                        sent += 1
                        ack = lora.encode_ack_frame(
                            lora_mac_key=p.field.lora_mac_key,
                            flags=0,
                            field_tag=p.field.field_id[:4],
                            src_node=2,
                            packet_seq=1,
                            ttl=1,
                            ack_seq=f.packet_seq,
                            event_id_prefix=f.event_id[:8],
                            status=0,
                        )
                        s.sendto(ack, (e2e.HUB_HOST, ports.node_ports[1]))
                self.assertEqual(sent, 1, "expected 1 after valid ACK; never reset budget")
            finally:
                n.stop()
                s.close()

    def test_seen_only_full_storage_permits_fresh_sos(self) -> None:
        """When journal is full of pure historical SEEN records (TTL=1), compaction reclaims them so fresh SOS is admitted."""
        p = FakePhone("r9-seen-only-full")
        ports = e2e.make_ports(3620)

        def event(i: int, ttl: int) -> bytes:
            return lora.encode_event_frame(
                lora_mac_key=p.field.lora_mac_key, flags=0,
                field_tag=p.field.field_id[:4], src_node=2,
                packet_seq=i, ttl=ttl,
                event_id=(100000 + i).to_bytes(16, "little"),
                event_type=1, priority=1, hlc_ms=1000 + i,
                hlc_counter=0, payload=b"\x00" * 22,
            )

        def parsed(raw: bytes):
            return lora.verify_lora_frame(raw, lora_mac_key=p.field.lora_mac_key).parsed

        def ack(f):
            return lora.encode_ack_frame(
                lora_mac_key=p.field.lora_mac_key, flags=0,
                field_tag=p.field.field_id[:4], src_node=2,
                packet_seq=1, ttl=1, ack_seq=f.packet_seq,
                event_id_prefix=f.event_id[:8], status=0,
            )

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "node_1.journal"
            n = e2e.NodeProcess(e2e.node_exe_path(), 1, p.field.secret.hex(), Path(d) / "n", ports)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind((e2e.HUB_HOST, ports.hub_port))
            s.settimeout(2.0)
            try:
                n.start()
                self.assertTrue(n.wait_ready())
                for i in range(2000, 4000):
                    s.sendto(event(i, 1), (e2e.HUB_HOST, ports.node_ports[1]))
                    while True:
                        f = parsed(s.recvfrom(2048)[0])
                        if f and f.ptype == 2 and f.ack_seq == i:
                            self.assertEqual(f.status, 0)
                            break
                    data = path.read_bytes()
                    off = 0
                    kinds = []
                    while off + 12 <= len(data):
                        kinds.append(data[off + 5])
                        off += int.from_bytes(data[off + 6:off + 8], "little")
                    if kinds and all(k == 2 for k in kinds) and len(kinds) == 1170:
                        break
                else:
                    self.fail("failed to prepare pure full SEEN history")

                target = p.sos(1000)
                e2e.inject_ble(1, [(p.anon_user_id[:8], target.envelope_bytes)], ports)
                sent = 0
                deadline = time.monotonic() + 1.0
                s.settimeout(0.1)
                while time.monotonic() < deadline and sent < 6:
                    try:
                        f = parsed(s.recvfrom(2048)[0])
                    except socket.timeout:
                        continue
                    if f and f.ptype == 1 and f.event_id == target.envelope_id:
                        sent += 1
                        s.sendto(ack(f), (e2e.HUB_HOST, ports.node_ports[1]))
                self.assertEqual(sent, 1, "Fresh SOS must be admitted and transmitted once despite 1170 pure SEEN records")
            finally:
                n.stop()
                s.close()

    def test_long_running_ack_budget_locked(self) -> None:
        """After 512 successful ACKs, unpersisted ACK tracking does not overflow and never retransmits upon journal full."""
        p = FakePhone("r9-long-running-ack")
        ports = e2e.make_ports(3660)

        def event(i: int, ttl: int) -> bytes:
            return lora.encode_event_frame(
                lora_mac_key=p.field.lora_mac_key, flags=0,
                field_tag=p.field.field_id[:4], src_node=2,
                packet_seq=i, ttl=ttl,
                event_id=(100000 + i).to_bytes(16, "little"),
                event_type=1, priority=1, hlc_ms=1000 + i,
                hlc_counter=0, payload=b"\x00" * 22,
            )

        def parsed(raw: bytes):
            return lora.verify_lora_frame(raw, lora_mac_key=p.field.lora_mac_key).parsed

        def ack(f):
            return lora.encode_ack_frame(
                lora_mac_key=p.field.lora_mac_key, flags=0,
                field_tag=p.field.field_id[:4], src_node=2,
                packet_seq=1, ttl=1, ack_seq=f.packet_seq,
                event_id_prefix=f.event_id[:8], status=0,
            )

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "node_1.journal"
            n = e2e.NodeProcess(e2e.node_exe_path(), 1, p.field.secret.hex(), Path(d) / "n", ports)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind((e2e.HUB_HOST, ports.hub_port))
            s.settimeout(2.0)
            try:
                n.start()
                self.assertTrue(n.wait_ready())
                for i in range(512):
                    s.sendto(event(i, 2), (e2e.HUB_HOST, ports.node_ports[1]))
                    while True:
                        f = parsed(s.recvfrom(2048)[0])
                        if f and f.ptype == 1 and f.event_id == (100000 + i).to_bytes(16, "little"):
                            s.sendto(ack(f), (e2e.HUB_HOST, ports.node_ports[1]))
                            break
                e2e.drain_udp(s)
                for i in range(2000, 4000):
                    s.sendto(event(i, 1), (e2e.HUB_HOST, ports.node_ports[1]))
                    while True:
                        f = parsed(s.recvfrom(2048)[0])
                        if f and f.ptype == 2 and f.ack_seq == i:
                            self.assertEqual(f.status, 0)
                            break
                    data = path.read_bytes()
                    off = 0
                    kinds = []
                    while off + 12 <= len(data):
                        kinds.append(data[off + 5])
                        off += int.from_bytes(data[off + 6:off + 8], "little")
                    if kinds and all(k == 2 for k in kinds) and len(kinds) == 1165:
                        break
                else:
                    self.fail("failed to prepare pure full SEEN history")

                target = p.sos(1000)
                e2e.inject_ble(1, [(p.anon_user_id[:8], target.envelope_bytes)], ports)
                sent = 0
                deadline = time.monotonic() + 1.0
                s.settimeout(0.1)
                while time.monotonic() < deadline and sent < 6:
                    try:
                        f = parsed(s.recvfrom(2048)[0])
                    except socket.timeout:
                        continue
                    if f and f.ptype == 1 and f.event_id == target.envelope_id:
                        sent += 1
                        s.sendto(ack(f), (e2e.HUB_HOST, ports.node_ports[1]))
                self.assertEqual(sent, 1, "target transmissions must be 1 after 512 successful deliveries")
            finally:
                n.stop()
                s.close()

    def test_mixed_seen_pending_exp_compaction_and_reboot_admits_fresh_sos(self) -> None:
        """Mixed state of historical SEEN + pending TX + sticky EXP must compact, reboot, and admit fresh SOS."""
        p = FakePhone("r10-mixed-e2e")
        ports = e2e.make_ports(3700)

        def event(i: int, ttl: int) -> bytes:
            return lora.encode_event_frame(
                lora_mac_key=p.field.lora_mac_key, flags=0,
                field_tag=p.field.field_id[:4], src_node=2,
                packet_seq=i, ttl=ttl,
                event_id=(100000 + i).to_bytes(16, "little"),
                event_type=1, priority=1, hlc_ms=2000 + i,
                hlc_counter=0, payload=b"\x00" * 22,
            )

        def parsed(raw: bytes):
            return lora.verify_lora_frame(raw, lora_mac_key=p.field.lora_mac_key).parsed

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "node_1.journal"
            exp_target = p.sos(8888)
            # Pre-populate 50 sticky EXP records
            b = bytearray()
            for i in range(50):
                eid = (500000 + i).to_bytes(16, "little")
                body = struct.pack("<IBBH", 0x49474E49, 1, 4, 28) + eid
                b.extend(body + struct.pack("<HH", lora.crc16_ccitt(body), 0x55AA))
            # Include exp_target as an expired record
            body = struct.pack("<IBBH", 0x49474E49, 1, 4, 28) + exp_target.envelope_id
            b.extend(body + struct.pack("<HH", lora.crc16_ccitt(body), 0x55AA))
            path.write_bytes(b)

            n = e2e.NodeProcess(e2e.node_exe_path(), 1, p.field.secret.hex(), Path(d) / "n", ports)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind((e2e.HUB_HOST, ports.hub_port))
            s.settimeout(2.0)
            try:
                n.start()
                self.assertTrue(n.wait_ready())
                old_sos = p.sos(1000)
                e2e.inject_ble(1, [(p.anon_user_id[:8], old_sos.envelope_bytes)], ports)
                while True:
                    f = parsed(s.recvfrom(2048)[0])
                    if f and f.ptype == 1 and f.event_id == old_sos.envelope_id:
                        break

                # 2. Inject TTL=1 events until journal is near capacity (>= 32,600 B)
                for i in range(1200):
                    data = path.read_bytes()
                    if len(data) >= 32600:
                        break
                    s.sendto(event(i, 1), (e2e.HUB_HOST, ports.node_ports[1]))
                    while True:
                        f = parsed(s.recvfrom(2048)[0])
                        if f and f.ptype == 2 and f.ack_seq == i:
                            self.assertEqual(f.status, 0)
                            break

                data = path.read_bytes()
                self.assertGreater(len(data), 32000, "precondition: journal must be near capacity")

                # 3. Inject fresh SOS: must trigger compaction, reclaim unrelated SEEN, and admit fresh SOS
                fresh_sos = p.sos(9000)
                e2e.inject_ble(1, [(p.anon_user_id[:8], fresh_sos.envelope_bytes)], ports)
                time.sleep(0.15)
                lines = [x for x in n.stdout_text().splitlines() if fresh_sos.event_id_hex in x]
                self.assertTrue(any("NODE_RECEIPT" in x and "accepted" in x for x in lines),
                                "Fresh SOS must be accepted in mixed state")

                # 4. Reboot node and verify data recovery
                n.stop()
                e2e.drain_udp(s)
                n = e2e.NodeProcess(e2e.node_exe_path(), 1, p.field.secret.hex(), Path(d) / "n", ports)
                n.start()
                self.assertTrue(n.wait_ready())

                # The old SOS must still be recovered as pending and retransmitted
                s.settimeout(2.0)
                reboot_old_transmitted = False
                deadline = time.monotonic() + 2.0
                while time.monotonic() < deadline:
                    try:
                        raw, _ = s.recvfrom(2048)
                    except socket.timeout:
                        break
                    f = parsed(raw)
                    if f and f.ptype == 1 and f.event_id == old_sos.envelope_id:
                        reboot_old_transmitted = True
                        break
                self.assertTrue(reboot_old_transmitted, "Pending SOS must survive reboot and be retransmitted")

                # The expired event must still be rejected (sticky EXP survives reboot)
                e2e.inject_ble(1, [(p.anon_user_id[:8], exp_target.envelope_bytes)], ports)
                deadline = time.monotonic() + 1.0
                exp_lines = []
                while time.monotonic() < deadline:
                    trace = n.stdout_text()
                    exp_lines = [x for x in trace.splitlines() if exp_target.event_id_hex in x]
                    if any("rejected" in x for x in exp_lines):
                        break
                    time.sleep(0.01)
                self.assertTrue(any("rejected" in x for x in exp_lines), "Sticky EXP must reject on reboot")
            finally:
                n.stop()
                s.close()

    def test_r11_exp_heavy_preserves_space_for_fresh_sos(self) -> None:
        """R11 P1: EXP-heavy workload must account for required transaction bytes and reclaim unrelated SEEN."""
        p = FakePhone("r11-exp-heavy")
        ports = e2e.make_ports(4950)

        def parsed(raw: bytes):
            return lora.verify_lora_frame(raw, lora_mac_key=p.field.lora_mac_key).parsed

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "node_1.journal"
            n = e2e.NodeProcess(e2e.node_exe_path(), 1, p.field.secret.hex(), Path(d) / "n", ports)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind((e2e.HUB_HOST, ports.hub_port))
            s.settimeout(2.0)
            try:
                records = bytearray()
                for k in range(1000):
                    body = struct.pack("<IBBH", 0x49474E49, 1, 4, 28) + (500000 + k).to_bytes(16, "little")
                    records.extend(body + struct.pack("<HH", lora.crc16_ccitt(body), 0x55AA))
                path.write_bytes(records)
                n.start()
                self.assertTrue(n.wait_ready())
                old = p.sos(1000)
                e2e.inject_ble(1, [(p.anon_user_id[:8], old.envelope_bytes)], ports)
                while True:
                    f = parsed(s.recvfrom(2048)[0])
                    if f and f.ptype == 1 and f.event_id == old.envelope_id:
                        break
                for i in range(165):
                    raw = lora.encode_event_frame(lora_mac_key=p.field.lora_mac_key, flags=0,
                                                  field_tag=p.field.field_id[:4], src_node=2,
                                                  packet_seq=i, ttl=1,
                                                  event_id=(100000 + i).to_bytes(16, "little"),
                                                  event_type=1, priority=1, hlc_ms=2000 + i,
                                                  hlc_counter=0, payload=b"\x00" * 22)
                    s.sendto(raw, (e2e.HUB_HOST, ports.node_ports[1]))
                    while True:
                        f = parsed(s.recvfrom(2048)[0])
                        if f and f.ptype == 2 and f.ack_seq == i:
                            self.assertEqual(f.status, 0)
                            break
                data = path.read_bytes()
                off = 0
                pending = set()
                seen = 0
                while off + 12 <= len(data):
                    kind = data[off + 5]
                    eid = data[off + 8:off + 24]
                    if kind == 1:
                        pending.add(eid)
                    if kind in (3, 4):
                        pending.discard(eid)
                    if kind == 2:
                        seen += 1
                    off += int.from_bytes(data[off + 6:off + 8], "little")
                self.assertEqual(len(data), 32765)
                self.assertIn(old.envelope_id, pending)
                self.assertEqual(len(pending), 1)

                fresh = p.sos(9000)
                e2e.inject_ble(1, [(p.anon_user_id[:8], fresh.envelope_bytes)], ports)
                deadline = time.monotonic() + 1.0
                lines = []
                while time.monotonic() < deadline:
                    lines = [x for x in n.stdout_text().splitlines() if fresh.event_id_hex in x]
                    if any("NODE_RECEIPT" in x and "accepted" in x for x in lines):
                        break
                    time.sleep(0.01)
                self.assertTrue(any("NODE_RECEIPT" in x and "accepted" in x for x in lines),
                                "One pending event must not disable reclamation of unrelated historical SEEN")
            finally:
                n.stop()
                s.close()

    def test_r11_process_restart_wait_ready_tracks_new_session(self) -> None:
        """R11 P2: wait_ready must track start offset and only accept tokens from current process session."""
        p = FakePhone("r11-ready")
        ports = e2e.make_ports(4980)
        with tempfile.TemporaryDirectory() as d:
            n = e2e.NodeProcess(e2e.node_exe_path(), 1, p.field.secret.hex(), Path(d) / "n", ports)
            try:
                n.start()
                self.assertTrue(n.wait_ready())
                n.stop()
                offset = n.out_path.stat().st_size
                n = e2e.NodeProcess(e2e.node_exe_path(), 1, p.field.secret.hex(), Path(d) / "n", ports)
                n.start()
                ready = n.wait_ready()
                tail = n.out_path.read_bytes()[offset:]
                self.assertTrue(ready)
                self.assertIn(b"node 1 ready on hub", tail, "wait_ready must wait for current session token")
            finally:
                n.stop()

    def test_r12_ble_eviction_reserves_cancellation_record(self) -> None:
        """R12 P2: BLE priority eviction must reserve cancellation ACK and roll back atomically on failure."""
        p = FakePhone("r12-ble-evict")
        ports = e2e.make_ports(4990)

        def pending(data: bytes):
            ids = set()
            off = 0
            while off + 12 <= len(data):
                sz = int.from_bytes(data[off + 6:off + 8], "little")
                kind = data[off + 5]
                eid = bytes(data[off + 8:off + 24])
                if kind == 1:
                    ids.add(eid)
                elif kind in (3, 4):
                    ids.discard(eid)
                off += sz
            return ids

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "node_1.journal"
            out = Path(d) / "n"
            n = e2e.NodeProcess(e2e.node_exe_path(), 1, p.field.secret.hex(), out, ports)
            try:
                n.start()
                self.assertTrue(n.wait_ready())
                events = [p.presence(1000 + i) for i in range(8)]
                sos = p.sos(2000)
                e2e.inject_ble(1, [(p.anon_user_id[:8], x.envelope_bytes) for x in events], ports)
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    if path.exists() and len(pending(path.read_bytes())) == 8:
                        break
                    time.sleep(0.01)
                n.stop()
                data = bytearray(path.read_bytes())
                self.assertEqual(len(pending(data)), 8)

                # Pad with sticky EXPs leaving free space in the critical boundary window:
                # >= 145 B (fits new TX+SEEN alone) but < 173 B (cannot fit 28 B cancellation record).
                for i in range((32768 - len(data) - 145) // 28):
                    body = struct.pack("<IBBH", 0x49474E49, 1, 4, 28) + (900000 + i).to_bytes(16, "little")
                    data.extend(body + struct.pack("<HH", lora.crc16_ccitt(body), 0x55AA))
                path.write_bytes(data)
                free_space = 32768 - len(data)
                self.assertGreaterEqual(free_space, 145)
                self.assertLess(free_space, 173)

                # Restart and inject high priority SOS: must fail atomically without evicting
                n = e2e.NodeProcess(e2e.node_exe_path(), 1, p.field.secret.hex(), out, ports)
                n.start()
                self.assertTrue(n.wait_ready())
                e2e.inject_ble(1, [(p.anon_user_id[:8], sos.envelope_bytes)], ports)
                deadline = time.monotonic() + 2
                tail = ""
                while time.monotonic() < deadline:
                    tail = out.read_bytes()[n.start_offset:].decode(errors="replace")
                    if sos.event_id_hex in tail and "NODE_RECEIPT" in tail:
                        break
                    time.sleep(0.01)
                n.stop()
                post_data = path.read_bytes()
                ids = pending(post_data)
                self.assertNotIn("evicted-for-prio", tail)
                self.assertEqual(sum(x.envelope_id in ids for x in events), 8)
                self.assertEqual(len(ids), 8)
            finally:
                n.stop()

    def test_r12_lora_relay_eviction_reserves_cancellation_record(self) -> None:
        """R12 P2: LoRa relay priority eviction must reserve cancellation ACK and roll back atomically on failure."""
        p = FakePhone("r12-lora-evict")
        ports = e2e.make_ports(4992)

        def parsed(raw: bytes):
            return lora.verify_lora_frame(raw, lora_mac_key=p.field.lora_mac_key).parsed

        def pending(data: bytes):
            ids = set()
            off = 0
            while off + 12 <= len(data):
                sz = int.from_bytes(data[off + 6:off + 8], "little")
                kind = data[off + 5]
                eid = bytes(data[off + 8:off + 24])
                if kind == 1:
                    ids.add(eid)
                elif kind in (3, 4):
                    ids.discard(eid)
                off += sz
            return ids

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "node_1.journal"
            out = Path(d) / "n"
            n = e2e.NodeProcess(e2e.node_exe_path(), 1, p.field.secret.hex(), out, ports)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind((e2e.HUB_HOST, ports.hub_port))
            s.settimeout(2.0)
            try:
                n.start()
                self.assertTrue(n.wait_ready())
                # Admit 8 relay events (priority 3, TTL=2) into node
                relay_events = []
                for i in range(8):
                    eid = (100000 + i).to_bytes(16, "little")
                    raw = lora.encode_event_frame(lora_mac_key=p.field.lora_mac_key, flags=0,
                                                  field_tag=p.field.field_id[:4], src_node=2,
                                                  packet_seq=i, ttl=2,
                                                  event_id=eid, event_type=3, priority=3,
                                                  hlc_ms=2000 + i, hlc_counter=0, payload=b"\x00" * 22)
                    s.sendto(raw, (e2e.HUB_HOST, ports.node_ports[1]))
                    relay_events.append(eid)
                    while True:
                        f = parsed(s.recvfrom(2048)[0])
                        if f and f.ptype == 2 and f.ack_seq == i:
                            self.assertEqual(f.status, 0)
                            break
                n.stop()
                data = bytearray(path.read_bytes())
                self.assertEqual(len(pending(data)), 8)

                # Pad with sticky EXPs leaving free space in the critical boundary window:
                # >= 145 B (fits new TX+SEEN alone) but < 173 B (cannot fit 28 B cancellation record).
                for i in range((32768 - len(data) - 145) // 28):
                    body = struct.pack("<IBBH", 0x49474E49, 1, 4, 28) + (900000 + i).to_bytes(16, "little")
                    data.extend(body + struct.pack("<HH", lora.crc16_ccitt(body), 0x55AA))
                path.write_bytes(data)
                free_space = 32768 - len(data)
                self.assertGreaterEqual(free_space, 145)
                self.assertLess(free_space, 173)

                # Restart node and send a high-priority relay SOS (priority 1)
                e2e.drain_udp(s)
                n = e2e.NodeProcess(e2e.node_exe_path(), 1, p.field.secret.hex(), out, ports)
                n.start()
                self.assertTrue(n.wait_ready())
                sos_eid = (999999).to_bytes(16, "little")
                raw_sos = lora.encode_event_frame(lora_mac_key=p.field.lora_mac_key, flags=0,
                                                   field_tag=p.field.field_id[:4], src_node=2,
                                                   packet_seq=99, ttl=2,
                                                   event_id=sos_eid, event_type=1, priority=1,
                                                   hlc_ms=5000, hlc_counter=0, payload=b"\x00" * 22)
                s.sendto(raw_sos, (e2e.HUB_HOST, ports.node_ports[1]))
                f = None
                while True:
                    f = parsed(s.recvfrom(2048)[0])
                    if f and f.ptype == 2 and f.ack_seq == 99:
                        break
                # Storage full for cancellation record: relay must be REJECTED (2)
                self.assertEqual(f.status, 2)
                n.stop()
                post_data = path.read_bytes()
                ids = pending(post_data)
                # All 8 old relay events must be preserved
                self.assertEqual(sum(x in ids for x in relay_events), 8)
                self.assertEqual(len(ids), 8)
            finally:
                n.stop()
                s.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
