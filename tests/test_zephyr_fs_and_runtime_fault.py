"""Zephyr FS and Node Runtime fault injection tests.

Verifies:
1. Zephyr FS rename failure during compaction preserves the original journal.
2. Zephyr FS read EIO during journal init sets fault=true, is_durable=false, and blocks appends.
3. Zephyr FS short-write during append safely truncates back to pre_pos and preserves prior records.
4. Zephyr FS transaction rollback clears fault and invalidates uncommitted records.
5. Runtime startup recovery failure fails closed, sets core_inited=false, and never touches radio.
6. Runtime startup recovery correctly recovers SEEN and EXP without union buffer aliasing.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

MOCK_C_SRC = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>

#include "zephyr/fs/fs.h"
#include "core/persistence.h"

static int s_rename_fail = 0;
static int s_read_fail = 0;
static int s_short_write = 0;
static int s_wrap_recover_fail = 0;

int fs_mount(struct fs_mount_t *m) { (void)m; return 0; }
void fs_file_t_init(struct fs_file_t *f) { f->fp = NULL; }
int fs_open(struct fs_file_t *f, const char *p, int flags) {
    f->fp = fopen(p, (flags & FS_O_APPEND) ? "a+b" : (flags & FS_O_CREATE) ? "w+b" : (flags & FS_O_WRITE) ? "r+b" : "rb");
    return f->fp ? 0 : -errno;
}
ssize_t fs_read(struct fs_file_t *f, void *b, size_t n) {
    if (s_read_fail) return -EIO;
    return (ssize_t)fread(b, 1, n, f->fp);
}
ssize_t fs_write(struct fs_file_t *f, const void *b, size_t n) {
    if (s_short_write) {
        return (ssize_t)fwrite(b, 1, n > 4 ? 4 : n / 2, f->fp);
    }
    return (ssize_t)fwrite(b, 1, n, f->fp);
}
int fs_close(struct fs_file_t *f) { return fclose(f->fp); }
int fs_sync(struct fs_file_t *f) { return fflush(f->fp); }
int fs_seek(struct fs_file_t *f, off_t n, int w) { return fseek(f->fp, n, w); }
off_t fs_tell(struct fs_file_t *f) { return ftell(f->fp); }
int fs_truncate(struct fs_file_t *f, off_t n) {
    fflush(f->fp);
    return ftruncate(fileno(f->fp), n);
}
int fs_unlink(const char *p) { return unlink(p); }
int fs_rename(const char *a, const char *b) {
    if (s_rename_fail) return -EIO;
    return rename(a, b);
}

/* Mock node runtime environment */
#define CONFIG_IGNIRELAY_NODE_ID "NODEA"

#include "wire/lora_wire.h"
#include "transport/lora_transport.h"
#include "node/node.h"
#include "logging/structured_log.h"

static int s_mock_radio_calls = 0;
int ir_sx1262_lora_transport_init(struct ir_lora_transport *t, uint16_t id) {
    (void)t; (void)id;
    s_mock_radio_calls++;
    return -EIO;
}
void ir_structured_log(const struct ir_log_record *r) { (void)r; }
uint64_t ir_node_current_epoch_ms(const struct ir_node *n, uint64_t now) { (void)n; (void)now; return 0; }
int ir_node_set_clock(struct ir_node *n, uint64_t e, uint64_t u, int q) { (void)n; (void)e; (void)u; (void)q; return 0; }
ir_lora_reason_t ir_node_ingest_lora(struct ir_node *n, const uint8_t *b, size_t z, uint64_t t) {
    (void)n; (void)b; (void)z; (void)t;
    return IR_LORA_OK;
}
const char *ir_lora_reason_str(ir_lora_reason_t r) { (void)r; return "mock"; }
int ir_lora_encode(const struct ir_lora_frame *f, const uint8_t *k, uint8_t *b, size_t c, size_t *z) {
    (void)f; (void)k; (void)b; (void)c; (void)z;
    return -1;
}
ir_lora_reason_t ir_lora_verify(const uint8_t *b, size_t n, const uint8_t *k, const struct ir_lora_verify_opts *o, struct ir_lora_frame *f) {
    (void)k; (void)o; (void)n;
    memset(f, 0, sizeof(*f));
    memcpy(f->event_id, b, 16);
    f->event_type = 1;
    f->ttl = 3;
    return IR_LORA_OK;
}

int ir_node_init(struct ir_node *n, uint16_t id, const uint8_t *s, size_t z) {
    (void)s; (void)z;
    memset(n, 0, sizeof(*n));
    n->node_id = id;
    ir_dedupe_init(&n->seen);
    ir_dedupe_init(&n->expired);
    ir_queue_init(&n->queue);
    return 0;
}

#include "node/node_runtime.c"

int __real_ir_journal_recover_ext(struct ir_journal *j, struct ir_recovered_tx *out_tx,
                                  size_t max_tx, size_t *out_tx_count,
                                  struct ir_event_id *out_seen, size_t max_seen,
                                  size_t *out_seen_count,
                                  struct ir_event_id *out_expired, size_t max_expired,
                                  size_t *out_expired_count);

int __wrap_ir_journal_recover_ext(struct ir_journal *j, struct ir_recovered_tx *out_tx,
                                  size_t max_tx, size_t *out_tx_count,
                                  struct ir_event_id *out_seen, size_t max_seen,
                                  size_t *out_seen_count,
                                  struct ir_event_id *out_expired, size_t max_expired,
                                  size_t *out_expired_count) {
    if (s_wrap_recover_fail) {
        j->fault = true;
        return -1;
    }
    return __real_ir_journal_recover_ext(j, out_tx, max_tx, out_tx_count,
                                         out_seen, max_seen, out_seen_count,
                                         out_expired, max_expired, out_expired_count);
}

static int s_wrap_init_preload = 0;
static uint8_t s_preload_exp[16] = { 0xA1 };
static uint8_t s_preload_seen[16] = { 0xB2 };

int __real_ir_journal_init(struct ir_journal *j, const char *p, uint8_t *b, size_t n);
int __wrap_ir_journal_init(struct ir_journal *j, const char *p, uint8_t *b, size_t n) {
    if (s_wrap_init_preload == 1) {
        int rc = __real_ir_journal_init(j, NULL, b, n);
        ir_journal_append_expired(j, s_preload_exp);
        ir_journal_append_seen(j, s_preload_seen);
        return rc;
    }
    if (s_wrap_init_preload == 2) {
        int rc = __real_ir_journal_init(j, NULL, b, n);
        uint8_t id[16];
        memset(id, 0, 16); id[0] = 0xEE; id[1] = 1; ir_journal_append_expired(j, id);
        memset(id, 0, 16); id[0] = 0x55; id[1] = 1; ir_journal_append_seen(j, id);
        memset(id, 0, 16); id[0] = 0x55; id[1] = 2; ir_journal_append_seen(j, id);
        memset(id, 0, 16); id[0] = 0xEE; id[1] = 2; ir_journal_append_expired(j, id);
        memset(id, 0, 16); id[0] = 0xEE; id[1] = 3; ir_journal_append_expired(j, id);
        for (int i = 3; i <= 10; i++) {
            memset(id, 0, 16); id[0] = 0x55; id[1] = (uint8_t)i; ir_journal_append_seen(j, id);
        }
        memset(id, 0, 16); id[0] = 0xEE; id[1] = 4; ir_journal_append_expired(j, id);
        memset(id, 0, 16); id[0] = 0xEE; id[1] = 5; ir_journal_append_expired(j, id);
        return rc;
    }
    return __real_ir_journal_init(j, p, b, n);
}

static uint8_t s_mem1[32768];
static uint8_t s_mem2[32768];
static uint8_t s_frame[10] = { 0xAA };

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <case_name>\n", argv[0]);
        return 1;
    }
    const char *test = argv[1];

    if (strcmp(test, "zephyr_fs_rename_fail_preserves_old_journal") == 0) {
        const char *p = "/tmp/test_zephyr_fs_rename.journal";
        unlink(p);
        struct ir_journal j, k;
        uint8_t e[16] = { 0x01 };
        if (ir_journal_init(&j, p, s_mem1, sizeof(s_mem1)) != 0) return 10;
        if (ir_journal_append_tx(&j, e, 0, 1, 999, s_frame, sizeof(s_frame)) != 0) return 11;
        s_rename_fail = 1;
        int comp_rc = ir_journal_compact(&j);
        s_rename_fail = 0;
        if (comp_rc != -1) return 12;
        if (access(p, F_OK) != 0) return 13; /* Original journal must survive */
        struct ir_recovered_tx rtx[4];
        size_t n = 0;
        if (ir_journal_init(&k, p, s_mem2, sizeof(s_mem2)) != 0) return 14;
        if (ir_journal_recover(&k, rtx, 4, &n, NULL, 0, NULL) != 0) return 15;
        if (n != 1) return 16;
        if (memcmp(rtx[0].event_id, e, 16) != 0) return 17;
        unlink(p);
        return 0;
    }

    if (strcmp(test, "zephyr_fs_read_eio_during_init_sets_fault") == 0) {
        const char *p = "/tmp/test_zephyr_fs_read_eio.journal";
        unlink(p);
        struct ir_journal j, k;
        uint8_t e[16] = { 0x01 };
        if (ir_journal_init(&j, p, s_mem1, sizeof(s_mem1)) != 0) return 20;
        if (ir_journal_append_tx(&j, e, 0, 1, 999, s_frame, sizeof(s_frame)) != 0) return 21;
        s_read_fail = 1;
        int init_rc = ir_journal_init(&k, p, s_mem2, sizeof(s_mem2));
        s_read_fail = 0;
        if (init_rc != -1) return 22;
        if (k.is_durable) return 23;
        if (!k.fault) return 24;
        if (k.size != 0) return 25;
        uint8_t next[16] = { 0x02 };
        if (ir_journal_append_tx(&k, next, 0, 1, 999, s_frame, sizeof(s_frame)) != -1) return 26;
        unlink(p);
        return 0;
    }

    if (strcmp(test, "zephyr_fs_append_short_write_preserves_prior") == 0) {
        const char *p = "/tmp/test_zephyr_fs_short_write.journal";
        unlink(p);
        struct ir_journal j, k;
        uint8_t e1[16] = { 0x01 }, e2[16] = { 0x02 };
        if (ir_journal_init(&j, p, s_mem1, sizeof(s_mem1)) != 0) return 30;
        if (ir_journal_append_tx(&j, e1, 0, 1, 999, s_frame, sizeof(s_frame)) != 0) return 31;
        s_short_write = 1;
        int app_rc = ir_journal_append_tx(&j, e2, 0, 1, 999, s_frame, sizeof(s_frame));
        s_short_write = 0;
        if (app_rc != -1) return 32;
        struct ir_recovered_tx rtx[4];
        size_t n = 0;
        if (ir_journal_init(&k, p, s_mem2, sizeof(s_mem2)) != 0) return 33;
        if (ir_journal_recover(&k, rtx, 4, &n, NULL, 0, NULL) != 0) return 34;
        if (n != 1) return 35;
        if (memcmp(rtx[0].event_id, e1, 16) != 0) return 36;
        unlink(p);
        return 0;
    }

    if (strcmp(test, "zephyr_fs_transaction_rollback_clears_fault") == 0) {
        const char *p = "/tmp/test_zephyr_fs_rollback.journal";
        unlink(p);
        struct ir_journal j, k;
        uint8_t e1[16] = { 0x01 }, e2[16] = { 0x02 };
        if (ir_journal_init(&j, p, s_mem1, sizeof(s_mem1)) != 0) return 40;
        if (ir_journal_append_tx(&j, e1, 0, 1, 999, s_frame, sizeof(s_frame)) != 0) return 41;
        size_t checkpoint = j.size;
        if (ir_journal_append_tx(&j, e2, 0, 1, 999, s_frame, sizeof(s_frame)) != 0) return 42;
        s_short_write = 1;
        int seen_rc = ir_journal_append_seen(&j, e2);
        s_short_write = 0;
        if (seen_rc != -1) return 43;
        if (!j.fault) return 44;
        if (ir_journal_rollback(&j, checkpoint) != 0) return 45;
        if (j.fault) return 46;
        struct ir_recovered_tx rtx[4];
        size_t n = 0;
        if (ir_journal_init(&k, p, s_mem2, sizeof(s_mem2)) != 0) return 47;
        if (ir_journal_recover(&k, rtx, 4, &n, NULL, 0, NULL) != 0) return 48;
        if (n != 1) return 49;
        if (memcmp(rtx[0].event_id, e1, 16) != 0) return 50;
        unlink(p);
        return 0;
    }

    if (strcmp(test, "runtime_recovery_failure_stops_and_never_calls_radio") == 0) {
        s_mock_radio_calls = 0;
        s_core_inited = false;
        s_radio_ready = false;
        s_physical_inited = false;
        s_wrap_recover_fail = 1;
        int rc = ir_node_init_sx1262();
        s_wrap_recover_fail = 0;
        if (rc != -EIO) return 60;
        if (s_core_inited) return 61;
        if (s_radio_ready) return 62;
        if (s_physical_inited) return 63;
        if (s_mock_radio_calls != 0) return 64; /* Radio transport init must NEVER be called */
        return 0;
    }

    if (strcmp(test, "runtime_recovery_mixed_seen_and_exp_no_aliasing") == 0) {
        s_core_inited = false;
        s_radio_ready = false;
        s_physical_inited = false;
        s_wrap_recover_fail = 0;
        s_wrap_init_preload = 1;
        int rc = ir_node_init_sx1262();
        s_wrap_init_preload = 0;
        (void)rc;
        struct ir_event_id a = { .len = 16 }, b = { .len = 16 };
        memcpy(a.bytes, s_preload_exp, 16);
        memcpy(b.bytes, s_preload_seen, 16);
        if (ir_dedupe_seen(&s_physical_node.expired, &a) != 1) return 73;
        if (ir_dedupe_seen(&s_physical_node.expired, &b) != 0) return 74; /* Must NOT alias into expired */
        if (ir_dedupe_seen(&s_physical_node.seen, &b) != 1) return 75;
        return 0;
    }

    if (strcmp(test, "runtime_recovery_multiple_interleaved_counts") == 0) {
        s_core_inited = false;
        s_radio_ready = false;
        s_physical_inited = false;
        s_wrap_recover_fail = 0;
        s_wrap_init_preload = 2;
        int rc = ir_node_init_sx1262();
        s_wrap_init_preload = 0;
        (void)rc;
        uint8_t id[16];
        for (int i = 1; i <= 5; i++) {
            memset(id, 0, 16); id[0] = 0xEE; id[1] = (uint8_t)i;
            struct ir_event_id e = { .len = 16 }; memcpy(e.bytes, id, 16);
            if (ir_dedupe_seen(&s_physical_node.expired, &e) != 1) return 80;
            if (ir_dedupe_seen(&s_physical_node.seen, &e) != 0) return 81;
        }
        for (int i = 1; i <= 10; i++) {
            memset(id, 0, 16); id[0] = 0x55; id[1] = (uint8_t)i;
            struct ir_event_id s = { .len = 16 }; memcpy(s.bytes, id, 16);
            if (ir_dedupe_seen(&s_physical_node.seen, &s) != 1) return 82;
            if (ir_dedupe_seen(&s_physical_node.expired, &s) != 0) return 83;
        }
        return 0;
    }

    fprintf(stderr, "Unknown test: %s\n", test);
    return 2;
}
"""

class ZephyrFSAndRuntimeFaultTests(unittest.TestCase):
    _binary_path: str | None = None
    _tmp_dir: tempfile.TemporaryDirectory | None = None

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp_dir = tempfile.TemporaryDirectory()
        tmp = Path(cls._tmp_dir.name)

        zephyr_dir = tmp / "zephyr"
        fs_dir = zephyr_dir / "fs"
        sys_dir = zephyr_dir / "sys"
        zephyr_dir.mkdir(parents=True, exist_ok=True)
        fs_dir.mkdir(parents=True, exist_ok=True)
        sys_dir.mkdir(parents=True, exist_ok=True)

        (zephyr_dir / "kernel.h").write_text(r"""#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <errno.h>
#define ARG_UNUSED(x) (void)(x)
static inline int64_t k_uptime_get(void) { return 1000; }
static inline void k_msleep(int x) { (void)x; }
""")

        (sys_dir / "printk.h").write_text(r"""#pragma once
#include <stdio.h>
#define printk printf
""")

        (fs_dir / "fs.h").write_text(r"""#pragma once
#include <stdio.h>
#include <sys/types.h>
#define FS_O_READ 0x01
#define FS_O_WRITE 0x02
#define FS_O_CREATE 0x04
#define FS_O_APPEND 0x08
#define FS_SEEK_SET 0
#define FS_SEEK_CUR 1
#define FS_SEEK_END 2
#define FS_LITTLEFS 1
struct fs_file_t { FILE *fp; };
struct fs_mount_t {
    int type;
    void *fs_data;
    void *storage_dev;
    const char *mnt_point;
};
int fs_mount(struct fs_mount_t *m);
void fs_file_t_init(struct fs_file_t *f);
int fs_open(struct fs_file_t *f, const char *p, int flags);
ssize_t fs_read(struct fs_file_t *f, void *b, size_t n);
ssize_t fs_write(struct fs_file_t *f, const void *b, size_t n);
int fs_close(struct fs_file_t *f);
int fs_sync(struct fs_file_t *f);
int fs_seek(struct fs_file_t *f, off_t n, int w);
off_t fs_tell(struct fs_file_t *f);
int fs_truncate(struct fs_file_t *f, off_t n);
int fs_unlink(const char *p);
int fs_rename(const char *a, const char *b);
""")

        (fs_dir / "littlefs.h").write_text(r"""#pragma once
#define FS_LITTLEFS_DECLARE_DEFAULT_CONFIG(x) static int x
""")

        storage_dir = zephyr_dir / "storage"
        storage_dir.mkdir(parents=True, exist_ok=True)
        (storage_dir / "flash_map.h").write_text(r"""#pragma once
#define FIXED_PARTITION_EXISTS(x) 1
#define FIXED_PARTITION_ID(x) 1
""")

        mock_c = tmp / "mock_fs_runtime.c"
        mock_c.write_text(MOCK_C_SRC)

        bin_path = tmp / "fs_runtime_runner"
        field_node_dir = Path(__file__).resolve().parent.parent.parent / "ignirelay-field-node"

        srcs = [
            str(mock_c),
            str(field_node_dir / "src" / "core" / "persistence.c"),
            str(field_node_dir / "src" / "wire" / "crc16.c"),
            str(field_node_dir / "src" / "core" / "dedupe.c"),
            str(field_node_dir / "src" / "core" / "queue.c"),
            str(field_node_dir / "src" / "core" / "retry.c"),
            str(field_node_dir / "src" / "core" / "ttl.c"),
            str(field_node_dir / "src" / "core" / "w0_contract.c"),
            str(field_node_dir / "src" / "core" / "event.c"),
        ]

        cmd = [
            "gcc",
            "-D__ZEPHYR__",
            "-DCONFIG_FILE_SYSTEM",
            "-DCONFIG_FILE_SYSTEM_LITTLEFS",
            "-DFIXED_PARTITION_EXISTS(x)=1",
            f"-I{tmp}",
            f"-I{field_node_dir / 'src'}",
            "-Wl,--wrap=ir_journal_recover_ext",
            "-Wl,--wrap=ir_journal_init",
            *srcs,
            "-o",
            str(bin_path),
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"Failed to compile Zephyr FS / runtime fault harness:\nSTDOUT: {res.stdout}\nSTDERR: {res.stderr}")
        cls._binary_path = str(bin_path)

    @classmethod
    def tearDownClass(cls) -> None:
        if cls._tmp_dir is not None:
            cls._tmp_dir.cleanup()

    def _run_case(self, case_name: str) -> None:
        assert self._binary_path is not None
        res = subprocess.run([self._binary_path, case_name], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"Case {case_name} failed with code {res.returncode}:\nSTDOUT: {res.stdout}\nSTDERR: {res.stderr}")

    def test_zephyr_fs_rename_fail_preserves_old_journal(self) -> None:
        """Rename failure during compact must leave old journal intact and uncorrupted."""
        self._run_case("zephyr_fs_rename_fail_preserves_old_journal")

    def test_zephyr_fs_read_eio_during_init_sets_fault(self) -> None:
        """Read EIO during init must set fault=true, durable=false, size=0, and reject appends."""
        self._run_case("zephyr_fs_read_eio_during_init_sets_fault")

    def test_zephyr_fs_append_short_write_preserves_prior(self) -> None:
        """Short-write during append must safely truncate back to pre_pos without truncating prior data to 0."""
        self._run_case("zephyr_fs_append_short_write_preserves_prior")

    def test_zephyr_fs_transaction_rollback_clears_fault(self) -> None:
        """Rollback must invalidate magic at target_size, clear fault, and restore clean prior state."""
        self._run_case("zephyr_fs_transaction_rollback_clears_fault")

    def test_runtime_recovery_failure_stops_and_never_calls_radio(self) -> None:
        """Journal recovery failure must fail closed: core_inited=false and radio init never called."""
        self._run_case("runtime_recovery_failure_stops_and_never_calls_radio")

    def test_runtime_recovery_mixed_seen_and_exp_no_aliasing(self) -> None:
        """SEEN and EXP recovery in two passes must not alias union buffer or corrupt caches."""
        self._run_case("runtime_recovery_mixed_seen_and_exp_no_aliasing")

    def test_runtime_recovery_multiple_interleaved_counts(self) -> None:
        """Interleaved SEEN and EXP across multiple records and counts must correctly populate respective caches."""
        self._run_case("runtime_recovery_multiple_interleaved_counts")


if __name__ == "__main__":
    unittest.main()
