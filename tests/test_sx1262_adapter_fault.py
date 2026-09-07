"""Fault injection and recovery tests for the SX1262 LoRa transport adapter.

Verifies:
1. TX config failure: send returns -EIO, RX is unconditionally restored, RX_active is 1.
2. RX restart failure after TX: send returns 0 (prevents false retransmission),
   RX is down, health records RX down, recv returns -EIO (never -EAGAIN).
3. Init RX config failure: init returns -EIO, recv returns -EIO (never -EAGAIN).
4. Init async start failure: init returns -EIO, recv returns -EIO (never -EAGAIN).
5. Transient RX restart failure: bounded recovery succeeds within 3 attempts.
6. Health query and transport reset: ir_sx1262_get_health and ir_sx1262_transport_reset work correctly.
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

#include "transport/lora_transport.h"
#include <zephyr/drivers/lora.h>

struct device review_device = { 1 };
static int s_rx_active = 0;
static int s_fail_tx_config = 0;
static int s_fail_rx_config = 0;
static int s_fail_start = 0;
static int s_fail_start_countdown = 0;
static int s_send_calls = 0;

int lora_config(const struct device *d, struct lora_modem_config *c)
{
    (void)d;
    if (c->tx && s_fail_tx_config) {
        return -EIO;
    }
    if (!c->tx && s_fail_rx_config) {
        return -EIO;
    }
    return 0;
}

int lora_recv_async(const struct device *d, lora_recv_cb cb, void *u)
{
    (void)d;
    (void)u;
    if (!cb) {
        s_rx_active = 0;
        return 0;
    }
    if (s_fail_start_countdown > 0) {
        s_fail_start_countdown--;
        return -EIO;
    }
    if (s_fail_start) {
        return -EIO;
    }
    s_rx_active = 1;
    return 0;
}

int lora_send(const struct device *d, uint8_t *b, uint32_t n)
{
    (void)d;
    (void)b;
    (void)n;
    s_send_calls++;
    return 0;
}

static void test_reset(void)
{
    s_rx_active = 0;
    s_fail_tx_config = 0;
    s_fail_rx_config = 0;
    s_fail_start = 0;
    s_fail_start_countdown = 0;
    s_send_calls = 0;
    ir_sx1262_transport_reset();
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <case_name>\n", argv[0]);
        return 1;
    }

    const char *test = argv[1];
    struct ir_lora_transport t;
    uint8_t buf[32] = { 0x42 };
    size_t out_len = 0;
    int rc;

    if (strcmp(test, "tx_config_fail_restores_rx") == 0) {
        test_reset();
        rc = ir_sx1262_lora_transport_init(&t, 1);
        if (rc != 0) { return 10; }
        s_fail_tx_config = 1;
        rc = t.send(&t, buf, sizeof(buf));
        struct ir_sx1262_health h;
        ir_sx1262_get_health(&h);
        /* TX failed, but RX must be unconditionally restored to active */
        if (rc != -EIO) { return 11; }
        if (s_rx_active != 1) { return 12; }
        if (!h.rx_listening) { return 13; }
        if (h.last_tx_result != -EIO) { return 14; }
        return 0;
    }

    if (strcmp(test, "rx_restart_fail_after_tx") == 0) {
        test_reset();
        rc = ir_sx1262_lora_transport_init(&t, 1);
        if (rc != 0) { return 20; }
        s_fail_start = 1;
        rc = t.send(&t, buf, sizeof(buf));
        struct ir_sx1262_health h;
        ir_sx1262_get_health(&h);
        /* TX succeeded (0) so caller does not false-retransmit; RX down */
        if (rc != 0) { return 21; }
        if (s_rx_active != 0) { return 22; }
        if (h.rx_listening) { return 23; }
        if (h.last_tx_result != 0) { return 24; }
        if (h.last_rx_error != -EIO) { return 25; }
        /* recv() must report error, NEVER -EAGAIN */
        int recv_rc = t.recv(&t, buf, sizeof(buf), &out_len);
        if (recv_rc != -EIO) { return 26; }
        return 0;
    }

    if (strcmp(test, "init_rx_config_fail") == 0) {
        test_reset();
        s_fail_rx_config = 1;
        rc = ir_sx1262_lora_transport_init(&t, 1);
        struct ir_sx1262_health h;
        ir_sx1262_get_health(&h);
        if (rc != -EIO) { return 30; }
        if (h.initialized) { return 31; }
        if (s_rx_active != 0) { return 32; }
        /* recv() must report error, NEVER -EAGAIN */
        int recv_rc = t.recv(&t, buf, sizeof(buf), &out_len);
        if (recv_rc != -EIO) { return 33; }
        return 0;
    }

    if (strcmp(test, "init_start_fail") == 0) {
        test_reset();
        s_fail_start = 1;
        rc = ir_sx1262_lora_transport_init(&t, 1);
        struct ir_sx1262_health h;
        ir_sx1262_get_health(&h);
        if (rc != -EIO) { return 40; }
        if (h.initialized) { return 41; }
        if (s_rx_active != 0) { return 42; }
        /* recv() must report error, NEVER -EAGAIN */
        int recv_rc = t.recv(&t, buf, sizeof(buf), &out_len);
        if (recv_rc != -EIO) { return 43; }
        return 0;
    }

    if (strcmp(test, "transient_rx_restart_recovers") == 0) {
        test_reset();
        rc = ir_sx1262_lora_transport_init(&t, 1);
        if (rc != 0) { return 50; }
        /* Fail the first 2 attempts; 3rd attempt succeeds */
        s_fail_start_countdown = 2;
        rc = t.send(&t, buf, sizeof(buf));
        struct ir_sx1262_health h;
        ir_sx1262_get_health(&h);
        if (rc != 0) { return 51; }
        if (s_rx_active != 1) { return 52; }
        if (!h.rx_listening) { return 53; }
        if (h.last_rx_error != 0) { return 54; }
        return 0;
    }

    fprintf(stderr, "Unknown test: %s\n", test);
    return 2;
}
"""

class SX1262AdapterFaultTests(unittest.TestCase):
    _binary_path: str | None = None
    _tmp_dir: tempfile.TemporaryDirectory | None = None

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp_dir = tempfile.TemporaryDirectory()
        tmp = Path(cls._tmp_dir.name)
        
        # Create minimal Zephyr mock headers matching reviewer harness
        zephyr_dir = tmp / "zephyr"
        drivers_dir = zephyr_dir / "drivers"
        sys_dir = zephyr_dir / "sys"
        zephyr_dir.mkdir(parents=True, exist_ok=True)
        drivers_dir.mkdir(parents=True, exist_ok=True)
        sys_dir.mkdir(parents=True, exist_ok=True)

        (zephyr_dir / "device.h").write_text(r"""#pragma once
struct device { int ready; };
extern struct device review_device;
static inline int device_is_ready(const struct device *d) { return d->ready; }
#define DT_NODE_EXISTS(n) 1
#define DT_NODELABEL(n) 0
#define DEVICE_DT_GET(n) (&review_device)
""")

        (zephyr_dir / "kernel.h").write_text(r"""#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#define K_NO_WAIT 0
struct k_msgq { int unused; };
#define K_MSGQ_DEFINE(name,size,count,align) struct k_msgq name
static inline int k_msgq_put(struct k_msgq *q, const void *p, int t) { (void)q;(void)p;(void)t; return 0; }
static inline int k_msgq_get(struct k_msgq *q, void *p, int t) { (void)q;(void)p;(void)t; return -1; }
""")

        (sys_dir / "util.h").write_text(r"""#pragma once
#define ARG_UNUSED(x) (void)(x)
""")

        (drivers_dir / "lora.h").write_text(r"""#pragma once
#include <zephyr/kernel.h>
#include <zephyr/device.h>
#define BW_125_KHZ 125
#define SF_8 8
#define CR_4_5 1
struct lora_modem_config {
    uint32_t frequency;
    int bandwidth, datarate, coding_rate;
    uint16_t preamble_len;
    int8_t tx_power;
    bool tx, iq_inverted, public_network, packet_crc_disable;
};
typedef void (*lora_recv_cb)(const struct device *, uint8_t *, uint16_t, int16_t, int8_t, void *);
int lora_config(const struct device *d, struct lora_modem_config *c);
int lora_recv_async(const struct device *d, lora_recv_cb cb, void *u);
int lora_send(const struct device *d, uint8_t *b, uint32_t n);
""")

        mock_c = tmp / "mock_test.c"
        mock_c.write_text(MOCK_C_SRC)

        bin_path = tmp / "test_runner"
        field_node_dir = Path(__file__).resolve().parent.parent.parent / "ignirelay-field-node"
        transport_c = field_node_dir / "src" / "transport" / "sx1262_lora_transport.c"

        cmd = [
            "gcc",
            "-DCONFIG_LORA",
            f"-I{tmp}",
            f"-I{field_node_dir / 'src'}",
            str(mock_c),
            str(transport_c),
            "-o",
            str(bin_path),
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"Failed to compile SX1262 fault test harness:\nSTDOUT: {res.stdout}\nSTDERR: {res.stderr}")
        cls._binary_path = str(bin_path)

    @classmethod
    def tearDownClass(cls) -> None:
        if cls._tmp_dir is not None:
            cls._tmp_dir.cleanup()

    def _run_case(self, case_name: str) -> None:
        assert self._binary_path is not None
        res = subprocess.run([self._binary_path, case_name], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"Case {case_name} failed with code {res.returncode}:\n{res.stderr}")

    def test_tx_config_fail_restores_rx(self) -> None:
        """TX config failure must unconditionally restore RX and update health."""
        self._run_case("tx_config_fail_restores_rx")

    def test_rx_restart_fail_after_tx(self) -> None:
        """RX restart failure after TX returns send=0 to avoid false retransmit, but recv reports -EIO (not -EAGAIN)."""
        self._run_case("rx_restart_fail_after_tx")

    def test_init_rx_config_fail(self) -> None:
        """Init RX config failure returns explicit error; recv reports -EIO (never -EAGAIN)."""
        self._run_case("init_rx_config_fail")

    def test_init_start_fail(self) -> None:
        """Init async start failure returns explicit error; recv reports -EIO (never -EAGAIN)."""
        self._run_case("init_start_fail")

    def test_transient_rx_restart_recovers(self) -> None:
        """Bounded retry (up to 3 attempts) successfully restores RX after transient failure."""
        self._run_case("transient_rx_restart_recovers")

    def test_xiao_ble_physical_entry_symbols_present(self) -> None:
        """Physical firmware ELF must retain run loop, adapter, and static buffers."""
        elf_path = Path("/root/test_xiao/ignirelay-field-node/zephyr/zephyr.elf")
        if not elf_path.exists():
            self.skipTest(f"Physical ELF not found at {elf_path}")

        nm_bin = "/root/zephyr-sdk-0.17.4/arm-zephyr-eabi/bin/arm-zephyr-eabi-nm"
        if not Path(nm_bin).exists():
            nm_bin = "nm"

        res = subprocess.run([nm_bin, str(elf_path)], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"nm failed: {res.stderr}")
        symbols = res.stdout

        required_symbols = [
            "ir_node_init_sx1262",
            "ir_node_run_sx1262",
            "ir_node_runtime_step",
            "ir_sx1262_lora_transport_init",
            "sx1262_send",
            "sx1262_recv",
            "s_physical_jbuf",
            "s_physical_node",
            "s_physical_tx",
        ]
        for sym in required_symbols:
            self.assertIn(sym, symbols, f"Missing required symbol in physical ELF: {sym}")


if __name__ == "__main__":
    unittest.main()

