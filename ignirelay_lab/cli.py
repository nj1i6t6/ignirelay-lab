"""Lab scenario runner / GATE-SCEN (B3).

`python -m ignirelay_lab.cli --all` runs every scenario on real bytes and
evaluates a genuine invariant per scenario (no hard-coded expected output — the
checks are semantic: "SOS delivered", "exactly one canonical", "expired rejected"
…, derived from the run + its structured log). Exits non-zero if any FAIL.
"""

from __future__ import annotations

import argparse
import json

from .channel import ChannelProfile
from .log_parser import parse_jsonl
from .scenario import ScenarioResult, run_scenario

DEFAULTS = {
    "normal": "profiles/normal.json",
    "loss_20": "profiles/loss_20.json",
    "busy_sos": "profiles/channel_busy_80.json",
    "gateway_cli": "profiles/normal.json",
    "node_reboot": "profiles/normal.json",
    "gateway_reboot": "profiles/normal.json",
    "duplicate_storm_10_nodes": "profiles/duplicate_storm_10_nodes.json",
    "replayed_valid_packet": "profiles/normal.json",
    "expired_event": "profiles/normal.json",
    "e2e_real_stack": "profiles/normal.json",  # profile unused (real node exes)
}

DEFAULT_SEEDS = {
    "normal": 7,
    "loss_20": 7,
    "busy_sos": 1,
    "gateway_cli": 7,
    "node_reboot": 7,
    "gateway_reboot": 7,
    "duplicate_storm_10_nodes": 7,
    "replayed_valid_packet": 7,
    "expired_event": 7,
    "e2e_real_stack": 7,
}

CLI_GATEWAY_SCENARIOS = {"gateway_cli", "gateway_reboot"}


def _reasons(result: ScenarioResult) -> set[str]:
    return {r["reason"] for r in parse_jsonl(result.log_path)}


def evaluate(result: ScenarioResult) -> tuple[bool, str]:
    """Return (passed, detail). Genuine invariants, not echoed expectations."""
    delivered = result.delivered_event_ids
    n = len(delivered)
    no_dup = len(delivered) == len(set(delivered)) and n <= len(
        set(result.accepted_event_ids) or delivered)
    sos_ok = result.sos_event_id in delivered if result.sos_event_id else False
    name = result.name

    if name in {"normal", "gateway_cli"}:
        ok = n == 2 and sos_ok and no_dup
        return ok, f"delivered={n} sos={'ok' if sos_ok else 'MISSING'}"
    if name == "loss_20":
        ok = sos_ok and no_dup  # 20% loss: SOS delivery 100%, no visible dup
        return ok, f"sos_delivery={'100%' if sos_ok else 'FAILED'} delivered={n}"
    if name == "busy_sos":
        return sos_ok, f"sos_delivery={'ok' if sos_ok else 'FAILED'} delivered={n}"
    if name in {"node_reboot", "replayed_valid_packet"}:
        ok = n == 1 and "replay-duplicate" in _reasons(result)
        return ok, f"delivered={n} replay-duplicate={'logged' if ok else 'MISSING'}"
    if name == "duplicate_storm_10_nodes":
        ok = n == 1 and "replay-duplicate" in _reasons(result)
        return ok, f"canonical={n} (10 relays) dedupe={'ok' if ok else 'MISSING'}"
    if name == "gateway_reboot":
        return n == 1, f"canonical={n} (sqlite dedupe across restart)"
    if name == "expired_event":
        ok = n == 0 and "envelope-expired" in _reasons(result)
        return ok, f"delivered={n} expired-rejected={'logged' if ok else 'MISSING'}"
    if name == "e2e_real_stack":
        if result.e2e_skipped:
            return True, f"SKIPPED ({result.e2e_skipped})"
        pres_ok = result.presence_event_id in delivered
        sos_only_once = sos_ok and n == 2 and no_dup
        order_ok = bool(result.e2e_sos_before_presence)
        receipts_ok = (result.e2e_nodeA_receipts or 0) >= 1
        restart_ok = bool(result.e2e_no_dup_after_restart)
        ok = pres_ok and sos_only_once and order_ok and receipts_ok and restart_ok
        return ok, (f"presence={'ok' if pres_ok else 'MISS'} sos={'ok' if sos_ok else 'MISS'} "
                    f"canonical={n} sos<presence={order_ok} "
                    f"nodeA_receipts={result.e2e_nodeA_receipts} "
                    f"no_dup_after_restart={restart_ok}")
    return False, "no expectation defined"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run IgniRelay Mode B lab scenarios.")
    parser.add_argument("--scenario", choices=sorted(DEFAULTS), default="normal")
    parser.add_argument("--profile", default=None)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--gateway-mode", choices=["fake", "cli"], default=None)
    parser.add_argument("--all", action="store_true")
    args = parser.parse_args()

    names = sorted(DEFAULTS) if args.all else [args.scenario]
    results: list[dict] = []
    verdicts: list[tuple[str, bool, str]] = []
    for name in names:
        profile_path = args.profile if args.profile and len(names) == 1 else DEFAULTS[name]
        scenario_seed = args.seed if args.seed is not None else DEFAULT_SEEDS[name]
        gateway_mode = args.gateway_mode
        if gateway_mode is None:
            gateway_mode = "cli" if name in CLI_GATEWAY_SCENARIOS else "fake"
        result = run_scenario(
            name,
            ChannelProfile.from_file(profile_path),
            seed=scenario_seed,
            gateway_mode=gateway_mode,
        )
        passed, detail = evaluate(result)
        verdicts.append((name, passed, detail))
        results.append({**result.__dict__, "pass": passed, "detail": detail})

    print(json.dumps(results, indent=2, sort_keys=True))

    failures = [v for v in verdicts if not v[1]]
    print("\n=== GATE-SCEN ===")
    for name, passed, detail in verdicts:
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}: {detail}")
    print(f"scenarios: {len(verdicts)}  pass: {len(verdicts) - len(failures)}  "
          f"fail: {len(failures)}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
