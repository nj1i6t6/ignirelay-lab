from __future__ import annotations

import argparse
import json

from .channel import ChannelProfile
from .scenario import run_scenario


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
}

CLI_GATEWAY_SCENARIOS = {"gateway_cli", "gateway_reboot"}


def main() -> int:
    parser = argparse.ArgumentParser(description="Run IgniRelay Mode B lab scenarios.")
    parser.add_argument("--scenario", choices=sorted(DEFAULTS), default="normal")
    parser.add_argument("--profile", default=None)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--gateway-mode", choices=["fake", "cli"], default=None)
    parser.add_argument("--all", action="store_true")
    args = parser.parse_args()

    names = sorted(DEFAULTS) if args.all else [args.scenario]
    results = []
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
        results.append(result.__dict__)

    print(json.dumps(results, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
