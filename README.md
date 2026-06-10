# IgniRelay Lab

Phase 0b-parallel Mode B simulator for the IgniRelay field-node path. This is a
protocol and integration lab, not an RF simulator and not proof of real mobile
BLE behavior.

Included actors:

- `FakePhone`
- `SimNode A`
- `SimNode B`
- `FakeLoRaChannel`
- `FakeGatewaySink`
- `GatewayCliSink`, which calls the sibling `ignirelay-gateway` CLI

Included scenarios:

- `normal`
- `loss_20`
- `busy_sos`
- `gateway_cli`
- `node_reboot`
- `gateway_reboot`
- `duplicate_storm_10_nodes`
- `replayed_valid_packet`
- `expired_event`

Run all scenarios:

```powershell
python -m ignirelay_lab.cli --all
```

Run selected scenarios:

```powershell
python -m ignirelay_lab.cli --scenario normal
python -m ignirelay_lab.cli --scenario gateway_cli
python -m ignirelay_lab.cli --scenario gateway_reboot
python -m ignirelay_lab.cli --scenario duplicate_storm_10_nodes
```

Gateway CLI integration expects the gateway repo at the sibling path
`..\ignirelay-gateway`. Override with `IGNIRELAY_GATEWAY_DIR` if needed.

Logs are JSON lines written to `logs/<scenario-name>/scenario.log`. Gateway CLI
integration also writes `gateway_packets.jsonl`, `gateway.sqlite`,
`gateway_events.json`, and `gateway_events.csv` under the scenario log folder.

Structured log schema notes are in [docs/log_schema.md](docs/log_schema.md).

Run tests:

```powershell
python -m unittest discover -s tests
```
