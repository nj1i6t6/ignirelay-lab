# Structured Log Schema

Phase 0b logs are JSON Lines. They are for protocol debugging only and are not
the final App-to-Node or Gateway contract.

Required fields:

- `timestamp_ms`
- `node_id`
- `layer`
- `event_id`
- `packet_seq`
- `src`
- `dst`
- `priority`
- `ttl`
- `action`
- `reason`

Optional fields:

- `rssi`
- `snr`
- `extra`

Common `action` values currently used by the lab spike:

- `enqueue`
- `tx`
- `busy`
- `drop`
- `retry`
- `await_ack`
- `rx`
- `ack`
- `store`
- `dedupe`
- `drop_expired`
- `queue_cli_ingest`
- `reboot`

Use the parser smoke check with:

```powershell
python -m unittest tests.test_log_parser
```
