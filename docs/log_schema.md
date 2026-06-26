# Structured Log Schema

Phase 0b logs are JSON Lines, for protocol debugging. As of **B3** the simulator
runs real `EventEnvelopeV2` (BLE ingest) and real LORA-WIRE v1 frames (on air);
`drop_reason` values are the **spec** vocabularies, not lab placeholders.

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
- `extra` (e.g. NODE_RECEIPT carries `{"receipt_segment": "PHONE_TO_NODE_ACCEPTED",
  "queue_depth": N}`)

## Layers (B3)

- `BLE_INGEST` — App→Node first hop (envelope verify + NODE_RECEIPT). `action` ∈
  {`accepted`, `duplicate`, `rejected`}.
- `QUEUE` — node queue management. `action` = `drop`.
- `LORA_TX` — node→air. `action` ∈ {`tx`, `tx_corrupt`, `duplicate`, `busy`,
  `defer`, `await_ack`, `retry`, `drop`}.
- `LORA_RX` — air→node. `action` ∈ {`rx`, `drop`}.
- `NODE` — lifecycle. `action` = `reboot`.
- `GATEWAY_RX` / `GATEWAY_CLI` — Gateway sink. `action` ∈ {`store`, `dedupe`,
  `queue_cli_ingest`}.

## drop_reason vocabularies (spec, normative)

**LORA-WIRE §8.1** (LoRa receive pipeline — `lora_wire_v1.md`):
`truncated`, `unknown-version`, `unknown-ptype`, `length-mismatch`,
`payload-too-long`, `crc-mismatch`, `mac-mismatch`, `ttl-expired`,
`replay-window`, `replay-duplicate`.

**Envelope / BLE ingest** (`envelope_v2_spec` §3.4/§21 + `app_node_gatt_v1`):
`malformed-envelope`, `unknown-protocol-version`, `unknown-sig-algo`,
`signature-invalid`, `field-mac-invalid`, `envelope-expired`, `queue-full`.

**Node transmit/queue policy** (lab):
`channel-busy`, `packet-loss`, `corrupt-percent`, `bounded-retry`,
`retry-exhausted`, `queue-full-evict-lower-priority`.

## NODE_RECEIPT segment discipline

`BLE_INGEST` receipts attest only segment 1, `PHONE_TO_NODE_ACCEPTED`
(`app_node_gatt_v1.md` §6). They MUST NOT be read as `HOP_ACKED` (LoRa ACK) or
`GATEWAY_CONFIRMED`.

Use the parser smoke check with:

```powershell
python -m unittest tests.test_log_parser
```
