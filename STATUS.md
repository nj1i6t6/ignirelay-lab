# Status

## Completed

- Created multi-node simulator skeleton.
- Added FakePhone, SimNode A/B, FakeLoRaChannel, and FakeGatewaySink.
- Added GatewayCliSink integration that invokes the sibling gateway CLI.
- Added chaos profile loader and structured JSONL logs.
- Added normal, 20% loss, SOS-under-busy-channel, node reboot, gateway reboot,
  10-node duplicate storm, replayed valid packet, and expired event scenarios.
- Added invariant tests for P0/SOS priority, P4 queue-pressure drop behavior,
  duplicate suppression, and bounded retry.
- Added structured log schema notes, sample log, and parser smoke test.

## Incomplete

- This is not a true RF simulator.
- Store-and-forward persistence is represented only by small scenario skeletons.
- Bloom/IBLT-style reconciliation is not modeled yet.
- Replay/expired checks are placeholders, not final security validation.

## Blockers

- App-to-Node wire/GATT contract is not frozen.
- Gateway packet/security contract is not frozen.
- Real radio profile and LoRa packet budget remain contract work.

## Next Steps

- Add partition healing and node restart persistence tests with explicit expected
  outcomes.
- Add richer ACK idempotency assertions once the ACK packet contract exists.
- Feed gateway exports into an AI-readable report summary.

## App-to-Node Contract Dependency

Yes. Event payloads are deliberately tiny fake JSON dictionaries and do not
represent final EventEnvelope, GATT, key, MAC, checksum, or chunk formats.
