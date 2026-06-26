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

---

## [2026-06-26] B2 — Python 參考實作（envelope_v3 + lora_v1 + keys） DONE

- repo/commit: ignirelay-lab @ `4cc1e5f`（本 STATUS 為其 `docs:` commit）
- 任務: MASTER_EXECUTION_PLAN §6 B2（前置 A12/B1）。lab 端 Python 參考實作，**逐位元組鏡像 App 凍結契約、零自創契約**；對 App `docs/specs/` 既有 corpus/vectors 逐筆驗證（不抽測、不重生）。
- 範圍紀律: **未碰 App repo 任何檔案**（App working tree 全程 clean）；不手寫/重生 App vectors 或 corpus；新依賴僅 `cryptography`（附錄 F）。
- 交付物 `ignirelay_lab/wire/`:
  - `keys.py`: `field_id=SHA-256(secret)[0..15]`；`field_mac_key=HKDF(secret, info="ignirelay/field-mac/v3")`；`lora_mac_key=HKDF(secret, info="ignirelay/lora-mac/v1")`（domain-separated）；`compute_field_mac`/`lora_mac8`。HKDF info 字串與 App `FieldAuthV2` 逐字一致 → 重現 corpus test_field 三把 key。
  - `envelope_v3.py`: 手寫 proto3 reader/writer（鏡像 `proto_wire.dart`）；`EventEnvelopeV2` decode/encode（欄位 1..15，v3 加 14 field_id / 15 field_mac，含 §3.4/§21.2 required-field 檢查）；`canonical_sig_input_v3`（141B、LE，鏡像 `canonical_encoder_v2.dart`）；Ed25519 verify；field_mac HMAC；payload structs（LocationEvidence/StatusUpdate/Presence/Checkpoint/Hazard/Admin/NodeReceipt/NeedEntry/Hlc）decode+encode；LCG payload 生成器；negative-case classifier（envelope_v2_spec §3.4/§21 + native_transport_v1 §4 chunk guards）。
  - `lora_v1.py`: LORA-WIRE v1 codec — encode/decode/reencode、CRC-16/CCITT-FALSE、`mac8=HMAC[0..7]`、§8 接收管線固定順序 + drop_reason 詞彙、replay（去重環 + 48h HLC 窗）+ TTL 檢查。
- 測試（讀 App `docs/specs/`，路徑可用 `IGNIRELAY_APP_DIR` 覆寫）:
  - `tests/test_envelope_v3_conformance.py`: **全部 108 個 envelope_samples**（≥104）逐筆驗 payload SHA-256 / 141B canonical hex / field_mac / Ed25519 簽章（signed=38、control=1〔zero field_id、無 mac〕）；typed payload struct decode + round-trip（status bearing absent/north-0、hazard flood、node_receipt）；EventEnvelopeV2 proto encode→decode round-trip；**全部 11 個 negative_cases** 以規格 `expected_drop_reason` 拒絕。**不抽測、不跳過**；sample 數印出。
  - `tests/test_lora_v1_vectors.py`: CRC `0x29B1`；lora_mac_key 重現 + domain separation；**全部 51 正樣本** verify + re-encode 位元一致 + committed mac8/crc16 相符；**全部 11 負樣本** 以宣告 reason 拒絕；總數 62（≥50）。
- gates:
  - 原樣指令: `python -m unittest discover -s tests`（於 ignirelay-lab）→ exit code 0
    ```
    ........................
    ----------------------------------------------------------------------
    Ran 24 tests in 0.992s

    OK

    [B2] envelope_samples verified: 108 (signed=38, control=1)
    [B2] negative_cases rejected: 11
    [B2] lora negative frames: 11
    [B2] lora positive frames: 51 (event=45, ack=6)
    [B2] lora total vectors: 62
    ```
  - 既有 13 測試（log_parser/scenarios）續綠；B2 新增 11 → 共 24。
- deviations: **G13 環境偏差** — 附錄 F pin `cryptography==43.x`，但 43.x 早於 Python 3.14 無對應 wheel，本機工具鏈為 Python 3.14.1，故 `requirements.txt` pin `==47.0.0`（Ed25519/HKDF/HMAC/SHA-256 API 與 43.x 相同，且已對 corpus 逐筆驗證）。Owner 若指定 Python ≤3.12 可改回 43.x。其餘無偏差。
- next: B3（lab FakePhone/SimNode 改跑真位元組，吃本 B2 codec）。⚠ 只記 B2 DONE，**不得**宣稱 Stage B DONE / STAGE-B-EXIT。
