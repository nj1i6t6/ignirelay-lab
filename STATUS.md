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

---

## [2026-06-26] B3 — lab 升級：FakePhone / SimNode 改跑真位元組 DONE

- repo/commit: ignirelay-lab @ `00a480b`（本 STATUS 為其 `docs:` commit）
- 任務: MASTER_EXECUTION_PLAN §6 B3（前置 A12/B1/B2）。lab 模擬器全面改跑**真 EventEnvelopeV2 v3 + 真 LORA-WIRE v1 位元組**，吃 B2 codec；**未改 App 任何凍結契約**（App working tree 全程 clean）、未改 gateway repo、未重生 corpus/vectors。
- Owner 已接受 B2 G13 環境偏差（Python 3.14.1 → `cryptography==47.0.0`，B2/B3 lab 適用）。
- 交付物（lab repo）:
  - `ignirelay_lab/wire/compact.py`（新）：LORA-WIRE §5 緊湊 payload 翻譯/解碼（loc13 / PRESENCE 10B / SOS 22B / CHECKPOINT 10B），**逐位元組鏡像 frozen generator `generate_lora_wire_vectors.dart`**；測試對 `lora_wire_v1_vectors.json` 重現 presence/sos/checkpoint payload。
  - `ignirelay_lab/corpus_fixtures.py`（新）：TEST-ONLY 金鑰/identity 單一來源＝App corpus `#test_field`（`IGNIRELAY_APP_DIR` 可覆寫）；重現 field_id/field_mac_key/lora_mac_key；author seed 用 corpus 的全零 `test_only_private_key_hex`。
  - `actors.py`：**FakePhone** 真簽 v3 envelope（PRESENCE/SOS/CHECKPOINT，Ed25519 + field_mac + protocol_version=3 + 141B canonical），經 **FakeBleLink**（假 BLE 函式注入）交 SimNode；**SimNode** BLE ingest = decode→驗章(Ed25519)→驗 field_mac→expiry→去重→§5 翻譯→優先佇列（P0 插隊）；LoRa TX = 真 LORA-WIRE frame；LoRa RX = lora_v1 §8 全管線（crc/mac/ttl/replay/hlc-window）；**NODE_RECEIPT** 三態（accepted/duplicate/rejected）回 phone，語意只承諾 **PHONE_TO_NODE_ACCEPTED**（段1，§6，不冒充 HOP_ACKED/GATEWAY_CONFIRMED）。
  - `channel.py`：FakeLoRaChannel 載**真 frame bytes**；TransmitOutcome SENT/BUSY/LOST；busy=CSMA 延遲（不耗重試預算）、loss=ACK 重試、corrupt=翻位元組（在收端由 CRC/MAC 擋，發端重送）。
  - `model.py`：移除 `Packet`/`security_placeholder` 占位；`WirePriority`(=PriorityV2 1..6)、`QueuedEvent`、`LoraFrame`(raw bytes)、`GatewayInbound`。
  - `scenario.py` / `cli.py`：9 情境全改真 bytes；GATE-SCEN 加**真不變量逐情境 PASS/FAIL + exit code**（非 hardcode 預期；語意判定）。
  - `gateway_cli.py`：gateway record 由 `GatewayInbound` 真欄位生成，**移除 placeholder 欄位**（gateway repo 內部自帶預設，B4 處理）。
  - `docs/log_schema.md`：drop_reason 改 spec 詞彙、新 layer/action、NODE_RECEIPT segment 紀律。
- **gates（原樣指令 + exit code + 輸出）**:
  - 原樣指令 `grep -rn "TODO_CONTRACT\|security_placeholder\|PLACEHOLDER" ignirelay_lab/` → **0 行（exit 1 = no match）**；`TODO_APP_NODE_PLACEHOLDER`/`LAB_EPOCH_PLACEHOLDER` 全 repo 亦 0。
  - 原樣指令 `python -m unittest discover -s tests`（GATE-LAB，於 ignirelay-lab）→ **exit 0**
    ```
    .........................................
    ----------------------------------------------------------------------
    Ran 41 tests in 1.063s

    OK

    [B2] envelope_samples verified: 108 (signed=38, control=1)
    [B2] negative_cases rejected: 11
    [B2] lora negative frames: 11

    [B2] lora positive frames: 51 (event=45, ack=6)
    [B2] lora total vectors: 62
    ```
    （B2 既有 24 續綠；B3 新增 17 → 共 41。）
  - 原樣指令 `python -m ignirelay_lab.cli --all`（GATE-SCEN，於 ignirelay-lab）→ **exit 0**
    ```
    === GATE-SCEN ===
      [PASS] busy_sos: sos_delivery=ok delivered=2
      [PASS] duplicate_storm_10_nodes: canonical=1 (10 relays) dedupe=ok
      [PASS] expired_event: delivered=0 expired-rejected=logged
      [PASS] gateway_cli: delivered=2 sos=ok
      [PASS] gateway_reboot: canonical=1 (sqlite dedupe across restart)
      [PASS] loss_20: sos_delivery=100% delivered=2
      [PASS] node_reboot: delivered=1 replay-duplicate=logged
      [PASS] normal: delivered=2 sos=ok
      [PASS] replayed_valid_packet: delivered=1 replay-duplicate=logged
    scenarios: 9  pass: 9  fail: 0
    ```
    （情境數 = 9，不減；全 PASS。）
- **D4 壞通道 20% loss SOS 送達率**：`run_scenario("loss_20", ...)` 跨 300 seeds → **SOS delivered 300/300（missed=0）**；busy_sos 亦 300/300；無使用者可見重複（gateway 以 event_id 去重，canonical ≤ accepted）。corrupt 路徑實證：busy 情境 seed=6 `tx_corrupt=1` → 收端 `LORA_RX drop crc-mismatch=1` 且 SOS 仍送達（發端重送）。
- **§6.1 不變量 → 測試對照表**:
  | 不變量 | 測試 |
  |---|---|
  | P0/SOS preempt | `test_invariants.PriorityInvariants.test_p0_sos_preempts_lower_priority` |
  | 最低優先（heartbeat=NORMAL）壓力下先丟 | `...PriorityInvariants.test_lowest_priority_shed_first_under_queue_pressure` |
  | SOS 於忙線仍 preempt P3/P4 | `...PriorityInvariants.test_sos_preempts_under_busy_channel` |
  | bounded retry（達預算即丟，不無限） | `...RetryInvariants.test_bounded_loss_retry_then_drop` |
  | retry jitter | `...RetryInvariants.test_retry_uses_jitter` |
  | NODE_RECEIPT 冪等（重複 envelope→DUPLICATE，佇列不增） | `...AckIdempotency.test_node_receipt_idempotent_on_duplicate_envelope` |
  | LoRa ACK 冪等（不入去重環） | `...AckIdempotency.test_lora_ack_is_idempotent` |
  | duplicate event_id 無 user-visible 重複（replay） | `test_scenarios.test_replayed_valid_packet_deduped` |
  | 10 節點風暴無重複 canonical | `test_scenarios.test_duplicate_storm_single_canonical` |
  | 真驗證（簽章/field_mac/expiry 被拒、非 stub） | `...IngestVerification.*`（4 條） |
  | 真 CRC/MAC 擋壞幀/偽 MAC | `...LoraIntegrity.test_corrupted_frame_rejected_by_crc` / `test_forged_mac_rejected` |
  | §5 緊湊 payload 對 frozen vectors 位元一致 | `test_compact.*`（7 條） |
- 範圍紀律: 一刀只 B3，**未混 B4**；未碰 gateway repo（B4 才動）；B1/B2 凍結契約與 corpus/vectors 未動。
- deviations: 沿用 B2 的 G13（`cryptography==47.0.0`，Owner 已接受）。其餘無偏差。
- next: B4（gateway 真驗證 + 真封包）。⚠ 只記 B3 DONE，**不得**宣稱 Stage B DONE / STAGE-B-EXIT。

---

## [2026-06-27] B4 — lab gateway_cli E2E 改送真 LoRa 幀（B4 一部分）— 執行者：Claude（主理 AI session）

- repo/commit: ignirelay-lab `ffd79dc`（`[B4] lab gateway_cli E2E sends real LoRa frames`）／本 STATUS commit。
  gateway 端主刀於 gateway repo `aa70db5`（見該 repo STATUS B4 條目）。
- 範圍: B4 的 E2E glue（task #6）。lab 的 `gateway_cli`/`gateway_reboot` 情境改把**位元精確的在空 LoRa 幀**
  交給 sibling gateway，由 gateway **自行**重驗 mac8/crc16/ttl（真驗證），取代先前的「解碼記錄」交接。
- 交付:
  - `model.py`：`GatewayInbound` 加 `raw_frame`（節點驗過的在空幀 bytes）。
  - `actors.py`：`_to_gateway` 把 `frame.raw` 帶進 inbound。
  - `gateway_cli.py`：`_to_record` 改發 `{frame_hex, last_hop_node_id, observed_at_ms}`；
    `_write_test_config` 寫 **TEST-ONLY** `gateway_config.test.json`（corpus `field_join_secret` b64，落在
    gitignored `logs/` 下，**非** production 憑證），ingest 以 `--config` 帶入讓 gateway 能驗場域 HMAC。
- gates（原樣指令 + exit code）:
  - `python -m unittest discover -s tests`（GATE-LAB）→ **exit 0**，`Ran 41 tests ... OK`（不減）。
  - `python -m ignirelay_lab.cli --all`（GATE-SCEN）→ **exit 0**，**9/9 PASS**（情境數不減）；
    gateway_cli `delivered=2`、gateway_reboot `canonical=1`（sqlite dedupe across restart）皆走真 gateway 驗證。
- 紅線: 未碰 App / gateway frozen contracts 與 corpus/vectors；secret 僅 TEST-ONLY 且不入版控；
  僅做 B4 E2E glue，**未宣稱 Stage B DONE / STAGE-B-EXIT**。
