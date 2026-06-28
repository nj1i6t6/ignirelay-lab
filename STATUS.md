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

---

## [2026-06-28] B6 support — C 向量生成器 `tools/gen_c_vectors.py`（B6 一部分）— 執行者：Claude（主理 AI session）

- repo/commit: ignirelay-lab `35aed3f`（`[B6] gen_c_vectors generator + test`）／本 STATUS commit。
  field-node 主刀於 field-node repo `0817245`（見該 repo STATUS B6 條目）。
- 範圍: MASTER §6 B6 步驟1「lab 提供 `tools/gen_c_vectors.py` 把 vectors 轉 field-node `.inc`」。
- 交付:
  - `tools/gen_c_vectors.py`：讀 App 凍結 `docs/specs/lora_wire_v1_vectors.json` 與
    `wire_conformance_v1.json`（envelope_samples，event_type∈{1,50} 之 BLE-ingest 子集），輸出
    field-node `tests/wire/lora_vectors.inc`（51 正 + 11 負）與 `envelope_vectors.inc`（33 canonical +
    10 signed + 3 typed），檔頭標「GENERATED — DO NOT EDIT」。**REGENERATE 無契約、不重生 App corpus**：
    所有期望值（frame/mac8/crc16/drop_reason、canonical/signature/field_mac/payload_sha256/keys）逐字
    自 App JSON 複製；唯一計算物是 decoder 輸入用的 EventEnvelopeV2 protobuf（由 B2 reference
    `envelope_v3.encode` 產生，正確性錨定於 corpus 期望 canonical/sig/field_mac）。`--check` 偵測 drift。
  - `tests/test_gen_c_vectors.py`：守衛 committed `.inc` 與生成器 in-sync、§8.1 drop_reason 詞彙全覆蓋、
    子集計數（33/10/3）、確定性、不偽造 PRESENCE(3)/CHECKPOINT(4)（corpus 無此型別 → 子集只 STATUS(1)+HAZARD(50)）。
- gates（原樣指令 + exit code）:
  - `python -m tools.gen_c_vectors --check` → exit 0（committed .inc in-sync）。
  - `python -m unittest discover -s tests`（GATE-LAB）→ exit 0，`Ran 45 tests ... OK`（B2/B3 41 + 本刀 +4）。
- 紅線: 未碰 App / gateway frozen contracts 與 corpus/vectors（App working tree 全程 0 changed）；
  僅做 B6 的 lab 生成器部分，**未宣稱 Stage B DONE / STAGE-B-EXIT**。

---

## [2026-06-28] B7 — 模擬端到端 `e2e_real_stack`（跑真 B6 C 執行檔）— 執行者：Claude（主理 AI session）

- repo/commit: ignirelay-lab `c38a071`（code）／本 STATUS commit。搭配 field-node B7 支援
  （PRESENCE 轉發 + UDP runtime，field-node repo `4b33257`，見該 repo STATUS B7 條目）。
- 範圍: MASTER §6 B7「模擬端到端」。**不在 Python 重新實作 node 邏輯**——以 2 個子行程啟動
  field-node B6 `zephyr.exe`（bsim native）真執行檔；Python 只做 UDP hub（FakeLoRaChannel）、
  FakePhone 真簽 envelope 注入、與 B4 gateway 真驗證 sink。

### 拓樸
```
FakePhone(真簽 EventEnvelopeV2 v3) --BLE(UDP)--> NodeA(真 C exe)
   --LoRa(UDP hub 搬真 LORA-WIRE bytes)--> NodeB(真 C exe)
   hub 每個 on-air frame tap --> Gateway(B4 真驗證+去重 by canonical event_id)
```

### 交付（lab）
- `ignirelay_lab/e2e_real_stack.py`（新）：
  - `NodeProcess`：spawn B6 exe（**nrf_bsim 單槓 `-opt=value` 參數**：`-lora-hub=ip:port`
    `-node-id` `-node-port` `-ble-port` `-field-secret`〔corpus TEST-ONLY，不入版控〕；`-nosim` standalone）。
  - `LoRaUdpHub`：綁 127.0.0.1:9300，frame 扇出到其他 node 埠（共享介質 → NodeA+NodeB 都被 gateway
    聽到 → 真多跳重複進 B4 去重）；每 frame tap 進 gateway feed（`{frame_hex,last_hop_node_id,observed_at_ms}`）。
  - `inject_ble`：`[anon8(8)][len u16 LE][envelope]*` 批次經 BLE-UDP 注入 NodeA。
  - `ingest_feed`：沿用 B4 gateway CLI（`ingest`+`export`，TEST-ONLY `--config` 帶場域 HMAC，
    DB 跨呼叫保留→斷言⑤重啟後驗無重複 canonical）。
  - `count_node_receipt_emits`：逐行匹配 `layer=NODE_RECEIPT` ∧ `action=emit`（log 行欄位非相鄰）。
- `ignirelay_lab/scenario.py` / `cli.py`：接 `e2e_real_stack` 進 GATE-SCEN；evaluate() 真不變量
  （presence∈canonical ∧ sos∈canonical ∧ n==2 ∧ 無重複 ∧ sos 先於 presence ∧ nodeA_receipts≥1 ∧
  重啟後無新 canonical）。exe 不在則 SKIP（純 Python 情境仍跑）。
- `tests/test_e2e_real_stack.py`（新）：5 斷言一條一 test（exe 缺則 skipUnless）。

### 5 斷言（檔名:行號）— `tests/test_e2e_real_stack.py`
1. `test_presence_exactly_one_canonical` — **L46**：PRESENCE 到 Gateway SQLite 恰一筆 canonical。
2. `test_sos_exactly_one_canonical` — **L57**：SOS(RED) 恰一筆 canonical（多跳多幀去重成一）。
3. `test_sos_arrives_before_presence` — **L68**：同窗 SOS（prio1）先於 P3 PRESENCE（prio3）到 gateway。
4. `test_nodeA_emits_node_receipt` — **L78**：NodeA log 有 `NODE_RECEIPT ... action=emit` 發出記錄。
5. `test_nodeB_restart_no_duplicate_canonical` — **L90**：殺 NodeB 重啟 + replay 後 Gateway 無重複 canonical。

### gates（原樣指令 + exit code；WSL2 Ubuntu，venv python 有 cryptography，IGNIRELAY_NODE_EXE=bsim zephyr.exe）
```
python -m ignirelay_lab.cli --scenario e2e_real_stack  -> exit 0
   [PASS] e2e_real_stack: presence=ok sos=ok canonical=2 sos<presence=True nodeA_receipts=2 no_dup_after_restart=True
python -m ignirelay_lab.cli --all (GATE-SCEN)           -> exit 0  ->  10/10 PASS（含 e2e_real_stack）
python -m unittest discover -s tests (GATE-LAB)         -> exit 0  ->  Ran 50 tests OK（B6 45 + B7 +5）
# 旁證未回歸：gateway repo GATE-GW python -m unittest discover -s tests -> exit 0 Ran 26 OK（B4 未動）
# field-node 4 build 全 EXIT=0（見 field-node STATUS B7）；exe 由同源 pristine rebuild、E2E 對新 binary 仍 PASS
```

- 紅線: 未碰 App frozen contracts / corpus / vectors（App working tree 全程 0 changed）；
  gateway repo 0 changed（沿用 B4 sink）；**未在 Python 假裝 E2E——跑真 B6 C 執行檔**；
  secret 僅 TEST-ONLY 不入版控；**只記 B7 DONE，未宣稱 Stage B DONE / STAGE-B-EXIT，未進 B8**。

---

## [2026-06-28] B8 — chaos 全綠（真位元組版）— 執行者：Claude（主理 AI session）

- repo/commit: ignirelay-lab `b0c3107`（code）／本 STATUS commit。搭配 field-node B8 支援
  （node_runtime bounded retry，field-node repo `c4f2e4d`，見該 repo STATUS B8 條目）。
- 範圍: MASTER §6 B8。對 B7 `e2e_real_stack` 拓樸（真 B6 C 執行檔 + 真 LORA-WIRE 幀 + 真 B4 gateway
  驗證）加 chaos。**送達韌性全由真 C node 的 bounded retry（≤3）+ TTL relay 提供，hub 只丟/壞/分區位元組，
  絕不替 node 重送**。

### 交付（lab）
- `LoRaUdpHub` chaos：每接收方獨立套 packet-loss / corrupt（翻位元組→收端 CRC 拒）/ partition / asymmetric
  one-way link，作用於位元組精確幀；逐連結統計。`PortLayout` 讓每情境用**不相交 UDP 埠基底**
  （sequential-safe；Owner 提醒：固定埠勿並行兩個 e2e_real_stack）。
- `profiles/`：**loss_50**（50% 每連結丟包）、**partition_heal**（`drop_first_frames` 計數窗——
  **clock-independent**，因 bsim node clock 快於 wall-clock，用幀數而非 wall-ms 才能確定性覆蓋已知數量的
  retry 嘗試）、**asymmetric_link**（`2->1` 反向連結 down）。
- `run_chaos_real_stack`：注入 PRESENCE + N SOS，寫 `logs/<scenario>/report.json`
  〔seed / 封包幀統計 / 不變量 / delivered·canonical·dedup / drop·retry 摘要 / ports〕。
- `scenario.py`/`cli.py`：3 chaos 情境接進 GATE-SCEN，真不變量；exe 不在則 SKIP。
- `tests/test_chaos_real_stack.py`：DoD 斷言（檔名:行號於該檔）——
  L80 loss_50 SOS 最終送達+無重複、L96 20% loss 100% 送達、L106 partition_heal heal 後經 retry 送達、
  L120 asymmetric 經工作方向送達+有 retry、**L133 retry 逐 event_id ≤3（紅線守衛）**。

### 種子（固定+記錄，重現性）
所有 chaos 情境 seed=**7**（記於各 report.json）；驗過跨 6 個 seed（7/11/23/101/202/303）皆穩健，非 seed-luck。
**未調 profile 數值作弊**（loss 維持 50/20、partition=前 4 幀、asymmetric=2->1 down）；
**未提高 retry 上限超 spec**（每事件 ≤3 transmit，L133 斷言；report.json node_a.transmit/retransmit 佐證）。

### DoD 證據（WSL2，venv python 有 cryptography，IGNIRELAY_NODE_EXE=bsim exe）
```
python -m ignirelay_lab.cli --scenario loss_50          -> PASS（sos_delivered no_dup retransmit ratio=1.0）
python -m ignirelay_lab.cli --scenario partition_heal   -> PASS（heal 後 retry 送達、drop_first 4 幀）
python -m ignirelay_lab.cli --scenario asymmetric_link  -> PASS（dedup=6 證多跳收斂、retry 因無反向 echo）
python -m ignirelay_lab.cli --all (GATE-SCEN)           -> exit 0  ->  13/13 PASS
python -m unittest discover -s tests (GATE-LAB)         -> exit 0  ->  Ran 55 OK（B7 50 + B8 +5）
# 20% loss SOS 100%：6 SOS burst（≤TX buffer 8）全送達 ratio=1.0（跨 5 seed 皆 6/6）
# 50% loss SOS 最終送達+無重複：1 SOS（跨 6 seed 皆送達）
# report paths: logs/{loss_50,partition_heal,asymmetric_link,loss_20_realstack}/report.json
# 旁證未回歸：gateway GATE-GW Ran 26 OK（B4 未動）；field-node 4 build EXIT=0、core16/16、wire12/12
```

### 重要工程發現（誠實記錄）
1. **B7 runtime 每幀只送一次**——B8 50% loss「最終送達」需真 node 多次嘗試＝spec bounded ACK-retry。
   B7 漏接；依「驗收發現走 bugfix」於 field-node `c4f2e4d` 補上（≤3、隱式 ACK；B7-normal 不變）。
2. **TX buffer 上限 IR_RT_TX_CAP=8**——一次注入 >8 事件會溢位丟最後幾筆（真有界緩衝行為）；故 20% 100%
   測試注入 6 SOS（含 burst ≤8）誠實展示，非作弊。
3. **bsim node clock 快於 wall-clock**——故 partition 用幀數窗（非 wall-ms）才確定性對齊 retry 排程。

- 紅線: 未碰 App / gateway frozen contracts 與 corpus/vectors（App + gateway working tree 全程 0 changed）；
  **跑真 B6 C 執行檔，未用 Python 重新實作 node 取代**；secret 僅 TEST-ONLY 不入版控；
  **只記 B8 DONE，未宣稱 Stage B DONE / STAGE-B-EXIT，未進 B9**。caveat：純編譯 + bsim native 模擬（無硬體）。
