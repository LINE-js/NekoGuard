# NekoGuard

[LINE.js](https://github.com/JS-PACKAGE/LINE.js) 的獨立 Node.js／TypeScript 反詐騙外掛，使用 `/api/ws` 的 `scam:check` 呼叫既有 Jev 系統。詐騙機率達到 `config.yaml` 的門檻（預設 **≥ 70%**）時，重新取得社群當下管理員／共同管理員，在原聊天室回覆來源訊息並真正 @ 提及所有查得的管理員，附上機率、疑似手法與手法信心度。

自己的訊息在付費分析前排除，包含同帳號手機訊息及外掛警示。OpenChat 的 `p…` 成員 ID 與一般帳號的 `u…` ID 分別比對；不能取得自身社群身分時，不猜測、不呼叫 Jev。

## 安裝

需要 Node.js ≥ 22、npm，以及已登入的 LINE.js。**先用次要 LINE 帳號驗證**；此服務使用非官方 LINE API，可能觸發帳號風控。

### 1. 套用 LINE.js 後端擴充

上游原有 API 無法列出完整管理員，也不允許標記尚未發言的人，因此本專案附帶必要補丁：

- `integrations/linejs-admins.patch`：後端實作、回歸測試與上游說明更新。
- `integrations/linejs-base.json`：基準是 LINE.js **1.6.5**，commit [`8f1e4813dd69593fec06924744913ea1f7b224f3`](https://github.com/JS-PACKAGE/LINE.js/tree/8f1e4813dd69593fec06924744913ea1f7b224f3)。

在 NekoGuard 目錄執行：

```sh
npm ci
npm run build
npm run patch:linejs -- /path/to/LINE.js
```

安裝器先核對 commit 並執行 `git apply --check`；版本不同、已套用或有衝突會拒絕，不會自動切換版本、丟棄本機修改或重新啟動服務。若現有 LINE.js 版本不同，請準備基準 commit 的獨立工作副本，不要強制覆蓋既有環境。補丁修改來自 Apache-2.0 授權的 LINE.js 專案；上游的授權檔案保持不變。

套用後，在 **LINE.js 目錄**執行 `npm ci`、`npm run build`，並於完成下一步設定後重新啟動 LINE.js。這是本機補丁；升級上游前需重新檢查相容性，不能假設更新後仍保留擴充。

### 2. 設定 LINE.js

在 **LINE.js 自己的 `config.yaml`** 合併下列區段，不要覆蓋其他設定：

```yaml
api:
  enabled: true
  chats:
    - m0123456789abcdef0123456789abcdef # 換成要監測的社群聊天室 ID
  sendsPerMinute: 20
jev:
  token: '' # 在 LINE.js 本機填入 TypeSafe API key
  model: jev-1.13.0
```

重新啟動 LINE.js，確認已登入，再於該目錄執行 `npm run cli -- token` 產生機器人 Token。Token 只顯示一次，請勿貼到日誌、版本控制或聊天。

**兩種金鑰不同**：TypeSafe key 只放 LINE.js；NekoGuard 使用 LINE.js 產生的機器人 Token，不讀取 `session.json`，不自行登入 LINE。

### 3. 設定並啟動 NekoGuard

本機已有 `config.yaml`；若是從版本控制取得的新副本，先將 `config.example.yaml` 複製成 `config.yaml`（不要覆蓋既有檔案）。

```yaml
api:
  url: ws://127.0.0.1:3789/api/ws
  token: '' # 填入 LINE.js 機器人 Token
detection:
  thresholdPercent: 70
```

`NEKOGUARD_API_TOKEN` 環境變數可覆蓋 `api.token`；空 Token 會拒絕啟動。`config.yaml` 已列入 `.gitignore`，請保持權限 `600`。遠端連線必須使用 `wss://`，只有本機回送位址允許 `ws://`；URL 不得夾帶金鑰、query 或 fragment。

```sh
npm start
# 或使用另一份設定
npm start -- --config /path/to/config.yaml
```

設定修改後重新啟動外掛。看見 `MONITORING_READY` 表示 LINE 已登入且後端支援管理員擴充；`SCAM_ALERT_SENT probability=70% admins=20/21` 表示一批通知已由 LINE.js 確認送出（不是管理員已讀）。`SIGINT`／`SIGTERM` 可停止程序。

## 行為與限制

- **範圍**：監測 `api.chats` 內的 OpenChat（`square`）即時文字與文字編輯。一般群組、多人聊天室、私聊沒有此套 OpenChat 管理員角色，因此不監測；不拿全體成員或曾發言的管理員冒充完整名單。
- **門檻**：`probability >= thresholdPercent / 100`，不先四捨五入；70% 含等號。`tactic.confidence` 是手法分類信心，不是詐騙判定門檻。缺少手法時明確顯示未提供，不自行編造。
- **通知**：在原聊天室回覆來源訊息，每則最多標記 20 人、UTF-16 範圍符合上游限制。可標記未發言管理員；後端僅授權同一連線、同一聊天室的查證名單。重新查詢或登出會撤銷舊授權。沒有管理員或查詢失敗時記錄錯誤，不改標記全體成員。
- **訊息排除**：自己的訊息、歷史 snapshot、已收回、無法解密、系統事件、圖片／其他非文字都不分析。自己在手機發出的社群訊息亦排除，不會讓警示形成分析迴圈。
- **重複與競態**：記住最近 5000 則訊息版本；相同內容不重複分析，修改後重新判定。分析期間編輯、收回、登出或停止會作廢尚未送出的舊結果；已送出的警示不自動收回。
- **頻率**：沿用上游所有機器人合計每分鐘 10 次 Jev 分析；管理員查詢亦合計每分鐘 10 次，分別以至少 6.1 秒間隔排程。通知至少間隔 3.1 秒，配合預設每分鐘 20 則上限。多個機器人或較低的伺服器發送上限仍可能收到 `RATE_LIMITED`。建議一個 NekoGuard 實例，不要為提高流量而繞過上游限額。
- **繁忙與斷線**：記憶體佇列最多 500 則，滿載會記錄 `ANALYSIS_QUEUE_FULL` 並略過新項目；等待過久、訊息被上游快取淘汰也可能分析失敗。斷線會停止並以非零代碼退出，不自動重連或補抓離線歷史；待服務／Token 修復後重新啟動。不保證高流量或離線期間的完整涵蓋。
- **失敗處理**：請求逾時、限流或發送失敗不會自動重試，避免付費重複分析或不確定是否已送出的重複通知；部分批次成功會留下已通知人數紀錄。無法分析不代表安全。
- **資料與費用**：外掛不保存聊天內容或登入 session 到磁碟。自動分析會將別人的文字透過 LINE.js 送至 TypeSafe，依其方案計費；請先告知社群並確認資料處理政策。模型結果只供查證，不是事實判定，不會自動刪訊息、踢人或封鎖。
- **名單一致性**：每次通知前重新完整分頁查詢目前成員，不使用 senderRole 快取；LINE 沒有跨頁原子快照，查詢／發送期間的人員異動仍可能競態。任何頁面失敗或缺漏都不回部分名單。

## 驗證

```sh
npm test
npm run typecheck
npm audit --audit-level=high
```

已在 Node.js 26.7.0 執行：

- 外掛建置與 18 項測試通過；npm audit 無已知漏洞。
- 補丁後 LINE.js 前後端型別檢查、建置與 219 項測試通過。
- 補丁安裝器已在乾淨的基準副本實際套用成功。
- 隔離 smoke：實際啟動 `dist/main.js`，經 Bearer 認證的真實 WebSocket／LINE.js hub，使用實際 Jev 回應解析、Provider 分頁及發送 metadata 組裝；確認 69.999% 不通知、70% 分兩批標記 21 位最新管理員（含未發言者），自己的手機訊息與警示回流不送分析。

smoke 中僅外部 LINE／TypeSafe 回應使用受控 fixture，沒有對真實帳號發送或產生 TypeSafe 費用。**真實 LINE 成員查詢、手機上的 @ 顯示與真實 Jev 判讀尚未驗證**；需要你在本機設定上述金鑰並使用次要帳號完成驗收。
