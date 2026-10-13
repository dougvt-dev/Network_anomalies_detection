# AI Agent Service

Nhận cảnh báo từ [anomaly-detection](../anomaly-detection/README.md), **phân tích và giải thích** bất thường cho người quản trị, **đề xuất hành động** và **xin duyệt** qua Telegram trước khi gửi lệnh cho action-service. Định kỳ tạo report tổng hợp, lưu trên server.

```
Kafka: anomalies
   │
   ▼
① Correlation ── gộp cảnh báo thành sự cố theo thiết bị, nhận ra chuỗi tấn công      (correlation.py)
② Triage ─────── priority P1–P4, verdict, độ tin cậy, MITRE ATT&CK, allowlist        (triage.py)    ← không dùng LLM
③ Phân tích ──── LLM giải thích + giả thuyết + chọn hành động; kiểm tra output;      (analyst.py)
                 LLM lỗi / bịa dữ kiện → dùng mẫu văn bản
④ Đề xuất ───── chính sách + guardrails (allowlist, chặn có thời hạn, giới hạn số lần chặn)   (policy.py)
⑤ Xin duyệt ─── Telegram [Approve] [Reject] hoặc REST API; quá hạn → expired, KHÔNG thực thi (approvals.py)
   │
   ▼  chỉ lệnh đã duyệt
Kafka: decisions ──▶ action-service ──▶ Kafka: action_results ──▶ cập nhật tin nhắn Telegram

⑥ Report mỗi giờ / mỗi ngày → reports/ (JSON + Markdown); Telegram /report trả bản tóm tắt     (reporting.py)
```

## Nguyên tắc thiết kế

- **Dữ kiện do hệ thống viết, LLM chỉ giải thích.** Mọi IP, số liệu, thời gian trong thông báo (mục *Facts*) được dựng trực tiếp từ cảnh báo. LLM chỉ viết phần *Analysis* và chọn hành động trong danh sách cho phép. Output của LLM bị loại (chuyển sang mẫu văn bản) khi:
  - sai schema;
  - chọn hành động không được phép;
  - nhắc tới IP hoặc MAC không có trong dữ kiện (bịa).
- **Chống prompt injection.** Tên miền, SNI… trong bằng chứng có thể do kẻ tấn công đặt ra. Prompt yêu cầu LLM coi đó là dữ liệu. Ngay cả khi LLM bị dẫn dắt, nó cũng không tự thực thi được gì:
  - hành động chỉ chọn trong danh sách của policy;
  - guardrails áp dụng sau cùng;
  - người quản trị duyệt.
- **Không có gì tự thực thi.** Mọi lệnh chặn đều phải được duyệt. Hết hạn mà chưa duyệt thì bỏ.
- **Agent không nắm quyền firewall.** Việc thực thi nằm ở action-service trên gateway (tách riêng vì lý do bảo mật và vị trí chạy).

## Đổi LLM: Ollama ↔ vLLM

Agent gọi LLM qua **API tương thích OpenAI** (`/v1/chat/completions`). Ollama, vLLM và LM Studio đều có API này, nên đổi server chỉ cần đổi biến môi trường, không sửa code:

```bash
# Ollama
LLM_PROVIDER=ollama   LLM_MODEL=qwen3.5:4b   LLM_EXTRA_BODY={"reasoning_effort": "none"}
# vLLM
LLM_PROVIDER=vllm     LLM_MODEL=<model đang serve>   LLM_BASE_URL=http://gpu-server:8000/v1 \
                      LLM_EXTRA_BODY={"chat_template_kwargs": {"enable_thinking": false}}
# Không dùng LLM (chỉ mẫu văn bản)
LLM_PROVIDER=none
```

- **`agent/llm/base.py`:** interface `BaseLLMClient`, chỉ có một hàm `generate_json(system, user, schema)`. Phần còn lại của agent chỉ biết interface này.
- **`agent/llm/client.py`:** `LLMClient`, implementation gọi API tương thích OpenAI bằng `httpx`.
- **`agent/llm/factory.py`:** tạo client từ cấu hình. Nếu một server *không* tương thích OpenAI, hoặc muốn gọi LLM qua LangChain/LlamaIndex, viết class mới theo `BaseLLMClient` rồi đăng ký ở đây.
- **`LLM_EXTRA_BODY`:** tham số riêng của từng server (JSON), được gộp vào request. Quan trọng nhất là **tắt chế độ thinking** của Qwen3/3.5. Nếu không tắt, model dùng hết `max_tokens` cho phần suy nghĩ và trả về nội dung rỗng.
- `LLM_RESPONSE_FORMAT=json_schema` yêu cầu server ép output đúng JSON schema. Cả Ollama ≥ 0.5 và vLLM đều hỗ trợ.

Đánh giá nhanh một model trên 7 cảnh báo mẫu, không cần Kafka hay Telegram:

```bash
cd src && python -m agent.dump < ../tests/fixtures/anomalies.jsonl
```

Kết quả trên máy dev (RTX 4060 8 GB, Ollama 0.40.3, 7 cảnh báo mẫu):

| Model | Thời gian / phân tích | LLM được dùng | Ghi chú |
|---|---|---|---|
| `gemma:latest` (9B) | > 90 s, lỗi `unexpected EOF` | 2/7 | Chiếm khoảng 8,8 GB, bị đẩy 18% sang CPU |
| `qwen3.5:4b` (bật thinking) | 60 s | 0/7 | Hết `max_tokens` cho phần suy nghĩ, nội dung rỗng |
| `qwen3.5:4b` + `{"reasoning_effort": "none"}` | **3–5 s** | **6/7** | Bản bị loại: LLM ghi sai IP (`203.0.168.50` thay vì `203.0.113.50`), bộ kiểm tra đã chặn. Lỗi chưa bắt được: ghi "four" thay vì 40 lookup (chưa kiểm tra số liệu) |

## Telegram

1. Tạo bot với `@BotFather` (lệnh `/newbot`) và lấy token.
2. Thêm bot vào group quản trị, lấy chat ID của group và user ID của từng người được duyệt.
3. Điền `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `TELEGRAM_ADMIN_IDS` vào `.env`.

Đặc điểm của bot:
- **Long polling:** bot tự hỏi Telegram có tin nhắn mới không, nên không cần mở cổng vào máy chạy agent.
- **Chỉ user trong `TELEGRAM_ADMIN_IDS` được bấm nút hoặc ra lệnh.** Người khác bấm sẽ bị từ chối và bị ghi log.
- **Gửi văn bản thuần** (không HTML/Markdown), để dữ liệu từ traffic không chèn được định dạng.
- **Lưu ý:** nội dung cảnh báo (IP, tên miền) đi qua máy chủ Telegram.

| Lệnh | Trả về |
|---|---|
| `/pending` | Các đề xuất đang chờ duyệt |
| `/report` | Tóm tắt report giờ gần nhất |
| `/report daily` | Tóm tắt report ngày gần nhất |
| `/report now` | Tóm tắt 60 phút vừa qua (không lưu) |
| `/report 2026-10-13` hoặc `/report 2026-10-13_14` | Report đã lưu của ngày / giờ đó |
| `/status` | Trạng thái agent |

Ví dụ tóm tắt:

```
📊 Hourly report 2026-10-13_14
Period: 2026-10-13 14:00 → 15:00
Anomalies checked: 7
Incidents analyzed: 7 (LLM: 7)
Handled: 6 (notified 4, approved 1, rejected 1)
Expired without decision: 0 · Pending now: 1
Actions executed: 1 · Failed: 0
By priority: P1 1, P2 2, P3 4
```

Khi chưa cấu hình Telegram, thông báo được in ra log và duyệt qua API.

## REST API (port 5003)

Mặc định API chỉ nghe `127.0.0.1`. Các API thay đổi trạng thái cần header `X-API-Token: <API_TOKEN>`. Nếu `API_TOKEN` để trống thì các API này bị tắt.

| Method | Path | |
|---|---|---|
| GET | `/health` | |
| GET | `/api/proposals?status=pending` | Danh sách đề xuất |
| GET | `/api/proposals/{id}` | Chi tiết, gồm dữ kiện, phân tích, hành động, kết quả |
| POST | `/api/proposals/{id}/approve` | Body `{"by": "tên", "note": "..."}` |
| POST | `/api/proposals/{id}/reject` | |
| GET | `/api/reports/{hourly\|daily}` | Danh sách report |
| GET | `/api/reports/{hourly\|daily}/{name\|latest}?summary=true` | Report đầy đủ hoặc tóm tắt |

## Cấu hình

**`config/agent.yaml`** (chính sách, có chú thích trong file):
- `assets`: tài sản quan trọng và IP/MAC không bao giờ chặn (`never_block`).
- `expected_behavior`: hành vi hợp lệ đã biết, ví dụ máy quét bảo mật. Các cảnh báo khớp được coi là benign.
- `mitre`: ánh xạ loại bất thường sang MITRE ATT&CK.
- `policy`: hành động cho từng loại, mục tiêu chặn (`entity_ip`, `entity_mac`, `probe_source`), priority tối thiểu để đề xuất chặn, thời hạn chặn.
- `guardrails`: số đề xuất chặn tối đa mỗi giờ, thời hạn chặn tối đa.
- `approval.timeout_seconds`, `reports`.

**`.env`:** kết nối Kafka, LLM, Telegram, API (xem `.env.example`).

**Priority** = mức độ cao nhất của cảnh báo, cộng 1 bậc cho mỗi điều kiện sau:
- loại nguy hiểm (`arp_spoofing`, `data_exfiltration`, `dns_tunneling`);
- liên quan tài sản quan trọng;
- chuỗi từ 2 loại bất thường trở lên;
- lặp lại ≥ 3 lần.

Mặc định chỉ đề xuất chặn từ **P2** trở lên. P3/P4 chỉ thông báo, không cần duyệt.

## Chạy (conda `net_env`)

```bash
cd services/ai-agent
pip install -r requirements-dev.txt
cp .env.example .env

python -m pytest                 # không cần Kafka / LLM / Telegram
cd src && python -m agent.main   # cần Kafka; LLM và Telegram là tùy chọn
```

Docker Compose (từ thư mục `project/`): `docker compose -f docker-compose.yml -f docker-compose.service.yml up -d ai-agent`. Container gọi Ollama trên máy host qua `host.docker.internal`.

## Định dạng `decisions` (cho action-service)

```json
{"schema_version": 1, "decision_id": "a1b2c3d4e5f6", "proposal_id": "5cb3f145", "incident_id": "2eb7957b1e37",
 "sensor_id": "gw-01", "action": {"type": "block_mac", "target": "de:ad:be:ef:00:01", "duration_seconds": 3600},
 "approved_by": "telegram:admin(111)", "approved_at": 1791531600.0, "reason": "..."}
```

action-service trả kết quả về topic `action_results`:

```json
{"schema_version": 1, "decision_id": "...", "proposal_id": "...", "status": "executed", "detail": "...", "executed_at": 1791531601.0}
```

`status` là một trong `executed`, `dry_run`, `failed`, `reverted`.

## Dữ liệu test

`tests/fixtures/anomalies.jsonl` gồm 7 cảnh báo thật, do anomaly-detection sinh từ các kịch bản tấn công. Sinh lại:

```bash
cd services/anomaly-detection
zcat tests/fixtures/attack_scenarios.normalized.jsonl.gz | (cd src && python -m detection.dump) > ../ai-agent/tests/fixtures/anomalies.jsonl
```

## Hạn chế hiện tại

- **Trạng thái nằm trong RAM:** sự cố, đề xuất và nhật ký cho report mất khi restart. Đề xuất đang chờ duyệt cũng mất.
- **Mỗi lần chỉ phân tích một sự cố:** phân tích chậm sẽ làm hàng đợi dài ra. P1 vẫn được xử lý trước.
- **Tool cho vòng ReAct mới có dữ liệu nội bộ** (lịch sử sự cố, tài sản, MITRE). Knowledge base, GeoIP và threat intel sẽ cắm thêm khi có service tương ứng.
- **Chưa có hành động "theo dõi tăng cường"** (cần packet-capture hỗ trợ).
