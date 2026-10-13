# Network AI Agent

Hệ thống giám sát mạng theo kiến trúc microservice. Hệ thống bắt traffic của các thiết bị trong mạng LAN, phát hiện hành vi bất thường của từng thiết bị, rồi dùng LLM giải thích cho người quản trị và đề xuất hành động. **Mọi lệnh chặn đều phải được người quản trị duyệt qua Telegram trước khi thực thi.**

```
[Thiết bị LAN] ──▶ [Máy thu / gateway] ──NAT──▶ Internet
                          │ tshark (card phía LAN)
                          ▼
 packet-capture ──▶ packets_raw ──▶ packet-normalizer ──▶ packets_normalized
                                                                │
                                                                ▼
                                    host_features ◀── anomaly-detection
                                                                │
                                                                ▼ anomalies
                                                           ai-agent ◀──▶ LLM (Ollama / vLLM)
                                                                │  ▲
                                         Telegram duyệt ◀───────┘  │ action_results
                                                                │  │
                                                                ▼ decisions (chỉ lệnh đã duyệt)
                                                          action-service (chưa xây)
```

Các service giao tiếp với nhau qua **Kafka**. Mỗi service chỉ làm một bước, có thể chạy và test riêng, và có công cụ `dump` để chạy offline trên file JSONL mà không cần Kafka.

## Trạng thái các service

| Service | Trạng thái | Vai trò | Vào → Ra |
|---|---|---|---|
| [packet-capture](services/packet-capture/README.md) | ✅ Đã xây | Bắt gói bằng tshark (card mạng hoặc replay file pcap), chỉ lấy metadata, không lưu payload | card mạng / pcap → `packets_raw` |
| [packet-normalizer](services/packet-normalizer/README.md) | ✅ Đã xây | Ép kiểu, xác định chiều traffic so với LAN, `flow_id`, metadata DNS/TLS/HTTP/ARP | `packets_raw` → `packets_normalized` |
| [anomaly-detection](services/anomaly-detection/README.md) | ✅ Giai đoạn 1 | Gom hành vi theo thiết bị trong cửa sổ 60 giây; phát hiện bằng rule + ARP + baseline EWMA; chấm điểm, chống spam | `packets_normalized` → `anomalies`, `host_features` |
| [ai-agent](services/ai-agent/README.md) | ✅ Đã xây | Gộp sự cố, phân loại P1–P4, LLM giải thích, đề xuất theo chính sách + guardrails, xin duyệt qua Telegram, report định kỳ | `anomalies` → `decisions` |
| action-service | ⏳ Khung | Chạy trên gateway, thực thi lệnh chặn đã duyệt (bắt đầu ở chế độ dry-run) | `decisions` → `action_results` |
| log-storage | ⏳ Khung | Lưu cảnh báo, gom thành sự cố, API tra lịch sử thiết bị | |
| knowledge-base | ⏳ Khung | Tri thức (CVE, threat intel) cho agent | |
| metrics-monitor | ⏳ Khung | Metrics Prometheus | |
| api-gateway | ⏳ Khung | Điểm truy cập chung | |

"Khung" nghĩa là service mới chỉ có endpoint `/health`.

## Các topic Kafka

| Topic | Producer → Consumer | Key | Thời gian giữ |
|---|---|---|---|
| `packets_raw` | packet-capture → packet-normalizer | IP nguồn (hoặc MAC) | 6 giờ |
| `packets_normalized` | packet-normalizer → anomaly-detection | IP của thiết bị LAN | 3 ngày |
| `anomalies` | anomaly-detection → ai-agent | IP/MAC thiết bị | 30 ngày |
| `host_features` | anomaly-detection → (dữ liệu train ML ở giai đoạn 2) | IP thiết bị | 7 ngày |
| `decisions` | ai-agent → action-service | | |
| `action_results` | action-service → ai-agent | | |

Định dạng chi tiết của từng topic nằm trong README của service tạo ra topic đó.

## Mô hình triển khai

Máy thu là một **máy Linux chạy trực tiếp** (không dùng WSL), làm gateway và phát mạng (Wi-Fi hotspot hoặc LAN) cho các thiết bị cần giám sát. tshark bắt gói ở card phía LAN, trước NAT, nên thấy được IP thật của từng thiết bị. Cách dựng hotspot có trong [README packet-capture](services/packet-capture/README.md#mô-hình-triển-khai-máy-thu-làm-gateway).

Máy dev chạy WSL2 nên không làm gateway được. Trên máy dev, dùng chế độ replay file pcap hoặc các công cụ `dump`.

> Chỉ giám sát thiết bị của mình hoặc thiết bị đã đồng ý.

## Cấu trúc thư mục

```
project/
├── docker-compose.yml           # hạ tầng: Zookeeper, Kafka, Redis, InfluxDB, Elasticsearch, ClickHouse, Prometheus, Grafana
├── docker-compose.service.yml   # các microservice (dùng kèm file trên)
├── infrastructure/monitoring/prometheus.yml
├── services/
│   ├── packet-capture/
│   ├── packet-normalizer/
│   ├── anomaly-detection/
│   ├── ai-agent/
│   └── action-service/ log-storage/ knowledge-base/ metrics-monitor/ api-gateway/   # khung
├── docs/                        # ghi chú thiết kế ban đầu (chưa cập nhật theo code)
├── README_Docker.md             # lỗi mount prometheus.yml trên WSL
└── README_tshark.md             # hướng dẫn nhanh tshark
```

Các service đã xây đều theo cùng một bố cục:
- `src/common/`: `config.py`, `kafka.py`, `log.py`.
- `src/<tên>/`: `main.py` (worker hoặc API), `dump.py` (chạy offline), `schema.py` (định dạng đầu ra).
- `tests/`: kèm fixture được sinh từ chính pipeline thật.
- `.env.example`, `Dockerfile` (python:3.12-slim), `requirements.txt`, `requirements-dev.txt`.

## Bắt đầu nhanh

### 1. Môi trường dev

```bash
conda activate net_env
for s in packet-capture packet-normalizer anomaly-detection ai-agent; do
  pip install -r services/$s/requirements-dev.txt
  cp -n services/$s/.env.example services/$s/.env     # rồi chỉnh theo máy
done
```

packet-capture cần tshark ≥ 4.x (`sudo apt install tshark`), và user phải thuộc nhóm `wireshark`.

### 2. Chạy test (không cần Kafka, LLM hay Telegram)

```bash
for s in packet-capture packet-normalizer anomaly-detection ai-agent; do
  (cd services/$s && python -m pytest -q)
done
```

### 3. Chạy toàn bộ pipeline offline (không cần Kafka)

Từ file pcap ra đề xuất của agent, nối các công cụ `dump` bằng pipe:

```bash
cd services
(cd packet-capture/src    && python -m capture.dump /path/file.pcap) \
  | (cd packet-normalizer/src  && python -m normalizer.dump) \
  | (cd anomaly-detection/src  && python -m detection.dump) \
  | (cd ai-agent/src           && python -m agent.dump)
```

Bộ dữ liệu tấn công mẫu có sẵn (8 kịch bản) ở `anomaly-detection/tests/fixtures/attack_scenarios.normalized.jsonl.gz`.

### 4. Chạy bằng Docker Compose

Luôn dùng cả hai file compose, vì các service phụ thuộc vào Kafka khai báo trong `docker-compose.yml`:

```bash
docker compose -f docker-compose.yml -f docker-compose.service.yml up -d \
  zookeeper kafka packet-capture packet-normalizer anomaly-detection ai-agent
```

| Thành phần | Địa chỉ |
|---|---|
| Kafka | `localhost:9092` (từ host), `kafka:29092` (trong mạng docker) |
| packet-capture API | `http://localhost:5001/docs` (host network) |
| ai-agent API | `http://127.0.0.1:5003` (chỉ mở trên máy chủ) |
| Prometheus / Grafana | `localhost:9090` / `localhost:3000` |

Ghi chú:
- packet-capture dùng `network_mode: host` để thấy card mạng thật. Chế độ này chỉ chạy được trên Docker Engine của Linux, Docker Desktop không thấy card mạng thật.
- ai-agent gọi Ollama trên máy host qua `host.docker.internal:11434`.
- Nếu Prometheus báo lỗi mount `prometheus.yml`, xem [README_Docker.md](README_Docker.md).

## Nguyên tắc thiết kế

- **Phát hiện theo hành vi, không theo từng gói.** Một gói tin nhìn riêng hầu như không nói lên điều gì. Cảnh báo được tạo từ hồ sơ hành vi của mỗi thiết bị trong một cửa sổ thời gian, kèm lý do và bằng chứng cụ thể.
- **Cảnh báo giải thích được.** Giai đoạn 1 dùng rule, ARP và baseline thống kê thay cho ML, vì chưa có dữ liệu thật để train. Topic `host_features` đang thu dữ liệu cho giai đoạn ML.
- **Dữ kiện do hệ thống viết, LLM chỉ giải thích.** IP và số liệu trong thông báo được lấy thẳng từ cảnh báo. Output của LLM bị loại nếu sai schema, chọn hành động ngoài danh sách cho phép, hoặc nhắc tới IP không có trong dữ kiện.
- **Không có gì tự thực thi.** Lệnh chặn phải qua chính sách, guardrails, rồi người quản trị duyệt. Agent không nắm quyền firewall.
- **Đổi LLM chỉ cần đổi cấu hình.** Agent gọi LLM qua API tương thích OpenAI, nên chuyển giữa Ollama và vLLM chỉ cần đổi biến môi trường.
- **Hợp đồng dữ liệu giữa các service được test.** Fixture của mỗi service được sinh bằng code của service phía trước nó.

## Hạn chế hiện tại

- **Chưa chạy end-to-end với Kafka thật.** Test hiện dùng producer/consumer giả lập.
- **Trạng thái nằm trong RAM:** baseline của anomaly-detection, sự cố và đề xuất đang chờ duyệt của ai-agent mất khi restart.
- **Mất dữ liệu khi capture dừng.** Khi Kafka gặp sự cố, dữ liệu chỉ được giữ tạm trong RAM của producer.
- **Bảo mật cần xử lý trước khi triển khai thật:**
  - API của packet-capture chưa có xác thực và nghe trên `0.0.0.0` trong host network;
  - API cho phép truyền đường dẫn `pcap_file` tùy ý;
  - Kafka đang dùng plaintext;
  - mật khẩu mặc định của InfluxDB và Grafana nằm trong `docker-compose.yml`.
- **Hạ tầng lưu trữ đã có trong compose nhưng chưa được dùng:** InfluxDB, Elasticsearch, ClickHouse, Redis.

## Lộ trình

1. **action-service:** chạy trên gateway, dry-run trước, chặn có thời hạn, trả kết quả về `action_results`.
2. **log-storage:** lưu `anomalies` vào Elasticsearch, gom thành sự cố, API `/api/devices/{ip}/history` cho agent.
3. **anomaly-detection giai đoạn 2:** Isolation Forest train từ `host_features`, phát hiện beaconing.
4. **Lưu trạng thái:** đưa baseline và đề xuất sang Redis.
5. **Vận hành:** metrics Prometheus, dashboard Grafana, đánh giá ngưỡng trên dataset công khai (CICIDS2017…).
