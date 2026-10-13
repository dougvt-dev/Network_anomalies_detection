# Anomaly Detection Service

Phát hiện hành vi bất thường của từng thiết bị trong mạng, từ các gói tin đã chuẩn hóa ([packet-normalizer](../packet-normalizer/README.md)). Mỗi cảnh báo kèm lý do và bằng chứng cụ thể, gửi cho AI Agent.

```
packets_normalized ─▶ WindowAggregator ─▶ Detectors ─▶ Scoring ─▶ Suppression ─▶ Kafka: anomalies ─▶ AI Agent
                      (theo thiết bị,     (rule, ARP,   (gộp theo   (chống spam)
                       cửa sổ 60s)         baseline)     loại)        └──────────▶ Kafka: host_features (dữ liệu train ML)
```

## Ý tưởng chính

Một gói tin nhìn riêng hầu như không nói lên điều gì. **Bất thường nằm ở hành vi theo thời gian**, ví dụ "thiết bị X gửi SYN tới 150 port của một máy trong 60 giây". Vì vậy service không chấm điểm từng gói. Nó làm theo hai bước:

1. **Gom** gói tin thành *hồ sơ hành vi* của từng thiết bị LAN trong mỗi cửa sổ 60s (25 chỉ số, xem `FEATURE_NAMES` trong `detection/features.py`).
2. **Phát hiện** trên hồ sơ đó bằng 3 loại detector:

| Detector | Cách hoạt động | Loại bất thường (`category`) |
|---|---|---|
| **Rule** (`detectors/rules.py`) | So chỉ số với ngưỡng cố định | `port_scan`, `host_sweep`, `dos` (SYN flood), `brute_force`, `dns_tunneling`, `dga`, `inbound_scan` |
| **ARP** (`detectors/arp.py`) | Theo từng gói: một IP bị khai báo bởi MAC khác | `arp_spoofing` |
| **Baseline** (`detectors/baseline.py`) | z-score so với trung bình trượt (EWMA) của *chính thiết bị đó*; tự học khi chạy, cảnh báo sau 10 cửa sổ | `data_exfiltration`, `traffic_spike`, `unusual_destinations`, `dns_anomaly` |

Chưa dùng ML (Isolation Forest) ở giai đoạn này, vì chưa có dữ liệu thật của mạng để train. Topic `host_features` ghi lại hồ sơ mọi cửa sổ, làm dữ liệu train cho giai đoạn sau.

### Các bước xử lý

- **Cửa sổ theo event time:** dựa vào `ts` của gói tin, không dựa vào giờ hệ thống. Nhờ vậy replay pcap tốc độ cao vẫn cho kết quả đúng. Một cửa sổ đóng khi đã thấy gói có `ts` vượt quá cuối cửa sổ cộng `allowed_lateness_seconds`. Gói đến sau đó bị bỏ và được đếm vào `dropped_late_or_invalid`. Nếu không có gói nào trong `idle_flush_seconds` (giờ thật), mọi cửa sổ đều được đóng.
- **Gói thuộc về thiết bị nào** (khớp với Kafka key của normalizer):
  - `outbound` / `external`: tính vào chiều *gửi* của `src_ip`.
  - `inbound`: tính vào chiều *nhận* của `dst_ip`.
  - `internal`: tính cả hai.
- **Scoring:** rule cho 0.7 khi vừa chạm ngưỡng và tăng dần tới 1.0 khi gấp 3 lần ngưỡng. Nhiều detector cùng chỉ ra một loại thì gộp bằng noisy-OR (`1 − ∏(1 − s)`). Severity tính theo score: `medium` ≥ 0.7, `high` ≥ 0.8, `critical` ≥ 0.9. Dưới `min_score` (0.6) thì không gửi.
- **Suppression:** cùng thiết bị và cùng loại trong `cooldown_seconds` (5 phút) chỉ gửi một lần. Lần gửi tiếp theo có `occurrences` = số lần đã bị gộp. Nếu severity tăng thì gửi ngay. Lý do: mỗi cảnh báo tốn một lượt suy luận của LLM.

## Cấu trúc thư mục

```
anomaly-detection/
├── config/detection.yaml       # ngưỡng của mọi detector (chỉnh ở đây, không sửa code)
├── src/
│   ├── common/                 # config.py (biến môi trường), kafka.py, log.py
│   └── detection/
│       ├── main.py             # DetectionWorker: Kafka ↔ engine, lưu offset
│       ├── dump.py             # công cụ: phát hiện offline JSONL stdin → stdout
│       ├── engine.py           # DetectionEngine: ghép các bước, không phụ thuộc Kafka
│       ├── windowing.py        # WindowAggregator, HostAccumulator: gom gói → hồ sơ
│       ├── features.py         # HostWindowFeatures, FEATURE_NAMES
│       ├── detectors/          # base.py (Finding), rules.py, arp.py, baseline.py
│       ├── scoring.py          # gộp finding → Anomaly, severity
│       ├── suppression.py      # cooldown
│       ├── state.py            # StateStore (hiện lưu trong bộ nhớ)
│       └── schema.py           # Anomaly (Pydantic): định dạng đầu ra
└── tests/
    ├── attack_traffic.py       # sinh pcap: traffic bình thường + 8 kịch bản tấn công (scapy)
    ├── fixtures/attack_scenarios.normalized.jsonl.gz
    └── test_*.py
```

**Gợi ý đọc code:** `tests/test_scenarios.py` (toàn cảnh) → `engine.py` → `windowing.py` (`add_sent`, `add_received`, `finalize`) → `detectors/rules.py` → `scoring.py`.

## Cài đặt và chạy (conda `net_env`)

```bash
conda activate net_env
cd services/anomaly-detection
pip install -r requirements-dev.txt
cp .env.example .env

python -m pytest                    # không cần Kafka
cd src && python -m detection.main  # cần Kafka
```

Chạy phát hiện offline, không cần Kafka: đọc gói tin chuẩn hóa (JSONL) từ stdin, in cảnh báo ra stdout. Dùng để thử ngưỡng trên dữ liệu có sẵn, hoặc sinh fixture cho ai-agent:

```bash
zcat tests/fixtures/attack_scenarios.normalized.jsonl.gz | (cd src && python -m detection.dump) > anomalies.jsonl
```

Docker Compose (từ thư mục `project/`):

```bash
docker compose -f docker-compose.yml -f docker-compose.service.yml up -d zookeeper kafka anomaly-detection
```

`config/` được mount vào container, nên sửa ngưỡng xong chỉ cần restart container, không phải build lại image.

Mỗi cảnh báo được ghi ra log dạng `ANOMALY [high] host_sweep 192.168.1.67: ...`. Thống kê được in mỗi 60 giây.

## Cấu hình

**Biến môi trường (`.env`):**

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `INSTANCE_ID` | hostname | Dùng làm Kafka client id |
| `KAFKA_BROKERS` | `localhost:9092` | Trong mạng docker: `kafka:29092` (ghi đè trong compose) |
| `KAFKA_INPUT_TOPIC` | `packets_normalized` | Topic đầu vào |
| `KAFKA_ANOMALY_TOPIC` | `anomalies` | Cảnh báo cho AI Agent (giữ 30 ngày) |
| `KAFKA_FEATURES_TOPIC` | `host_features` | Hồ sơ mọi cửa sổ (giữ 7 ngày). Để trống để tắt |
| `KAFKA_CONSUMER_GROUP` | `anomaly-detection` | |
| `DETECTION_CONFIG` | `config/detection.yaml` | File ngưỡng |

**Ngưỡng (`config/detection.yaml`):** mỗi rule có `enabled` và các ngưỡng riêng, kèm chú thích. Đây là các giá trị khởi điểm. **Khi chạy trên mạng thật cần theo dõi cảnh báo nhầm rồi tinh chỉnh.** Ví dụ, máy chủ DNS nội bộ hoặc máy quét bảo mật hợp lệ sẽ chạm ngưỡng `dns_*` hoặc `port_scan`.

## Đầu ra

### `anomalies` (key = IP hoặc MAC của thiết bị)

```json
{"schema_version": 1, "anomaly_id": "6f1c...", "detected_at": 1791531560.12,
 "window": {"start": 1700000040.0, "end": 1700000100.0}, "sensor_id": "sensor-01",
 "entity": {"ip": "192.168.1.67", "mac": "aa:bb:cc:00:01:43"},
 "category": "host_sweep", "severity": "high", "score": 0.85,
 "summary": "Sent unanswered SYN to 60 hosts on port 445 within 60s",
 "findings": [{"detector": "rule.host_sweep", "score": 0.85, "reason": "...",
               "details": {"port": 445, "targets": 60, "targets_sample": ["192.168.1.100", "..."]}}],
 "evidence": {"metrics": {"syn_out": 60, "max_unanswered_dsts_per_port": 60, "...": 0},
              "sweep_port": 445, "top_destinations": [{"ip": "192.168.1.100", "bytes": 54}]},
 "occurrences": 1}
```

- `summary`: lý do chính của cảnh báo, viết bằng tiếng Anh để LLM đọc tốt hơn.
- `findings`: danh sách các detector cùng chỉ ra bất thường này.
- `evidence`: các chỉ số khác 0 của cửa sổ, cộng bối cảnh (đích bị dò, domain, mẫu DNS, SNI…).
- Định nghĩa đầy đủ: `detection/schema.py`.

### `host_features` (key = IP thiết bị)

```json
{"schema_version": 1, "host": "192.168.1.10", "mac": "...", "sensor_id": "...",
 "window_start": 1700000040.0, "window_end": 1700000100.0, "metrics": {"packets_out": 10, "...": 0}}
```

## Dữ liệu test

`tests/fixtures/attack_scenarios.normalized.jsonl.gz` gồm 944 gói và được sinh qua **pipeline thật**:

```
attack_traffic.py → pcap → capture.dump (packet-capture) → normalizer.dump (packet-normalizer)
```

Như vậy test kiểm tra cả chuỗi ba service. Fixture có 8 kịch bản, mỗi kịch bản do một thiết bị riêng thực hiện, cùng một thiết bị bình thường (không được có cảnh báo):

| Thiết bị | Kịch bản |
|---|---|
| 192.168.1.66 | Port scan: SYN tới 150 port của một máy |
| 192.168.1.67 | Host sweep: SYN tới port 445 của 60 máy |
| 192.168.1.68 | SYN flood: 250 SYN không bắt tay (test hạ ngưỡng xuống 3 SYN/s) |
| 192.168.1.69 | Brute force: 30 kết nối SSH |
| 192.168.1.70 | DNS tunneling: 80 subdomain ngẫu nhiên dài 45 ký tự |
| 192.168.1.71 | DGA: 40 domain đều NXDOMAIN |
| 192.168.1.30 | Bị IP bên ngoài quét 80 port |
| 192.168.1.1 | ARP spoofing: gateway bị máy khác nhận IP |
| 192.168.1.10 | Bình thường: 3 kết nối HTTPS, 3 DNS query, 1 ping |

Sinh lại fixture, ví dụ khi đổi kịch bản hoặc khi định dạng của normalizer thay đổi:

```bash
cd services
python anomaly-detection/tests/attack_traffic.py /tmp/attacks.pcap
(cd packet-capture/src && python -m capture.dump /tmp/attacks.pcap --sensor-id fixture-sensor) \
  | (cd packet-normalizer/src && python -m normalizer.dump --lan-cidrs 192.168.0.0/16) \
  | gzip -9 > anomaly-detection/tests/fixtures/attack_scenarios.normalized.jsonl.gz
```

## Hạn chế hiện tại / việc tiếp theo

- **Trạng thái nằm trong bộ nhớ:** baseline, bảng IP↔MAC và danh sách đích đã gặp mất khi restart. Muốn giữ thì viết một `StateStore` dùng Redis.
- **Offset của gói thuộc cửa sổ chưa đóng đã được lưu.** Nếu worker dừng đột ngột, dữ liệu của cửa sổ đang mở (tối đa khoảng 60s) bị mất.
- **Nhiều instance:** gói `internal` từ B về A có key B, nên phần "nhận" của A có thể nằm ở instance khác (xem README packet-normalizer). Nên chạy 1 instance cho tới khi lưu lượng đòi hỏi nhiều hơn.
- **Tên miền gốc** được tách bằng 2 nhãn cuối, nên chưa đúng với các đuôi `.com.vn`, `.co.uk`.
- **Giai đoạn 2:** train Isolation Forest từ `host_features`, phát hiện beaconing (C2 gọi về theo chu kỳ).
- **Giai đoạn 3:** metrics Prometheus, đánh giá và tinh chỉnh ngưỡng trên dataset công khai (CICIDS2017…).
