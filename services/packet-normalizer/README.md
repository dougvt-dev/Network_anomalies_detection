# Packet Normalizer Service

Đọc raw record (`raw.v1`) do [packet-capture](../packet-capture/README.md) sinh ra, chuẩn hóa thành `NormalizedPacket` rồi publish cho các service phía sau (anomaly-detection, log-storage...).

```
packet-capture ─▶ Kafka: packets_raw ─▶ packet-normalizer ─▶ Kafka: packets_normalized ─▶ anomaly-detection, ...
```

- Mỗi gói được chuẩn hóa như sau:
  - ép kiểu các trường;
  - gộp IPv4 và IPv6;
  - xác định transport và port;
  - xác định chiều traffic so với LAN;
  - tạo `flow_id` hai chiều;
  - giải mã cờ TCP;
  - lấy metadata DNS, TLS SNI và HTTP.
- **At-least-once:** offset chỉ được lưu sau khi Kafka xác nhận đã nhận bản ghi chuẩn hóa. Nếu worker dừng giữa chừng, lô đang xử lý sẽ được xử lý lại, nên có thể có bản ghi trùng.
- **Scale ngang:** chạy nhiều instance trong cùng `KAFKA_CONSUMER_GROUP`, Kafka sẽ chia partition cho từng instance. Số instance có ích tối đa bằng số partition của `packets_raw`.
- Không cần tshark và không cần quyền mạng đặc biệt. Có thể chạy tập trung trên server, tách khỏi máy thu.

## Cấu trúc thư mục

```
packet-normalizer/
├── src/
│   ├── common/
│   │   ├── config.py        # Settings: đọc biến môi trường / .env
│   │   ├── kafka.py         # tạo consumer, producer, tạo topic kèm retention
│   │   └── log.py
│   └── normalizer/
│       ├── main.py          # NormalizerWorker: consume → normalize → produce → lưu offset
│       ├── dump.py          # công cụ: chuẩn hóa JSONL stdin → stdout (không cần Kafka)
│       ├── normalizer.py    # PacketNormalizer: logic chuẩn hóa
│       └── schema.py        # NormalizedPacket (Pydantic): định dạng đầu ra
├── tests/
│   ├── fixtures/raw_v1_samples.jsonl   # raw record thật do packet-capture sinh ra
│   ├── test_contract.py                # chuẩn hóa fixture → kiểm tra kết quả
│   └── test_normalizer.py              # unit test các trường hợp đặc biệt
├── .env.example
├── Dockerfile               # python:3.12-slim, không có tshark
├── requirements.txt
└── requirements-dev.txt     # + pytest
```

**Gợi ý đọc code:** `normalizer/schema.py` (đầu ra) → `normalizer/normalizer.py` (`normalize`) → `normalizer/main.py` (`run_batch`).

## Cài đặt và chạy (conda `net_env`)

```bash
conda activate net_env
cd services/packet-normalizer
pip install -r requirements-dev.txt
cp .env.example .env

python -m pytest                    # test, không cần Kafka
cd src && python -m normalizer.main # cần Kafka
```

Chuẩn hóa offline, không cần Kafka: đọc raw record (JSONL) từ stdin, in bản ghi chuẩn hóa ra stdout. Dùng để xem dữ liệu hoặc sinh fixture cho service phía sau:

```bash
(cd ../packet-capture/src && python -m capture.dump file.pcap) | (cd src && python -m normalizer.dump) > normalized.jsonl
```

Docker Compose (từ thư mục `project/`):

```bash
docker compose -f docker-compose.yml -f docker-compose.service.yml up -d zookeeper kafka packet-normalizer
docker compose -f docker-compose.yml -f docker-compose.service.yml up -d --scale packet-normalizer=3
```

Worker ghi log thống kê mỗi 30 giây: `consumed`, `produced`, `invalid` (message không hợp lệ, bị bỏ qua), `kafka_errors`.

## Cấu hình (`.env`)

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `INSTANCE_ID` | hostname | Dùng làm Kafka client id |
| `KAFKA_BROKERS` | `localhost:9092` | Trên host: `localhost:9092`; trong mạng docker: `kafka:29092` (ghi đè trong compose) |
| `KAFKA_RAW_TOPIC` | `packets_raw` | Topic đầu vào, do packet-capture tạo |
| `KAFKA_NORMALIZED_TOPIC` | `packets_normalized` | Topic đầu ra, service này tự tạo nếu chưa có |
| `KAFKA_CONSUMER_GROUP` | `packet-normalizer` | Consumer group |
| `KAFKA_TOPIC_PARTITIONS` / `KAFKA_REPLICATION_FACTOR` | `3` / `1` | Dùng khi tự tạo topic |
| `KAFKA_NORMALIZED_RETENTION_MS` | 3 ngày | Thời gian giữ dữ liệu trong `packets_normalized` |
| `LAN_CIDRS` | dải private | Dải mạng nội bộ phía LAN của gateway, dùng để xác định `direction` (vd hotspot: `10.42.0.0/24`) |
| `LOG_LEVEL` | `INFO` | |

## Đầu ra: `packets_normalized`

**Kafka key là IP của thiết bị LAN** mà gói tin thuộc về (hàm `device_key` trong `normalizer/normalizer.py`):

| `direction` | Key |
|---|---|
| `inbound` | `dst_ip` (thiết bị LAN là bên nhận) |
| `outbound`, `internal`, `external` | `src_ip` (bên gửi) |
| Không có IP (ARP...) | `arp_sender_ip`, nếu không có thì `src_mac` |

Nhờ vậy gói một thiết bị gửi đi và gói phản hồi về thiết bị đó nằm cùng partition. Service phía sau (anomaly-detection) có thể gom hồ sơ hành vi theo thiết bị mà vẫn chạy được nhiều instance. Riêng traffic `internal` (hai thiết bị LAN nói chuyện với nhau): gói A→B theo key A, gói B→A theo key B, nên phần "nhận" của một thiết bị có thể nằm ở partition khác.

Các trường có giá trị null bị bỏ khỏi JSON. Định nghĩa đầy đủ ở `src/normalizer/schema.py`.

```json
{"schema_version": 1, "ts": 1700000000.0, "sensor_id": "sensor-01", "source": "local", "iface": "wlan0",
 "length": 74, "protocols": ["eth", "ethertype", "ip", "udp", "dns"], "app_protocol": "DNS",
 "src_mac": "aa:bb:cc:00:00:01", "dst_mac": "aa:bb:cc:00:00:fe",
 "ip_version": 4, "src_ip": "10.42.0.15", "dst_ip": "8.8.8.8", "ttl": 64, "direction": "outbound",
 "transport": "UDP", "src_port": 5353, "dst_port": 53, "flow_id": "3f2a9c...",
 "dns_query": "example.com", "dns_qtype": 1, "dns_is_response": false}
```

| Nhóm | Trường |
|---|---|
| Nguồn | `ts` (epoch giây, thời điểm gói tin), `sensor_id`, `source`, `iface` |
| Khung | `length`, `protocols`, `app_protocol`, `src_mac`, `dst_mac` |
| Lớp 3 | `ip_version`, `src_ip`, `dst_ip`, `ttl` (TTL hoặc hop limit), `direction` |
| Lớp 4 | `transport`, `src_port`, `dst_port`, `flow_id`, `tcp_flags`, `tcp_window`, `tcp_payload_len`, `tcp_stream`, `icmp_type`, `icmp_code` |
| Ứng dụng | `dns_query`, `dns_qtype`, `dns_is_response`, `dns_rcode`, `tls_sni`, `http_host`, `http_method` |
| ARP | `arp_opcode` (1 = request, 2 = reply), `arp_sender_ip`, `arp_sender_mac`, `arp_target_ip`, `arp_target_mac` |

Một số quy tắc:
- `direction`: dựa trên `LAN_CIDRS`. Giá trị là `outbound` (LAN → ngoài), `inbound`, `internal`, `external` hoặc `unknown` (gói không có IP, vd ARP).
- `flow_id`: giống nhau cho cả hai chiều của cùng một flow (cùng transport, IP và port).
- `transport`: lấy theo lớp ngoài cùng. Gói ICMP lỗi chứa UDP bên trong vẫn là `ICMP` và không có port.
- Thêm trường mới không làm hỏng consumer cũ. Đổi tên hoặc xóa trường thì tăng `schema_version`.

## Hợp đồng dữ liệu với packet-capture

Normalizer phụ thuộc vào tên các trường tshark trong `fields` của `raw.v1` (danh sách nằm ở `TSHARK_FIELDS`, file `packet-capture/src/capture/tshark.py`). Để hai service không lệch nhau, `tests/fixtures/raw_v1_samples.jsonl` được sinh bằng chính code của packet-capture.

Khi packet-capture thêm hoặc đổi trường:

```bash
# 1. Sinh lại fixture từ bộ 7 gói mẫu của packet-capture (cần scapy + tshark)
cd services/packet-capture
python tests/sample_packets.py /tmp/sample.pcap
cd src && python -m capture.dump /tmp/sample.pcap --sensor-id fixture-sensor \
    > ../../packet-normalizer/tests/fixtures/raw_v1_samples.jsonl

# 2. Cập nhật normalizer/schema.py + normalizer/normalizer.py, thêm assert vào tests/test_contract.py
cd ../../packet-normalizer && python -m pytest
```

## Hạn chế hiện tại / việc tiếp theo

- Chưa chạy thử với Kafka thật.
- Message không hợp lệ chỉ bị đếm và bỏ qua, chưa đẩy sang topic lỗi (dead-letter).
- Chưa có health endpoint và metrics Prometheus.
