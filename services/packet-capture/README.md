# Packet Capture Service

Thu thập gói tin bằng **tshark** trên máy thu và publish từng gói thành một raw record (`raw.v1`) lên Kafka. Việc chuẩn hóa do service [packet-normalizer](../packet-normalizer/README.md) đảm nhận.

```
card mạng / file pcap ─▶ CaptureSource ─▶ tshark -T fields ─▶ tách trường ─▶ raw.v1 ─▶ Kafka: packets_raw ─▶ packet-normalizer
```

Service này cố ý chỉ làm việc nhẹ (tách trường, đóng gói) để theo kịp tốc độ capture. Kafka giữ dữ liệu ở giữa, nên khi normalizer chậm hoặc dừng, capture vẫn chạy bình thường.

## Mô hình triển khai: máy thu làm gateway

Máy thu là một máy Linux chạy trực tiếp (không dùng WSL), phát mạng (Wi-Fi hotspot hoặc LAN) cho các thiết bị cần giám sát. Toàn bộ traffic của các thiết bị đó đi qua máy thu:

```
[Thiết bị] ──Wi-Fi/LAN──▶ [Máy thu: wlan0 (LAN)] ──NAT──▶ [eth0 (WAN)] ──▶ Router ──▶ Internet
                                    ▲
                          tshark bắt ở card phía LAN (trước NAT, thấy IP thật của thiết bị)
```

Dựng hotspot nhanh bằng NetworkManager (card Wi-Fi phải hỗ trợ chế độ AP, kiểm tra bằng `iw list`):

```bash
nmcli device wifi hotspot ifname wlan0 ssid NetAgent password <mật-khẩu>
ip -4 addr show wlan0          # NetworkManager mặc định cấp dải 10.42.0.0/24
```

Sau đó đặt `CAPTURE_INTERFACE=wlan0` ở đây và `LAN_CIDRS=10.42.0.0/24` ở packet-normalizer.

> Chỉ giám sát thiết bị của mình hoặc thiết bị đã đồng ý. Payload không bị lưu: tshark chỉ xuất các trường metadata trong `TSHARK_FIELDS`.

## Cấu trúc thư mục

```
packet-capture/
├── src/
│   ├── common/
│   │   ├── config.py        # Settings: đọc biến môi trường / .env
│   │   ├── kafka.py         # tạo producer, tạo topic kèm retention
│   │   └── log.py
│   └── capture/
│       ├── main.py          # FastAPI + vòng đời service
│       ├── pipeline.py      # CapturePipeline: source → tshark → Kafka, thống kê, tự restart
│       ├── tshark.py        # TSHARK_FIELDS, build_command, parse_line, TsharkProcess (async)
│       ├── dump.py          # công cụ: replay pcap → in raw.v1 ra stdout (không cần Kafka)
│       └── sources/         # base.py (interface), local.py (card mạng), pcap.py (replay file)
├── tests/                   # pcap sinh bằng scapy + tshark thật, Kafka giả lập (FakeProducer)
├── .env.example
├── Dockerfile               # python:3.12-slim + tshark
├── requirements.txt
└── requirements-dev.txt     # + pytest, scapy
```

**Gợi ý đọc code** (theo đường đi của một gói tin): `tests/test_pipeline.py` (toàn cảnh) → `capture/main.py` → `capture/pipeline.py` (`_supervise` → `_run_once` → `_handle_line`) → `capture/tshark.py`.

## Cài đặt môi trường dev (conda `net_env`)

Yêu cầu: tshark ≥ 4.x (`sudo apt install tshark`). User cần thuộc nhóm `wireshark` để bắt gói không cần root:

```bash
sudo usermod -aG wireshark $USER    # đăng nhập lại để có hiệu lực

conda activate net_env
cd services/packet-capture
pip install -r requirements-dev.txt
cp .env.example .env                # rồi chỉnh theo máy
```

## Cấu hình (`.env`)

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `SENSOR_ID` | hostname | Định danh máy thu, gắn vào mọi bản ghi |
| `CAPTURE_SOURCE` | `local` | `local` (card mạng) hoặc `pcap` (replay file) |
| `CAPTURE_INTERFACE` | `eth0` | Card mạng cần bắt; với gateway là card phía LAN |
| `CAPTURE_BPF_FILTER` | | BPF filter cho live capture, vd `not port 22` |
| `CAPTURE_DISPLAY_FILTER` | | Display filter của tshark (`-Y`), áp dụng cho mọi nguồn |
| `PCAP_FILE` | | File pcap khi `CAPTURE_SOURCE=pcap` |
| `CAPTURE_AUTOSTART` | `false` | Tự bắt đầu capture khi service khởi động |
| `TSHARK_PATH` | `tshark` | Đường dẫn tshark |
| `RESTART_BACKOFF_MAX` | `30` | Thời gian chờ tối đa (giây) giữa các lần khởi động lại tshark |
| `KAFKA_BROKERS` | `localhost:9092` | Trên host / `network_mode: host`: `localhost:9092`; trong mạng docker: `kafka:29092` |
| `KAFKA_RAW_TOPIC` | `packets_raw` | Topic đầu ra |
| `KAFKA_TOPIC_PARTITIONS` / `KAFKA_REPLICATION_FACTOR` | `3` / `1` | Dùng khi tự tạo topic |
| `KAFKA_RAW_RETENTION_MS` | 6 giờ | Thời gian giữ dữ liệu trong `packets_raw` |
| `API_HOST` / `API_PORT` / `LOG_LEVEL` | `0.0.0.0` / `5001` / `INFO` | |

Service tự tạo topic `packets_raw` (kèm retention) khi khởi động, nếu topic chưa tồn tại.

## Chạy

### Local

```bash
python -m pytest                    # test, không cần Kafka

cd src
python -m capture.main              # API: http://localhost:5001/docs
python -m capture.dump file.pcap    # xem raw record của một file pcap, không cần Kafka
```

Khi chưa có Kafka, capture vẫn chạy và đếm `packets_read`, nhưng `packets_published` = 0. Lệnh stop sẽ chờ khoảng 10s để producer flush.

### Docker Compose (từ thư mục `project/`)

```bash
docker compose -f docker-compose.yml -f docker-compose.service.yml up -d zookeeper kafka packet-capture
```

Container dùng `network_mode: host` + `NET_RAW`/`NET_ADMIN` để thấy card mạng của host, và kết nối Kafka qua `localhost:9092` (ghi đè trong compose). Host networking chạy tốt trên Docker Engine của Linux. Trên Docker Desktop thì không thấy được card mạng thật.

## API

| Method | Path | Mô tả |
|---|---|---|
| GET | `/health` | Trạng thái service và trạng thái capture |
| POST | `/api/capture/start` | Bắt đầu capture. Body tùy chọn, dùng để ghi đè `.env` cho lần chạy này |
| POST | `/api/capture/stop` | Dừng capture, trả về thống kê |
| GET | `/api/capture/status` | Thống kê chi tiết |

```bash
curl -X POST localhost:5001/api/capture/start                     # dùng cấu hình .env
curl -X POST localhost:5001/api/capture/start -H 'Content-Type: application/json' \
     -d '{"source": "local", "interface": "wlan0", "bpf_filter": "not port 22"}'
curl -X POST localhost:5001/api/capture/start -H 'Content-Type: application/json' \
     -d '{"source": "pcap", "pcap_file": "/data/sample.pcap"}'
curl localhost:5001/api/capture/status
curl -X POST localhost:5001/api/capture/stop
```

Các trạng thái (`state`): `idle`, `running`, `restarting` (tshark lỗi, đang chờ khởi động lại), `stopped`, `completed` (đã đọc hết file pcap), `error`.

Các chỉ số chính trong `status`:
- `packets_read`: số gói đã đọc.
- `packets_published`: số gói Kafka đã xác nhận.
- `buffer_full_drops`: số gói bị bỏ vì Kafka chậm hoặc mất kết nối.
- `delivery_errors`: số lỗi khi gửi lên Kafka.
- `tshark_restarts`: số lần tshark phải khởi động lại.
- `packets_per_second`: tốc độ đọc trung bình.

## Đầu ra: `packets_raw` (định dạng `raw.v1`)

Mỗi gói tin là một message JSON. Key là IP nguồn; gói không có IP (ARP...) thì dùng MAC nguồn:

```json
{"schema": "raw.v1", "sensor_id": "sensor-01", "source": "local", "iface": "wlan0",
 "captured_at": 1700000000.12,
 "fields": {"frame.time_epoch": "1700000000.000000000", "frame.len": "74", "ip.src": "10.42.0.15", "...": "..."}}
```

`fields` chứa các trường trong `TSHARK_FIELDS` dưới dạng chuỗi, đúng như tshark xuất ra. Các trường rỗng bị bỏ.

**Đây là hợp đồng dữ liệu với packet-normalizer.** Khi thêm hoặc đổi trường:
1. Sửa `TSHARK_FIELDS` trong `capture/tshark.py`. Kiểm tra tên trường bằng `tshark -G fields | grep <tên>`.
2. Sinh lại fixture cho packet-normalizer và cập nhật phía normalizer (xem [README của packet-normalizer](../packet-normalizer/README.md#hợp-đồng-dữ-liệu-với-packet-capture)).
3. Chỉ thêm trường thì giữ `raw.v1`. Đổi tên hoặc xóa trường thì tăng version (`RAW_SCHEMA` trong `capture/pipeline.py`).

## Mở rộng

- **Thêm nguồn capture** (vd SSH, ERSPAN): kế thừa `CaptureSource` (`capture/sources/base.py`), đăng ký trong `create_source`, rồi thêm vào `Literal` của `StartRequest` (`capture/main.py`).

## Hạn chế hiện tại / việc tiếp theo

- Chưa chạy thử end-to-end với Kafka thật. Test hiện dùng `FakeProducer`.
- Chưa có metrics Prometheus.
- Chưa lưu file pcap gốc để điều tra sự cố.
