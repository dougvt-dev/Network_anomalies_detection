# TShark CLI - Hướng dẫn Nhanh

## 1. Cài đặt

### Ubuntu / Debian

```bash
sudo apt update
sudo apt install -y tshark
```

### Kiểm tra version

```bash
tshark --version
```

---

# 2. Liệt kê interface mạng

```bash
tshark -D
```

Ví dụ:

```text
1. eth0
2. wlan0
3. docker0
4. lo
```

---

# 3. Capture gói tin cơ bản

## Capture realtime

```bash
tshark -i eth0
```

## Capture 100 packets

```bash
tshark -i eth0 -c 100
```

## Capture trong 30 giây

```bash
tshark -i eth0 -a duration:30
```

---

# 4. Lưu traffic vào file PCAP

## Lưu cơ bản

```bash
tshark -i eth0 -w capture.pcap
```

## Lưu 1000 packets

```bash
tshark -i eth0 -c 1000 -w capture.pcap
```

## Lưu có timestamp

```bash
tshark -i eth0 \
  -w "capture_$(date +%Y%m%d_%H%M%S).pcap"
```

---

# 5. Rotation file (quan trọng)

## Xoay file mỗi 500MB

```bash
tshark -i eth0 \
  -w "capture_%Y%m%d_%H%M%S.pcap" \
  -b filesize:500000 \
  -b files:24
```

Giải thích:

- `filesize:500000` → xoay khi file đạt 500MB
- `files:24` → giữ tối đa 24 file

---

# 6. Filter cơ bản (BPF Filter)

## Chỉ TCP

```bash
tshark -i eth0 -f "tcp"
```

## Chỉ UDP

```bash
tshark -i eth0 -f "udp"
```

## HTTP / HTTPS

```bash
tshark -i eth0 -f "port 80 or port 443"
```

## DNS

```bash
tshark -i eth0 -f "udp port 53"
```

## SSH

```bash
tshark -i eth0 -f "tcp port 22"
```

## Theo IP

```bash
tshark -i eth0 -f "host 192.168.1.100"
```

## Theo subnet

```bash
tshark -i eth0 -f "net 192.168.1.0/24"
```

---

# 7. Xuất dữ liệu quan trọng

## Xuất JSON

```bash
tshark -i eth0 -c 100 -T json > packets.json
```

## Xuất các field quan trọng

```bash
tshark -i eth0 -T fields \
  -e ip.src \
  -e ip.dst \
  -e tcp.dstport
```

Ví dụ output:

```text
192.168.1.10    8.8.8.8    443
```

---

# 8. DNS Monitoring

## Lấy domain được query

```bash
tshark -i eth0 \
  -f "udp port 53" \
  -T fields \
  -e dns.qry.name
```

---

# 9. HTTPS Domain Monitoring

## Lấy SNI domain từ TLS

```bash
tshark -i eth0 \
  -f "tcp port 443" \
  -T fields \
  -e tls.handshake.extensions_server_name
```

Ví dụ:

```text
google.com
github.com
openai.com
```

---

# 10. SYN Flood Detection

## Capture SYN packets

```bash
tshark -i eth0 \
  -f "tcp[tcpflags] & tcp-syn != 0"
```

## Đếm IP gửi SYN nhiều nhất

```bash
tshark -i eth0 \
  -f "tcp[tcpflags] & tcp-syn != 0" \
  -T fields -e ip.src | \
  sort | uniq -c | sort -rn
```

---

# 11. Đọc file PCAP

## Đọc file

```bash
tshark -r capture.pcap
```

## Chỉ đọc DNS packets

```bash
tshark -r capture.pcap -f "udp port 53"
```

## Xuất JSON từ PCAP

```bash
tshark -r capture.pcap -T json > analysis.json
```

---

# 12. Chạy background

```bash
nohup tshark -i eth0 \
  -w capture.pcap \
  > capture.log 2>&1 &
```

## Dừng capture

```bash
pkill tshark
```

---

# 13. Các field quan trọng

| Field | Ý nghĩa |
|---|---|
| `ip.src` | Source IP |
| `ip.dst` | Destination IP |
| `tcp.srcport` | Source Port |
| `tcp.dstport` | Destination Port |
| `dns.qry.name` | Domain query |
| `http.host` | HTTP host |
| `tls.handshake.extensions_server_name` | HTTPS domain |
| `frame.len` | Packet size |
| `frame.time_epoch` | Timestamp |

---

# 14. Các lệnh quan trọng nhất

| Mục đích | Lệnh |
|---|---|
| List interface | `tshark -D` |
| Capture | `tshark -i eth0` |
| Save pcap | `tshark -i eth0 -w capture.pcap` |
| DNS monitoring | `tshark -i eth0 -f "udp port 53"` |
| HTTPS monitoring | `tshark -i eth0 -f "port 443"` |
| SYN detection | `tcp[tcpflags] & tcp-syn != 0` |
| Read pcap | `tshark -r capture.pcap` |
| JSON export | `-T json` |
| Extract fields | `-T fields -e ...` |

---

# 15. Tips quan trọng

## Permission denied

```bash
sudo tshark -i eth0
```

---

## Interface không tồn tại

```bash
tshark -D
```

---

## Capture traffic toàn máy

```bash
tshark -i any
```

---

## Giảm tải CPU

Dùng filter:

```bash
tshark -i eth0 -f "port 80 or port 443"
```

thay vì capture toàn bộ traffic.

---

# 16. Khuyến nghị cho AI Network Monitoring

## Capture layer

Dùng:

- tcpdump
- tshark
- Zeek

---

## Storage layer

Lưu:

- PCAP
- JSON
- metadata

---

## AI Analysis

Nên extract:

- DNS queries
- TLS SNI
- IP flows
- SYN patterns
- packet size
- traffic frequency