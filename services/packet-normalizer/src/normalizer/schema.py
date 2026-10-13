"""Schema bản ghi gói tin đã chuẩn hóa (topic packets_normalized) — đầu vào cho các service phía sau."""
from typing import Literal

from pydantic import BaseModel

Direction = Literal["outbound", "inbound", "internal", "external", "unknown"]


class NormalizedPacket(BaseModel):
    schema_version: int = 1

    # Nguồn
    ts: float                          # thời điểm gói tin (epoch giây, từ tshark)
    sensor_id: str
    source: str                        # local | pcap
    iface: str | None = None

    # Khung / lớp 2
    length: int
    protocols: list[str]               # chuỗi giao thức, vd ["eth","ethertype","ip","tcp","tls"]
    app_protocol: str | None = None    # giao thức cao nhất tshark nhận diện, vd "DNS", "TLSv1.3"
    src_mac: str | None = None
    dst_mac: str | None = None

    # Lớp 3
    ip_version: Literal[4, 6] | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    ttl: int | None = None             # IPv4 TTL hoặc IPv6 hop limit
    direction: Direction = "unknown"   # so với LAN_CIDRS

    # Lớp 4
    transport: str | None = None       # TCP | UDP | ICMP | ICMPv6 | GRE | ... | IP-<số>
    src_port: int | None = None
    dst_port: int | None = None
    flow_id: str | None = None         # id hai chiều của flow (5-tuple)
    tcp_flags: list[str] | None = None
    tcp_window: int | None = None
    tcp_payload_len: int | None = None
    tcp_stream: int | None = None
    icmp_type: int | None = None
    icmp_code: int | None = None

    # Metadata ứng dụng
    dns_query: str | None = None
    dns_qtype: int | None = None
    dns_is_response: bool | None = None
    dns_rcode: int | None = None
    tls_sni: str | None = None
    http_host: str | None = None
    http_method: str | None = None
    arp_opcode: int | None = None      # 1 = request, 2 = reply
    arp_sender_ip: str | None = None   # IP mà bên gửi ARP khai báo là của mình
    arp_sender_mac: str | None = None
    arp_target_ip: str | None = None
    arp_target_mac: str | None = None
