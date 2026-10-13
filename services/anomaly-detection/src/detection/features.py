"""Hồ sơ hành vi của một thiết bị trong một cửa sổ thời gian."""
import math
from collections import Counter
from dataclasses import dataclass, field

# Thứ tự cố định: dùng làm vector đầu vào cho ML ở giai đoạn sau
FEATURE_NAMES: tuple[str, ...] = (
    "packets_out",
    "bytes_out",
    "packets_in",
    "bytes_in",
    "unique_dst_ips",
    "unique_dst_ports",
    "new_dst_ips",                    # đích chưa từng gặp ở các cửa sổ trước
    "max_ports_per_dst",              # nhiều port nhất mà thiết bị dò trên một đích (port scan)
    "max_unanswered_dsts_per_port",   # nhiều đích nhất trên một port mà SYN không được trả lời (host sweep)
    "icmp_echo_targets",
    "syn_out",
    "synack_in",
    "syn_completion_ratio",           # synack_in / syn_out
    "rst_in",
    "max_auth_attempts",              # nhiều lần thử nhất tới cùng một dst_ip:port đăng nhập
    "dns_queries",
    "dns_unique_qnames",
    "dns_responses",
    "dns_nxdomain",
    "dns_nxdomain_ratio",
    "dns_top_domain_subdomains",      # số subdomain khác nhau dưới domain bị hỏi nhiều nhất
    "dns_top_domain_avg_length",
    "dns_top_domain_avg_entropy",
    "inbound_syn",                    # SYN từ bên ngoài LAN gửi tới thiết bị
    "max_ports_probed_by_source",     # nhiều port nhất mà một IP bên ngoài dò trên thiết bị
)


@dataclass
class HostWindowFeatures:
    host: str                          # IP thiết bị (trùng Kafka key của packets_normalized)
    window_start: float
    window_end: float
    metrics: dict[str, float]
    mac: str | None = None
    sensor_id: str | None = None
    context: dict = field(default_factory=dict)   # bằng chứng kèm cảnh báo: đích bị dò, domain, mẫu DNS...

    def vector(self) -> list[float]:
        return [float(self.metrics.get(name, 0.0)) for name in FEATURE_NAMES]

    def to_record(self) -> dict:
        """Bản ghi cho topic host_features."""
        return {
            "schema_version": 1,
            "host": self.host,
            "mac": self.mac,
            "sensor_id": self.sensor_id,
            "window_start": self.window_start,
            "window_end": self.window_end,
            "metrics": {name: self.metrics.get(name, 0) for name in FEATURE_NAMES},
        }


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum(c / total * math.log2(c / total) for c in counts.values())


def split_domain(qname: str) -> tuple[str, str]:
    """Tách 'a1b2.t.evil.com' thành ('evil.com', 'a1b2.t').

    Lấy 2 nhãn cuối làm domain gốc — cách đơn giản, chưa xử lý đúng các đuôi như .com.vn, .co.uk.
    """
    labels = qname.rstrip(".").lower().split(".")
    if len(labels) <= 2:
        return ".".join(labels), ""
    return ".".join(labels[-2:]), ".".join(labels[:-2])
