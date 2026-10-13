"""Gom gói tin đã chuẩn hóa thành hồ sơ hành vi theo thiết bị, cửa sổ tumbling theo event time (ts)."""
import math
from collections import Counter, defaultdict

from detection.features import HostWindowFeatures, shannon_entropy, split_domain

MAX_TRACKED = 10_000   # giới hạn kích thước mỗi tập hợp để không tràn bộ nhớ khi bị flood
ICMP_ECHO_REQUEST = {("ICMP", 8), ("ICMPv6", 128)}
DNS_RCODE_NXDOMAIN = 3


def _add(collection: set, item) -> None:
    if len(collection) < MAX_TRACKED:
        collection.add(item)


def attribute(packet: dict) -> list[tuple[str, str]]:
    """Gói tin thuộc về thiết bị nào, ở vai trò gửi (sent) hay nhận (received).

    Khớp với Kafka key của packet-normalizer (device_key).
    """
    direction = packet.get("direction")
    src, dst = packet.get("src_ip"), packet.get("dst_ip")
    if not src or not dst:
        return []                      # gói không có IP (ARP...) do detector riêng xử lý
    if direction == "inbound":
        return [(dst, "received")]
    if direction == "internal":
        return [(src, "sent"), (dst, "received")]
    return [(src, "sent")]             # outbound / external


def _tcp_kind(packet: dict) -> str | None:
    if packet.get("transport") != "TCP":
        return None
    flags = packet.get("tcp_flags") or []
    if "SYN" in flags:
        return "synack" if "ACK" in flags else "syn"
    if "RST" in flags:
        return "rst"
    return None


class HostAccumulator:
    """Thống kê thô của một thiết bị trong một cửa sổ."""

    def __init__(self):
        self.mac: str | None = None
        self.sensor_id: str | None = None
        self.packets_out = self.bytes_out = self.packets_in = self.bytes_in = 0
        self.dst_ips: set[str] = set()
        self.dst_ports: set[int] = set()
        self.bytes_by_dst: Counter = Counter()
        self.ports_by_dst: dict[str, set] = defaultdict(set)          # đích -> port đã dò (SYN / UDP)
        self.syn_dsts_by_port: dict[int, set] = defaultdict(set)      # port -> đích đã gửi SYN
        self.synack_from: set[tuple[str, int]] = set()                # (ip, port) đã trả lời SYN-ACK
        self.icmp_echo_targets: set[str] = set()
        self.syn_out = self.synack_in = self.rst_in = 0
        self.auth_attempts: Counter = Counter()                       # (dst_ip, port) -> số SYN
        self.dns_queries = self.dns_responses = self.dns_nxdomain = 0
        self.qnames: set[str] = set()
        self.subdomains_by_domain: dict[str, set] = defaultdict(set)
        self.server_names: Counter = Counter()                        # TLS SNI / HTTP host
        self.inbound_syn = 0
        self.probed_ports_by_src: dict[str, set] = defaultdict(set)

    def add_sent(self, p: dict, auth_ports: set[int]) -> None:
        self.mac = p.get("src_mac") or self.mac
        self.sensor_id = p.get("sensor_id") or self.sensor_id
        length = p.get("length", 0)
        self.packets_out += 1
        self.bytes_out += length

        dst, dport = p.get("dst_ip"), p.get("dst_port")
        _add(self.dst_ips, dst)
        if len(self.bytes_by_dst) < MAX_TRACKED or dst in self.bytes_by_dst:
            self.bytes_by_dst[dst] += length
        if dport is not None:
            _add(self.dst_ports, dport)

        kind = _tcp_kind(p)
        if kind == "syn":
            self.syn_out += 1
            if dport is not None:
                self._probe(dst, dport)
                _add(self.syn_dsts_by_port[dport], dst)
                if dport in auth_ports:
                    self.auth_attempts[(dst, dport)] += 1
        elif p.get("transport") == "UDP" and dport is not None:
            self._probe(dst, dport)

        if (p.get("transport"), p.get("icmp_type")) in ICMP_ECHO_REQUEST:
            _add(self.icmp_echo_targets, dst)

        qname = p.get("dns_query")
        if qname and p.get("dns_is_response") is False:
            self.dns_queries += 1
            _add(self.qnames, qname)
            domain, sub = split_domain(qname)
            if sub:
                _add(self.subdomains_by_domain[domain], sub)

        server_name = p.get("tls_sni") or p.get("http_host")
        if server_name and (len(self.server_names) < MAX_TRACKED or server_name in self.server_names):
            self.server_names[server_name] += 1

    def add_received(self, p: dict) -> None:
        self.sensor_id = p.get("sensor_id") or self.sensor_id
        self.packets_in += 1
        self.bytes_in += p.get("length", 0)

        kind = _tcp_kind(p)
        if kind == "synack":
            self.synack_in += 1
            _add(self.synack_from, (p.get("src_ip"), p.get("src_port")))
        elif kind == "rst":
            self.rst_in += 1
        elif kind == "syn" and p.get("direction") == "inbound":
            self.inbound_syn += 1
            if p.get("dst_port") is not None:
                _add(self.probed_ports_by_src[p.get("src_ip")], p.get("dst_port"))

        if p.get("dns_is_response") is True:
            self.dns_responses += 1
            if p.get("dns_rcode") == DNS_RCODE_NXDOMAIN:
                self.dns_nxdomain += 1

    def _probe(self, dst: str, port: int) -> None:
        if dst in self.ports_by_dst or len(self.ports_by_dst) < MAX_TRACKED:
            _add(self.ports_by_dst[dst], port)

    def finalize(
        self,
        host: str,
        window_start: float,
        window_end: float,
        known_dsts: set[str] | None,
        auth_ports: dict[int, str],
    ) -> HostWindowFeatures:
        context: dict = {}

        scan_target, scan_ports = max(self.ports_by_dst.items(), key=lambda kv: len(kv[1]), default=(None, set()))
        if scan_target:
            context["scan_target"] = scan_target
            context["scan_ports_sample"] = sorted(scan_ports)[:20]

        unanswered_by_port = {
            port: {d for d in dsts if (d, port) not in self.synack_from}
            for port, dsts in self.syn_dsts_by_port.items()
        }
        sweep_port, sweep_dsts = max(unanswered_by_port.items(), key=lambda kv: len(kv[1]), default=(None, set()))
        if sweep_dsts:
            context["sweep_port"] = sweep_port
            context["sweep_targets_sample"] = sorted(sweep_dsts)[:20]

        auth_target, auth_count = (self.auth_attempts.most_common(1) or [((None, None), 0)])[0]
        if auth_count:
            context["auth_target"] = {"ip": auth_target[0], "port": auth_target[1],
                                      "service": auth_ports.get(auth_target[1])}

        top_domain, subdomains = max(self.subdomains_by_domain.items(), key=lambda kv: len(kv[1]), default=(None, set()))
        if top_domain:
            context["dns_top_domain"] = top_domain
        avg_len = sum(len(s) for s in subdomains) / len(subdomains) if subdomains else 0.0
        avg_entropy = sum(shannon_entropy(s.replace(".", "")) for s in subdomains) / len(subdomains) if subdomains else 0.0
        if self.qnames:
            context["dns_samples"] = sorted(self.qnames)[:10]

        probe_src, probe_ports = max(self.probed_ports_by_src.items(), key=lambda kv: len(kv[1]), default=(None, set()))
        if probe_src:
            context["probe_source"] = probe_src

        if self.bytes_by_dst:
            context["top_destinations"] = [{"ip": ip, "bytes": b} for ip, b in self.bytes_by_dst.most_common(5)]
        if self.server_names:
            context["top_server_names"] = [name for name, _ in self.server_names.most_common(5)]

        metrics = {
            "packets_out": self.packets_out,
            "bytes_out": self.bytes_out,
            "packets_in": self.packets_in,
            "bytes_in": self.bytes_in,
            "unique_dst_ips": len(self.dst_ips),
            "unique_dst_ports": len(self.dst_ports),
            # Lần đầu thấy thiết bị: chưa có lịch sử, không tính đích "mới"
            "new_dst_ips": len(self.dst_ips - known_dsts) if known_dsts is not None else 0,
            "max_ports_per_dst": len(scan_ports),
            "max_unanswered_dsts_per_port": len(sweep_dsts),
            "icmp_echo_targets": len(self.icmp_echo_targets),
            "syn_out": self.syn_out,
            "synack_in": self.synack_in,
            "syn_completion_ratio": round(self.synack_in / self.syn_out, 3) if self.syn_out else 1.0,
            "rst_in": self.rst_in,
            "max_auth_attempts": auth_count,
            "dns_queries": self.dns_queries,
            "dns_unique_qnames": len(self.qnames),
            "dns_responses": self.dns_responses,
            "dns_nxdomain": self.dns_nxdomain,
            "dns_nxdomain_ratio": round(self.dns_nxdomain / self.dns_responses, 3) if self.dns_responses else 0.0,
            "dns_top_domain_subdomains": len(subdomains),
            "dns_top_domain_avg_length": round(avg_len, 1),
            "dns_top_domain_avg_entropy": round(avg_entropy, 3),
            "inbound_syn": self.inbound_syn,
            "max_ports_probed_by_source": len(probe_ports),
        }
        return HostWindowFeatures(
            host=host, window_start=window_start, window_end=window_end,
            metrics=metrics, mac=self.mac, sensor_id=self.sensor_id, context=context,
        )


class WindowAggregator:
    """Cửa sổ tumbling theo event time. Cửa sổ đóng khi ts lớn nhất đã thấy vượt quá cuối cửa sổ + allowed_lateness."""

    def __init__(self, window_seconds: float, allowed_lateness: float, auth_ports: dict[int, str]):
        self.window_seconds = window_seconds
        self.allowed_lateness = allowed_lateness
        self.auth_ports = auth_ports
        self._auth_port_set = set(auth_ports)
        self.windows: dict[float, dict[str, HostAccumulator]] = {}
        self.max_ts: float | None = None
        self.closed_before: float = -math.inf    # gói thuộc cửa sổ bắt đầu trước mốc này là gói trễ
        self.late_packets = 0

    @property
    def has_open_windows(self) -> bool:
        return bool(self.windows)

    def add(self, packet: dict) -> bool:
        """Thêm gói vào cửa sổ. Trả về False nếu gói bị bỏ (trễ hoặc thiếu ts)."""
        ts = packet.get("ts")
        if ts is None:
            return False
        start = math.floor(ts / self.window_seconds) * self.window_seconds
        if start < self.closed_before:
            self.late_packets += 1
            return False
        self.max_ts = ts if self.max_ts is None else max(self.max_ts, ts)

        targets = attribute(packet)
        if targets:
            hosts = self.windows.setdefault(start, {})
            for host, role in targets:
                acc = hosts.get(host)
                if acc is None:
                    acc = hosts[host] = HostAccumulator()
                if role == "sent":
                    acc.add_sent(packet, self._auth_port_set)
                else:
                    acc.add_received(packet)
        return True

    def pop_closed(self) -> list[tuple[float, float, str, HostAccumulator]]:
        if self.max_ts is None:
            return []
        cutoff = self.max_ts - self.allowed_lateness
        return self._pop([s for s in self.windows if s + self.window_seconds <= cutoff])

    def pop_all(self) -> list[tuple[float, float, str, HostAccumulator]]:
        return self._pop(list(self.windows))

    def _pop(self, starts: list[float]) -> list[tuple[float, float, str, HostAccumulator]]:
        closed = []
        for start in sorted(starts):
            end = start + self.window_seconds
            for host, acc in self.windows.pop(start).items():
                closed.append((start, end, host, acc))
            self.closed_before = max(self.closed_before, end)
        return closed
