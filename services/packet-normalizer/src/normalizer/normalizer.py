"""Chuyển bản ghi raw (các trường tshark dạng chuỗi) thành NormalizedPacket."""
import hashlib
import ipaddress

from normalizer.schema import Direction, NormalizedPacket

# Tên lớp giao thức (trong frame.protocols) -> tên transport chuẩn hóa
TRANSPORT_BY_LAYER = {
    "tcp": "TCP",
    "udp": "UDP",
    "icmp": "ICMP",
    "icmpv6": "ICMPv6",
    "sctp": "SCTP",
    "gre": "GRE",
    "esp": "ESP",
    "ah": "AH",
    "igmp": "IGMP",
}

TCP_FLAG_BITS = (
    (0x001, "FIN"),
    (0x002, "SYN"),
    (0x004, "RST"),
    (0x008, "PSH"),
    (0x010, "ACK"),
    (0x020, "URG"),
    (0x040, "ECE"),
    (0x080, "CWR"),
    (0x100, "AE"),
)


class NormalizationError(ValueError):
    pass


def device_key(packet: NormalizedPacket) -> str:
    """Kafka key: thiết bị LAN mà gói tin thuộc về.

    Mọi traffic của một thiết bị (gói nó gửi đi + gói phản hồi về nó) vào cùng một partition,
    để service phía sau gom hồ sơ hành vi theo thiết bị mà vẫn scale được nhiều instance.
    - inbound: thiết bị LAN là bên nhận (dst_ip)
    - outbound / internal / external: bên gửi (src_ip)
    - không có IP (ARP...): IP bên gửi ARP, nếu không có thì MAC nguồn
    """
    if packet.direction == "inbound" and packet.dst_ip:
        return packet.dst_ip
    if packet.src_ip:
        return packet.src_ip
    return packet.arp_sender_ip or packet.src_mac or ""


def decode_tcp_flags(value: str | None) -> list[str] | None:
    if not value:
        return None
    bits = int(value, 16)
    return [name for bit, name in TCP_FLAG_BITS if bits & bit]


def _int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value, 0) if value.startswith("0x") else int(value)
    except ValueError:
        return None


def _bool(value: str | None) -> bool | None:
    if value is None:
        return None
    return value.lower() in ("true", "1")


def _flow_id(transport: str | None, src: str, sport: int | None, dst: str, dport: int | None) -> str:
    # Sắp xếp hai đầu để gói đi và gói về có cùng flow_id
    a, b = sorted([(src, sport or 0), (dst, dport or 0)])
    raw = f"{transport}|{a[0]}|{a[1]}|{b[0]}|{b[1]}"
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


class PacketNormalizer:

    def __init__(self, lan_cidrs: list[str]):
        self.lan_networks = [ipaddress.ip_network(cidr, strict=False) for cidr in lan_cidrs]

    def normalize(self, raw: dict) -> NormalizedPacket:
        if not isinstance(raw, dict) or not isinstance(raw.get("fields"), dict):
            raise NormalizationError("raw message must be an object with a 'fields' object")
        fields: dict[str, str] = raw["fields"]
        ts = fields.get("frame.time_epoch")
        if not ts:
            raise NormalizationError("missing frame.time_epoch")

        protocols = fields.get("frame.protocols", "").split(":") if fields.get("frame.protocols") else []

        if "ip.src" in fields:
            ip_version, src_ip, dst_ip, ttl = 4, fields["ip.src"], fields.get("ip.dst"), _int(fields.get("ip.ttl"))
            ip_proto = fields.get("ip.proto")
        elif "ipv6.src" in fields:
            ip_version, src_ip, dst_ip, ttl = 6, fields["ipv6.src"], fields.get("ipv6.dst"), _int(fields.get("ipv6.hlim"))
            ip_proto = fields.get("ipv6.nxt")
        else:
            ip_version = src_ip = dst_ip = ttl = ip_proto = None

        transport = self._transport(protocols, ip_proto) if ip_version else None

        # Chỉ lấy port của đúng transport (gói ICMP lỗi có thể chứa UDP/TCP bên trong)
        if transport == "TCP":
            src_port, dst_port = _int(fields.get("tcp.srcport")), _int(fields.get("tcp.dstport"))
        elif transport == "UDP":
            src_port, dst_port = _int(fields.get("udp.srcport")), _int(fields.get("udp.dstport"))
        else:
            src_port = dst_port = None

        if transport == "ICMPv6":
            icmp_type, icmp_code = _int(fields.get("icmpv6.type")), _int(fields.get("icmpv6.code"))
        elif transport == "ICMP":
            icmp_type, icmp_code = _int(fields.get("icmp.type")), _int(fields.get("icmp.code"))
        else:
            icmp_type = icmp_code = None

        is_tcp = transport == "TCP"
        return NormalizedPacket(
            ts=float(ts),
            sensor_id=raw.get("sensor_id", "unknown"),
            source=raw.get("source", "unknown"),
            iface=raw.get("iface"),
            length=_int(fields.get("frame.len")) or 0,
            protocols=protocols,
            app_protocol=fields.get("_ws.col.protocol"),
            src_mac=fields.get("eth.src"),
            dst_mac=fields.get("eth.dst"),
            ip_version=ip_version,
            src_ip=src_ip,
            dst_ip=dst_ip,
            ttl=ttl,
            direction=self._direction(src_ip, dst_ip),
            transport=transport,
            src_port=src_port,
            dst_port=dst_port,
            flow_id=_flow_id(transport, src_ip, src_port, dst_ip, dst_port) if src_ip and dst_ip else None,
            tcp_flags=decode_tcp_flags(fields.get("tcp.flags")) if is_tcp else None,
            tcp_window=_int(fields.get("tcp.window_size_value")) if is_tcp else None,
            tcp_payload_len=_int(fields.get("tcp.len")) if is_tcp else None,
            tcp_stream=_int(fields.get("tcp.stream")) if is_tcp else None,
            icmp_type=icmp_type,
            icmp_code=icmp_code,
            dns_query=fields.get("dns.qry.name"),
            dns_qtype=_int(fields.get("dns.qry.type")),
            dns_is_response=_bool(fields.get("dns.flags.response")),
            dns_rcode=_int(fields.get("dns.flags.rcode")),
            tls_sni=fields.get("tls.handshake.extensions_server_name"),
            http_host=fields.get("http.host"),
            http_method=fields.get("http.request.method"),
            arp_opcode=_int(fields.get("arp.opcode")),
            arp_sender_ip=fields.get("arp.src.proto_ipv4"),
            arp_sender_mac=fields.get("arp.src.hw_mac"),
            arp_target_ip=fields.get("arp.dst.proto_ipv4"),
            arp_target_mac=fields.get("arp.dst.hw_mac"),
        )

    @staticmethod
    def _transport(protocols: list[str], ip_proto: str | None) -> str | None:
        # Lấy lớp transport đầu tiên trong chuỗi giao thức (lớp ngoài cùng)
        for layer in protocols:
            if layer in TRANSPORT_BY_LAYER:
                return TRANSPORT_BY_LAYER[layer]
        return f"IP-{ip_proto}" if ip_proto else None

    def _direction(self, src_ip: str | None, dst_ip: str | None) -> Direction:
        if not src_ip or not dst_ip:
            return "unknown"
        src_lan, dst_lan = self._is_lan(src_ip), self._is_lan(dst_ip)
        if src_lan and dst_lan:
            return "internal"
        if src_lan:
            return "outbound"
        if dst_lan:
            return "inbound"
        return "external"

    def _is_lan(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.lan_networks if net.version == addr.version)
