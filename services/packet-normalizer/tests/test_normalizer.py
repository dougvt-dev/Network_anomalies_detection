import json

import pytest

from normalizer.main import NormalizerWorker
from normalizer.normalizer import NormalizationError, PacketNormalizer, decode_tcp_flags, device_key

LAN = ["192.168.0.0/16", "fe80::/10"]


def raw(**fields):
    return {"schema": "raw.v1", "sensor_id": "s1", "source": "pcap", "iface": None,
            "fields": {"frame.time_epoch": "1700000000.25", "frame.len": "60", **fields}}


@pytest.fixture
def normalizer():
    return PacketNormalizer(LAN)


def test_decode_tcp_flags():
    assert decode_tcp_flags("0x0012") == ["SYN", "ACK"]
    assert decode_tcp_flags("0x0000") == []
    assert decode_tcp_flags(None) is None


def test_tcp_packet(normalizer):
    p = normalizer.normalize(raw(**{
        "frame.protocols": "eth:ethertype:ip:tcp", "ip.src": "192.168.1.10", "ip.dst": "1.1.1.1",
        "ip.ttl": "64", "ip.proto": "6", "tcp.srcport": "40000", "tcp.dstport": "443",
        "tcp.flags": "0x0002", "tcp.len": "0",
    }))
    assert (p.ip_version, p.transport, p.src_port, p.dst_port) == (4, "TCP", 40000, 443)
    assert p.tcp_flags == ["SYN"] and p.ttl == 64 and p.ts == 1700000000.25
    assert p.direction == "outbound"


def test_flow_id_is_bidirectional(normalizer):
    common = {"frame.protocols": "eth:ethertype:ip:udp", "ip.proto": "17"}
    out = normalizer.normalize(raw(**common, **{"ip.src": "192.168.1.10", "ip.dst": "8.8.8.8",
                                                "udp.srcport": "5353", "udp.dstport": "53"}))
    back = normalizer.normalize(raw(**common, **{"ip.src": "8.8.8.8", "ip.dst": "192.168.1.10",
                                                 "udp.srcport": "53", "udp.dstport": "5353"}))
    assert out.flow_id == back.flow_id
    assert back.direction == "inbound"


def test_icmp_error_ignores_inner_udp_ports(normalizer):
    p = normalizer.normalize(raw(**{
        "frame.protocols": "eth:ethertype:ip:icmp:ip:udp", "ip.src": "1.1.1.1", "ip.dst": "192.168.1.10",
        "ip.proto": "1", "icmp.type": "3", "icmp.code": "3", "udp.srcport": "5353", "udp.dstport": "53",
    }))
    assert p.transport == "ICMP" and p.src_port is None and (p.icmp_type, p.icmp_code) == (3, 3)


def test_non_ip_packet(normalizer):
    p = normalizer.normalize(raw(**{"frame.protocols": "eth:ethertype:arp", "_ws.col.protocol": "ARP",
                                    "eth.src": "aa:bb:cc:00:00:01", "arp.opcode": "1"}))
    assert p.ip_version is None and p.transport is None and p.flow_id is None
    assert p.direction == "unknown" and p.arp_opcode == 1


def test_invalid_messages(normalizer):
    with pytest.raises(NormalizationError):
        normalizer.normalize({"fields": {"ip.src": "1.2.3.4"}})
    with pytest.raises(NormalizationError):
        normalizer.normalize([1, 2])


def test_worker_process_value(normalizer):
    worker = NormalizerWorker(consumer=None, producer=None, normalizer=normalizer, output_topic="out")
    key, value = worker.process_value(json.dumps(raw(**{"ip.src": "192.168.1.10", "ip.dst": "8.8.8.8"})).encode())
    doc = json.loads(value)
    assert doc["src_ip"] == "192.168.1.10" and "dns_query" not in doc   # bỏ trường None
    assert key == b"192.168.1.10"   # outbound: key = IP thiết bị LAN gửi đi
    assert worker.process_value(b"not json") is None and worker.stats["invalid"] == 1


def test_device_key(normalizer):
    common = {"frame.protocols": "eth:ethertype:ip:tcp", "ip.proto": "6"}
    out = normalizer.normalize(raw(**common, **{"ip.src": "192.168.1.10", "ip.dst": "1.1.1.1"}))
    back = normalizer.normalize(raw(**common, **{"ip.src": "1.1.1.1", "ip.dst": "192.168.1.10"}))
    internal = normalizer.normalize(raw(**common, **{"ip.src": "192.168.1.20", "ip.dst": "192.168.1.10"}))
    arp = normalizer.normalize(raw(**{"frame.protocols": "eth:ethertype:arp", "eth.src": "aa:bb:cc:00:00:01",
                                      "arp.opcode": "2", "arp.src.proto_ipv4": "192.168.1.1"}))
    no_ip = normalizer.normalize(raw(**{"frame.protocols": "eth:ethertype:lldp", "eth.src": "aa:bb:cc:00:00:09"}))
    # Gói đi và gói phản hồi của cùng một thiết bị có cùng key
    assert device_key(out) == device_key(back) == "192.168.1.10"
    assert device_key(internal) == "192.168.1.20"
    assert device_key(arp) == "192.168.1.1"
    assert device_key(no_ip) == "aa:bb:cc:00:00:09"
