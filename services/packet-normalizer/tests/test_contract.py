"""Contract test: chuẩn hóa các raw record (raw.v1) do packet-capture thực sự sinh ra.

Fixture `fixtures/raw_v1_samples.jsonl` gồm 7 gói: DNS query/response, TCP SYN, HTTP GET, IPv6/UDP, ICMP echo, ARP.
Khi packet-capture đổi TSHARK_FIELDS, sinh lại fixture (xem README) và chạy lại test này.
"""
import json
from pathlib import Path

import pytest

from normalizer.normalizer import PacketNormalizer

FIXTURE = Path(__file__).parent / "fixtures" / "raw_v1_samples.jsonl"
MAC_CLIENT = "aa:bb:cc:00:00:01"


@pytest.fixture(scope="module")
def packets():
    normalizer = PacketNormalizer(["192.168.0.0/16", "fe80::/10"])
    raws = [json.loads(line) for line in FIXTURE.read_text().splitlines() if line.strip()]
    assert all(r["schema"] == "raw.v1" for r in raws)
    return [normalizer.normalize(r) for r in raws]


def test_fixture_size(packets):
    assert len(packets) == 7
    assert all(p.sensor_id == "fixture-sensor" and p.source == "pcap" for p in packets)


def test_dns(packets):
    dns_q, dns_r = packets[0], packets[1]
    assert (dns_q.transport, dns_q.dst_port, dns_q.dns_query, dns_q.dns_is_response) == ("UDP", 53, "example.com", False)
    assert dns_q.direction == "outbound" and dns_q.ts == 1_700_000_000.0
    assert dns_r.dns_is_response is True and dns_r.dns_rcode == 0 and dns_r.direction == "inbound"
    assert dns_q.flow_id == dns_r.flow_id


def test_tcp_and_http(packets):
    syn, http = packets[2], packets[3]
    assert syn.tcp_flags == ["SYN"] and syn.direction == "outbound"
    assert http.http_host == "example.com" and http.http_method == "GET"
    assert set(http.tcp_flags) == {"PSH", "ACK"} and http.tcp_payload_len > 0
    assert syn.flow_id == http.flow_id


def test_ipv6_icmp_arp(packets):
    ipv6, icmp, arp = packets[4], packets[5], packets[6]
    assert (ipv6.ip_version, ipv6.ttl, ipv6.transport, ipv6.dst_port) == (6, 255, "UDP", 443)
    assert icmp.transport == "ICMP" and icmp.icmp_type == 8 and icmp.direction == "internal"
    assert arp.ip_version is None and arp.app_protocol == "ARP" and arp.src_mac == MAC_CLIENT
    assert arp.arp_opcode == 1 and arp.direction == "unknown"
    assert (arp.arp_sender_ip, arp.arp_sender_mac) == ("192.168.1.10", MAC_CLIENT)
    assert arp.arp_target_ip == "192.168.1.1"
