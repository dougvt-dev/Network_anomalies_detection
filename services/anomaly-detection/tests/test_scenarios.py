"""Kịch bản tấn công end-to-end: pcap (scapy) → packet-capture → packet-normalizer → DetectionEngine.

Fixture sinh bởi tests/attack_traffic.py qua capture.dump và normalizer.dump (xem README).
"""
from collections import defaultdict

import pytest

import attack_traffic as at
from conftest import load_normalized_fixture
from detection.engine import DetectionEngine


@pytest.fixture(scope="module")
def packets():
    return load_normalized_fixture()


@pytest.fixture
def detected(cfg, packets):
    # Fixture chỉ có 250 SYN để giữ nhỏ gọn; hạ ngưỡng SYN flood tương ứng (mặc định 50/s)
    cfg["rules"]["syn_flood"]["min_syn_per_second"] = 3
    engine = DetectionEngine(cfg)
    anomalies = []
    for packet in packets:
        engine.ingest(packet)
        anomalies += engine.advance().anomalies
    anomalies += engine.flush().anomalies

    by_entity = defaultdict(dict)
    for anomaly in anomalies:
        by_entity[anomaly.entity.ip][anomaly.category] = anomaly
    return by_entity


def test_each_scenario_detected_exactly(detected):
    assert {ip: set(cats) for ip, cats in detected.items()} == {
        at.PORT_SCANNER: {"port_scan"},
        at.SWEEPER: {"host_sweep"},
        at.FLOODER: {"dos"},
        at.BRUTE_FORCER: {"brute_force"},
        at.DNS_TUNNELER: {"dns_tunneling"},
        at.DGA_INFECTED: {"dga"},
        at.SCAN_VICTIM: {"inbound_scan"},
        at.GATEWAY_IP: {"arp_spoofing"},
    }


def test_normal_device_has_no_anomaly(detected):
    assert at.NORMAL not in detected


def test_evidence_points_at_the_right_targets(detected):
    assert detected[at.PORT_SCANNER]["port_scan"].evidence["scan_target"] == at.SCAN_TARGET
    assert detected[at.SWEEPER]["host_sweep"].findings[0].details["port"] == 445
    assert detected[at.BRUTE_FORCER]["brute_force"].findings[0].details["service"] == "ssh"
    assert detected[at.DNS_TUNNELER]["dns_tunneling"].evidence["dns_top_domain"] == "evil-tunnel.com"
    assert detected[at.SCAN_VICTIM]["inbound_scan"].evidence["probe_source"] == at.EXTERNAL_SCANNER

    arp = detected[at.GATEWAY_IP]["arp_spoofing"]
    assert (arp.entity.mac, arp.evidence["previous_mac"]) == (at.ARP_SPOOFER_MAC, at.GATEWAY_MAC)
    assert arp.severity == "critical"


def test_anomaly_output_format(detected):
    anomaly = detected[at.PORT_SCANNER]["port_scan"]
    doc = anomaly.model_dump(exclude_none=True)
    assert {"anomaly_id", "detected_at", "window", "entity", "category", "severity", "score",
            "summary", "findings", "evidence", "occurrences"} <= doc.keys()
    assert doc["window"] == {"start": at.BASE_TS, "end": at.BASE_TS + 60}
    assert doc["sensor_id"] == "fixture-sensor" and 0 < doc["score"] <= 1
