from conftest import BASE_TS, pkt
from detection.windowing import WindowAggregator, attribute

AUTH_PORTS = {22: "ssh"}


def make_aggregator():
    return WindowAggregator(window_seconds=60, allowed_lateness=5, auth_ports=AUTH_PORTS)


def test_attribute_by_direction():
    assert attribute(pkt(direction="outbound")) == [("192.168.1.10", "sent")]
    assert attribute(pkt(src_ip="1.1.1.1", dst_ip="192.168.1.10", direction="inbound")) == [("192.168.1.10", "received")]
    assert attribute(pkt(dst_ip="192.168.1.20", direction="internal")) == [("192.168.1.10", "sent"),
                                                                          ("192.168.1.20", "received")]
    assert attribute({"ts": BASE_TS, "direction": "unknown", "arp_opcode": 1}) == []


def test_window_closes_after_lateness_and_drops_late_packets():
    agg = make_aggregator()
    agg.add(pkt(ts=BASE_TS + 10))
    agg.add(pkt(ts=BASE_TS + 62))           # cửa sổ kế tiếp, nhưng chưa quá allowed_lateness
    assert agg.pop_closed() == []
    agg.add(pkt(ts=BASE_TS + 66))
    closed = agg.pop_closed()
    assert [(start, host) for start, _, host, _ in closed] == [(BASE_TS, "192.168.1.10")]

    assert agg.add(pkt(ts=BASE_TS + 30)) is False   # thuộc cửa sổ đã đóng
    assert agg.late_packets == 1
    assert len(agg.pop_all()) == 1                   # cửa sổ thứ hai


def test_finalize_metrics():
    agg = make_aggregator()
    host = "192.168.1.10"
    # SYN tới port 445 của 3 máy, chỉ .101 trả lời SYN-ACK
    for dst in ("192.168.1.100", "192.168.1.101", "192.168.1.102"):
        agg.add(pkt(dst_ip=dst, direction="internal", dst_port=445, flags=["SYN"]))
    agg.add(pkt(src_ip="192.168.1.101", dst_ip=host, direction="internal", src_port=445, dst_port=40000,
                flags=["SYN", "ACK"]))
    # 2 lần thử SSH
    for _ in range(2):
        agg.add(pkt(dst_ip="192.168.1.5", direction="internal", dst_port=22, flags=["SYN"]))
    # DNS: query + NXDOMAIN
    agg.add(pkt(transport="UDP", dst_ip="8.8.8.8", dst_port=53, dns_query="abc.x.example.com", dns_is_response=False))
    agg.add(pkt(transport="UDP", src_ip="8.8.8.8", dst_ip=host, direction="inbound", src_port=53, dst_port=40000,
                dns_query="abc.x.example.com", dns_is_response=True, dns_rcode=3))

    (_, _, _, acc), = [c for c in agg.pop_all() if c[2] == host]
    f = acc.finalize(host, BASE_TS, BASE_TS + 60, known_dsts=None, auth_ports=AUTH_PORTS)
    m = f.metrics
    assert m["syn_out"] == 5 and m["synack_in"] == 1 and m["syn_completion_ratio"] == 0.2
    assert m["max_unanswered_dsts_per_port"] == 2 and f.context["sweep_port"] == 445
    assert m["max_auth_attempts"] == 2 and f.context["auth_target"] == {"ip": "192.168.1.5", "port": 22, "service": "ssh"}
    assert m["dns_queries"] == 1 and m["dns_nxdomain"] == 1 and m["dns_nxdomain_ratio"] == 1.0
    assert m["dns_top_domain_subdomains"] == 1 and f.context["dns_top_domain"] == "example.com"
    assert m["new_dst_ips"] == 0                     # lần đầu gặp thiết bị: chưa có lịch sử

    f2 = acc.finalize(host, BASE_TS, BASE_TS + 60, known_dsts={"8.8.8.8"}, auth_ports=AUTH_PORTS)
    assert f2.metrics["new_dst_ips"] == m["unique_dst_ips"] - 1
    assert len(f.vector()) == len(f.to_record()["metrics"])
