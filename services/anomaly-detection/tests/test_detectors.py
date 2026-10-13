from conftest import BASE_TS
from detection.detectors import ArpSpoofDetector, BaselineDetector, RuleDetector, threshold_score
from detection.features import FEATURE_NAMES, HostWindowFeatures
from detection.state import InMemoryStateStore


def features(host="192.168.1.10", start=BASE_TS, context=None, **metrics) -> HostWindowFeatures:
    m = {name: 0 for name in FEATURE_NAMES}
    m["syn_completion_ratio"] = 1.0
    m.update(metrics)
    return HostWindowFeatures(host=host, window_start=start, window_end=start + 60, metrics=m, context=context or {})


def test_threshold_score():
    assert threshold_score(99, 100) == 0.0
    assert threshold_score(100, 100) == 0.7
    assert threshold_score(200, 100) == 0.85
    assert threshold_score(1000, 100) == 1.0


def test_rules_fire_only_above_threshold(cfg):
    rules = RuleDetector(cfg["rules"], window_seconds=60)
    assert rules.evaluate(features(max_ports_per_dst=99)) == []

    (finding,) = rules.evaluate(features(max_ports_per_dst=150, context={"scan_target": "192.168.1.20"}))
    assert (finding.category, finding.details["target"]) == ("port_scan", "192.168.1.20")
    assert "150 distinct ports" in finding.reason


def test_syn_flood_requires_low_completion(cfg):
    rules = RuleDetector(cfg["rules"], window_seconds=60)
    assert rules.evaluate(features(syn_out=5000, syn_completion_ratio=0.9)) == []   # nhiều kết nối thật
    (finding,) = rules.evaluate(features(syn_out=5000, syn_completion_ratio=0.0))
    assert finding.category == "dos"


def test_dns_tunneling_requires_random_looking_names(cfg):
    rules = RuleDetector(cfg["rules"], window_seconds=60)
    assert rules.evaluate(features(dns_top_domain_subdomains=80, dns_top_domain_avg_length=8,
                                   dns_top_domain_avg_entropy=2.5)) == []
    (finding,) = rules.evaluate(features(dns_top_domain_subdomains=80, dns_top_domain_avg_length=47,
                                         dns_top_domain_avg_entropy=4.6, context={"dns_top_domain": "evil.com"}))
    assert finding.category == "dns_tunneling"


def test_disabled_rule(cfg):
    cfg["rules"]["port_scan"]["enabled"] = False
    assert RuleDetector(cfg["rules"], window_seconds=60).evaluate(features(max_ports_per_dst=500)) == []


def test_baseline_warmup_spike_and_adaptation(cfg):
    detector = BaselineDetector(cfg["baseline"], InMemoryStateStore())
    for i in range(cfg["baseline"]["min_history"]):
        assert detector.evaluate(features(start=BASE_TS + 60 * i, unique_dst_ips=60 + i % 3)) == []

    (finding,) = detector.evaluate(features(start=BASE_TS + 6000, unique_dst_ips=400))
    assert finding.category == "unusual_destinations" and finding.details["z_score"] >= cfg["baseline"]["z_threshold"]

    # Thiết bị chuyển hẳn sang mức traffic mới: baseline học dần, hết cảnh báo
    alerts = [bool(detector.evaluate(features(start=BASE_TS + 6060 + 60 * i, unique_dst_ips=150))) for i in range(40)]
    assert alerts[0] and not alerts[-1]


def test_baseline_ignores_small_absolute_values(cfg):
    detector = BaselineDetector(cfg["baseline"], InMemoryStateStore())
    for i in range(20):
        detector.evaluate(features(start=BASE_TS + 60 * i, unique_dst_ips=1))
    assert detector.evaluate(features(start=BASE_TS + 6000, unique_dst_ips=30)) == []   # < min_value 50


def test_arp_spoofing(cfg):
    detector = ArpSpoofDetector(cfg["arp_spoofing"], InMemoryStateStore())

    def arp(mac, ts, ip="192.168.1.1"):
        return {"ts": ts, "arp_opcode": 2, "arp_sender_ip": ip, "arp_sender_mac": mac}

    assert detector.observe(arp("aa:aa:aa:aa:aa:aa", BASE_TS)) is None
    assert detector.observe(arp("aa:aa:aa:aa:aa:aa", BASE_TS + 10)) is None      # cùng MAC
    finding = detector.observe(arp("de:ad:be:ef:00:01", BASE_TS + 20))
    assert finding.category == "arp_spoofing" and finding.details["previous_mac"] == "aa:aa:aa:aa:aa:aa"
    # Quá binding_ttl: coi như IP được cấp lại (DHCP), không cảnh báo
    assert detector.observe(arp("11:11:11:11:11:11", BASE_TS + 20 + cfg["arp_spoofing"]["binding_ttl_seconds"] + 1)) is None
    assert detector.observe(arp("22:22:22:22:22:22", BASE_TS + 30, ip="0.0.0.0")) is None   # ARP probe
