from conftest import BASE_TS
from detection.detectors import Finding
from detection.features import HostWindowFeatures
from detection.scoring import build_anomalies, combine_scores, severity_for
from detection.suppression import Suppressor


def host_features(start=BASE_TS):
    return HostWindowFeatures(host="192.168.1.66", mac="aa:bb:cc:00:00:66", sensor_id="s1",
                              window_start=start, window_end=start + 60,
                              metrics={"max_ports_per_dst": 150, "bytes_out": 0}, context={"scan_target": "192.168.1.20"})


def test_combine_and_severity(cfg):
    assert combine_scores([0.7]) == 0.7
    assert combine_scores([0.7, 0.6]) == 0.88
    levels = cfg["alerting"]["severity"]
    assert [severity_for(s, levels) for s in (0.65, 0.75, 0.85, 0.95)] == ["low", "medium", "high", "critical"]


def test_build_anomalies_groups_by_category(cfg):
    findings = [
        Finding("rule.port_scan", "port_scan", 0.8, "scan"),
        Finding("baseline.zscore", "port_scan", 0.6, "baseline"),
        Finding("baseline.zscore", "traffic_spike", 0.3, "too weak"),          # dưới min_score
    ]
    (anomaly,) = build_anomalies(findings, cfg["alerting"], 60, host_features())
    assert anomaly.category == "port_scan" and anomaly.score == 0.92 and anomaly.severity == "critical"
    assert anomaly.summary == "scan" and [f.detector for f in anomaly.findings] == ["rule.port_scan", "baseline.zscore"]
    assert anomaly.entity.ip == "192.168.1.66" and anomaly.window.start == BASE_TS
    assert anomaly.evidence["metrics"] == {"max_ports_per_dst": 150}                 # bỏ metric bằng 0
    assert anomaly.evidence["scan_target"] == "192.168.1.20"


def test_suppression(cfg):
    suppressor = Suppressor(cooldown_seconds=300)

    def anomaly(start, score):
        (a,) = build_anomalies([Finding("rule.port_scan", "port_scan", score, "scan")], cfg["alerting"], 60,
                               host_features(start))
        return a

    assert suppressor.admit(anomaly(BASE_TS, 0.75))
    assert not suppressor.admit(anomaly(BASE_TS + 60, 0.75))       # trong cooldown
    assert not suppressor.admit(anomaly(BASE_TS + 120, 0.75))
    escalated = anomaly(BASE_TS + 180, 0.95)                      # severity tăng: gửi ngay
    assert suppressor.admit(escalated) and escalated.occurrences == 3
    later = anomaly(BASE_TS + 180 + 300, 0.75)                    # hết cooldown
    assert suppressor.admit(later) and later.occurrences == 1
