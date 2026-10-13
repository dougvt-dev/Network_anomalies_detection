"""Gộp các finding thành cảnh báo: mỗi (thiết bị, loại bất thường) một cảnh báo."""
import math
import time
import uuid
from collections import defaultdict

from detection.detectors.base import Finding
from detection.features import HostWindowFeatures
from detection.schema import Anomaly, Entity, FindingOut, Window

SEVERITY_ORDER = ("low", "medium", "high", "critical")


def combine_scores(scores: list[float]) -> float:
    """Noisy-OR: nhiều detector độc lập cùng chỉ ra một loại bất thường thì độ tin cậy cao hơn từng cái."""
    return round(1 - math.prod(1 - s for s in scores), 3)


def severity_for(score: float, levels: dict[str, float]) -> str:
    for name in ("critical", "high", "medium"):
        if score >= levels[name]:
            return name
    return "low"


def build_anomalies(
    findings: list[Finding],
    alerting_cfg: dict,
    window_seconds: float,
    features: HostWindowFeatures | None = None,
) -> list[Anomaly]:
    by_category: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        by_category[finding.category].append(finding)

    anomalies = []
    for category, group in by_category.items():
        score = combine_scores([f.score for f in group])
        if score < alerting_cfg["min_score"]:
            continue
        group.sort(key=lambda f: f.score, reverse=True)
        top = group[0]

        if features is not None:
            entity = Entity(ip=features.host, mac=features.mac)
            window = Window(start=features.window_start, end=features.window_end)
            sensor_id = features.sensor_id
            evidence = {"metrics": {k: v for k, v in features.metrics.items() if v}, **features.context}
        else:
            # Finding theo từng gói (ARP): lấy cửa sổ chứa thời điểm của gói
            start = math.floor(top.ts / window_seconds) * window_seconds
            entity = Entity(ip=top.entity_ip, mac=top.entity_mac)
            window = Window(start=start, end=start + window_seconds)
            sensor_id = top.sensor_id
            evidence = dict(top.details)

        anomalies.append(Anomaly(
            anomaly_id=str(uuid.uuid4()),
            detected_at=round(time.time(), 3),
            window=window,
            sensor_id=sensor_id,
            entity=entity,
            category=category,
            severity=severity_for(score, alerting_cfg["severity"]),
            score=score,
            summary=top.reason,
            findings=[FindingOut(detector=f.detector, score=f.score, reason=f.reason, details=f.details) for f in group],
            evidence=evidence,
        ))
    return anomalies
