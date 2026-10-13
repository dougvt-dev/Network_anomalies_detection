"""DetectionEngine: gói tin chuẩn hóa → cửa sổ → detectors → cảnh báo. Không phụ thuộc Kafka (dễ test)."""
import logging
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from detection.detectors import ArpSpoofDetector, BaselineDetector, Finding, RuleDetector, WindowDetector
from detection.features import HostWindowFeatures
from detection.schema import Anomaly
from detection.scoring import build_anomalies
from detection.state import InMemoryStateStore, StateStore
from detection.suppression import Suppressor
from detection.windowing import WindowAggregator

logger = logging.getLogger(__name__)

KNOWN_DSTS_NAMESPACE = "known_dsts"
MAX_KNOWN_DSTS = 5_000


def load_detection_config(path: str | Path) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


@dataclass
class EngineOutput:
    anomalies: list[Anomaly] = field(default_factory=list)
    features: list[HostWindowFeatures] = field(default_factory=list)


class DetectionEngine:

    def __init__(self, cfg: dict, store: StateStore | None = None):
        self.cfg = cfg
        self.store = store or InMemoryStateStore()
        self.window_seconds = cfg["window"]["size_seconds"]
        auth_ports = cfg["rules"].get("brute_force", {}).get("ports", {})

        self.aggregator = WindowAggregator(self.window_seconds, cfg["window"]["allowed_lateness_seconds"], auth_ports)
        self.window_detectors: list[WindowDetector] = [RuleDetector(cfg["rules"], self.window_seconds)]
        if cfg["baseline"].get("enabled"):
            self.window_detectors.append(BaselineDetector(cfg["baseline"], self.store))
        self.arp = ArpSpoofDetector(cfg["arp_spoofing"], self.store) if cfg["arp_spoofing"].get("enabled") else None
        self.suppressor = Suppressor(cfg["alerting"]["cooldown_seconds"])

        self._pending: list[Finding] = []       # finding theo từng gói, chờ gửi ở lần advance kế tiếp
        self.stats = Counter()

    @property
    def has_open_windows(self) -> bool:
        return self.aggregator.has_open_windows

    def ingest(self, packet: dict) -> None:
        self.stats["packets"] += 1
        if self.arp:
            finding = self.arp.observe(packet)
            if finding:
                self._pending.append(finding)
        if not self.aggregator.add(packet):
            self.stats["dropped_late_or_invalid"] += 1

    def advance(self) -> EngineOutput:
        """Xử lý các cửa sổ đã đóng (theo event time)."""
        return self._process(self.aggregator.pop_closed())

    def flush(self) -> EngineOutput:
        """Đóng mọi cửa sổ đang mở (khi dừng service hoặc lâu không có dữ liệu)."""
        return self._process(self.aggregator.pop_all())

    def _process(self, closed) -> EngineOutput:
        output = EngineOutput()
        candidates: list[Anomaly] = []

        for start, end, host, acc in closed:
            known = self.store.get(KNOWN_DSTS_NAMESPACE, host)
            features = acc.finalize(host, start, end, known, self.aggregator.auth_ports)
            self.store.set(KNOWN_DSTS_NAMESPACE, host, _cap((known or set()) | acc.dst_ips, MAX_KNOWN_DSTS))
            output.features.append(features)

            findings = [finding for detector in self.window_detectors for finding in detector.evaluate(features)]
            if findings:
                candidates += build_anomalies(findings, self.cfg["alerting"], self.window_seconds, features)

        for finding in self._pending:
            candidates += build_anomalies([finding], self.cfg["alerting"], self.window_seconds)
        self._pending.clear()

        for anomaly in candidates:
            if self.suppressor.admit(anomaly):
                output.anomalies.append(anomaly)
            else:
                self.stats["suppressed"] += 1
        self.stats["windows"] += len(output.features)
        self.stats["anomalies"] += len(output.anomalies)
        return output


def _cap(items: set, limit: int) -> set:
    return items if len(items) <= limit else set(list(items)[:limit])
