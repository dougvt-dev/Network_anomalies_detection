"""So sánh với baseline của chính thiết bị: z-score so với trung bình trượt EWMA của từng feature.

Không cần train trước — baseline tự học khi chạy. Cảnh báo chỉ bắt đầu sau `min_history` cửa sổ.
"""
import math

from detection.detectors.base import Finding, WindowDetector
from detection.features import HostWindowFeatures
from detection.state import StateStore

NAMESPACE = "baseline"


class BaselineDetector(WindowDetector):
    name = "baseline.zscore"

    def __init__(self, cfg: dict, store: StateStore):
        self.alpha = cfg["alpha"]
        self.min_history = cfg["min_history"]
        self.z_threshold = cfg["z_threshold"]
        self.features: dict[str, dict] = cfg["features"]
        self.store = store

    def evaluate(self, f: HostWindowFeatures) -> list[Finding]:
        findings = []
        for name, fcfg in self.features.items():
            value = float(f.metrics.get(name, 0))
            key = f"{f.host}|{name}"
            state = self.store.get(NAMESPACE, key)       # (mean, var, n)

            if state and state[2] >= self.min_history and value >= fcfg["min_value"]:
                mean, var, _ = state
                std = max(math.sqrt(var), fcfg["min_std"])
                z = (value - mean) / std
                if z >= self.z_threshold:
                    score = round(0.6 + 0.4 * min(1.0, (z - self.z_threshold) / self.z_threshold), 3)
                    findings.append(Finding(
                        self.name, fcfg["category"], score,
                        f"{name} = {value:.0f}, {z:.1f} standard deviations above this device's baseline ({mean:.0f})",
                        {"feature": name, "value": value, "baseline_mean": round(mean, 1),
                         "baseline_std": round(std, 1), "z_score": round(z, 2)},
                    ))

            self.store.set(NAMESPACE, key, self._update(state, value, fcfg["min_std"]))
        return findings

    def _update(self, state, value: float, min_std: float):
        if not state:
            return (value, 0.0, 1)
        mean, var, n = state
        # Cắt giá trị đột biến trước khi học, để một đợt tấn công không kéo baseline lên quá nhanh
        if n >= self.min_history:
            value = min(value, mean + 3 * max(math.sqrt(var), min_std))
        diff = value - mean
        increment = self.alpha * diff
        return (mean + increment, (1 - self.alpha) * (var + diff * increment), n + 1)
