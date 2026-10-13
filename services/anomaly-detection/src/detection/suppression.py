"""Chống spam cảnh báo: cùng thiết bị + cùng loại trong thời gian cooldown thì gộp lại.

Mỗi cảnh báo gửi đi tốn một lượt suy luận của AI Agent (LLM), nên không gửi lặp mỗi cửa sổ.
Vẫn gửi ngay nếu mức độ nghiêm trọng tăng lên. Thời gian tính theo event time (cửa sổ dữ liệu).
"""
from dataclasses import dataclass

from detection.schema import Anomaly
from detection.scoring import SEVERITY_ORDER

MAX_KEYS = 100_000


@dataclass
class _Emitted:
    at: float              # window.end của lần gửi gần nhất
    severity_rank: int
    suppressed: int = 0    # số lần bị gộp kể từ lần gửi gần nhất


class Suppressor:

    def __init__(self, cooldown_seconds: float):
        self.cooldown = cooldown_seconds
        self._last: dict[tuple, _Emitted] = {}

    def admit(self, anomaly: Anomaly) -> bool:
        key = (anomaly.entity.ip or anomaly.entity.mac, anomaly.category)
        now = anomaly.window.end
        rank = SEVERITY_ORDER.index(anomaly.severity)
        last = self._last.get(key)

        if last and now - last.at < self.cooldown and rank <= last.severity_rank:
            last.suppressed += 1
            return False

        anomaly.occurrences = 1 + (last.suppressed if last else 0)
        self._last[key] = _Emitted(at=now, severity_rank=rank)
        if len(self._last) > MAX_KEYS:
            self._prune(now)
        return True

    def _prune(self, now: float) -> None:
        self._last = {k: v for k, v in self._last.items() if now - v.at < self.cooldown}
