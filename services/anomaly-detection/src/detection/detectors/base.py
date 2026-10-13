from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from detection.features import HostWindowFeatures


@dataclass
class Finding:
    """Kết quả của một detector: một dấu hiệu bất thường kèm lý do."""
    detector: str
    category: str
    score: float                      # 0..1
    reason: str                       # câu mô tả cho người vận hành / AI Agent
    details: dict = field(default_factory=dict)
    # Chỉ dùng cho finding không gắn với hồ sơ cửa sổ của thiết bị (vd ARP spoofing)
    entity_ip: str | None = None
    entity_mac: str | None = None
    ts: float | None = None
    sensor_id: str | None = None


class WindowDetector(ABC):
    """Detector chạy trên hồ sơ hành vi của một thiết bị khi cửa sổ đóng."""

    name: str

    @abstractmethod
    def evaluate(self, features: HostWindowFeatures) -> list[Finding]:
        ...


def threshold_score(value: float, threshold: float) -> float:
    """0 nếu dưới ngưỡng; 0.7 khi chạm ngưỡng, tăng tuyến tính tới 1.0 khi gấp 3 lần ngưỡng."""
    if threshold <= 0 or value < threshold:
        return 0.0
    return round(min(1.0, 0.7 + 0.3 * (value / threshold - 1) / 2), 3)
