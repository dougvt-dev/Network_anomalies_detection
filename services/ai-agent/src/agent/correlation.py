"""Gộp cảnh báo thành sự cố theo thiết bị (bộ nhớ ngắn hạn, trong RAM)."""
import uuid
from dataclasses import dataclass, field

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
MAX_ANOMALIES_PER_INCIDENT = 50


@dataclass
class CategoryState:
    first_seen: float
    count: int = 0
    max_severity_rank: int = 0
    max_score: float = 0.0
    max_occurrences: int = 1
    latest: dict = field(default_factory=dict)      # cảnh báo mới nhất của loại này


@dataclass
class Incident:
    incident_id: str
    entity_key: str
    ip: str | None
    mac: str | None
    sensor_id: str | None
    opened_at: float
    last_seen: float
    categories: dict[str, CategoryState] = field(default_factory=dict)
    anomaly_ids: list[str] = field(default_factory=list)
    status: str = "open"
    analyzed_signature: tuple | None = None          # trạng thái tại lần phân tích gần nhất

    @property
    def max_severity_rank(self) -> int:
        return max((c.max_severity_rank for c in self.categories.values()), default=0)

    @property
    def max_score(self) -> float:
        return max((c.max_score for c in self.categories.values()), default=0.0)

    def signature(self) -> tuple:
        """Đổi khi có loại bất thường mới hoặc mức độ tăng — khi đó cần phân tích lại."""
        return tuple(sorted(self.categories)), self.max_severity_rank

    def categories_by_time(self) -> list[str]:
        return sorted(self.categories, key=lambda c: self.categories[c].first_seen)


class IncidentTracker:

    def __init__(self, idle_close_seconds: float, history_seconds: float):
        self.idle_close = idle_close_seconds
        self.history_seconds = history_seconds
        self.open: dict[str, Incident] = {}             # entity_key -> sự cố đang mở
        self.closed: list[Incident] = []
        self.by_id: dict[str, Incident] = {}

    def add(self, anomaly: dict, now: float) -> tuple[Incident, bool]:
        """Thêm cảnh báo. Trả về (sự cố, cần_phân_tích)."""
        entity = anomaly.get("entity") or {}
        key = entity.get("ip") or entity.get("mac") or "unknown"
        incident = self.open.get(key)
        if incident is None:
            incident = Incident(
                incident_id=uuid.uuid4().hex[:12], entity_key=key, ip=entity.get("ip"), mac=entity.get("mac"),
                sensor_id=anomaly.get("sensor_id"), opened_at=now, last_seen=now,
            )
            self.open[key] = incident
            self.by_id[incident.incident_id] = incident

        incident.last_seen = now
        incident.mac = incident.mac or entity.get("mac")
        incident.sensor_id = anomaly.get("sensor_id") or incident.sensor_id
        if len(incident.anomaly_ids) < MAX_ANOMALIES_PER_INCIDENT:
            incident.anomaly_ids.append(anomaly.get("anomaly_id", ""))

        category = anomaly.get("category", "unknown")
        state = incident.categories.get(category)
        if state is None:
            state = incident.categories[category] = CategoryState(first_seen=now)
        state.count += 1
        state.max_severity_rank = max(state.max_severity_rank, SEVERITY_RANK.get(anomaly.get("severity"), 0))
        state.max_score = max(state.max_score, float(anomaly.get("score", 0)))
        state.max_occurrences = max(state.max_occurrences, int(anomaly.get("occurrences", 1)))
        state.latest = anomaly

        return incident, incident.signature() != incident.analyzed_signature

    def close_idle(self, now: float) -> list[Incident]:
        closing = [i for i in self.open.values() if now - i.last_seen >= self.idle_close]
        for incident in closing:
            incident.status = "closed"
            del self.open[incident.entity_key]
            self.closed.append(incident)
        # Bỏ sự cố đã đóng quá lâu
        keep = []
        for incident in self.closed:
            if now - incident.last_seen < self.history_seconds:
                keep.append(incident)
            else:
                self.by_id.pop(incident.incident_id, None)
        self.closed = keep
        return closing

    def history(self, entity_key: str, exclude_id: str | None = None) -> list[Incident]:
        """Sự cố trước đây của cùng thiết bị (đã đóng, còn trong history_seconds)."""
        return [i for i in self.closed if i.entity_key == entity_key and i.incident_id != exclude_id]
