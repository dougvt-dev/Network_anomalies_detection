"""Schema cảnh báo bất thường (topic anomalies) — đầu vào cho AI Agent."""
from typing import Literal

from pydantic import BaseModel

Severity = Literal["low", "medium", "high", "critical"]


class Entity(BaseModel):
    ip: str | None = None
    mac: str | None = None


class Window(BaseModel):
    start: float
    end: float


class FindingOut(BaseModel):
    detector: str
    score: float
    reason: str
    details: dict = {}


class Anomaly(BaseModel):
    schema_version: int = 1
    anomaly_id: str
    detected_at: float                 # thời điểm phát hiện (giờ hệ thống, epoch giây)
    window: Window                     # cửa sổ dữ liệu (theo ts của gói tin)
    sensor_id: str | None = None
    entity: Entity                     # thiết bị có hành vi bất thường
    category: str                      # port_scan, host_sweep, dos, brute_force, dns_tunneling, dga,
                                       # inbound_scan, arp_spoofing, data_exfiltration, traffic_spike, ...
    severity: Severity
    score: float                       # 0..1
    summary: str                       # lý do chính, một câu
    findings: list[FindingOut]         # các detector cùng chỉ ra bất thường này
    evidence: dict = {}                # số liệu cửa sổ + bối cảnh (đích bị dò, domain, mẫu DNS...)
    occurrences: int = 1               # số lần phát hiện (gồm các lần bị gộp trong thời gian cooldown)
