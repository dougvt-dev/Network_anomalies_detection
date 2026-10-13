"""Phân loại sự cố: priority, verdict, độ tin cậy, MITRE. Hoàn toàn xác định (không dùng LLM)."""
from dataclasses import dataclass

from agent.correlation import Incident
from agent.schema import Mitre

PRIORITIES = ("P4", "P3", "P2", "P1")


@dataclass
class TriageResult:
    priority: str
    verdict: str
    confidence: float
    mitre: list[Mitre]
    reasons: list[str]                  # vì sao ra priority này (đưa vào dữ kiện)
    benign_reason: str | None = None


class Assets:
    """Tra cứu tài sản (config `assets`) và hành vi hợp lệ đã biết (`expected_behavior`)."""

    def __init__(self, assets: list[dict], expected: list[dict]):
        self.by_ip = {a["ip"]: a for a in assets if a.get("ip")}
        self.protected = {a[k] for a in assets if a.get("never_block") for k in ("ip", "mac") if a.get(k)}
        self.expected = expected

    def describe(self, ip: str | None) -> dict | None:
        return self.by_ip.get(ip) if ip else None

    def is_critical(self, ip: str | None) -> bool:
        return bool((self.describe(ip) or {}).get("critical"))

    def is_protected(self, target: str | None) -> bool:
        return target in self.protected

    def expected_reason(self, ip: str | None, categories: list[str]) -> str | None:
        for rule in self.expected:
            if rule.get("ip") == ip and set(categories) <= set(rule.get("categories", [])):
                return rule.get("reason", "Expected behavior")
        return None


def related_ips(incident: Incident) -> set[str]:
    """IP của thiết bị và các đích nằm trong bằng chứng (máy bị dò, dịch vụ bị brute force...)."""
    ips = {incident.ip} if incident.ip else set()
    for state in incident.categories.values():
        evidence = state.latest.get("evidence", {})
        for key in ("scan_target", "probe_source"):
            if evidence.get(key):
                ips.add(evidence[key])
        if isinstance(evidence.get("auth_target"), dict) and evidence["auth_target"].get("ip"):
            ips.add(evidence["auth_target"]["ip"])
    return ips


class Triage:

    def __init__(self, cfg: dict, assets: Assets):
        self.high_risk = set(cfg["triage"]["high_risk_categories"])
        self.recurrence = cfg["triage"]["recurrence_threshold"]
        self.mitre_map = cfg["mitre"]
        self.assets = assets

    def assess(self, incident: Incident) -> TriageResult:
        categories = incident.categories_by_time()
        mitre = [Mitre(**self.mitre_map[c]) for c in categories if c in self.mitre_map]

        benign = self.assets.expected_reason(incident.ip, categories)
        if benign:
            return TriageResult("P4", "benign", round(incident.max_score, 2), mitre,
                                [f"matches expected behavior: {benign}"], benign_reason=benign)

        level = incident.max_severity_rank
        reasons = [f"max severity rank {level}"]
        if self.high_risk & set(categories):
            level += 1
            reasons.append(f"high-risk category ({', '.join(sorted(self.high_risk & set(categories)))})")
        critical = sorted(ip for ip in related_ips(incident) if self.assets.is_critical(ip))
        if critical:
            level += 1
            reasons.append(f"involves critical asset ({', '.join(critical)})")
        if len(categories) >= 2:
            level += 1
            reasons.append(f"attack chain of {len(categories)} anomaly types")
        if max(c.max_occurrences for c in incident.categories.values()) >= self.recurrence:
            level += 1
            reasons.append("recurring anomaly")

        priority = PRIORITIES[min(level, 3)]
        confidence = round(min(0.99, incident.max_score + 0.05 * (len(categories) - 1)), 2)
        verdict = "malicious" if confidence >= 0.8 else "suspicious"
        return TriageResult(priority, verdict, confidence, mitre, reasons)
