"""Hành động ứng viên theo chính sách (config `policy`) và các giới hạn an toàn (`guardrails`).

Guardrails là luật cứng áp dụng SAU cùng — kể cả đề xuất của LLM cũng không vượt qua được.
"""
from agent.correlation import Incident
from agent.schema import EXECUTABLE_ACTIONS, ProposedAction
from agent.triage import Assets, TriageResult


class PolicyEngine:

    def __init__(self, cfg: dict):
        self.default = cfg["policy"]["default"]
        self.categories = cfg["policy"]["categories"]
        self.block_max_priority = cfg["policy"]["block_max_priority"]
        self.durations = cfg["policy"]["block_duration_seconds"]

    def candidates(self, incident: Incident, triage: TriageResult) -> list[ProposedAction]:
        """Hành động được phép cho sự cố này (LLM chỉ được chọn trong danh sách này)."""
        if triage.verdict == "benign":
            return [ProposedAction(type="alert")]

        allow_block = triage.priority <= self.block_max_priority       # "P1" < "P2" < ...
        actions: dict[tuple, ProposedAction] = {("alert", None): ProposedAction(type="alert")}
        for category in incident.categories_by_time():
            rule = self.categories.get(category, self.default)
            for action_type in rule["actions"]:
                if action_type in EXECUTABLE_ACTIONS:
                    if not allow_block:
                        continue
                    target = self._target(incident, category, rule.get("target", "entity_ip"))
                    action = ProposedAction(type=action_type, target=target,
                                            duration_seconds=self.durations.get(triage.priority))
                    actions.setdefault((action_type, target), action)
        return list(actions.values())

    @staticmethod
    def _target(incident: Incident, category: str, kind: str) -> str | None:
        if kind == "entity_ip":
            return incident.ip
        if kind == "entity_mac":
            return incident.mac
        if kind == "probe_source":
            return incident.categories[category].latest.get("evidence", {}).get("probe_source")
        return None


class Guardrails:

    def __init__(self, cfg: dict, assets: Assets):
        self.max_blocks_per_hour = cfg["guardrails"]["max_block_proposals_per_hour"]
        self.max_block_seconds = cfg["guardrails"]["max_block_seconds"]
        self.assets = assets

    def apply(self, actions: list[ProposedAction], recent_block_proposals: int) -> tuple[list[ProposedAction], list[str]]:
        allowed, notes = [], []
        for action in actions:
            if action.type in EXECUTABLE_ACTIONS:
                if not action.target:
                    notes.append(f"{action.type} removed: no target")
                    continue
                if self.assets.is_protected(action.target):
                    name = (self.assets.describe(action.target) or {}).get("name", "protected asset")
                    notes.append(f"{action.type} {action.target} removed: protected asset ({name})")
                    continue
                if recent_block_proposals >= self.max_blocks_per_hour:
                    notes.append(f"{action.type} {action.target} removed: block proposal limit "
                                 f"({self.max_blocks_per_hour}/hour) reached")
                    continue
                if not action.duration_seconds or action.duration_seconds > self.max_block_seconds:
                    action = action.model_copy(update={"duration_seconds": self.max_block_seconds})
            allowed.append(action)
        if not any(a.type == "alert" for a in allowed):
            allowed.insert(0, ProposedAction(type="alert"))
        return allowed, notes
