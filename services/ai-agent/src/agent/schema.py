"""Định dạng dữ liệu của ai-agent: đề xuất (Proposal), quyết định gửi action-service (Decision), kết quả (ActionResult)."""
from typing import Literal

from pydantic import BaseModel, Field

Priority = Literal["P1", "P2", "P3", "P4"]
Verdict = Literal["malicious", "suspicious", "benign"]
ActionType = Literal["alert", "block_ip", "block_mac"]
EXECUTABLE_ACTIONS = ("block_ip", "block_mac")     # cần người duyệt, do action-service thực thi

# pending    : chờ người quản trị duyệt
# notified   : chỉ thông báo (không có hành động cần duyệt)
# approved   : đã duyệt, đã gửi lệnh cho action-service
# executed / failed : action-service báo kết quả
# rejected / expired / superseded (bị thay bởi đề xuất mới hơn của cùng sự cố)
ProposalStatus = Literal["pending", "notified", "approved", "executed", "failed", "rejected", "expired", "superseded"]


class Entity(BaseModel):
    ip: str | None = None
    mac: str | None = None


class Mitre(BaseModel):
    tactic: str
    technique: str
    name: str


class ProposedAction(BaseModel):
    type: ActionType
    target: str | None = None
    duration_seconds: int | None = None


class Analysis(BaseModel):
    explanation: str
    malicious_hypothesis: str = ""
    benign_hypothesis: str = ""
    action_rationale: str = ""
    recommended_actions: list[str] = []
    analyzed_by: Literal["llm", "template"]
    model: str | None = None
    note: str | None = None             # vd lý do LLM bị loại và phải dùng mẫu văn bản


class Proposal(BaseModel):
    proposal_id: str
    incident_id: str
    created_at: float
    expires_at: float | None = None
    sensor_id: str | None = None
    entity: Entity
    categories: list[str]
    anomaly_ids: list[str]
    priority: Priority
    verdict: Verdict
    confidence: float
    mitre: list[Mitre]
    facts: list[str]                    # dữ kiện do hệ thống tạo — nguồn tin cậy, không qua LLM
    analysis: Analysis
    actions: list[ProposedAction]
    guardrail_notes: list[str] = []
    status: ProposalStatus
    decided_by: str | None = None
    decided_at: float | None = None
    note: str | None = None
    decision_ids: list[str] = []
    results: list[dict] = []
    notification_ref: dict | None = Field(default=None, exclude=True)

    @property
    def requires_approval(self) -> bool:
        return any(a.type in EXECUTABLE_ACTIONS for a in self.actions)


class Decision(BaseModel):
    """Lệnh đã được duyệt — topic decisions, action-service thực thi."""
    schema_version: int = 1
    decision_id: str
    proposal_id: str
    incident_id: str
    sensor_id: str | None = None        # gateway nào thực thi
    action: ProposedAction
    approved_by: str
    approved_at: float
    reason: str


class ActionResult(BaseModel):
    """Kết quả thực thi — topic action_results, do action-service gửi về."""
    schema_version: int = 1
    decision_id: str
    proposal_id: str
    status: Literal["executed", "dry_run", "failed", "reverted"]
    detail: str = ""
    executed_at: float
    sensor_id: str | None = None
