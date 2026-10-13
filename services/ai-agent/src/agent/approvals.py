"""Vòng đời đề xuất: pending → approved → executed/failed, hoặc rejected / expired / superseded.

Không có đường nào để hành động tự thực thi khi người quản trị không trả lời: quá hạn = expired.
"""
import uuid

from agent.schema import EXECUTABLE_ACTIONS, ActionResult, Decision, Proposal

FINAL_STATUSES = {"notified", "executed", "failed", "rejected", "expired", "superseded"}


class ProposalError(Exception):
    pass


class ProposalStore:

    def __init__(self, max_items: int = 5000):
        self.items: dict[str, Proposal] = {}
        self.by_decision: dict[str, str] = {}
        self.max_items = max_items

    def add(self, proposal: Proposal) -> None:
        self.items[proposal.proposal_id] = proposal
        if len(self.items) > self.max_items:                       # bỏ đề xuất cũ nhất đã kết thúc
            for pid, p in list(self.items.items()):
                if p.status in FINAL_STATUSES:
                    del self.items[pid]
                    break

    def get(self, proposal_id: str) -> Proposal:
        proposal = self.items.get(proposal_id)
        if proposal is None:
            raise ProposalError(f"Proposal {proposal_id} not found")
        return proposal

    def find(self, status: str | None = None) -> list[Proposal]:
        items = [p for p in self.items.values() if status is None or p.status == status]
        return sorted(items, key=lambda p: p.created_at, reverse=True)

    def pending_for_incident(self, incident_id: str) -> list[Proposal]:
        return [p for p in self.items.values() if p.incident_id == incident_id and p.status == "pending"]

    def approve(self, proposal_id: str, by: str, now: float, note: str | None = None) -> list[Decision]:
        proposal = self._pending(proposal_id)
        proposal.status, proposal.decided_by, proposal.decided_at, proposal.note = "approved", by, now, note
        decisions = []
        for action in proposal.actions:
            if action.type not in EXECUTABLE_ACTIONS:
                continue
            decision = Decision(
                decision_id=uuid.uuid4().hex[:12], proposal_id=proposal.proposal_id, incident_id=proposal.incident_id,
                sensor_id=proposal.sensor_id, action=action, approved_by=by, approved_at=now,
                reason=proposal.analysis.explanation[:500],
            )
            decisions.append(decision)
            proposal.decision_ids.append(decision.decision_id)
            self.by_decision[decision.decision_id] = proposal.proposal_id
        return decisions

    def reject(self, proposal_id: str, by: str, now: float, note: str | None = None) -> Proposal:
        proposal = self._pending(proposal_id)
        proposal.status, proposal.decided_by, proposal.decided_at, proposal.note = "rejected", by, now, note
        return proposal

    def supersede(self, proposal: Proposal, new_id: str, now: float) -> None:
        proposal.status, proposal.decided_at, proposal.note = "superseded", now, f"Superseded by {new_id}"

    def expire_due(self, now: float) -> list[Proposal]:
        expired = [p for p in self.items.values()
                   if p.status == "pending" and p.expires_at is not None and now >= p.expires_at]
        for p in expired:
            p.status, p.decided_at, p.note = "expired", now, "Not approved in time — no action taken"
        return expired

    def record_result(self, result: ActionResult) -> Proposal | None:
        proposal = self.items.get(self.by_decision.get(result.decision_id, ""))
        if proposal is None:
            return None
        proposal.results.append(result.model_dump())
        if result.status == "failed":
            proposal.status = "failed"
        elif proposal.status == "approved":
            done = {r["decision_id"] for r in proposal.results}
            if set(proposal.decision_ids) <= done:
                proposal.status = "executed"
        return proposal

    def count_block_proposals_since(self, since: float) -> int:
        return sum(1 for p in self.items.values() if p.created_at >= since and p.requires_approval)

    def _pending(self, proposal_id: str) -> Proposal:
        proposal = self.get(proposal_id)
        if proposal.status != "pending":
            raise ProposalError(f"Proposal {proposal_id} is {proposal.status}, not pending")
        return proposal
