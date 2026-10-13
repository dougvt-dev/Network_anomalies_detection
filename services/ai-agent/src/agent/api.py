"""REST API: xem / duyệt đề xuất, xem report. Kênh duyệt dự phòng (và cho Web UI sau này).

Các API thay đổi trạng thái cần header X-API-Token; nếu API_TOKEN chưa cấu hình thì các API đó bị tắt.
"""
import hmac

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from agent.approvals import ProposalError
from agent.reporting import summary_text
from agent.service import REPORT_NAME, AgentService


class DecisionRequest(BaseModel):
    by: str
    note: str | None = None


def create_app(service: AgentService, api_token: str) -> FastAPI:
    app = FastAPI(title="AI Agent", version="1.0.0")

    def require_token(token: str | None) -> None:
        if not api_token:
            raise HTTPException(403, "API_TOKEN is not configured: approval via API is disabled")
        if not token or not hmac.compare_digest(token, api_token):
            raise HTTPException(401, "Invalid API token")

    @app.get("/health")
    async def health():
        return {"status": "ok", "service": "ai-agent", "pending": len(service.proposals.find("pending")),
                "analysis_queue": service.queue.qsize()}

    @app.get("/api/proposals")
    async def list_proposals(status: str | None = None, limit: int = 50):
        return [p.model_dump() for p in service.proposals.find(status)[:limit]]

    @app.get("/api/proposals/{proposal_id}")
    async def get_proposal(proposal_id: str):
        try:
            return service.proposals.get(proposal_id).model_dump()
        except ProposalError as e:
            raise HTTPException(404, str(e))

    @app.post("/api/proposals/{proposal_id}/approve")
    async def approve(proposal_id: str, req: DecisionRequest, x_api_token: str | None = Header(default=None)):
        require_token(x_api_token)
        try:
            return (await service.approve(proposal_id, by=f"api:{req.by}", note=req.note)).model_dump()
        except ProposalError as e:
            raise HTTPException(409, str(e))

    @app.post("/api/proposals/{proposal_id}/reject")
    async def reject(proposal_id: str, req: DecisionRequest, x_api_token: str | None = Header(default=None)):
        require_token(x_api_token)
        try:
            return (await service.reject(proposal_id, by=f"api:{req.by}", note=req.note)).model_dump()
        except ProposalError as e:
            raise HTTPException(409, str(e))

    @app.get("/api/reports/{kind}")
    async def list_reports(kind: str):
        if kind not in ("hourly", "daily"):
            raise HTTPException(404, "kind must be hourly or daily")
        return service.reports.names(kind)

    @app.get("/api/reports/{kind}/{name}")
    async def get_report(kind: str, name: str, summary: bool = False):
        if kind not in ("hourly", "daily") or not (name == "latest" or REPORT_NAME.match(name)):
            raise HTTPException(404, "Report not found")
        report = service.reports.load(kind, None if name == "latest" else name)
        if report is None:
            raise HTTPException(404, "Report not found")
        return {"summary": summary_text(report)} if summary else report

    return app
