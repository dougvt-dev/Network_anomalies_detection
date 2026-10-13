"""Nội dung thông báo dạng văn bản thuần (không markdown/HTML: dữ liệu từ traffic không thể chèn định dạng)."""
from datetime import datetime

from agent.schema import Proposal

PRIORITY_ICON = {"P1": "🔴", "P2": "🟠", "P3": "🟡", "P4": "⚪"}
STATUS_LINE = {
    "pending": "⏳ Waiting for approval",
    "notified": "ℹ️ Notification only — no action requires approval",
    "approved": "✅ Approved by {by} — sent for execution",
    "executed": "✅ Executed (approved by {by})",
    "failed": "⚠️ Execution failed (approved by {by})",
    "rejected": "❌ Rejected by {by}",
    "expired": "⌛ Expired — not approved in time, no action taken",
    "superseded": "↪️ {note}",
}
MAX_MESSAGE = 3900          # Telegram giới hạn 4096 ký tự


def _hm(ts: float | None) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M %d/%m") if ts else "-"


def describe_action(action) -> str:
    if action.type == "alert":
        return "Notify administrator"
    minutes = f" for {action.duration_seconds // 60} min" if action.duration_seconds else ""
    what = "IP" if action.type == "block_ip" else "MAC"
    return f"Block {what} {action.target}{minutes}"


def proposal_text(p: Proposal) -> str:
    who = p.entity.ip or p.entity.mac
    title = f"{PRIORITY_ICON.get(p.priority, '')} [{p.priority}] {', '.join(p.categories)} — {who}"
    lines = [title, f"Proposal {p.proposal_id} · {_hm(p.created_at)} · verdict {p.verdict} · confidence {p.confidence}", ""]
    lines += ["Facts:"] + [f"• {f.strip()}" for f in p.facts]
    lines += ["", f"Analysis ({p.analysis.analyzed_by}{', ' + p.analysis.model if p.analysis.model else ''}):",
              p.analysis.explanation]
    if p.analysis.malicious_hypothesis:
        lines.append(f"If malicious: {p.analysis.malicious_hypothesis}")
    if p.analysis.benign_hypothesis:
        lines.append(f"If benign: {p.analysis.benign_hypothesis}")
    lines += ["", "Proposed actions:"] + [f"{i}. {describe_action(a)}" for i, a in enumerate(p.actions, 1)]
    if p.guardrail_notes:
        lines += ["Guardrails:"] + [f"• {n}" for n in p.guardrail_notes]
    if p.status == "pending" and p.expires_at:
        lines.append(f"Expires at {_hm(p.expires_at)} if not approved.")
    lines += ["", STATUS_LINE[p.status].format(by=p.decided_by or "-", note=p.note or "")]
    for r in p.results:
        lines.append(f"• {r['status']}: {r.get('detail', '')}")
    text = "\n".join(lines)
    return text if len(text) <= MAX_MESSAGE else text[:MAX_MESSAGE] + "\n…(truncated)"
