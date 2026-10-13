"""Report tổng hợp định kỳ: lưu đầy đủ trên server (JSON + Markdown), Telegram chỉ nhận bản tóm tắt khi được hỏi."""
import json
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

HANDLED = {"notified", "approved", "executed", "failed", "rejected"}
JOURNAL_KEEP_SECONDS = 3 * 24 * 3600


@dataclass
class Event:
    ts: float
    kind: str               # anomaly | proposal | proposal_status | action_result
    data: dict = field(default_factory=dict)


class EventJournal:
    """Nhật ký sự kiện trong RAM — nguồn số liệu cho report."""

    def __init__(self):
        self.events: list[Event] = []

    def add(self, kind: str, ts: float | None = None, **data) -> None:
        now = ts if ts is not None else time.time()
        self.events.append(Event(now, kind, data))
        if len(self.events) % 1000 == 0:
            self.events = [e for e in self.events if now - e.ts < JOURNAL_KEEP_SECONDS]

    def between(self, start: float, end: float) -> list[Event]:
        return [e for e in self.events if start <= e.ts < end]


def period_name(kind: str, start: datetime) -> str:
    return start.strftime("%Y-%m-%d_%H") if kind == "hourly" else start.strftime("%Y-%m-%d")


def build_report(kind: str, start: datetime, end: datetime, journal: EventJournal, pending_now: int) -> dict:
    events = journal.between(start.timestamp(), end.timestamp())
    anomalies = [e.data for e in events if e.kind == "anomaly"]
    proposals = [e.data for e in events if e.kind == "proposal"]
    statuses = [e.data for e in events if e.kind == "proposal_status"]
    results = [e.data for e in events if e.kind == "action_result"]
    status_counts = Counter(s["status"] for s in statuses)

    return {
        "schema_version": 1,
        "kind": kind,
        "name": period_name(kind, start),
        "period": {"start": start.isoformat(timespec="minutes"), "end": end.isoformat(timespec="minutes")},
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "counts": {
            "anomalies_checked": len(anomalies),
            "incidents_analyzed": len(proposals),
            "analyzed_by_llm": sum(1 for p in proposals if p["analyzed_by"] == "llm"),
            "handled": sum(n for s, n in status_counts.items() if s in HANDLED),
            "notified_only": status_counts["notified"],
            "approved": status_counts["approved"],
            "rejected": status_counts["rejected"],
            "expired": status_counts["expired"],
            "pending_now": pending_now,
            "actions_executed": sum(1 for r in results if r["status"] in ("executed", "dry_run")),
            "actions_failed": sum(1 for r in results if r["status"] == "failed"),
        },
        "by_category": dict(Counter(a["category"] for a in anomalies).most_common()),
        "by_severity": dict(Counter(a["severity"] for a in anomalies).most_common()),
        "by_priority": dict(sorted(Counter(p["priority"] for p in proposals).items())),
        "top_devices": [{"entity": k, "anomalies": n} for k, n in Counter(a["entity"] for a in anomalies).most_common(5)],
        "notable": [p for p in proposals if p["priority"] in ("P1", "P2")][:20],
    }


def summary_text(report: dict) -> str:
    """Tóm tắt ngắn gửi qua Telegram."""
    c = report["counts"]
    lines = [
        f"📊 {report['kind'].capitalize()} report {report['name']}",
        f"Period: {report['period']['start'].replace('T', ' ')} → {report['period']['end'][11:]}",
        f"Anomalies checked: {c['anomalies_checked']}",
        f"Incidents analyzed: {c['incidents_analyzed']} (LLM: {c['analyzed_by_llm']})",
        f"Handled: {c['handled']} (notified {c['notified_only']}, approved {c['approved']}, rejected {c['rejected']})",
        f"Expired without decision: {c['expired']} · Pending now: {c['pending_now']}",
        f"Actions executed: {c['actions_executed']} · Failed: {c['actions_failed']}",
    ]
    if report["by_priority"]:
        lines.append("By priority: " + ", ".join(f"{k} {v}" for k, v in report["by_priority"].items()))
    if report["by_category"]:
        lines.append("Top categories: " + ", ".join(f"{k} {v}" for k, v in list(report["by_category"].items())[:4]))
    if report["top_devices"]:
        lines.append("Top devices: " + ", ".join(f"{d['entity']} ({d['anomalies']})" for d in report["top_devices"][:3]))
    return "\n".join(lines)


def markdown(report: dict) -> str:
    c = report["counts"]
    out = [f"# {report['kind'].capitalize()} report {report['name']}", "",
           f"Period: {report['period']['start']} → {report['period']['end']}  ",
           f"Generated: {report['generated_at']}", "", "## Summary", "", "| Metric | Value |", "|---|---|"]
    out += [f"| {k.replace('_', ' ')} | {v} |" for k, v in c.items()]
    for title, key in (("By category", "by_category"), ("By severity", "by_severity"), ("By priority", "by_priority")):
        if report[key]:
            out += ["", f"## {title}", "", "| | Count |", "|---|---|"] + [f"| {k} | {v} |" for k, v in report[key].items()]
    if report["top_devices"]:
        out += ["", "## Top devices", "", "| Device | Anomalies |", "|---|---|"]
        out += [f"| {d['entity']} | {d['anomalies']} |" for d in report["top_devices"]]
    if report["notable"]:
        out += ["", "## Notable incidents (P1/P2)", ""]
        for p in report["notable"]:
            out.append(f"- **{p['priority']}** {datetime.fromtimestamp(p['created_at']).strftime('%H:%M')} "
                       f"`{p['entity']}` {', '.join(p['categories'])} — {p['explanation']} (proposal `{p['proposal_id']}`)")
    return "\n".join(out) + "\n"


class ReportStore:
    """Lưu report ra thư mục: {report_dir}/{hourly|daily}/{name}.json + .md"""

    def __init__(self, report_dir: str | Path, keep_days: int = 30):
        self.dir = Path(report_dir)
        self.keep_days = keep_days

    def save(self, report: dict) -> Path:
        folder = self.dir / report["kind"]
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f"{report['name']}.json"
        path.write_text(json.dumps(report, ensure_ascii=False, indent=2))
        (folder / f"{report['name']}.md").write_text(markdown(report))
        self._prune(folder)
        return path

    def names(self, kind: str) -> list[str]:
        folder = self.dir / kind
        return sorted(p.stem for p in folder.glob("*.json")) if folder.exists() else []

    def load(self, kind: str, name: str | None = None) -> dict | None:
        """name=None: bản mới nhất. Tên chỉ chấp nhận ký tự an toàn (không cho đi ra ngoài thư mục)."""
        names = self.names(kind)
        if name is None:
            name = names[-1] if names else None
        if name is None or name not in names:
            return None
        return json.loads((self.dir / kind / f"{name}.json").read_text())

    def _prune(self, folder: Path) -> None:
        cutoff = time.time() - self.keep_days * 86400
        for path in folder.iterdir():
            if path.stat().st_mtime < cutoff:
                path.unlink()


class ReportScheduler:
    """Xác định khi nào đến hạn tạo report giờ / ngày (theo giờ địa phương)."""

    def __init__(self, hourly: bool, daily: bool, now: datetime | None = None):
        now = now or datetime.now()
        self.hourly, self.daily = hourly, daily
        self.last_hour = now.replace(minute=0, second=0, microsecond=0)
        self.last_day = now.replace(hour=0, minute=0, second=0, microsecond=0)

    def due(self, now: datetime) -> list[tuple[str, datetime, datetime]]:
        periods = []
        hour = now.replace(minute=0, second=0, microsecond=0)
        if self.hourly and hour > self.last_hour:
            periods.append(("hourly", hour - timedelta(hours=1), hour))
        self.last_hour = max(self.last_hour, hour)
        day = now.replace(hour=0, minute=0, second=0, microsecond=0)
        if self.daily and day > self.last_day:
            periods.append(("daily", day - timedelta(days=1), day))
        self.last_day = max(self.last_day, day)
        return periods
