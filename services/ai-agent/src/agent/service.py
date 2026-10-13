"""AgentService: cảnh báo → sự cố → triage → phân tích → đề xuất → xin duyệt → quyết định → kết quả.

Không phụ thuộc Kafka/HTTP trực tiếp: producer, notifier, LLM được truyền vào (dễ test, dễ thay).
"""
import asyncio
import itertools
import json
import logging
import re
import time
import uuid
from collections import Counter
from datetime import datetime

from agent.analyst import Analyst, build_facts
from agent.approvals import ProposalError, ProposalStore
from agent.correlation import IncidentTracker
from agent.notifier.formatting import describe_action
from agent.policy import Guardrails, PolicyEngine
from agent.reporting import EventJournal, ReportScheduler, ReportStore, build_report, summary_text
from agent.schema import ActionResult, Decision, Entity, Proposal
from agent.triage import Assets, Triage

logger = logging.getLogger(__name__)

PRIORITY_ORDER = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
REPORT_NAME = re.compile(r"^\d{4}-\d{2}-\d{2}(_\d{2})?$")
HELP = ("Commands:\n/pending — proposals waiting for approval\n/report — latest hourly report summary\n"
        "/report daily — latest daily report\n/report now — summary of the last 60 minutes\n"
        "/report 2026-10-13 or 2026-10-13_14 — a specific report\n/status — agent status")


class AgentService:

    def __init__(self, cfg: dict, analyst: Analyst, notifier, producer, decision_topic: str,
                 report_store: ReportStore, clock=time.time):
        self.cfg = cfg
        self.analyst = analyst
        self.notifier = notifier
        self.producer = producer
        self.decision_topic = decision_topic
        self.clock = clock

        self.assets = Assets(cfg.get("assets") or [], cfg.get("expected_behavior") or [])
        self.tracker = IncidentTracker(cfg["incident"]["idle_close_seconds"], cfg["incident"]["history_seconds"])
        self.triage = Triage(cfg, self.assets)
        self.policy = PolicyEngine(cfg)
        self.guardrails = Guardrails(cfg, self.assets)
        self.proposals = ProposalStore()
        self.journal = EventJournal()
        self.reports = report_store
        self.scheduler = ReportScheduler(cfg["reports"]["hourly"], cfg["reports"]["daily"],
                                         datetime.fromtimestamp(clock()))
        self.approval_timeout = cfg["approval"]["timeout_seconds"]

        self.queue: asyncio.PriorityQueue = asyncio.PriorityQueue(maxsize=cfg["analysis"]["queue_size"])
        self._queued: set[str] = set()
        self._seq = itertools.count()
        self.stats = Counter()

    # ---------- đầu vào ----------

    async def handle_anomaly(self, anomaly: dict) -> None:
        if not isinstance(anomaly, dict) or not anomaly.get("category") or not isinstance(anomaly.get("entity"), dict):
            self.stats["invalid_anomalies"] += 1
            return
        now = self.clock()
        self.stats["anomalies"] += 1
        entity = anomaly["entity"].get("ip") or anomaly["entity"].get("mac")
        self.journal.add("anomaly", now, category=anomaly["category"], severity=anomaly.get("severity"), entity=entity)

        incident, needs_analysis = self.tracker.add(anomaly, now)
        if needs_analysis and incident.incident_id not in self._queued:
            rank = PRIORITY_ORDER[self.triage.assess(incident).priority]
            try:
                self.queue.put_nowait((rank, next(self._seq), incident.incident_id))
                self._queued.add(incident.incident_id)
            except asyncio.QueueFull:
                self.stats["analysis_queue_full"] += 1
                logger.warning(f"Analysis queue full, incident {incident.incident_id} skipped")

    async def handle_action_result(self, doc: dict) -> None:
        try:
            result = ActionResult.model_validate(doc)
        except ValueError:
            self.stats["invalid_results"] += 1
            return
        self.journal.add("action_result", self.clock(), status=result.status)
        proposal = self.proposals.record_result(result)
        if proposal:
            self._journal_status(proposal)
            await self._safe_update(proposal)

    # ---------- phân tích ----------

    async def analysis_worker(self) -> None:
        while True:
            _, _, incident_id = await self.queue.get()
            try:
                await self.process_incident(incident_id)
            except Exception:
                logger.exception(f"Failed to process incident {incident_id}")
            finally:
                self.queue.task_done()

    async def drain(self) -> None:
        """Xử lý hết hàng đợi (dùng trong test / công cụ offline)."""
        while not self.queue.empty():
            _, _, incident_id = self.queue.get_nowait()
            await self.process_incident(incident_id)

    async def process_incident(self, incident_id: str) -> Proposal | None:
        self._queued.discard(incident_id)
        incident = self.tracker.by_id.get(incident_id)
        if incident is None:
            return None
        incident.analyzed_signature = incident.signature()

        triage = self.triage.assess(incident)
        history = self.tracker.history(incident.entity_key, exclude_id=incident.incident_id)
        facts = build_facts(incident, triage, history, self.assets.describe(incident.ip))
        facts += [f"Priority {triage.priority} because: {'; '.join(triage.reasons)}"]
        candidates = self.policy.candidates(incident, triage)

        analysis = await self.analyst.analyze(incident, triage, facts, candidates)
        self.stats[f"analyzed_by_{analysis.analyzed_by}"] += 1
        chosen = [a for a in candidates if a.type in set(analysis.recommended_actions) | {"alert"}]
        now = self.clock()
        actions, notes = self.guardrails.apply(chosen, self.proposals.count_block_proposals_since(now - 3600))

        proposal = Proposal(
            proposal_id=uuid.uuid4().hex[:8], incident_id=incident.incident_id, created_at=now,
            sensor_id=incident.sensor_id, entity=Entity(ip=incident.ip, mac=incident.mac),
            categories=incident.categories_by_time(), anomaly_ids=list(incident.anomaly_ids),
            priority=triage.priority, verdict=triage.verdict, confidence=triage.confidence, mitre=triage.mitre,
            facts=facts, analysis=analysis, actions=actions, guardrail_notes=notes, status="pending",
        )
        if proposal.requires_approval:
            proposal.expires_at = now + self.approval_timeout
        else:
            proposal.status = "notified"

        for old in self.proposals.pending_for_incident(incident.incident_id):
            self.proposals.supersede(old, proposal.proposal_id, now)
            self._journal_status(old)
            await self._safe_update(old)

        self.proposals.add(proposal)
        self.stats["proposals"] += 1
        self.journal.add("proposal", now, proposal_id=proposal.proposal_id, priority=proposal.priority,
                         analyzed_by=analysis.analyzed_by, created_at=now, entity=incident.entity_key,
                         categories=proposal.categories, explanation=analysis.explanation[:300])
        if proposal.status == "notified":
            self._journal_status(proposal)

        try:
            proposal.notification_ref = await self.notifier.send_proposal(proposal)
        except Exception as e:
            self.stats["notify_errors"] += 1
            logger.error(f"Failed to send proposal {proposal.proposal_id}: {e}")
        return proposal

    # ---------- duyệt ----------

    async def approve(self, proposal_id: str, by: str, note: str | None = None) -> Proposal:
        decisions = self.proposals.approve(proposal_id, by, self.clock(), note)
        proposal = self.proposals.get(proposal_id)
        await self._publish(decisions)
        self._journal_status(proposal)
        await self._safe_update(proposal)
        logger.info(f"Proposal {proposal_id} approved by {by}: {[d.action.type for d in decisions]}")
        return proposal

    async def reject(self, proposal_id: str, by: str, note: str | None = None) -> Proposal:
        proposal = self.proposals.reject(proposal_id, by, self.clock(), note)
        self._journal_status(proposal)
        await self._safe_update(proposal)
        logger.info(f"Proposal {proposal_id} rejected by {by}")
        return proposal

    async def _publish(self, decisions: list[Decision]) -> None:
        for d in decisions:
            self.producer.produce(self.decision_topic, key=(d.sensor_id or "").encode(),
                                  value=d.model_dump_json().encode())
        if decisions:
            remaining = await asyncio.to_thread(self.producer.flush, 10)
            if remaining:
                logger.error(f"{remaining} decisions not delivered to Kafka")

    # ---------- định kỳ ----------

    async def tick(self) -> None:
        now = self.clock()
        for proposal in self.proposals.expire_due(now):
            self._journal_status(proposal)
            await self._safe_update(proposal)
        self.tracker.close_idle(now)
        for kind, start, end in self.scheduler.due(datetime.fromtimestamp(now)):
            report = build_report(kind, start, end, self.journal, len(self.proposals.find("pending")))
            path = self.reports.save(report)
            logger.info(f"Saved {kind} report {path}")

    async def tick_loop(self, interval: float = 15.0) -> None:
        while True:
            try:
                await self.tick()
            except Exception:
                logger.exception("Periodic tick failed")
            await asyncio.sleep(interval)

    # ---------- Telegram ----------

    async def handle_callback(self, user: str, data: str) -> str:
        action, _, proposal_id = data.partition(":")
        try:
            if action == "approve":
                await self.approve(proposal_id, by=user)
                return "Approved — sent for execution."
            if action == "reject":
                await self.reject(proposal_id, by=user)
                return "Rejected."
        except ProposalError as e:
            return str(e)
        return "Unknown action."

    async def handle_command(self, user: str, text: str) -> str:
        command, *args = text.split()
        command = command.split("@")[0].lower()           # /report@MyBot trong group
        if command == "/pending":
            pending = self.proposals.find("pending")
            if not pending:
                return "No proposals waiting for approval."
            return "\n".join(f"{p.priority} {p.proposal_id} {p.entity.ip or p.entity.mac} {', '.join(p.categories)}: "
                             f"{'; '.join(describe_action(a) for a in p.actions if a.type != 'alert')}"
                             for p in pending[:20])
        if command == "/report":
            return self._report_command(args[0] if args else "")
        if command == "/status":
            s = self.stats
            return (f"Anomalies received: {s['anomalies']}\nOpen incidents: {len(self.tracker.open)}\n"
                    f"Analysis queue: {self.queue.qsize()}\nProposals: {s['proposals']} "
                    f"(LLM {s['analyzed_by_llm']}, template {s['analyzed_by_template']})\n"
                    f"Pending approval: {len(self.proposals.find('pending'))}")
        return HELP

    def _report_command(self, arg: str) -> str:
        arg = arg.lower()
        if arg == "now":
            end = datetime.fromtimestamp(self.clock())
            start = datetime.fromtimestamp(self.clock() - 3600)
            report = build_report("live", start, end, self.journal, len(self.proposals.find("pending")))
            report["name"] = "last 60 min"
            return summary_text(report)
        if arg in ("", "hourly", "daily"):
            report = self.reports.load(arg or "hourly")
        elif REPORT_NAME.match(arg):
            report = self.reports.load("hourly" if "_" in arg else "daily", arg)
        else:
            return "Usage: /report [hourly|daily|now|YYYY-MM-DD|YYYY-MM-DD_HH]"
        if report is None:
            return "No saved report found. Use /report now for the last 60 minutes."
        return summary_text(report)

    # ---------- tiện ích ----------

    def _journal_status(self, proposal: Proposal) -> None:
        self.journal.add("proposal_status", self.clock(), proposal_id=proposal.proposal_id, status=proposal.status)

    async def _safe_update(self, proposal: Proposal) -> None:
        try:
            await self.notifier.update_proposal(proposal)
        except Exception as e:
            self.stats["notify_errors"] += 1
            logger.warning(f"Failed to update notification for {proposal.proposal_id}: {e}")


def parse_message(value: bytes) -> dict | None:
    try:
        doc = json.loads(value)
    except ValueError:
        return None
    return doc if isinstance(doc, dict) else None
