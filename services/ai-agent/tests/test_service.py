import asyncio
import time

import pytest

from conftest import Clock, FakeLLM, anomaly_of, good_llm_output, load_anomalies
from agent.approvals import ProposalError


def ingest(service, anomalies):
    async def go():
        for a in anomalies:
            await service.handle_anomaly(a)
        await service.drain()
    asyncio.run(go())


def test_all_scenarios_produce_proposals(make_service):
    service = make_service(FakeLLM(good_llm_output))
    ingest(service, load_anomalies())

    proposals = {p.entity.ip: p for p in service.proposals.find()}
    assert len(proposals) == 7 and len(service.notifier.sent) == 7
    arp = proposals["192.168.1.1"]
    assert arp.priority == "P1" and arp.status == "pending" and arp.expires_at is not None
    assert [(a.type, a.target) for a in arp.actions] == [("alert", None), ("block_mac", "de:ad:be:ef:00:01")]
    # P3 chỉ thông báo, không cần duyệt
    assert proposals["192.168.1.66"].status == "notified" and not proposals["192.168.1.66"].requires_approval
    assert all(p.analysis.analyzed_by == "llm" for p in proposals.values())


def test_analysis_queue_orders_by_priority(make_service):
    order = []

    def recording(user, schema):
        order.append(user.split("Device ")[1].split()[0])
        return good_llm_output(user, schema)

    service = make_service(FakeLLM(recording))
    ingest(service, load_anomalies())
    assert order[0] == "192.168.1.1"                      # P1 (ARP spoofing) được phân tích trước


def test_approve_publishes_decision(make_service):
    service = make_service(FakeLLM(good_llm_output))
    ingest(service, [anomaly_of("arp_spoofing")])
    proposal = service.proposals.find("pending")[0]

    asyncio.run(service.approve(proposal.proposal_id, by="admin"))
    (decision,) = service.producer.decisions()
    assert decision["action"] == {"type": "block_mac", "target": "de:ad:be:ef:00:01", "duration_seconds": 3600}
    assert decision["approved_by"] == "admin" and decision["proposal_id"] == proposal.proposal_id
    assert proposal.status == "approved" and (proposal.proposal_id, "approved") in service.notifier.updates

    with pytest.raises(ProposalError):                    # không duyệt hai lần
        asyncio.run(service.approve(proposal.proposal_id, by="admin"))

    result = {"decision_id": decision["decision_id"], "proposal_id": proposal.proposal_id,
              "status": "executed", "detail": "nft rule added", "executed_at": time.time()}
    asyncio.run(service.handle_action_result(result))
    assert proposal.status == "executed" and proposal.results[0]["detail"] == "nft rule added"


def test_reject_and_expire_never_publish(make_service):
    clock = Clock()
    service = make_service(FakeLLM(good_llm_output), clock=clock)
    first = anomaly_of("arp_spoofing")
    second = anomaly_of("arp_spoofing")
    second["entity"] = {"ip": "192.168.1.2", "mac": "de:ad:be:ef:00:02"}
    ingest(service, [first, second])
    p1, p2 = sorted(service.proposals.find("pending"), key=lambda p: p.entity.ip)

    asyncio.run(service.reject(p1.proposal_id, by="admin", note="false positive"))
    clock.advance(service.approval_timeout + 1)
    asyncio.run(service.tick())
    assert (p1.status, p2.status) == ("rejected", "expired")
    assert service.producer.decisions() == []             # quá hạn = không làm gì


def test_escalation_supersedes_pending_proposal(make_service):
    service = make_service(FakeLLM(good_llm_output))
    sweep = anomaly_of("host_sweep")                       # high → P2, có đề xuất chặn
    ingest(service, [sweep])
    old = service.proposals.find("pending")[0]
    brute = anomaly_of("brute_force")
    brute["entity"] = sweep["entity"]
    ingest(service, [brute])                               # loại mới trên cùng thiết bị → phân tích lại
    new = [p for p in service.proposals.find() if p.proposal_id != old.proposal_id][0]
    assert old.status == "superseded" and new.status == "pending" and new.priority == "P1"
    assert new.categories == ["host_sweep", "brute_force"]


def test_llm_down_still_notifies(make_service):
    service = make_service(llm=None)
    ingest(service, [anomaly_of("dns_tunneling")])
    (proposal,) = service.proposals.find()
    assert proposal.analysis.analyzed_by == "template" and service.notifier.sent


def test_telegram_commands_and_callbacks(make_service):
    service = make_service(FakeLLM(good_llm_output))
    ingest(service, load_anomalies())
    pending = asyncio.run(service.handle_command("telegram:admin(1)", "/pending"))
    assert "de:ad:be:ef:00:01" in pending and "P1" in pending

    proposal = service.proposals.find("pending")[0]
    reply = asyncio.run(service.handle_callback("telegram:admin(1)", f"approve:{proposal.proposal_id}"))
    assert reply.startswith("Approved") and proposal.status == "approved"
    assert "not pending" in asyncio.run(service.handle_callback("telegram:admin(1)", f"reject:{proposal.proposal_id}"))

    status = asyncio.run(service.handle_command("telegram:admin(1)", "/status@NetAgentBot"))
    assert "Anomalies received: 7" in status
    assert "Commands" in asyncio.run(service.handle_command("telegram:admin(1)", "/help"))
