from conftest import T0, anomaly_of
from agent.correlation import IncidentTracker
from agent.policy import Guardrails, PolicyEngine
from agent.schema import ProposedAction
from agent.triage import Assets, Triage


def setup(cfg):
    assets = Assets(cfg["assets"], cfg.get("expected_behavior") or [])
    return IncidentTracker(1800, 86400), Triage(cfg, assets), PolicyEngine(cfg), Guardrails(cfg, assets)


def test_single_medium_anomaly_is_p3_alert_only(cfg):
    tracker, triage, policy, _ = setup(cfg)
    incident, needs = tracker.add(anomaly_of("port_scan"), T0)
    result = triage.assess(incident)
    assert needs and result.priority == "P3" and result.mitre[0].technique == "T1046"
    assert [a.type for a in policy.candidates(incident, result)] == ["alert"]     # P3: chưa đề xuất chặn


def test_attack_chain_raises_priority_and_allows_block(cfg):
    tracker, triage, policy, _ = setup(cfg)
    scan = anomaly_of("port_scan")
    brute = anomaly_of("brute_force")
    brute["entity"] = scan["entity"]                       # cùng một thiết bị
    tracker.add(scan, T0)
    incident, needs = tracker.add(brute, T0 + 600)
    result = triage.assess(incident)
    assert needs and result.priority == "P2" and any("attack chain" in r for r in result.reasons)
    actions = policy.candidates(incident, result)
    assert ProposedAction(type="block_ip", target="192.168.1.66", duration_seconds=1800) in actions

    _, needs_again = tracker.add(brute, T0 + 700)          # cùng loại, cùng mức độ: không phân tích lại
    incident.analyzed_signature = incident.signature()
    _, needs_again = tracker.add(brute, T0 + 800)
    assert not needs_again


def test_targets_per_category(cfg):
    tracker, triage, policy, _ = setup(cfg)
    arp, _ = tracker.add(anomaly_of("arp_spoofing"), T0)
    arp_triage = triage.assess(arp)
    assert arp_triage.priority == "P1"                      # critical + loại nguy hiểm + tài sản quan trọng (gateway)
    assert ProposedAction(type="block_mac", target="de:ad:be:ef:00:01", duration_seconds=3600) in policy.candidates(arp, arp_triage)

    inbound = anomaly_of("inbound_scan")
    inbound["severity"] = "high"
    incident, _ = tracker.add(inbound, T0)
    targets = {a.target for a in policy.candidates(incident, triage.assess(incident)) if a.type == "block_ip"}
    assert targets == {"203.0.113.50"}                     # chặn IP bên ngoài, không chặn nạn nhân


def test_expected_behavior_is_benign(cfg):
    cfg["expected_behavior"] = [{"ip": "192.168.1.66", "categories": ["port_scan"], "reason": "Authorized scanner"}]
    tracker, triage, policy, _ = setup(cfg)
    incident, _ = tracker.add(anomaly_of("port_scan"), T0)
    result = triage.assess(incident)
    assert (result.verdict, result.priority, result.benign_reason) == ("benign", "P4", "Authorized scanner")
    assert [a.type for a in policy.candidates(incident, result)] == ["alert"]


def test_guardrails(cfg):
    *_, guardrails = setup(cfg)
    actions = [ProposedAction(type="block_ip", target="192.168.1.1", duration_seconds=600),      # gateway
               ProposedAction(type="block_ip", target="192.168.1.66", duration_seconds=999_999),
               ProposedAction(type="block_mac", target=None)]
    allowed, notes = guardrails.apply(actions, recent_block_proposals=0)
    assert [(a.type, a.target) for a in allowed] == [("alert", None), ("block_ip", "192.168.1.66")]
    assert allowed[1].duration_seconds == cfg["guardrails"]["max_block_seconds"]
    assert any("protected asset (gateway)" in n for n in notes) and any("no target" in n for n in notes)

    allowed, notes = guardrails.apply(actions[1:2], recent_block_proposals=cfg["guardrails"]["max_block_proposals_per_hour"])
    assert [a.type for a in allowed] == ["alert"] and "limit" in notes[0]


def test_idle_incident_closes_and_becomes_history(cfg):
    tracker, *_ = setup(cfg)
    first, _ = tracker.add(anomaly_of("dga"), T0)
    assert tracker.close_idle(T0 + 1800) == [first]
    second, needs = tracker.add(anomaly_of("dga"), T0 + 2000)
    assert needs and second.incident_id != first.incident_id
    assert tracker.history(second.entity_key, exclude_id=second.incident_id) == [first]
