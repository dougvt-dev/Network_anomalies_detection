import asyncio
from datetime import datetime, timedelta

from conftest import Clock, FakeLLM, good_llm_output, load_anomalies
from agent.reporting import ReportScheduler


def test_scheduler_due_periods():
    start = datetime(2026, 10, 13, 9, 30)
    scheduler = ReportScheduler(hourly=True, daily=True, now=start)
    assert scheduler.due(start + timedelta(minutes=20)) == []
    assert scheduler.due(datetime(2026, 10, 13, 10, 0, 5)) == [
        ("hourly", datetime(2026, 10, 13, 9), datetime(2026, 10, 13, 10))]
    due = scheduler.due(datetime(2026, 10, 14, 0, 0, 10))
    assert ("daily", datetime(2026, 10, 13), datetime(2026, 10, 14)) in due


def test_hourly_report_saved_and_summarized(make_service):
    start = datetime(2026, 10, 13, 14, 5)
    clock = Clock(start.timestamp())
    service = make_service(FakeLLM(good_llm_output), clock=clock)

    async def scenario():
        for a in load_anomalies():
            await service.handle_anomaly(a)
        await service.drain()
        pending = service.proposals.find("pending")
        await service.approve(pending[0].proposal_id, by="admin")
        await service.reject(pending[1].proposal_id, by="admin")
        clock.now = datetime(2026, 10, 13, 15, 0, 30).timestamp()
        await service.tick()

    asyncio.run(scenario())
    assert service.reports.names("hourly") == ["2026-10-13_14"]
    report = service.reports.load("hourly")
    c = report["counts"]
    assert c["anomalies_checked"] == 7 and c["incidents_analyzed"] == 7 and c["analyzed_by_llm"] == 7
    assert c["approved"] == 1 and c["rejected"] == 1 and c["handled"] == c["notified_only"] + 2
    assert report["by_priority"]["P1"] >= 1 and report["notable"]
    assert (service.reports.dir / "hourly" / "2026-10-13_14.md").read_text().startswith("# Hourly report")

    summary = asyncio.run(service.handle_command("telegram:admin(1)", "/report"))
    assert "Anomalies checked: 7" in summary and "Handled:" in summary and len(summary) < 1000
    assert "Anomalies checked: 7" in asyncio.run(service.handle_command("u", "/report 2026-10-13_14"))
    assert "No saved report" in asyncio.run(service.handle_command("u", "/report daily"))
    assert "Usage" in asyncio.run(service.handle_command("u", "/report ../../etc/passwd"))
    assert "last 60 min" in asyncio.run(service.handle_command("u", "/report now"))
