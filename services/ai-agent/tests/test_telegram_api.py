import asyncio
import json

import httpx
from fastapi.testclient import TestClient

from conftest import FakeLLM, anomaly_of, good_llm_output
from agent.api import create_app
from agent.notifier import TelegramNotifier

ADMIN, STRANGER = 111, 999


class FakeTelegram:
    """Giả lập Bot API: getUpdates trả về các update đã xếp sẵn, ghi lại mọi request."""

    def __init__(self, updates=None):
        self.updates = updates or []
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        method = request.url.path.rsplit("/", 1)[-1]
        params = json.loads(request.content or b"{}")
        self.calls.append((method, params))
        if method == "getUpdates":
            result, self.updates = self.updates, []
        elif method == "sendMessage":
            result = {"message_id": 42, "chat": {"id": params["chat_id"]}}
        else:
            result = True
        return httpx.Response(200, json={"ok": True, "result": result})

    def methods(self, name):
        return [p for m, p in self.calls if m == name]


def notifier_with(fake: FakeTelegram) -> TelegramNotifier:
    return TelegramNotifier("TOKEN", "-100", [str(ADMIN)], http=httpx.AsyncClient(transport=httpx.MockTransport(fake)))


def pending_service(make_service):
    service = make_service(FakeLLM(good_llm_output))
    asyncio.run(service.handle_anomaly(anomaly_of("arp_spoofing")))
    asyncio.run(service.drain())
    return service, service.proposals.find("pending")[0]


def test_proposal_message_has_buttons_and_plain_text(make_service):
    _, proposal = pending_service(make_service)
    fake = FakeTelegram()
    ref = asyncio.run(notifier_with(fake).send_proposal(proposal))
    (msg,) = fake.methods("sendMessage")
    assert ref == {"chat_id": "-100", "message_id": 42} and "parse_mode" not in msg
    buttons = msg["reply_markup"]["inline_keyboard"][0]
    assert [b["callback_data"] for b in buttons] == [f"approve:{proposal.proposal_id}", f"reject:{proposal.proposal_id}"]
    assert "Block MAC de:ad:be:ef:00:01 for 60 min" in msg["text"] and "Facts:" in msg["text"]


def test_only_admins_can_approve(make_service):
    service, proposal = pending_service(make_service)

    def callback(user_id):
        return {"update_id": user_id, "callback_query": {"id": f"q{user_id}", "from": {"id": user_id, "username": "u"},
                                                         "data": f"approve:{proposal.proposal_id}"}}

    fake = FakeTelegram([callback(STRANGER)])
    notifier = notifier_with(fake)
    asyncio.run(notifier.poll_once(service))
    assert proposal.status == "pending"
    assert "not authorized" in fake.methods("answerCallbackQuery")[0]["text"]

    fake.updates = [callback(ADMIN)]
    asyncio.run(notifier.poll_once(service))
    assert proposal.status == "approved" and proposal.decided_by == "telegram:u(111)"
    assert fake.methods("getUpdates")[-1]["offset"] == STRANGER + 1      # không xử lý lại update cũ


def test_commands_require_admin(make_service):
    service, _ = pending_service(make_service)
    fake = FakeTelegram([
        {"update_id": 1, "message": {"text": "/pending", "from": {"id": STRANGER}, "chat": {"id": 5}}},
        {"update_id": 2, "message": {"text": "/pending", "from": {"id": ADMIN}, "chat": {"id": 6}}},
        {"update_id": 3, "message": {"text": "hello", "from": {"id": ADMIN}, "chat": {"id": 6}}},
    ])
    asyncio.run(notifier_with(fake).poll_once(service))
    replies = fake.methods("sendMessage")
    assert replies[0] == {"chat_id": 5, "text": "You are not authorized to use this bot."}
    assert replies[1]["chat_id"] == 6 and "de:ad:be:ef:00:01" in replies[1]["text"]
    assert len(replies) == 2                                               # tin nhắn thường bị bỏ qua


def test_api_requires_token(make_service):
    service, proposal = pending_service(make_service)
    disabled = TestClient(create_app(service, api_token=""))
    assert disabled.post(f"/api/proposals/{proposal.proposal_id}/approve", json={"by": "x"}).status_code == 403

    api = TestClient(create_app(service, api_token="s3cret"))
    assert api.get("/api/proposals?status=pending").json()[0]["proposal_id"] == proposal.proposal_id
    assert api.post(f"/api/proposals/{proposal.proposal_id}/approve", json={"by": "x"},
                    headers={"X-API-Token": "wrong"}).status_code == 401
    ok = api.post(f"/api/proposals/{proposal.proposal_id}/approve", json={"by": "ops"}, headers={"X-API-Token": "s3cret"})
    assert ok.status_code == 200 and ok.json()["status"] == "approved" and ok.json()["decided_by"] == "api:ops"
    assert api.post(f"/api/proposals/{proposal.proposal_id}/reject", json={"by": "ops"},
                    headers={"X-API-Token": "s3cret"}).status_code == 409
    assert api.get("/api/reports/hourly/..%2Fsecret").status_code == 404
