import copy
import json
from pathlib import Path

import pytest
import yaml

from agent.analyst import Analyst
from agent.llm import LLMError
from agent.reporting import ReportStore
from agent.service import AgentService

SERVICE_DIR = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures"
T0 = 1_791_500_000.0         # mốc thời gian giả cho test


def load_anomalies() -> list[dict]:
    """7 cảnh báo thật do anomaly-detection sinh từ các kịch bản tấn công (xem README)."""
    return [json.loads(line) for line in (FIXTURES / "anomalies.jsonl").read_text().splitlines() if line.strip()]


def anomaly_of(category: str) -> dict:
    return copy.deepcopy(next(a for a in load_anomalies() if a["category"] == category))


@pytest.fixture(scope="session")
def _cfg() -> dict:
    return yaml.safe_load((SERVICE_DIR / "config" / "agent.yaml").read_text())


@pytest.fixture
def cfg(_cfg) -> dict:
    return copy.deepcopy(_cfg)


class Clock:
    def __init__(self, now: float = T0):
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class FakeLLM:
    """LLM giả: trả về output cấu hình sẵn (dict, hàm, hoặc exception) và ghi lại prompt."""

    model = "fake-model"

    def __init__(self, output=None):
        self.output = output
        self.calls: list[dict] = []

    async def generate_json(self, system, user, schema, schema_name="output"):
        self.calls.append({"system": system, "user": user, "schema": schema})
        out = self.output(user, schema) if callable(self.output) else self.output
        if isinstance(out, Exception):
            raise out
        if out is None:
            raise LLMError("no output configured")
        return out

    async def aclose(self):
        pass


def good_llm_output(user: str, schema: dict) -> dict:
    allowed = schema["properties"]["recommended_actions"]["items"]["enum"]
    return {"explanation": "The device shows behavior consistent with the detected anomaly.",
            "malicious_hypothesis": "An attacker controls the device.",
            "benign_hypothesis": "An authorized tool is running.",
            "recommended_actions": allowed, "action_rationale": "Contain the device."}


class FakeNotifier:
    def __init__(self):
        self.sent: list = []
        self.updates: list = []
        self.texts: list[str] = []

    async def send_proposal(self, proposal):
        self.sent.append(proposal)
        return {"chat_id": 1, "message_id": len(self.sent)}

    async def update_proposal(self, proposal):
        self.updates.append((proposal.proposal_id, proposal.status))

    async def send_text(self, text):
        self.texts.append(text)


class FakeProducer:
    def __init__(self):
        self.messages: list[tuple[str, bytes, bytes]] = []

    def produce(self, topic, value=None, key=None, on_delivery=None):
        self.messages.append((topic, key, value))

    def flush(self, timeout=None):
        return 0

    def decisions(self) -> list[dict]:
        return [json.loads(v) for t, _, v in self.messages if t == "decisions"]


@pytest.fixture
def make_service(cfg, tmp_path):
    def _make(llm=None, use_llm=True, clock=None):
        clock = clock or Clock()
        service = AgentService(cfg, Analyst(llm, use_llm), FakeNotifier(), FakeProducer(), "decisions",
                               ReportStore(tmp_path / "reports"), clock=clock)
        return service
    return _make
