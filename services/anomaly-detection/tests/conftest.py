import copy
import gzip
import json
from pathlib import Path

import pytest

from detection.engine import load_detection_config

SERVICE_DIR = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures"
BASE_TS = 1_700_000_040.0     # đầu một cửa sổ 60s


@pytest.fixture(scope="session")
def _default_cfg() -> dict:
    return load_detection_config(SERVICE_DIR / "config" / "detection.yaml")


@pytest.fixture
def cfg(_default_cfg) -> dict:
    """Bản sao cấu hình mặc định, test được phép sửa."""
    return copy.deepcopy(_default_cfg)


def load_normalized_fixture(name: str = "attack_scenarios.normalized.jsonl.gz") -> list[dict]:
    with gzip.open(FIXTURES / name, "rt") as f:
        return [json.loads(line) for line in f if line.strip()]


def pkt(ts: float = BASE_TS, src_ip="192.168.1.10", dst_ip="1.1.1.1", direction="outbound",
        transport="TCP", dst_port=443, src_port=40000, flags=None, length=60, **extra) -> dict:
    """Gói tin đã chuẩn hóa (định dạng packets_normalized) cho unit test."""
    packet = {
        "schema_version": 1, "ts": ts, "sensor_id": "test", "source": "pcap", "length": length,
        "src_ip": src_ip, "dst_ip": dst_ip, "direction": direction, "transport": transport,
        "src_port": src_port, "dst_port": dst_port, "src_mac": "aa:bb:cc:00:00:01",
    }
    if flags is not None:
        packet["tcp_flags"] = flags
    packet.update(extra)
    return {k: v for k, v in packet.items() if v is not None}


class FakeProducer:
    def __init__(self):
        self.messages: list[tuple[str, bytes, bytes]] = []

    def produce(self, topic, value=None, key=None, on_delivery=None):
        self.messages.append((topic, key, value))
        if on_delivery:
            on_delivery(None, None)

    def poll(self, timeout=0):
        return 0

    def flush(self, timeout=None):
        return 0

    def on(self, topic: str) -> list[dict]:
        return [json.loads(v) for t, _, v in self.messages if t == topic]


class FakeMessage:
    def __init__(self, value: bytes):
        self._value = value

    def error(self):
        return None

    def value(self):
        return self._value


class FakeConsumer:
    def __init__(self, values: list[bytes]):
        self.queue = [FakeMessage(v) for v in values]
        self.stored: list[FakeMessage] = []

    def consume(self, num_messages=1, timeout=None):
        batch, self.queue = self.queue[:num_messages], self.queue[num_messages:]
        return batch

    def store_offsets(self, message=None):
        self.stored.append(message)
