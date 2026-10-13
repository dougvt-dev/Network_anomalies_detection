import shutil

import pytest

from sample_packets import MAC_CLIENT, write_sample_pcap

requires_tshark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark is not installed")

__all__ = ["MAC_CLIENT", "requires_tshark"]


@pytest.fixture(scope="session")
def sample_pcap(tmp_path_factory) -> str:
    """File pcap 7 gói mẫu (xem sample_packets.py)."""
    return write_sample_pcap(str(tmp_path_factory.mktemp("pcap") / "sample.pcap"))


class FakeProducer:
    """Thay confluent_kafka.Producer trong test: lưu message vào list, xác nhận ngay khi poll/flush."""

    def __init__(self):
        self.messages: list[tuple[str, bytes, bytes]] = []
        self._pending = []

    def produce(self, topic, value=None, key=None, on_delivery=None):
        self.messages.append((topic, key, value))
        if on_delivery:
            self._pending.append(on_delivery)

    def poll(self, timeout=0):
        pending, self._pending = self._pending, []
        for callback in pending:
            callback(None, None)
        return len(pending)

    def flush(self, timeout=None):
        self.poll()
        return 0


@pytest.fixture
def fake_producer() -> FakeProducer:
    return FakeProducer()
