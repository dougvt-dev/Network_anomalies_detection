import json

from conftest import FakeConsumer, FakeProducer, load_normalized_fixture
from detection.engine import DetectionEngine
from detection.main import DetectionWorker


def test_worker_publishes_anomalies_features_and_stores_offsets(cfg):
    values = [json.dumps(p).encode() for p in load_normalized_fixture()] + [b"not json", b"[1, 2]"]
    consumer, producer = FakeConsumer(values), FakeProducer()
    worker = DetectionWorker(consumer, producer, DetectionEngine(cfg), anomaly_topic="anomalies",
                             features_topic="host_features")

    while worker.run_batch(timeout=0):
        pass
    worker.publish(worker.engine.flush())      # như khi dừng service

    assert worker.stats["invalid"] == 2
    assert len(consumer.stored) == len(values)  # mọi message đều được lưu offset sau khi xử lý

    anomalies = producer.on("anomalies")
    assert {a["category"] for a in anomalies} >= {"port_scan", "arp_spoofing", "dga"}
    keys = {k for t, k, _ in producer.messages if t == "anomalies"}
    assert b"192.168.1.66" in keys                # key = thiết bị bất thường

    features = producer.on("host_features")
    assert features and all(f["schema_version"] == 1 and "metrics" in f for f in features)


def test_worker_without_features_topic(cfg):
    consumer, producer = FakeConsumer([json.dumps(p).encode() for p in load_normalized_fixture()]), FakeProducer()
    worker = DetectionWorker(consumer, producer, DetectionEngine(cfg), anomaly_topic="anomalies")
    while worker.run_batch(timeout=0):
        pass
    worker.publish(worker.engine.flush())
    assert {t for t, _, _ in producer.messages} == {"anomalies"}
