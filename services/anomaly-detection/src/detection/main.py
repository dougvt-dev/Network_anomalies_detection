"""Anomaly detection worker: Kafka packets_normalized → DetectionEngine → Kafka anomalies (+ host_features).

Chạy (từ thư mục src/):  python -m detection.main
"""
import json
import logging
import signal
import time

from common.config import settings
from common.kafka import ensure_topics, make_consumer, make_producer
from common.log import setup_logging
from detection.engine import DetectionEngine, EngineOutput, load_detection_config

logger = logging.getLogger(__name__)

BATCH_SIZE = 500
REPORT_INTERVAL = 60.0


class DetectionWorker:

    def __init__(self, consumer, producer, engine: DetectionEngine, anomaly_topic: str,
                 features_topic: str = "", idle_flush_seconds: float = 90.0):
        self.consumer = consumer
        self.producer = producer
        self.engine = engine
        self.anomaly_topic = anomaly_topic
        self.features_topic = features_topic
        self.idle_flush_seconds = idle_flush_seconds
        self.running = True
        self.stats = {"consumed": 0, "invalid": 0, "anomalies": 0, "features": 0, "kafka_errors": 0}
        self._last_message_at = time.monotonic()

    def process_value(self, value: bytes) -> None:
        try:
            packet = json.loads(value)
        except ValueError:
            packet = None
        if not isinstance(packet, dict):
            self.stats["invalid"] += 1
            return
        self.engine.ingest(packet)

    def run_batch(self, timeout: float = 1.0) -> int:
        messages = self.consumer.consume(num_messages=BATCH_SIZE, timeout=timeout)
        processed = []
        for msg in messages:
            if msg.error():
                self.stats["kafka_errors"] += 1
                logger.warning(f"Consumer error: {msg.error()}")
                continue
            self.stats["consumed"] += 1
            self.process_value(msg.value())
            processed.append(msg)

        if processed:
            self._last_message_at = time.monotonic()
            self.publish(self.engine.advance())
        elif self.engine.has_open_windows and time.monotonic() - self._last_message_at > self.idle_flush_seconds:
            # Live capture tạm ngừng: không có gói mới để đẩy event time, đóng cửa sổ theo giờ thật
            self.publish(self.engine.flush())

        if processed:
            remaining = self.producer.flush(10)
            if remaining:
                raise RuntimeError(f"{remaining} messages not delivered, will reprocess batch")
            # Lưu ý: gói thuộc cửa sổ chưa đóng đã được commit; worker dừng đột ngột thì cửa sổ đó bị mất
            for msg in processed:
                self.consumer.store_offsets(message=msg)
        return len(processed)

    def publish(self, output: EngineOutput) -> None:
        for anomaly in output.anomalies:
            key = anomaly.entity.ip or anomaly.entity.mac or ""
            self._produce(self.anomaly_topic, key, anomaly.model_dump_json(exclude_none=True))
            self.stats["anomalies"] += 1
            logger.info(f"ANOMALY [{anomaly.severity}] {anomaly.category} {key}: {anomaly.summary}")
        if self.features_topic:
            for features in output.features:
                self._produce(self.features_topic, features.host, json.dumps(features.to_record()))
                self.stats["features"] += 1

    def run(self) -> None:
        last_report = time.monotonic()
        while self.running:
            self.run_batch()
            if time.monotonic() - last_report >= REPORT_INTERVAL:
                logger.info(f"Detection stats: {self.stats}, engine: {dict(self.engine.stats)}")
                last_report = time.monotonic()

    def _produce(self, topic: str, key: str, value: str) -> None:
        while True:
            try:
                self.producer.produce(topic, value=value.encode(), key=key.encode(), on_delivery=self._on_delivery)
                return
            except BufferError:
                self.producer.poll(0.1)

    def _on_delivery(self, err, msg) -> None:
        if err is not None:
            self.stats["kafka_errors"] += 1
            logger.warning(f"Delivery failed: {err}")


def main() -> None:
    setup_logging()
    cfg = load_detection_config(settings.DETECTION_CONFIG)
    topics = {settings.KAFKA_ANOMALY_TOPIC: settings.KAFKA_ANOMALY_RETENTION_MS}
    if settings.KAFKA_FEATURES_TOPIC:
        topics[settings.KAFKA_FEATURES_TOPIC] = settings.KAFKA_FEATURES_RETENTION_MS
    ensure_topics(topics)

    consumer = make_consumer(settings.KAFKA_CONSUMER_GROUP, [settings.KAFKA_INPUT_TOPIC])
    producer = make_producer(f"anomaly-detection-{settings.INSTANCE_ID}")
    worker = DetectionWorker(
        consumer, producer, DetectionEngine(cfg),
        anomaly_topic=settings.KAFKA_ANOMALY_TOPIC,
        features_topic=settings.KAFKA_FEATURES_TOPIC,
        idle_flush_seconds=cfg["window"]["idle_flush_seconds"],
    )

    def _shutdown(signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        worker.running = False

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    logger.info(f"Anomaly detection started: {settings.KAFKA_INPUT_TOPIC} -> {settings.KAFKA_ANOMALY_TOPIC}")
    try:
        worker.run()
    finally:
        worker.publish(worker.engine.flush())
        producer.flush(10)
        consumer.close()
        logger.info(f"Anomaly detection stopped: {worker.stats}")


if __name__ == "__main__":
    main()
