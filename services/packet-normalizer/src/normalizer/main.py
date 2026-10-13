"""Normalizer worker: Kafka packets_raw → chuẩn hóa → Kafka packets_normalized.

Chạy (từ thư mục src/):  python -m normalizer.main
Scale ngang bằng cách chạy nhiều instance cùng KAFKA_CONSUMER_GROUP.
"""
import json
import logging
import signal
import time

from common.config import settings
from common.kafka import ensure_topics, make_consumer, make_producer
from common.log import setup_logging
from normalizer.normalizer import NormalizationError, PacketNormalizer, device_key

logger = logging.getLogger(__name__)

BATCH_SIZE = 500
REPORT_INTERVAL = 30.0


class NormalizerWorker:

    def __init__(self, consumer, producer, normalizer: PacketNormalizer, output_topic: str):
        self.consumer = consumer
        self.producer = producer
        self.normalizer = normalizer
        self.output_topic = output_topic
        self.running = True
        self.stats = {"consumed": 0, "produced": 0, "invalid": 0, "kafka_errors": 0}

    def process_value(self, value: bytes) -> tuple[bytes, bytes] | None:
        """Chuẩn hóa một message raw. Trả về (key, value) để publish, None nếu message không hợp lệ."""
        try:
            packet = self.normalizer.normalize(json.loads(value))
        except (ValueError, NormalizationError) as e:
            self.stats["invalid"] += 1
            logger.debug(f"Invalid raw message: {e}")
            return None
        # Key theo thiết bị LAN: mọi traffic của một thiết bị vào cùng partition
        return device_key(packet).encode(), packet.model_dump_json(exclude_none=True).encode()

    def run_batch(self, timeout: float = 1.0) -> int:
        messages = self.consumer.consume(num_messages=BATCH_SIZE, timeout=timeout)
        processed = []
        for msg in messages:
            if msg.error():
                self.stats["kafka_errors"] += 1
                logger.warning(f"Consumer error: {msg.error()}")
                continue
            self.stats["consumed"] += 1
            result = self.process_value(msg.value())
            if result:
                key, value = result
                self._produce(key, value)
            processed.append(msg)

        if processed:
            # Chỉ lưu offset khi output đã được Kafka xác nhận (at-least-once)
            remaining = self.producer.flush(10)
            if remaining:
                raise RuntimeError(f"{remaining} normalized messages not delivered, will reprocess batch")
            for msg in processed:
                self.consumer.store_offsets(message=msg)
        return len(processed)

    def run(self) -> None:
        last_report = time.monotonic()
        while self.running:
            self.run_batch()
            if time.monotonic() - last_report >= REPORT_INTERVAL:
                logger.info(f"Normalizer stats: {self.stats}")
                last_report = time.monotonic()

    def _produce(self, key: bytes, value: bytes) -> None:
        while True:
            try:
                self.producer.produce(self.output_topic, value=value, key=key, on_delivery=self._on_delivery)
                return
            except BufferError:
                self.producer.poll(0.1)

    def _on_delivery(self, err, msg) -> None:
        if err is None:
            self.stats["produced"] += 1
        else:
            self.stats["kafka_errors"] += 1
            logger.warning(f"Delivery failed: {err}")


def main() -> None:
    setup_logging()
    # Topic packets_raw do packet-capture tạo; service này chỉ tạo topic đầu ra của mình
    ensure_topics({settings.KAFKA_NORMALIZED_TOPIC: settings.KAFKA_NORMALIZED_RETENTION_MS})
    consumer = make_consumer(settings.KAFKA_CONSUMER_GROUP, [settings.KAFKA_RAW_TOPIC])
    producer = make_producer(f"packet-normalizer-{settings.INSTANCE_ID}")
    worker = NormalizerWorker(
        consumer, producer, PacketNormalizer(settings.LAN_CIDRS), settings.KAFKA_NORMALIZED_TOPIC
    )

    def _shutdown(signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        worker.running = False

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    logger.info(f"Normalizer started: {settings.KAFKA_RAW_TOPIC} -> {settings.KAFKA_NORMALIZED_TOPIC}")
    try:
        worker.run()
    finally:
        producer.flush(10)
        consumer.close()
        logger.info(f"Normalizer stopped: {worker.stats}")


if __name__ == "__main__":
    main()
