"""Helper tạo Kafka producer/consumer (confluent-kafka) và khởi tạo topic."""
import logging

from confluent_kafka import Consumer, KafkaException, Producer
from confluent_kafka.admin import AdminClient, NewTopic

from common.config import settings

logger = logging.getLogger(__name__)


def make_producer(client_id: str) -> Producer:
    return Producer({
        "bootstrap.servers": settings.KAFKA_BROKERS,
        "client.id": client_id,
        "enable.idempotence": True,
        "compression.type": "lz4",
        "linger.ms": 50,
        "batch.num.messages": 10000,
        "queue.buffering.max.messages": 200000,
    })


def make_consumer(group_id: str, topics: list[str]) -> Consumer:
    consumer = Consumer({
        "bootstrap.servers": settings.KAFKA_BROKERS,
        "group.id": group_id,
        "auto.offset.reset": "earliest",
        # Chỉ lưu offset sau khi đã xử lý xong message (at-least-once)
        "enable.auto.offset.store": False,
        "enable.auto.commit": True,
    })
    consumer.subscribe(topics)
    return consumer


def ensure_topics(retention_by_topic: dict[str, int], timeout: float = 10.0) -> None:
    """Tạo topic nếu chưa có, kèm retention.ms. Không raise nếu Kafka chưa sẵn sàng."""
    admin = AdminClient({"bootstrap.servers": settings.KAFKA_BROKERS})
    try:
        existing = set(admin.list_topics(timeout=timeout).topics)
    except KafkaException as e:
        logger.warning(f"Cannot reach Kafka at {settings.KAFKA_BROKERS} to check topics: {e}")
        return

    new_topics = [
        NewTopic(
            name,
            num_partitions=settings.KAFKA_TOPIC_PARTITIONS,
            replication_factor=settings.KAFKA_REPLICATION_FACTOR,
            config={"retention.ms": str(retention_ms)},
        )
        for name, retention_ms in retention_by_topic.items()
        if name not in existing
    ]
    if not new_topics:
        return

    for name, future in admin.create_topics(new_topics).items():
        try:
            future.result()
            logger.info(f"Created Kafka topic '{name}'")
        except KafkaException as e:
            # Topic có thể đã được service khác tạo cùng lúc
            logger.warning(f"Create topic '{name}' failed: {e}")
