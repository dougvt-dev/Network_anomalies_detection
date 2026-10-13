"""Cấu hình của packet-normalizer.

Đọc từ biến môi trường, mặc định nạp thêm file `.env` ở thư mục gốc của service.
"""
import os
import socket
from pathlib import Path

from dotenv import load_dotenv

SERVICE_DIR = Path(__file__).resolve().parents[2]
load_dotenv(SERVICE_DIR / ".env")


def _env_list(name: str, default: str) -> list[str]:
    return [item.strip() for item in os.getenv(name, default).split(",") if item.strip()]


class Settings:
    INSTANCE_ID: str = os.getenv("INSTANCE_ID") or socket.gethostname()

    # Kafka
    KAFKA_BROKERS: str = os.getenv("KAFKA_BROKERS", "localhost:9092")
    KAFKA_RAW_TOPIC: str = os.getenv("KAFKA_RAW_TOPIC", "packets_raw")
    KAFKA_NORMALIZED_TOPIC: str = os.getenv("KAFKA_NORMALIZED_TOPIC", "packets_normalized")
    KAFKA_CONSUMER_GROUP: str = os.getenv("KAFKA_CONSUMER_GROUP", "packet-normalizer")
    KAFKA_TOPIC_PARTITIONS: int = int(os.getenv("KAFKA_TOPIC_PARTITIONS", "3"))
    KAFKA_REPLICATION_FACTOR: int = int(os.getenv("KAFKA_REPLICATION_FACTOR", "1"))
    KAFKA_NORMALIZED_RETENTION_MS: int = int(os.getenv("KAFKA_NORMALIZED_RETENTION_MS", str(3 * 24 * 3600 * 1000)))

    # Dải mạng nội bộ (phía LAN của gateway), dùng để xác định chiều traffic
    LAN_CIDRS: list[str] = _env_list(
        "LAN_CIDRS", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7,fe80::/10"
    )

    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")


settings = Settings()
