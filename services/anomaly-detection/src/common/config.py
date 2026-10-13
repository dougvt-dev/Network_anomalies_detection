"""Cấu hình của anomaly-detection (kết nối, topic). Ngưỡng phát hiện nằm ở config/detection.yaml.

Đọc từ biến môi trường, mặc định nạp thêm file `.env` ở thư mục gốc của service.
"""
import os
import socket
from pathlib import Path

from dotenv import load_dotenv

SERVICE_DIR = Path(__file__).resolve().parents[2]
load_dotenv(SERVICE_DIR / ".env")


class Settings:
    INSTANCE_ID: str = os.getenv("INSTANCE_ID") or socket.gethostname()

    # Kafka
    KAFKA_BROKERS: str = os.getenv("KAFKA_BROKERS", "localhost:9092")
    KAFKA_INPUT_TOPIC: str = os.getenv("KAFKA_INPUT_TOPIC", "packets_normalized")
    KAFKA_ANOMALY_TOPIC: str = os.getenv("KAFKA_ANOMALY_TOPIC", "anomalies")
    # Hồ sơ hành vi theo cửa sổ (dữ liệu train ML về sau). Để trống để tắt.
    KAFKA_FEATURES_TOPIC: str = os.getenv("KAFKA_FEATURES_TOPIC", "host_features")
    KAFKA_CONSUMER_GROUP: str = os.getenv("KAFKA_CONSUMER_GROUP", "anomaly-detection")
    KAFKA_TOPIC_PARTITIONS: int = int(os.getenv("KAFKA_TOPIC_PARTITIONS", "3"))
    KAFKA_REPLICATION_FACTOR: int = int(os.getenv("KAFKA_REPLICATION_FACTOR", "1"))
    KAFKA_ANOMALY_RETENTION_MS: int = int(os.getenv("KAFKA_ANOMALY_RETENTION_MS", str(30 * 24 * 3600 * 1000)))
    KAFKA_FEATURES_RETENTION_MS: int = int(os.getenv("KAFKA_FEATURES_RETENTION_MS", str(7 * 24 * 3600 * 1000)))

    # File ngưỡng phát hiện
    DETECTION_CONFIG: str = os.getenv("DETECTION_CONFIG") or str(SERVICE_DIR / "config" / "detection.yaml")

    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")


settings = Settings()
