"""Cấu hình của packet-capture.

Đọc từ biến môi trường, mặc định nạp thêm file `.env` ở thư mục gốc của service.
"""
import os
import socket
from pathlib import Path

from dotenv import load_dotenv

SERVICE_DIR = Path(__file__).resolve().parents[2]
load_dotenv(SERVICE_DIR / ".env")


def _env_bool(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes")


class Settings:
    # Định danh máy thu (phân biệt khi có nhiều sensor)
    SENSOR_ID: str = os.getenv("SENSOR_ID") or socket.gethostname()

    # Nguồn capture: local (card mạng) | pcap (replay file)
    CAPTURE_SOURCE: str = os.getenv("CAPTURE_SOURCE", "local")
    CAPTURE_INTERFACE: str = os.getenv("CAPTURE_INTERFACE", "eth0")
    CAPTURE_BPF_FILTER: str = os.getenv("CAPTURE_BPF_FILTER", "")         # chỉ áp dụng cho live capture
    CAPTURE_DISPLAY_FILTER: str = os.getenv("CAPTURE_DISPLAY_FILTER", "")  # tshark -Y, áp dụng cho mọi nguồn
    CAPTURE_AUTOSTART: bool = _env_bool("CAPTURE_AUTOSTART")
    PCAP_FILE: str = os.getenv("PCAP_FILE", "")
    TSHARK_PATH: str = os.getenv("TSHARK_PATH", "tshark")
    RESTART_BACKOFF_MAX: float = float(os.getenv("RESTART_BACKOFF_MAX", "30"))

    # Kafka
    KAFKA_BROKERS: str = os.getenv("KAFKA_BROKERS", "localhost:9092")
    KAFKA_RAW_TOPIC: str = os.getenv("KAFKA_RAW_TOPIC", "packets_raw")
    KAFKA_TOPIC_PARTITIONS: int = int(os.getenv("KAFKA_TOPIC_PARTITIONS", "3"))
    KAFKA_REPLICATION_FACTOR: int = int(os.getenv("KAFKA_REPLICATION_FACTOR", "1"))
    KAFKA_RAW_RETENTION_MS: int = int(os.getenv("KAFKA_RAW_RETENTION_MS", str(6 * 3600 * 1000)))

    # API điều khiển capture
    API_HOST: str = os.getenv("API_HOST", "0.0.0.0")
    API_PORT: int = int(os.getenv("API_PORT", "5001"))
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")


settings = Settings()
