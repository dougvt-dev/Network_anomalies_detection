"""Cấu hình của ai-agent: kết nối (Kafka, LLM, Telegram, API). Chính sách xử lý nằm ở config/agent.yaml.

Đọc từ biến môi trường, mặc định nạp thêm file `.env` ở thư mục gốc của service.
"""
import json
import os
import socket
from pathlib import Path

from dotenv import load_dotenv

SERVICE_DIR = Path(__file__).resolve().parents[2]
load_dotenv(SERVICE_DIR / ".env")


def _env_json(name: str) -> dict:
    value = os.getenv(name, "").strip()
    if not value:
        return {}
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise ValueError(f"{name} must be a JSON object")
    return parsed


def _env_list(name: str) -> list[str]:
    return [item.strip() for item in os.getenv(name, "").split(",") if item.strip()]


class Settings:
    INSTANCE_ID: str = os.getenv("INSTANCE_ID") or socket.gethostname()

    # Kafka
    KAFKA_BROKERS: str = os.getenv("KAFKA_BROKERS", "localhost:9092")
    KAFKA_ANOMALY_TOPIC: str = os.getenv("KAFKA_ANOMALY_TOPIC", "anomalies")
    KAFKA_DECISION_TOPIC: str = os.getenv("KAFKA_DECISION_TOPIC", "decisions")
    KAFKA_ACTION_RESULT_TOPIC: str = os.getenv("KAFKA_ACTION_RESULT_TOPIC", "action_results")
    KAFKA_CONSUMER_GROUP: str = os.getenv("KAFKA_CONSUMER_GROUP", "ai-agent")
    KAFKA_TOPIC_PARTITIONS: int = int(os.getenv("KAFKA_TOPIC_PARTITIONS", "3"))
    KAFKA_REPLICATION_FACTOR: int = int(os.getenv("KAFKA_REPLICATION_FACTOR", "1"))
    KAFKA_DECISION_RETENTION_MS: int = int(os.getenv("KAFKA_DECISION_RETENTION_MS", str(30 * 24 * 3600 * 1000)))

    # LLM — mọi server có API tương thích OpenAI (Ollama, vLLM, ...). Đổi server chỉ cần đổi các biến này.
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "ollama")            # ollama | vllm | openai_compat | none
    LLM_BASE_URL: str = os.getenv("LLM_BASE_URL", "")                  # trống = mặc định theo provider
    LLM_MODEL: str = os.getenv("LLM_MODEL", "gemma:latest")
    LLM_API_KEY: str = os.getenv("LLM_API_KEY", "")
    LLM_TIMEOUT_SECONDS: float = float(os.getenv("LLM_TIMEOUT_SECONDS") or 90)
    LLM_TEMPERATURE: float = float(os.getenv("LLM_TEMPERATURE") or 0.2)
    LLM_MAX_TOKENS: int = int(os.getenv("LLM_MAX_TOKENS") or 600)
    LLM_RESPONSE_FORMAT: str = os.getenv("LLM_RESPONSE_FORMAT", "json_schema")   # json_schema | json_object | none
    # Tham số riêng của server (JSON), vd tắt thinking: Ollama {"reasoning_effort": "none"},
    # vLLM + Qwen {"chat_template_kwargs": {"enable_thinking": false}}
    LLM_EXTRA_BODY: dict = _env_json("LLM_EXTRA_BODY")

    # Telegram (để trống token = không gửi Telegram, chỉ in thông báo ra log)
    TELEGRAM_BOT_TOKEN: str = os.getenv("TELEGRAM_BOT_TOKEN", "")
    TELEGRAM_CHAT_ID: str = os.getenv("TELEGRAM_CHAT_ID", "")           # nơi nhận đề xuất
    TELEGRAM_ADMIN_IDS: list[str] = _env_list("TELEGRAM_ADMIN_IDS")    # user ID được phép duyệt / ra lệnh

    # API (duyệt đề xuất, xem report). Để trống token = tắt các API thay đổi trạng thái.
    API_HOST: str = os.getenv("API_HOST", "127.0.0.1")
    API_PORT: int = int(os.getenv("API_PORT", "5003"))
    API_TOKEN: str = os.getenv("API_TOKEN", "")

    AGENT_CONFIG: str = os.getenv("AGENT_CONFIG") or str(SERVICE_DIR / "config" / "agent.yaml")
    REPORT_DIR: str = os.getenv("REPORT_DIR") or str(SERVICE_DIR / "reports")
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")


settings = Settings()
