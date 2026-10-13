"""AI agent: Kafka anomalies → phân tích → xin duyệt (Telegram / API) → Kafka decisions.

Chạy (từ thư mục src/):  python -m agent.main
Các tác vụ chạy song song trong một event loop: đọc Kafka, phân tích (LLM), Telegram polling, định kỳ, API.
"""
import asyncio
import logging
import signal

import uvicorn
import yaml

from agent.analyst import Analyst
from agent.api import create_app
from agent.llm import create_llm_client
from agent.notifier import ConsoleNotifier, TelegramNotifier
from agent.reporting import ReportStore
from agent.service import AgentService, parse_message
from common.config import settings
from common.kafka import ensure_topics, make_consumer, make_producer
from common.log import setup_logging

logger = logging.getLogger(__name__)


def build_notifier():
    if settings.TELEGRAM_BOT_TOKEN:
        if not settings.TELEGRAM_CHAT_ID or not settings.TELEGRAM_ADMIN_IDS:
            raise SystemExit("TELEGRAM_CHAT_ID and TELEGRAM_ADMIN_IDS are required when TELEGRAM_BOT_TOKEN is set")
        return TelegramNotifier(settings.TELEGRAM_BOT_TOKEN, settings.TELEGRAM_CHAT_ID, settings.TELEGRAM_ADMIN_IDS)
    logger.warning("TELEGRAM_BOT_TOKEN not set: notifications go to the log, approve via API")
    return ConsoleNotifier()


async def consume_loop(consumer, service: AgentService) -> None:
    while True:
        messages = await asyncio.to_thread(consumer.consume, 100, 1.0)
        for msg in messages:
            if msg.error():
                logger.warning(f"Consumer error: {msg.error()}")
                continue
            doc = parse_message(msg.value())
            if doc is None:
                service.stats["invalid_messages"] += 1
            elif msg.topic() == settings.KAFKA_ACTION_RESULT_TOPIC:
                await service.handle_action_result(doc)
            else:
                await service.handle_anomaly(doc)


async def run() -> None:
    setup_logging()
    with open(settings.AGENT_CONFIG) as f:
        cfg = yaml.safe_load(f)

    llm = create_llm_client(settings.LLM_PROVIDER, settings.LLM_MODEL, settings.LLM_BASE_URL, settings.LLM_API_KEY,
                            settings.LLM_TIMEOUT_SECONDS, settings.LLM_TEMPERATURE, settings.LLM_MAX_TOKENS,
                            settings.LLM_RESPONSE_FORMAT, settings.LLM_EXTRA_BODY)
    logger.info(f"LLM: {settings.LLM_PROVIDER} model={settings.LLM_MODEL if llm else '-'}")

    await asyncio.to_thread(ensure_topics, {settings.KAFKA_DECISION_TOPIC: settings.KAFKA_DECISION_RETENTION_MS})
    consumer = make_consumer(settings.KAFKA_CONSUMER_GROUP,
                             [settings.KAFKA_ANOMALY_TOPIC, settings.KAFKA_ACTION_RESULT_TOPIC])
    producer = make_producer(f"ai-agent-{settings.INSTANCE_ID}")
    notifier = build_notifier()
    service = AgentService(cfg, Analyst(llm, cfg["analysis"]["use_llm"]), notifier, producer,
                           settings.KAFKA_DECISION_TOPIC,
                           ReportStore(settings.REPORT_DIR, cfg["reports"]["keep_days"]))

    api = uvicorn.Server(uvicorn.Config(create_app(service, settings.API_TOKEN), host=settings.API_HOST,
                                        port=settings.API_PORT, log_level=settings.LOG_LEVEL.lower()))
    api.install_signal_handlers = lambda: None          # tín hiệu do vòng lặp chính xử lý
    tasks = [
        asyncio.create_task(consume_loop(consumer, service), name="kafka"),
        asyncio.create_task(service.analysis_worker(), name="analysis"),
        asyncio.create_task(service.tick_loop(), name="tick"),
        asyncio.create_task(api.serve(), name="api"),
    ]
    if isinstance(notifier, TelegramNotifier):
        tasks.append(asyncio.create_task(notifier.run_polling(service), name="telegram"))

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    logger.info(f"AI agent started: {settings.KAFKA_ANOMALY_TOPIC} -> {settings.KAFKA_DECISION_TOPIC}, "
                f"API http://{settings.API_HOST}:{settings.API_PORT}")

    done_task = asyncio.create_task(stop.wait())
    finished, _ = await asyncio.wait([done_task, *tasks], return_when=asyncio.FIRST_COMPLETED)
    for task in finished:
        if task is not done_task and task.exception():
            logger.error(f"Task {task.get_name()} crashed: {task.exception()!r}")

    logger.info("Shutting down AI agent...")
    api.should_exit = True
    for task in tasks:
        if task.get_name() != "api":
            task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    producer.flush(10)
    consumer.close()
    if llm:
        await llm.aclose()
    logger.info(f"AI agent stopped: {dict(service.stats)}")


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
