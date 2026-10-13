"""Phân tích cảnh báo (JSONL, định dạng topic anomalies) từ stdin và in đề xuất ra stdout. Không cần Kafka/Telegram.

Dùng để đánh giá LLM / chính sách trên dữ liệu có sẵn:
    python -m agent.dump < ../tests/fixtures/anomalies.jsonl
    LLM_PROVIDER=vllm LLM_MODEL=... python -m agent.dump --json < anomalies.jsonl
"""
import argparse
import asyncio
import sys
import time

import yaml

from agent.analyst import Analyst
from agent.llm import create_llm_client
from agent.notifier import proposal_text
from agent.reporting import ReportStore
from agent.service import AgentService, parse_message
from common.config import settings


class _NullProducer:
    def produce(self, *args, **kwargs):
        pass

    def flush(self, timeout=None):
        return 0


class _NullNotifier:
    async def send_proposal(self, proposal):
        return None

    async def update_proposal(self, proposal):
        pass

    async def send_text(self, text):
        pass


async def run(args) -> None:
    with open(args.config) as f:
        cfg = yaml.safe_load(f)
    llm = None if args.no_llm else create_llm_client(
        settings.LLM_PROVIDER, settings.LLM_MODEL, settings.LLM_BASE_URL, settings.LLM_API_KEY,
        settings.LLM_TIMEOUT_SECONDS, settings.LLM_TEMPERATURE, settings.LLM_MAX_TOKENS, settings.LLM_RESPONSE_FORMAT, settings.LLM_EXTRA_BODY)
    service = AgentService(cfg, Analyst(llm), _NullNotifier(), _NullProducer(), "decisions",
                           ReportStore("/dev/null"))
    for line in sys.stdin:
        doc = parse_message(line.encode()) if line.strip() else None
        if doc:
            await service.handle_anomaly(doc)

    while not service.queue.empty():
        _, _, incident_id = service.queue.get_nowait()
        started = time.monotonic()
        proposal = await service.process_incident(incident_id)
        took = time.monotonic() - started
        if args.json:
            print(proposal.model_dump_json())
        else:
            print(proposal_text(proposal))
            print(f"[analysis took {took:.1f}s{' — ' + proposal.analysis.note if proposal.analysis.note else ''}]")
            print("=" * 80)
    if llm:
        await llm.aclose()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default=settings.AGENT_CONFIG)
    parser.add_argument("--no-llm", action="store_true", help="chỉ dùng mẫu văn bản")
    parser.add_argument("--json", action="store_true", help="in Proposal dạng JSON")
    asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    main()
